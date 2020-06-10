import errno
import logging
import os
import grp
import re
import random
import shutil
import stat
import sys
import time
from typing import Set
import hashlib
import urllib
from pathlib import Path
from signal import getsignal, signal, SIG_DFL, SIGPIPE
from subprocess import PIPE, STDOUT, DEVNULL, TimeoutExpired, run
import magic

from .config import Config
from .util import (ARCHIVE_7Z,
                   ARCHIVE_BZ2,
                   ARCHIVE_GZ,
                   ARCHIVE_LZOP,
                   ARCHIVE_TAR,
                   ARCHIVE_UNKNOWN,
                   ARCHIVE_XZ,
                   ARCHIVE_ZIP,
                   ftp_init,
                   ftp_close,
                   human_readable_size,
                   splitFilename)

# filename: max_size (<= 0 unlimited)
ALLOWED_FILES = {
    "coredump": 0,
    "executable": 512,
    "package": 128,
    "packages": (1 << 20),  # 1MB
    "os_release": 128,
    "os_release_in_rootdir": 128,
    "rootdir": 256,
    "release": 128,
    "vmcore": 0,
    "vmcore.vmem": 0,
}

TASK_RETRACE, TASK_DEBUG, TASK_VMCORE, TASK_RETRACE_INTERACTIVE, \
  TASK_VMCORE_INTERACTIVE = range(5)

TASK_TYPES = [TASK_RETRACE, TASK_DEBUG, TASK_VMCORE,
              TASK_RETRACE_INTERACTIVE, TASK_VMCORE_INTERACTIVE]

REQUIRED_FILES = {
    TASK_RETRACE:             ["coredump", "executable", "package"],
    TASK_DEBUG:               ["coredump", "executable", "package"],
    TASK_VMCORE:              ["vmcore"],
    TASK_RETRACE_INTERACTIVE: ["coredump", "executable", "package"],
    TASK_VMCORE_INTERACTIVE:  ["vmcore"],
}

SUFFIX_MAP = {
    ARCHIVE_GZ: ".gz",
    ARCHIVE_BZ2: ".bz2",
    ARCHIVE_XZ: ".xz",
    ARCHIVE_ZIP: ".zip",
    ARCHIVE_7Z: ".7z",
    ARCHIVE_TAR: ".tar",
    ARCHIVE_LZOP: ".lzop",
    ARCHIVE_UNKNOWN: "",
}

SNAPSHOT_SUFFIXES = [".vmss", ".vmsn", ".vmem"]

BUGZILLA_STATUS = ["NEW", "ASSIGNED", "ON_DEV", "POST", "MODIFIED", "ON_QA", "VERIFIED",
                   "RELEASE_PENDING", "CLOSED"]

CORE_ARCH_PARSER = re.compile(r"core file,? .*(x86-64|80386|ARM|aarch64|IBM S/390|64-bit PowerPC)")
PACKAGE_PARSER = re.compile(r"^(.+)-([0-9]+(\.[0-9]+)*-[0-9]+)\.([^-]+)$")

REPODIR_NAME_PARSER = re.compile(r"^[^\-]+\-[^\-]+\-[^\-]+$")

KO_DEBUG_PARSER = re.compile(r"^.*/([a-zA-Z0-9_\-]+)\.ko\.debug$")

WORKER_RUNNING_PARSER = re.compile(r"^[ \t]*([0-9]+)[ \t]+[0-9]+[ \t]+([^ ^\t]+)[ \t]"
                                   r"+.*retrace-server-worker ([0-9]+)( .*)?$")

MD5_PARSER = re.compile(r"[a-fA-F0-9]{32}")


REPO_PREFIX = "retrace-"
EXPLOITABLE_SEPARATOR = "== EXPLOITABLE =="

TASKPASS_ALPHABET = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"


STATUS_ANALYZE, STATUS_INIT, STATUS_BACKTRACE, STATUS_CLEANUP, \
    STATUS_STATS, STATUS_FINISHING, STATUS_SUCCESS, STATUS_FAIL, \
    STATUS_DOWNLOADING, STATUS_POSTPROCESS, STATUS_CALCULATING_MD5SUM = range(11)

STATUS = [
    "Analyzing crash data",
    "Preparing environment for backtrace generation",
    "Generating backtrace",
    "Cleaning environment after backtrace generation",
    "Saving crash statistics",
    "Finishing task",
    "Retrace job finished successfully",
    "Retrace job failed",
    "Downloading remote resources",
    "Post-processing downloaded file",
    "Calculating md5sum",
]

ARCHITECTURES = {"src", "noarch", "i386", "i486", "i586", "i686", "x86_64",
                 "s390", "s390x", "ppc", "ppc64", "ppc64le", "ppc64iseries",
                 "armel", "armhfp", "armv5tel", "armv7l", "armv7hl",
                 "armv7hnl", "aarch64", "sparc", "sparc64", "mips4kec",
                 "ia64"}

# armhfp is not correct, but there is no way to distinguish armv5/armv6/armv7 coredumps
# as armhfp (RPM armv7hl) is the only supported now, let's approximate arm = armhfp

# "arm" has been intentionally removed - when guessing architecture, it matches
# "alarm" or "hdparm" and thus leads to wrong results.
# As soon as plain "arm" needs to be supported, this needs to be solved properly.
ARCH_MAP = {
    "i386": {"i386", "i486", "i586", "i686"},
    "armhfp": {"armhfp", "armel", "armv5tel", "armv7l", "armv7hl", "armv7hnl"},
    "x86_64": {"x86_64"},
    "s390x": {"s390x"},
    "ppc64": {"ppc64"},
    "ppc64le": {"ppc64le"},
    "aarch64": {"aarch64"},
}

PYTHON_LABEL_START = "----------PYTHON-START--------"
PYTHON_LABEL_END = "----------PYTHON--END---------"

RETRACE_GPG_KEYS = "/usr/share/distribution-gpg-keys/"


class RetraceError(Exception):
    pass


class RetraceWorkerError(RetraceError):
    def __init__(self, message=None, errorcode=1):
        super(RetraceWorkerError, self).__init__(message)
        self.errorcode = errorcode


logger = logging.getLogger(__name__)


def log_info(msg):
    logger.info(msg)


def log_debug(msg):
    logger.debug(msg)


def log_warn(msg):
    logger.warn(msg)


def log_error(msg):
    logger.error(msg)


def get_canon_arch(arch):
    for canon_arch, derived_archs in ARCH_MAP.items():
        if arch in derived_archs:
            return canon_arch

    return arch


def guess_arch(coredump_path):
    output = run(["file", coredump_path], stdout=PIPE, encoding='utf-8').stdout
    match = CORE_ARCH_PARSER.search(output)
    if match:
        if match.group(1) == "80386":
            return "i386"
        if match.group(1) == "x86-64":
            return "x86_64"
        if match.group(1) == "ARM":
            # hack - There is no reliable way to determine which ARM
            # version the coredump is. At the moment we only support
            # armv7hl / armhfp - let's approximate arm = armhfp
            return "armhfp"
        if match.group(1) == "aarch64":
            return "aarch64"
        if match.group(1) == "IBM S/390":
            return "s390x"
        if match.group(1) == "64-bit PowerPC":
            if "LSB" in output:
                return "ppc64le"

            return "ppc64"

    result = None
    lines = run(["strings", coredump_path], stdout=PIPE, stderr=STDOUT, encoding='utf-8').stdout.splitlines()
    for line in lines:
        for canon_arch, derived_archs in ARCH_MAP.items():
            if any(arch in line for arch in derived_archs):
                result = canon_arch
                break

        if result is not None:
            break

    # "ppc64le" matches both ppc64 and ppc64le
    # if file magic says little endian, fix it
    if result == "ppc64" and "LSB" in output:
        result = "ppc64le"

    return result


def get_supported_releases():
    result = []
    for f in Path(CONFIG["RepoDir"]).iterdir():
        if not f.is_dir():
            continue

        if REPODIR_NAME_PARSER.match(f.name) and Path(f, "repodata").is_dir():
            result.append(f.name)

    return result


def run_gdb(savedir, plugin, repopath, taskid=None):
    # exception is caught on the higher level
    savedir = Path(savedir)
    exec_file = open(savedir / "crash" / "executable", "r")
    executable = exec_file.read(ALLOWED_FILES["executable"])
    exec_file.close()

    if '"' in executable or "'" in executable:
        raise Exception("Executable contains forbidden characters")

    if CONFIG["RetraceEnvironment"] == "mock":
        output = run(["/usr/bin/mock", "chroot", "--configdir", savedir,
                      "--", "ls '%s'" % executable], stdout=PIPE, stderr=DEVNULL, encoding='utf-8').stdout
        if output.strip() != executable:
            raise Exception("The appropriate package set could not be installed")

        child = run(["/usr/bin/mock", "chroot", "--configdir", savedir,
                     "--", "/bin/chmod a+r '%s'" % executable], stdout=DEVNULL)
        if child.returncode:
            raise Exception("Unable to chmod the executable")

    batfile = savedir / "gdb.sh"
    with batfile.open(mode="w") as gdbfile:
        gdbfile.write("#!/usr/bin/sh\n\n%s -batch "
                      "-ex 'python exec(open(\"/usr/libexec/abrt-gdb-exploitable\").read())' \\\n"
                      "                    -ex 'file %s' \\\n"
                      "                    -ex 'core-file /var/spool/abrt/crash/coredump' \\\n"
                      "                    -ex 'echo %s\\n' \\\n"
                      "                    -ex 'py-bt' \\\n"
                      "                    -ex 'py-list' \\\n"
                      "                    -ex 'py-locals' \\\n"
                      "                    -ex 'echo %s\\n' \\\n"
                      "                    -ex 'thread apply all -ascending backtrace full 2048' \\\n"
                      "                    -ex 'info sharedlib' \\\n"
                      "                    -ex 'print (char*)__abort_msg' \\\n"
                      "                    -ex 'print (char*)__glib_assert_msg' \\\n"
                      "                    -ex 'info registers' \\\n"
                      "                    -ex 'disassemble' \\\n"
                      "                    -ex 'echo %s\\n' \\\n"
                      "                    -ex 'abrt-exploitable'"
                      % (plugin.gdb_executable, executable, PYTHON_LABEL_START,
                         PYTHON_LABEL_END, EXPLOITABLE_SEPARATOR))

    if CONFIG["RetraceEnvironment"] == "mock":
        child = run(["/usr/bin/mock", "--configdir", savedir, "--copyin",
                     batfile, "/var/spool/abrt/gdb.sh"], stdout=DEVNULL, stderr=DEVNULL)
        if child.returncode:
            raise Exception("Unable to copy GDB launcher into chroot")

        child = run(["/usr/bin/mock", "--configdir", savedir, "chroot",
                     "--", "/bin/chmod a+rx /var/spool/abrt/gdb.sh"], stdout=DEVNULL, stderr=DEVNULL)
        if child.returncode:
            raise Exception("Unable to chmod GDB launcher")

        child = run(["/usr/bin/mock", "chroot", "--configdir", savedir,
                     "--", "su mockbuild -c '/bin/sh /var/spool/abrt/gdb.sh' 2>&1"],
                    # redirect GDB's stderr, ignore mock's stderr
                    stdout=PIPE, stderr=DEVNULL, encoding='utf-8')

    elif CONFIG["RetraceEnvironment"] == "podman":
        podman_build_call = ["/usr/bin/podman", "build", "--file",
                             savedir / RetraceTask.DOCKERFILE,
                             "--volume=%s:%s:ro" % (repopath, repopath)]

        if CONFIG["RequireGPGCheck"]:
            podman_build_call.append("--volume=%s:%s:ro" % (RETRACE_GPG_KEYS, RETRACE_GPG_KEYS))

        if CONFIG["UseFafPackages"]:
            faf_link_dir = CONFIG["FafLinkDir"]
            log_debug("Using FAF repository")
            podman_build_call.append("--volume=%s:%s" % (faf_link_dir, faf_link_dir))

        img_cont_id = str(taskid)

        podman_build_call.extend(["--tag", "retrace-image:%s" % img_cont_id])

        child = run(podman_build_call, stdout=DEVNULL, stderr=DEVNULL)
        if child.returncode:
            raise Exception("Unable to build podman container")

        child = run(["/usr/bin/podman", "run", "-it", "--name=%s" % img_cont_id,
                     "--rm", "retrace-image:%s" % img_cont_id], stdout=PIPE, encoding='utf-8')
    else:
        raise Exception("RetraceEnvironment set to invalid value")

    if child.returncode:
        raise Exception("Running GDB failed")

    backtrace = child.stdout.strip()

    exploitable = None
    if EXPLOITABLE_SEPARATOR in backtrace:
        backtrace, exploitable = backtrace.rsplit(EXPLOITABLE_SEPARATOR, 1)

    if not backtrace:
        raise Exception("An unusable backtrace has been generated")

    python_labels = PYTHON_LABEL_START+'\n'+PYTHON_LABEL_END+'\n'
    if python_labels in backtrace:
        backtrace = backtrace.replace(python_labels, "")

    log_debug(backtrace)

    return backtrace, exploitable


def remove_epoch(nvr):
    pos = nvr.find(":")
    if pos > 0:
        return nvr[pos + 1:]
    return nvr


def is_package_known(package_nvr, arch, releaseid=None):
    if CONFIG["UseFafPackages"]:
        from pyfaf.storage import getDatabase
        from pyfaf.queries import get_package_by_nevra

        db = getDatabase()
        (n, v, r, e, _a) = splitFilename(package_nvr+".mockarch.rpm")
        for derived_archs in ARCH_MAP.values():
            if arch not in derived_archs:
                continue
            for a in derived_archs:
                p = get_package_by_nevra(db, n, e or 0, v, r, a)
                if p is not None:
                    return True
        # Try with noarch
        p = get_package_by_nevra(db, n, e or 0, v, r, "noarch")
        if p is not None:
            return True

        return False

    if releaseid is None:
        releases = get_supported_releases()
    else:
        releases = [releaseid]

    candidates = []
    package_nvr = remove_epoch(package_nvr)
    repodir = Path(CONFIG["RepoDir"])
    for release in releases:
        for derived_archs in ARCH_MAP.values():
            if arch not in derived_archs:
                continue

            for a in derived_archs:
                candidates.append(Path(repodir, release, "Packages", "%s.%s.rpm" % (package_nvr, a)))
                candidates.append(Path(repodir, release, "%s.%s.rpm" % (package_nvr, a)))
            break
        else:
            candidates.append(Path(repodir, release, "Packages", "%s.%s.rpm" % (package_nvr, arch)))
            candidates.append(Path(repodir, release, "%s.%s.rpm" % (package_nvr, arch)))

    return any([f.is_file() for f in candidates])


def find_kernel_debuginfo(kernelver):
    vers = [kernelver]

    for canon_arch, derived_archs in ARCH_MAP.items():
        if kernelver.arch == canon_arch:
            vers = []
            for arch in derived_archs:
                cand = KernelVer(str(kernelver))
                cand.arch = arch
                vers.append(cand)

    if CONFIG["UseFafPackages"]:
        from pyfaf.storage import getDatabase
        from pyfaf.queries import get_package_by_nevra
        db = getDatabase()
        for ver in vers:
            p = get_package_by_nevra(db, ver.package_name_base(debug=True),
                                     0, ver.version, ver.release, ver._arch)
            if p is None:
                log_debug("FAF package not found for {0}".format(str(ver)))
            else:
                log_debug("FAF package found for {0}".format(str(ver)))
                if p.has_lob("package"):
                    log_debug("LOB location {0}".format(p.get_lob_path("package")))
                    return p.get_lob_path("package")
                log_debug("LOB not found {0}".format(p.get_lob_path("package")))

    # search for the debuginfo RPM
    ver = None
    repodir = Path(CONFIG["RepoDir"])
    for release in repodir.iterdir():
        for ver in vers:
            testfile = release / "Packages" / ver.package_name(debug=True)
            log_debug("Trying debuginfo file: %s" % testfile)
            if testfile.is_file():
                return testfile

            # should not happen, but anyway...
            testfile = release / ver.package_name(debug=True)
            log_debug("Trying debuginfo file: %s" % testfile)
            if testfile.is_file():
                return testfile

    if ver is not None and ver.rt:
        basename = "kernel-rt"
    else:
        basename = "kernel"

    # koji-like root
    kojiroot = Path(CONFIG["KojiRoot"])
    for ver in vers:
        testfile = kojiroot / "packages" / basename / ver.version / ver.release\
                   / ver._arch / ver.package_name(debug=True)
        log_debug("Trying debuginfo file: %s" % testfile)
        if testfile.is_file():
            return testfile

    if CONFIG["WgetKernelDebuginfos"]:
        downloaddir = repodir / "download"
        if not downloaddir.is_dir():
            oldmask = os.umask(0o007)
            downloaddir.mkdir(parents=True)
            os.umask(oldmask)

        for ver in vers:
            pkgname = ver.package_name(debug=True)
            url = CONFIG["KernelDebuginfoURL"] \
                .replace("$VERSION", ver.version) \
                .replace("$RELEASE", ver.release) \
                .replace("$ARCH", ver._arch) \
                .replace("$BASENAME", basename)
            if not url.endswith("/"):
                url += "/"
            url += pkgname

            log_debug("Trying debuginfo URL: %s" % url)
            child = run(["wget", "-nv", "-P", downloaddir, url], stdout=DEVNULL, stderr=DEVNULL)
            if not child.returncode:
                return downloaddir / pkgname

    return None


def cache_files_from_debuginfo(debuginfo, basedir, files):
    # important! if empty list is specified, the whole debuginfo would be unpacked
    if not files:
        return

    if not debuginfo.is_file():
        raise Exception("Given debuginfo file does not exist")

    # prepend absolute path /usr/lib/debug/... with dot, so that cpio can match it
    for i in range(len(files)):
        if files[i][0] == "/":
            files[i] = ".%s" % files[i]

    rpm2cpio = run(["rpm2cpio", debuginfo], stdout=PIPE, stderr=DEVNULL)
    run(["cpio", "-id"] + files, input=rpm2cpio.stdout, cwd=basedir, stdout=DEVNULL, stderr=DEVNULL)


def get_files_sizes(directory):
    result = []

    for f in Path(directory).iterdir():
        if f.is_file():
            result.append((f, f.stat().st_size))
        elif f.is_dir():
            result += get_files_sizes(f)

    return sorted(result, key=lambda f_s: f_s[1], reverse=True)


def get_archive_type(path):
    ms = magic.open(magic.MAGIC_NONE)
    ms.load()
    filetype = ms.file(path).lower()
    log_debug("File type: %s" % filetype)

    if "bzip2 compressed data" in filetype:
        log_debug("bzip2 detected")
        return ARCHIVE_BZ2
    if "gzip compressed data" in filetype or \
         "compress'd data" in filetype:
        log_debug("gzip detected")
        return ARCHIVE_GZ
    if "xz compressed data" in filetype:
        log_debug("xz detected")
        return ARCHIVE_XZ
    if "7-zip archive data" in filetype:
        log_debug("7-zip detected")
        return ARCHIVE_7Z
    if "zip archive data" in filetype:
        log_debug("zip detected")
        return ARCHIVE_ZIP
    if "tar archive" in filetype:
        log_debug("tar detected")
        return ARCHIVE_TAR
    if "lzop compressed data" in filetype:
        log_debug("lzop detected")
        return ARCHIVE_LZOP

    log_debug("unknown file type, unpacking finished")
    return ARCHIVE_UNKNOWN

def add_snapshot_suffix(filename: str, snapshot: Path) -> str:
    """
    Adds a snapshot suffix to the filename.
    """
    suffix = snapshot.suffix
    if suffix in SNAPSHOT_SUFFIXES:
        return filename + suffix

    return filename

def rename_with_suffix(frompath: Path, topath: Path) -> Path:
    suffix = SUFFIX_MAP[get_archive_type(frompath)]

    # check if the file has a snapshot suffix
    # if it does, keep the suffix
    if not suffix:
        suffix = add_snapshot_suffix(suffix, frompath)

    if not topath.suffix == suffix:
        topath = topath.with_suffix(suffix)

    frompath.rename(topath)

    return topath

def unpack_vmcore(path: Path):
    vmcore_file = "vmcore"
    parentdir = path.parent
    archivebase = parentdir / "archive"
    archive = rename_with_suffix(path, archivebase)
    filetype = get_archive_type(archive)
    while filetype != ARCHIVE_UNKNOWN:
        files = set(f for (f, s) in get_files_sizes(parentdir))
        if filetype == ARCHIVE_GZ:
            check_run(["gunzip", archive])
        elif filetype == ARCHIVE_BZ2:
            check_run(["bunzip2", archive])
        elif filetype == ARCHIVE_XZ:
            check_run(["unxz", archive])
        elif filetype == ARCHIVE_ZIP:
            check_run(["unzip", archive, "-d", parentdir])
        elif filetype == ARCHIVE_7Z:
            check_run(["7za", "e", "-o%s" % parentdir, archive])
        elif filetype == ARCHIVE_TAR:
            check_run(["tar", "-C", parentdir, "-xf", archive])
        elif filetype == ARCHIVE_LZOP:
            check_run(["lzop", "-d", archive])
        else:
            raise Exception("Unknown archive type")

        if archive.is_file():
            archive.unlink()

        files_sizes = get_files_sizes(parentdir)
        newfiles = [f for (f, s) in files_sizes if f.suffix != ".vmem"]
        diff = set(newfiles) - files
        vmcore_candidate = 0
        while vmcore_candidate < len(newfiles) and newfiles[vmcore_candidate] not in diff:
            vmcore_candidate += 1

        # rename files with .vmem extension to vmcore.vmem
        for f in Path(parentdir).iterdir():
            if f.suffix == ".vmem":
                f.rename(Path(parentdir, vmcore_file + f.suffix))

        if len(diff) > 1:
            archive = rename_with_suffix(newfiles[vmcore_candidate], archivebase)
            for filename in newfiles:
                if filename not in diff or \
                   filename == newfiles[vmcore_candidate]:
                    continue

                filename.unlink()

        elif len(diff) == 1:
            archive = rename_with_suffix(diff.pop(), archivebase)

        # just be explicit here - if no file changed, an archive
        # has most probably been unpacked to a file with same name
        else:
            pass

        for filename in Path(parentdir).iterdir():
            if filename.is_dir():
                shutil.rmtree(filename)

        filetype = get_archive_type(archive)

    vmcore_file = add_snapshot_suffix(vmcore_file, archive)
    archive.rename(parentdir / vmcore_file)


def unpack_coredump(path: Path):
    processed: Set[Path] = set()
    parentdir = path.parent
    files = set(f for (f, s) in get_files_sizes(parentdir))
    # Keep unpacking
    while len(files - processed) > 0:
        archive = list(files - processed)[0]
        filetype = get_archive_type(archive)
        if filetype == ARCHIVE_GZ:
            check_run(["gunzip", archive])
        elif filetype == ARCHIVE_BZ2:
            check_run(["bunzip2", archive])
        elif filetype == ARCHIVE_XZ:
            check_run(["unxz", archive])
        elif filetype == ARCHIVE_ZIP:
            check_run(["unzip", archive, "-d", parentdir])
        elif filetype == ARCHIVE_7Z:
            check_run(["7za", "e", "-o%s" % parentdir, archive])
        elif filetype == ARCHIVE_TAR:
            check_run(["tar", "-C", parentdir, "-xf", archive])
        elif filetype == ARCHIVE_LZOP:
            check_run(["lzop", "-d", archive])

        if archive.is_file() and filetype != ARCHIVE_UNKNOWN:
            archive.unlink()
        processed.add(archive)

        files = set(f for (f, s) in get_files_sizes(parentdir))

    # If coredump is not present, the biggest file becomes it
    if "coredump" not in [f.name for f in parentdir.iterdir()]:
        get_files_sizes(parentdir)[0][0].rename(parentdir / self.COREDUMP_FILE)

    for filename in Path(parentdir).iterdir():
        if filename.is_dir():
            shutil.rmtree(filename)


def run_ps():
    lines = run(["ps", "-eo", "pid,ppid,etime,cmd"],
                stdout=PIPE, encoding='utf-8').stdout.split("\n")

    return lines


def get_running_tasks(ps_output=None):
    if not ps_output:
        ps_output = run_ps()

    result = []

    for line in ps_output:
        match = WORKER_RUNNING_PARSER.match(line)
        if match:
            result.append((int(match.group(1)), int(match.group(3)), match.group(2)))

    return result


def get_active_tasks():
    tasks = []

    for filename in Path(CONFIG["SaveDir"]).iterdir():
        if len(filename.name) != CONFIG["TaskIdLength"]:
            continue

        try:
            task = RetraceTask(int(filename.name))
        except Exception:
            continue

        if CONFIG["AllowTaskManager"] and task.get_managed():
            continue

        if not task.has_log():
            tasks.append(task.get_taskid())

    return tasks


def get_md5_tasks():
    tasks = []

    for filename in Path(CONFIG["SaveDir"]).iterdir():
        if len(filename.name) != CONFIG["TaskIdLength"]:
            continue

        try:
            task = RetraceTask(int(filename.name))
        except Exception:
            continue

        if not task.has_status():
            continue
        else:
            status = task.get_status()

        if status not in (STATUS_SUCCESS, STATUS_FAIL):
            continue

        if not task.has_finished_time():
            continue

        if not task.has_vmcore() and not task.has_coredump():
            continue

        if not task.has_md5sum():
            continue

        md5 = str.split(task.get_md5sum())[0]
        if not MD5_PARSER.search(md5):
            continue

        tasks.append(task)

    return tasks


def check_run(cmd):
    child = run(cmd, stdout=PIPE, stderr=STDOUT, encoding='utf-8')
    stdout = child.stdout
    if child.returncode:
        raise Exception("%s exited with %d: %s" % (cmd[0], child.returncode, stdout))


def move_dir_contents(source, dest):
    for filename in Path(source).iterdir():
        if filename.is_dir():
            move_dir_contents(filename, dest)
        elif filename.is_file():
            dest = Path(dest, filename)
            if dest.is_file():
                i = 0
                newdest = Path("%s.%d" % (dest, i))
                while newdest.is_file():
                    i += 1
                    newdest = Path("%s.%d" % (dest, i))

                dest = newdest

# try?
            filename.rename(dest)
# except?

    shutil.rmtree(source)


class KernelVer():
    FLAVOUR = ["debug", "highbank", "hugemem",
               "kirkwood", "largesmp", "PAE", "omap",
               "smp", "tegra", "xen", "xenU"]

    ARCH = ARCHITECTURES

    @property
    def arch(self):
        return get_canon_arch(self._arch)

    @arch.setter
    def arch(self, value):
        self._arch = value

    def __init__(self, kernelver_str):
        log_debug("Parsing kernel version '%s'" % kernelver_str)
        self.kernelver_str = kernelver_str
        self.flavour = None
        for kf in KernelVer.FLAVOUR:
            if kernelver_str.endswith(".%s" % kf):
                self.flavour = kf
                kernelver_str = kernelver_str[:-len(kf) - 1]
                break

        self._arch = None
        for ka in KernelVer.ARCH:
            if kernelver_str.endswith(".%s" % ka):
                self._arch = ka
                kernelver_str = kernelver_str[:-len(ka) - 1]
                break

        self.version, self.release = kernelver_str.split("-", 1)

        if self.flavour is None:
            for kf in KernelVer.FLAVOUR:
                if self.release.endswith(kf):
                    self.flavour = kf
                    self.release = self.release[:-len(kf)]
                    break

        self.rt = "rt" in self.release

        log_debug("Version: '%s'; Release: '%s'; Arch: '%s'; Flavour: '%s'; Realtime: %s"
                  % (self.version, self.release, self._arch, self.flavour, self.rt))

    def __str__(self):
        result = "%s-%s" % (self.version, self.release)

        if self._arch:
            result = "%s.%s" % (result, self._arch)

        if self.flavour:
            result = "%s.%s" % (result, self.flavour)

        return result

    def __repr__(self):
        return self.__str__()

    def package_name_base(self, debug=False):
        base = "kernel"
        if self.rt:
            base = "%s-rt" % base

        if self.flavour and not (debug and ".EL" in self.release):
            base = "%s-%s" % (base, self.flavour)

        if debug:
            base = "%s-debuginfo" % base

        return base

    def package_name(self, debug=False):
        if self._arch is None:
            raise Exception("Architecture is required for building package name")

        base = self.package_name_base(debug)

        return "%s-%s-%s.%s.rpm" % (base, self.version, self.release, self._arch)

    def needs_arch(self):
        return self._arch is None


class KernelVMcore:
    DUMP_LEVEL_PARSER = re.compile(r"^[ \t]*dump_level[ \t]*:[ \t]*([0-9]+).*$")

    def __init__(self, vmcore_path):
        self._vmcore_path = vmcore_path
        self._crashdir = Path(vmcore_path).parent
        self._is_flattened_format = None
        self._dump_level = None
        self._has_extra_pages = None
        self._release = None
        self._vmlinux = None
        self._vmem_path = self._crashdir / "vmcore.vmem"

    def get_path(self):
        return self._vmcore_path

    def is_flattened_format(self):
        """Returns True if vmcore is in makedumpfile flattened format"""
        if self._is_flattened_format is not None:
            return self._is_flattened_format
        try:
            with open(self._vmcore_path, "rb") as fd:
                fd.seek(0)
                # Read 16 bytes (SIG_LEN_MDF from crash-utility makedumpfile.h)
                b = fd.read(16)
                self._is_flattened_format = b.startswith(b'makedumpfile')
        except IOError as e:
            log_error("Failed to get makedumpfile header - failed open/seek/read of "
                      "%s with errno(%d - '%s')" %
                      (self._vmcore_path, e.errno, e.strerror))
        return self._is_flattened_format

    def convert_flattened_format(self):
        """Convert a vmcore in makedumpfile flattened format to normal dumpfile format
        Returns True if conversion has been done and was successful"""
        if not self._is_flattened_format:
            log_error("Cannot convert a non-flattened vmcore")
            return False
        newvmcore = "%s.normal" % self._vmcore_path
        try:
            with open(self._vmcore_path) as fd:
                child = run(["makedumpfile", "-R", newvmcore], stdin=fd)
                if child.returncode:
                    log_warn("makedumpfile -R exited with %d" % child.returncode)
                    if newvmcore.is_file():
                        newvmcore.unlink()
                else:
                    newvmcore.rename(self._vmcore_path)
        except IOError as e:
            log_error("Failed to convert flattened vmcore %s - errno(%d - '%s')" %
                      (self._vmcore_path, e.errno, e.strerror))
            return False

        self._is_flattened_format = False
        return True

    def get_dump_level(self, task):
        if self._dump_level is not None:
            return self._dump_level

        if not self._vmcore_path.is_file():
            return None

        dmesg_path = task.get_results_dir() / "dmesg"
        if dmesg_path.is_file():
            dmesg_path.unlink()

        cmd = ["makedumpfile", "-D", "--dump-dmesg", self._vmcore_path, dmesg_path]

        result = None
        lines = run(cmd, stdout=PIPE, stderr=DEVNULL, encoding='utf-8').stdout.splitlines()
        for line in lines:
            match = self.DUMP_LEVEL_PARSER.match(line)
            if match is None:
                continue

            result = int(match.group(1))
            break

        self._dump_level = result
        return result

    def has_extra_pages(self, task):
        """Returns True if vmcore has extra pages that can be stripped with makedumpfile"""
        if self._has_extra_pages is not None:
            return self._has_extra_pages

        # Assume the vmcore has extra pages if the VmcoreDumpLevel is set
        self._has_extra_pages = CONFIG["VmcoreDumpLevel"] > 0 and CONFIG["VmcoreDumpLevel"] < 32

        # Now try to read the dump_level from the vmcore
        dump_level = self.get_dump_level(task)
        if dump_level is None:
            log_warn("Unable to determine vmcore dump level")
        else:
            log_debug("Vmcore dump level is %d" % dump_level)

        # If dump_level was readable above, then check to see if stripping is worthwhile
        if (dump_level is not None
                and (dump_level & CONFIG["VmcoreDumpLevel"]) == CONFIG["VmcoreDumpLevel"]):
            log_info("Stripping to %d would have no effect" % CONFIG["VmcoreDumpLevel"])
            self._has_extra_pages = False
        return self._has_extra_pages

    def strip_extra_pages(self):
        """Strip extra pages from vmcore with makedumpfile"""
        if self._vmlinux is None:
            log_error("Cannot strip pages if vmlinux is not known for vmcore")
            return

        newvmcore = "%s.stripped" % self._vmcore_path
        child = run(["makedumpfile", "-c", "-d", "%d" % CONFIG["VmcoreDumpLevel"],
                     "-x", self._vmlinux, "--message-level", "0", self._vmcore_path, newvmcore])
        if child.returncode:
            log_warn("makedumpfile exited with %d" % child.returncode)
            if newvmcore.is_file():
                newvmcore.unlink()
        else:
            newvmcore.rename(self._vmcore_path)

    #
    # In real-world testing, approximately 60% of the time the kernel
    # version of a vmcore can be identified with the crash tool.
    # In the other 40% of the time, we must use some other method.
    #
    # The below function contains a couple regex searches that work
    # across a wide variety of vmcore formats and kernel versions.
    # We do not attempt to identify the file type since this is often not
    # reliable, but we assume the version information exists in some form
    # in the first portion of the file.  Testing has indicated that we do
    # not need to scan the entire file but can rely on a small portion
    # at the start of the file, which helps preserve useful pages in the
    # OS page cache.
    #
    # The following regex's are used for the 40% scenario
    # 1. Look for 'OSRELEASE='.  For example:
    # OSRELEASE=2.6.18-406.el5
    # NOTE: We can get "OSRELEASE=%" so we disallow the '%' character
    # after the '='
    OSRELEASE_VAR_PARSER = re.compile(b"OSRELEASE=([^%][^\x00\s]+)")
    #
    # 2. Look for "Linux version" string.  Note that this was taken from
    # CAS 'fingerprint' database code.  For more info, see
    # https://bugzilla.redhat.com/show_bug.cgi?id=1535592#c9 and
    # https://github.com/battlemidget/core-analysis-system/blob/master/lib/cas/core.py#L96
    # For exmaple:
    # Linux version 3.10.0-693.11.1.el7.x86_64 (mockbuild@x86-041.build.eng.bos.redhat.com)
    # (gcc version 4.8.5 20150623 (Red Hat 4.8.5-16) (GCC) ) #1 SMP Fri Oct 27 05:39:05 EDT 2017
    LINUX_VERSION_PARSER = re.compile(b'Linux\sversion\s(\S+)\s+(.*20\d{1,2}|#1\s.*20\d{1,2})')
    #
    # 3. Look for the actual kernel release. For example:
    # 2.6.32-209.el6.x86_64 | 2.6.18-197.el5
    KERNEL_RELEASE_PARSER = re.compile(b'(\d+\.\d+\.\d+)-(\d+\.[^\x00\s]+)')
    #

    def get_kernel_release(self, crash_cmd=["crash"]):
        if self._release is not None:
            return self._release

        core_path = self._vmcore_path
        if self._vmem_path.is_file():
            core_path = self._vmem_path

        # First use 'crash' to identify the kernel version.
        # set SIGPIPE to default handler for bz 1540253
        save = getsignal(SIGPIPE)
        signal(SIGPIPE, SIG_DFL)
        child = run(crash_cmd + ["--osrelease", core_path], stdout=PIPE, stderr=STDOUT, encoding='utf-8')
        release = child.stdout.strip()
        ret = child.returncode
        signal(SIGPIPE, save)

        # If the crash tool fails, we must try some other method.
        # Read the first small portion of the file and use a few different
        # regex searches on the file.
        if ret != 0 or \
           not release or \
           "\n" in release or \
           release == "unknown":
            try:
                with open(core_path, "rb") as fd:
                    fd.seek(0)
                    b = fd.read(64000000)
            except IOError as e:
                log_error("Failed to get kernel release - failed "
                          "open/seek/read of file %s with errno(%d - '%s')"
                          % (core_path, e.errno, e.strerror))
                return None
            release = self.OSRELEASE_VAR_PARSER.search(b)
            if release:
                release = release.group(1)
            if not release:
                release = self.LINUX_VERSION_PARSER.search(b)
                if release:
                    release = release.group(1)
            if not release:
                release = self.KERNEL_RELEASE_PARSER.search(b)
                if release:
                    release = release.group(0)
            if release:
                release = release.decode('utf-8')

        # Clean up the release before returning or calling KernelVer
        if release is None or release == "unknown":
            log_error("Failed to get kernel release from file %s" %
                      core_path)
            return None
        release = release.rstrip('\0 \t\n')

        # check whether architecture is present
        try:
            result = KernelVer(release)
        except Exception as ex:
            log_error("Failed to parse kernel release from file %s, release ="
                      " %s: %s" % (core_path, release, str(ex)))
            return None

        if result.arch is None:
            result.arch = guess_arch(core_path)
            if not result.arch:
                log_error("Unable to determine architecture from file %s, "
                          "release = %s, arch result = %s" %
                          (core_path, release, result))
                return None

        self._release = result
        return result

    def prepare_debuginfo(self, task, chroot=None, kernelver=None):
        log_info("Calling prepare_debuginfo ")
        if kernelver is None:
            kernelver = self.get_kernel_release()

        if kernelver is None:
            raise Exception("Unable to determine kernel version")

        if self._vmlinux is not None:
            return self._vmlinux

        # FIXME: get_kernel_release sets _release vs 'kernelver' here ?
        task.set_kernelver(kernelver)
        # Setting kernelver may reset crash_cmd
        crash_cmd = task.get_crash_cmd().split()

        debugdir_base = Path(CONFIG["RepoDir"], "kernel", kernelver.arch)
        if not debugdir_base.is_dir():
            debugdir_base.mkdir(parents=True)

        # First look in cache for vmlinux at the "typical" location, for example
        # CONFIG["RepoDir"]/kernel/x86_64/usr/lib/debug/lib/modules/2.6.32-504.el6.x86_64
        log_info("Version: '%s'; Release: '%s'; Arch: '%s'; _arch: '%s'; "
                 "Flavour: '%s'; Realtime: %s"
                 % (kernelver.version, kernelver.release, kernelver.arch,
                    kernelver._arch, kernelver.flavour, kernelver.rt))
        kernel_path = ""
        if kernelver.version is not None:
            kernel_path = kernel_path + str(kernelver.version)
        if kernelver.release is not None:
            kernel_path = kernel_path + "-" + str(kernelver.release)
        # Skip the 'arch' on RHEL5 and RHEL4 due to different kernel-debuginfo
        # path to vmlinux
        if kernelver._arch is not None and "EL" not in kernelver.release and\
           "el5" not in kernelver.release:
            kernel_path = kernel_path + "." + str(kernelver._arch)
        if kernelver.flavour is not None:
            # 'debug' flavours on rhel6 and above require a '.' before the 'debug'
            if "EL" not in kernelver.release and "el5" not in kernelver.release:
                kernel_path = kernel_path + "."
            kernel_path = kernel_path + str(kernelver.flavour)

        vmlinux_cache_path = debugdir_base + "usr/lib/debug/lib/modules" / kernel_path / "vmlinux"
        if vmlinux_cache_path.is_file():
            log_info("Found cached vmlinux at path: " + vmlinux_cache_path)
            vmlinux = vmlinux_cache_path
            task.set_vmlinux(vmlinux)
        else:
            log_info("Unable to find cached vmlinux at path: " + vmlinux_cache_path)
            vmlinux = None

        # For now, unconditionally search for kernel-debuginfo.  However,
        # if the vmlinux file existed in the cache, don't raise an exception
        # on the task since the vmcore may still be usable, and instead,
        # return early.  A second optimization would be to avoid this
        # completely if the modules files all exist in the cache.
        log_info("Searching for kernel-debuginfo package for " + str(kernelver))
        debuginfo = find_kernel_debuginfo(kernelver)
        if not debuginfo:
            if vmlinux is not None:
                return vmlinux
            raise Exception("Unable to find debuginfo package and "
                            "no cached vmlinux file")

        # FIXME: Merge kernel_path with this logic
        if "EL" in kernelver.release:
            if kernelver.flavour is None:
                pattern = "EL/vmlinux"
            else:
                pattern = "EL%s/vmlinux" % kernelver.flavour
        else:
            pattern = "/vmlinux"

        # Now open the kernel-debuginfo and get a listing of the files we may need
        vmlinux_path = None
        debugfiles = {}
        lines = run(["rpm", "-qpl", debuginfo],
                    stdout=PIPE, stderr=DEVNULL, encoding='utf-8').stdout.splitlines()
        for line in lines:
            if line.endswith(pattern):
                vmlinux_path = line
                continue

            match = KO_DEBUG_PARSER.match(line)
            if not match:
                continue

            # only pick the correct flavour for el4
            if "EL" in kernelver.release:
                if kernelver.flavour is None:
                    pattern2 = "EL/"
                else:
                    pattern2 = "EL%s/" % kernelver.flavour

                if pattern2 not in str(Path(line).parent):
                    continue

            # '-' in file name is transformed to '_' in module name
            debugfiles[match.group(1).replace("-", "_")] = line

        # Only look for the vmlinux file here if it's not already been found above
        # Note the dependency from this code on the debuginfo file list
        if vmlinux is None:
            vmlinux_debuginfo = debugdir_base / vmlinux_path.lstrip("/")
            cache_files_from_debuginfo(debuginfo, debugdir_base, [vmlinux_path])
            if vmlinux_debuginfo.is_file():
                log_info("Found cached vmlinux at new debuginfo location: " + vmlinux_debuginfo)
                vmlinux = vmlinux_debuginfo
                task.set_vmlinux(vmlinux)
            else:
                raise Exception("Failed vmlinux caching from debuginfo at location: " + vmlinux_debuginfo)

        # Obtain the list of modules this vmcore requires
        if chroot:
            crash_normal = ["/usr/bin/mock", "--configdir", chroot, "--cwd", crashdir,
                            "chroot", "--", "crash -s %s %s" % (self._vmcore_path, vmlinux)]
        else:
            crash_normal = crash_cmd + ["-s", self._vmcore_path, vmlinux]
        stdout, returncode = task.run_crash_cmdline(crash_normal, "mod\nquit")
        if returncode == 1 and "el5" in kernelver.release:
            log_info("Unable to list modules but el5 detected, trying crash fixup for vmss files")
            crash_cmd.append("--machdep")
            crash_cmd.append("phys_base=0x200000")
            log_info("trying crash_cmd = " + str(crash_cmd))
            # FIXME: mock
            crash_normal = crash_cmd + ["-s", self._vmcore_path, vmlinux]
            stdout, returncode = task.run_crash_cmdline(crash_normal, "mod\nquit")

        # If we fail to get the list of modules, is the vmcore even usable?
        if returncode:
            log_warn("Unable to list modules: crash exited with %d:\n%s" % (returncode, stdout))
            self._vmlinux = vmlinux
            return vmlinux

        modules = []
        for line in stdout.decode('utf-8').splitlines():
            # skip header
            if "NAME" in line:
                continue

            if " " in line:
                modules.append(line.split()[1])

        todo = []
        for module in modules:
            if module in debugfiles and not (debugdir_base / debugfiles[module].lstrip("/")).is_file():
                todo.append(debugfiles[module])

        cache_files_from_debuginfo(debuginfo, debugdir_base, todo)

        self._release = kernelver
        self._vmlinux = vmlinux
        return vmlinux


class RetraceTask:
    """Represents Retrace server's task."""

    BACKTRACE_FILE = Path("retrace_backtrace")
    CASENO_FILE = Path("caseno")
    BUGZILLANO_FILE = Path("bugzillano")
    CRASHRC_FILE = Path("crashrc")
    CRASH_CMD_FILE = Path("crash_cmd")
    DOWNLOADED_FILE = Path("downloaded")
    MD5SUM_FILE = Path("md5sum")
    FINISHED_FILE = Path("finished_time")
    KERNELVER_FILE = Path("kernelver")
    LOG_FILE = Path("retrace_log")
    MANAGED_FILE = Path("managed")
    RESULTS_DIR = Path("results")
    MOCK_LOG_DIR = Path("log")
    NOTES_FILE = Path("notes")
    NOTIFY_FILE = Path("notify")
    PASSWORD_FILE = Path("password")
    PROGRESS_FILE = Path("progress")
    REMOTE_FILE = Path("remote")
    STARTED_FILE = Path("started_time")
    STATUS_FILE = Path("status")
    TYPE_FILE = Path("type")
    URL_FILE = Path("url")
    VMLINUX_FILE = Path("vmlinux")
    VMCORE_FILE = Path("vmcore")
    VMEM_FILE = Path("vmcore.vmem")
    COREDUMP_FILE = Path("coredump")
    MOCK_DEFAULT_CFG = Path("default.cfg")
    MOCK_SITE_DEFAULTS_CFG = Path("site-defaults.cfg")
    MOCK_LOGGING_INI = Path("logging.ini")
    DOCKERFILE = Path("Dockerfile")

    def __init__(self, taskid=None):
        """Creates a new task if taskid is None,
        loads the task with given ID otherwise."""

        self.vmcore_file = self.VMCORE_FILE
        self._mock = False

        if taskid is None:
            # create a new task
            # create a retrace-group-writable directory
            oldmask = os.umask(0o007)
            self._taskid = None
            generator = random.SystemRandom()
            for i in range(50):
                taskid = generator.randint(pow(10, CONFIG["TaskIdLength"] - 1),
                                           pow(10, CONFIG["TaskIdLength"]) - 1)
                taskdir = Path(CONFIG["SaveDir"], "%d" % taskid)
                try:
                    taskdir.mkdir()
                except OSError as ex:
                    # dir exists, try another taskid
                    if ex.errno == errno.EEXIST:
                        continue
                    # error - re-raise original exception
                    else:
                        raise ex
                # directory created
                else:
                    self._taskid = taskid
                    self._savedir = taskdir
                    break

            if self._taskid is None:
                raise Exception("Unable to create new task")

            pwdfilepath = self._savedir / RetraceTask.PASSWORD_FILE
            with open(pwdfilepath, "w") as pwdfile:
                for i in range(CONFIG["TaskPassLength"]):
                    pwdfile.write(generator.choice(TASKPASS_ALPHABET))

            self.set_crash_cmd("crash")
            (self._savedir / RetraceTask.RESULTS_DIR).mkdir(parents=True)
            os.umask(oldmask)
        else:
            # existing task
            self._taskid = int(taskid)
            self._savedir = Path(CONFIG["SaveDir"], "%d" % self._taskid)
            if not self._savedir.is_dir():
                raise Exception("The task %d does not exist" % self._taskid)

    def set_mock(self, value):
        self._mock = value

    def get_mock(self):
        return self._mock

    def has_mock(self):
        """Verifies whether MOCK_SITE_DEFAULTS_CFG is present in the task directory."""
        return self.has(RetraceTask.MOCK_SITE_DEFAULTS_CFG)

    def _get_file_path(self, key):
        key_sanitized = str(key).replace("/", "_").replace(" ", "_")
        return self._savedir / key_sanitized

    def _start_local(self, debug=False, kernelver=None, arch=None):
        cmdline = ["/usr/bin/retrace-server-worker", "%d" % self._taskid]
        if debug:
            cmdline.append("-v")

        if kernelver is not None:
            cmdline.append("--kernelver")
            cmdline.append(kernelver)

        if arch is not None:
            cmdline.append("--arch")
            cmdline.append(arch)

        child = run(cmdline)
        return child.returncode

    def _start_remote(self, host, debug=False, kernelver=None, arch=None):
        starturl = "%s/%d/start" % (host, self._taskid)
        qs = {}
        if debug:
            qs["debug"] = ""

        if kernelver:
            qs["kernelver"] = kernelver

        if arch:
            qs["arch"] = arch

        qs_text = urllib.parse.urlencode(qs)

        if qs_text:
            starturl = "%s?%s" % (starturl, qs_text)

        url = urllib.request.urlopen(starturl)
        status = url.getcode()
        url.close()

        # 1/0 just to be consitent with call() in _start_local
        if status != 201:
            return 1

        return 0

    def get_taskid(self):
        """Returns task's ID"""
        return self._taskid

    def get_savedir(self) -> Path:
        """Returns task's savedir"""
        return self._savedir

    def get_crashdir(self):
        """Returns task's crashdir"""
        return self._savedir / "crash"

    def start(self, debug=False, kernelver=None, arch=None):
        if arch is None:
            crashdir = self.get_crashdir()

            if self.get_type() in [TASK_VMCORE, TASK_VMCORE_INTERACTIVE]:
                filename = self.get_vmcore_path()
            else:
                filename = crashdir / self.COREDUMP_FILE

            task_arch = guess_arch(filename)
        else:
            task_arch = arch

        ARCH_HOSTS = CONFIG.get_arch_hosts()
        if task_arch in ARCH_HOSTS:
            return self._start_remote(ARCH_HOSTS[task_arch], debug=debug,
                                      kernelver=kernelver, arch=arch)

        return self._start_local(debug=debug, kernelver=kernelver, arch=arch)

    def chgrp(self, key):
        gr = grp.getgrnam(CONFIG["AuthGroup"])
        try:
            os.chown(self._get_file_path(key), -1, gr.gr_gid)
        except OSError:
            pass

    def chmod(self, key):
        try:
            self._get_file_path(key).chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH)
        except OSError:
            pass

    def set(self, key, value, mode="w"):
        if mode not in ["w", "a"]:
            raise ValueError("mode must be either 'w' or 'a'")

        with open(self._get_file_path(key), mode) as f:
            f.write(value)
            self.chgrp(key)
            self.chmod(key)

    def set_atomic(self, key, value, mode="w"):
        if mode not in ["w", "a", "wb"]:
            raise ValueError("mode must be 'w', 'a', or 'wb'")

        tmpfilename = self._get_file_path("%s.tmp" % key)
        filename = self._get_file_path(key)
        if mode == "a":
            try:
                shutil.copyfile(filename, tmpfilename)
            except IOError as ex:
                if ex.errno != errno.ENOENT:
                    raise

        with open(tmpfilename, mode) as f:
            f.write(value)

        tmpfilename.rename(filename)
        self.chgrp(key)
        self.chmod(key)

    # 256MB should be enough by default
    def get(self, key, maxlen=268435456):
        if not self.has(key):
            return None

        filename = self._get_file_path(key)
        with open(filename, "r") as f:
            result = f.read(maxlen)

        return result

    def has(self, key):
        return self._get_file_path(key).is_file()

    def touch(self, key):
        open(self._get_file_path(key), "a").close()

    def delete(self, key):
        if self.has(key):
            self._get_file_path(key).unlink()

    def get_password(self):
        """Returns task's password"""
        return self.get(RetraceTask.PASSWORD_FILE, maxlen=CONFIG["TaskPassLength"])

    def verify_password(self, password):
        """Verifies if the given password matches task's password."""
        return self.get_password() == password

    def is_running(self, readproc=False):
        """Returns whether the task is running. Reads /proc if readproc=True
        otherwise just reads the STATUS_FILE."""
        if readproc:
            for pid, taskid, ppid in get_running_tasks():
                if taskid == self._taskid:
                    return True

            return False
        return self.has_status() and self.get_status() not in [STATUS_SUCCESS, STATUS_FAIL]

    def get_age(self):
        """Returns the age of the task in hours."""
        return int(time.time() - self._savedir.stat().st_mtime) // 3600

    def reset_age(self):
        """Reset the age of the task to the current time."""
        os.utime(self._savedir, None)

    def calculate_md5(self, file_name, chunk_size=65536):
        hash_md5 = hashlib.md5()
        with open(file_name, "rb") as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                hash_md5.update(chunk)
        return hash_md5.hexdigest()

    def get_type(self):
        """Returns task type. If TYPE_FILE is missing,
        task is considered standard TASK_RETRACE."""
        result = self.get(RetraceTask.TYPE_FILE, maxlen=8)
        if result is None:
            return TASK_RETRACE

        return int(result)

    def set_type(self, newtype):
        """Atomically writes given type into TYPE_FILE."""
        if newtype not in TASK_TYPES:
            newtype = TASK_RETRACE

        self.set_atomic(RetraceTask.TYPE_FILE, str(newtype))

    def has_backtrace(self):
        """Verifies whether BACKTRACE_FILE is present in the task directory."""
        return self.has(RetraceTask.BACKTRACE_FILE)

    def get_backtrace(self):
        """Returns None if there is no BACKTRACE_FILE in the task directory,
        BACKTRACE_FILE's contents otherwise."""
        # max 16 MB
        return self.get(RetraceTask.BACKTRACE_FILE, maxlen=1 << 24)

    def set_backtrace(self, backtrace, mode="w"):
        """Atomically writes given string into BACKTRACE_FILE."""
        self.set_atomic(RetraceTask.BACKTRACE_FILE, backtrace, mode)

    def has_log(self):
        """Verifies whether LOG_FILE is present in the task directory."""
        return self.has(RetraceTask.LOG_FILE)

    def get_log(self):
        """Returns None if there is no LOG_FILE in the task directory,
        LOG_FILE's contents otherwise."""
        return self.get(RetraceTask.LOG_FILE, maxlen=1 << 22)

    def set_log(self, log, append=False):
        """Atomically writes or appends given string into LOG_FILE."""
        mode = "w"
        if append:
            mode = "a"

        self.set_atomic(RetraceTask.LOG_FILE, log, mode=mode)

    def has_status(self):
        """Verifies whether STATUS_FILE is present in the task directory."""
        return self.has(RetraceTask.STATUS_FILE)

    def get_status(self):
        """Returns None if there is no STATUS_FILE in the task directory,
        an integer status code otherwise."""
        result = self.get(RetraceTask.STATUS_FILE, maxlen=8)
        if result is None:
            return None

        return int(result)

    def set_status(self, statuscode):
        """Atomically writes given statuscode into STATUS_FILE."""
        self.set_atomic(RetraceTask.STATUS_FILE, "%d" % statuscode)

    def has_remote(self):
        """Verifies whether REMOTE_FILE is present in the task directory."""
        return self.has(RetraceTask.REMOTE_FILE)

    def add_remote(self, url):
        """Appends a remote resource to REMOTE_FILE."""
        if "\n" in url:
            url = url.split("\n")[0]

        self.set(RetraceTask.REMOTE_FILE, "%s\n" % url, mode="a")

    def get_remote(self):
        """Returns the list of remote resources."""
        result = self.get(RetraceTask.REMOTE_FILE, maxlen=1 << 22)
        if result is None:
            return []

        return result.splitlines()

    def has_kernelver(self):
        """Verifies whether KERNELVER_FILE is present in the task directory."""
        return self.has(RetraceTask.KERNELVER_FILE)

    def get_kernelver(self):
        """Returns None if there is no KERNELVER_FILE in the task directory,
        KERNELVER_FILE's contents otherwise."""
        return self.get(RetraceTask.KERNELVER_FILE, maxlen=1 << 16)

    def set_kernelver(self, value):
        """Atomically writes given value into KERNELVER_FILE."""
        self.set_atomic(RetraceTask.KERNELVER_FILE, str(value))
        # Only use mock if we're cross arch, and there's no arch-specific crash available
        # Set crash_cmd based on arch and any config setting
        hostarch = get_canon_arch(os.uname()[4])
        if value.arch == hostarch:
            self.set_crash_cmd("crash")
            self.set_mock(False)
        elif CONFIG["Crash%s" % value.arch] and Path(CONFIG["Crash%s" % value.arch]).is_file():
            self.set_mock(False)
            self.set_crash_cmd(CONFIG["Crash%s" % value.arch])
        else:
            self.set_mock(True)
            self.set_crash_cmd("crash")

    def has_notes(self):
        return self.has(RetraceTask.NOTES_FILE)

    def get_notes(self):
        return self.get(RetraceTask.NOTES_FILE, maxlen=1 << 22)

    def set_notes(self, value):
        self.set_atomic(RetraceTask.NOTES_FILE, value)

    def has_notify(self):
        return self.has(RetraceTask.NOTIFY_FILE)

    def get_notify(self):
        result = self.get(RetraceTask.NOTIFY_FILE, maxlen=1 << 16)
        return [email for email in set(n.strip() for n in result.split("\n")) if email]

    def set_notify(self, values):
        if not isinstance(values, list) or not all([isinstance(v, str) for v in values]):
            raise Exception("values must be a list of strings")

        self.set_atomic(RetraceTask.NOTIFY_FILE,
                        "%s\n" % "\n".join(filter(None, set(v.strip().replace("\n", " ") for v in values))))

    def has_url(self):
        return self.has(RetraceTask.URL_FILE)

    def get_url(self):
        return self.get(RetraceTask.URL_FILE, maxlen=1 << 14)

    def set_url(self, value):
        self.set(RetraceTask.URL_FILE, value)

    def has_vmlinux(self):
        return self.has(RetraceTask.VMLINUX_FILE)

    def get_vmlinux(self):
        """Gets the contents of VMLINUX_FILE"""
        return self.get(RetraceTask.VMLINUX_FILE, maxlen=1 << 22)

    def set_vmlinux(self, value):
        self.set(RetraceTask.VMLINUX_FILE, value)

    def has_vmcore(self):
        vmcore_path = self.get_vmcore_path()
        return vmcore_path.is_file()

    def get_vmcore_path(self):
        """
        Return a path to vmcore file in crashdir.
        """
        return self.get_crashdir() / self.vmcore_file

    def add_vmcore_suffix(self, vmcore_path, filename):
        """
        Adds the suffix to a new vmcore path and sets a new vmcore name for the task.
        """
        vmcore_path = add_snapshot_suffix(vmcore_path, filename)
        self.vmcore_file = vmcore_path.name

        return vmcore_path

    def find_vmcore_file(self, filepath=""):
        """
        Return for "vmcore" file or vmcore snapshot files "vmcore(.vmss/.vmsn)" in the file path.
        Saves the file name for the task.

        Default filepath is task's crashdir.
        """
        if not filepath:
            filepath = self.get_crashdir()

        if not Path(filepath, self.VMCORE_FILE).exists():
            for f in sorted(Path(filepath).iterdir(), reverse=True):
                if f.stem == "vmcore" and (not f.suffix or f.suffix in SNAPSHOT_SUFFIXES):
                    self.vmcore_file = f.name
                    return f.name

        self.vmcore_file = self.VMCORE_FILE
        return self.VMCORE_FILE

    def has_coredump(self):
        coredump_path = self._savedir / self.COREDUMP_FILE
        return coredump_path.is_file()

    def download_block(self, data):
        self._progress_write_func(data)
        self._progress_current += len(data)
        progress = "%d%% (%s / %s)" % ((100 * self._progress_current) // self._progress_total,
                                       human_readable_size(self._progress_current),
                                       self._progress_total_str)
        self.set_atomic(RetraceTask.PROGRESS_FILE, progress)

    def run_crash_cmdline(self, crash_start, crash_cmdline):
        cmd_output = None
        returncode = 0
        crashdir = self.get_crashdir()
        try:
            t = 3600
            if CONFIG["ProcessCommunicateTimeout"]:
                t = CONFIG["ProcessCommunicateTimeout"]
            child = run(crash_start, stdout=PIPE, stderr=STDOUT,
                        cwd=crashdir, timeout=t,
                        input=crash_cmdline.encode())
            cmd_output = child.stdout
        except OSError as err:
            log_warn("crash command: '%s' triggered OSError " %
                     crash_cmdline.replace('\r', '; ').replace('\n', '; '))
            log_warn("  %s" % err)
        except TimeoutExpired:
            raise Exception("WARNING: crash command: '%s' exceeded " + str(t) +
                            " second timeout - damaged vmcore?" %
                            crash_cmdline.replace('\r', '; ').replace('\n', '; '))
        except Exception as err:
            log_warn("crash command: '%s' triggered Unknown exception %s" %
                     (crash_cmdline.replace('\r', '; ').replace('\n', '; '), err))
            log_warn("  %s" % sys.exc_info()[0])
        try:
            cmd_output.decode('utf-8')
        except UnicodeDecodeError as err:
            log_warn("crash command: '%s' triggered UnicodeDecodeError " %
                     crash_cmdline.replace('\r', '; ').replace('\n', '; '))
            log_warn("  %s" % err)

        if child.returncode:
            log_warn("crash '%s' exited with %d" % (crash_cmdline.replace('\r', '; ').replace('\n', '; '),
                                                    child.returncode))
            returncode = child.returncode

        return cmd_output, returncode

    def download_remote(self, unpack=True, timeout=0, kernelver=None):
        """Downloads all remote resources and returns a list of errors."""
        md5sums = []
        downloaded = []
        errors = []

        crashdir = self.get_crashdir()
        if not crashdir.is_dir():
            oldmask = os.umask(0o007)
            crashdir.mkdir(parents=True)
            os.umask(oldmask)

        for url in self.get_remote():
            self.set_status(STATUS_DOWNLOADING)
            log_info(STATUS[STATUS_DOWNLOADING])

            # download from a remote FTP
            if url.startswith("FTP "):
                filename = url[4:].strip()
                log_info("Retrieving FTP file '%s'" % filename)

                ftp = None
                try:
                    ftp = ftp_init()
                    with open(crashdir / filename, "wb") as target_file:
                        self._progress_write_func = target_file.write
                        self._progress_total = ftp.size(filename)
                        self._progress_total_str = human_readable_size(self._progress_total)
                        self._progress_current = 0

                        # the files are expected to be huge (even hundreds of gigabytes)
                        # use a larger buffer - 16MB by default
                        ftp.retrbinary("RETR %s" % filename, self.download_block,
                                       CONFIG["FTPBufferSize"] * (1 << 20))

                    downloaded.append(filename)
                except Exception as ex:
                    errors.append((url, str(ex)))
                    continue
                finally:
                    if ftp:
                        ftp_close(ftp)
            # download local file
            elif url.startswith("/") or url.startswith("file:///"):
                if url.startswith("file://"):
                    url = Path(url[7:])
                else:
                    url = Path(url)

                log_info("Retrieving local file '%s'" % url)

                if not url.is_file():
                    errors.append((url, "File not found"))
                    continue

                filename = url.name
                targetfile = crashdir / filename

                copy = True
                if get_archive_type(url) == ARCHIVE_UNKNOWN:
                    try:
                        log_debug("Trying hardlink")
                        os.link(url, targetfile)
                        copy = False
                        log_debug("Succeeded")
                    except OSError:
                        log_debug("Failed")

                if copy:
                    try:
                        log_debug("Copying")
                        shutil.copy(url, targetfile)
                    except Exception as ex:
                        errors.append((url, str(ex)))
                        continue

                downloaded.append(str(url))
            # use wget to download the remote file
            else:
                log_info("Retrieving remote file '%s'" % url)

                if "/" not in url:
                    errors.append((url, "malformed URL"))
                    continue

                child = run(["wget", "-nv", "-P", crashdir, url], stdout=PIPE, stderr=STDOUT, encoding='utf-8')
                stdout = child.stdout
                if child.returncode:
                    errors.append((url, "wget exited with %d: %s" % (child.returncode, stdout)))
                    continue

                filename = url.rsplit("/", 1)[1]
                downloaded.append(url)

            if self.has_md5sum():
                self.set_status(STATUS_CALCULATING_MD5SUM)
                log_info(STATUS[STATUS_CALCULATING_MD5SUM])
                md5v = self.calculate_md5(crashdir / filename)
                md5sums.append("{0} {1}".format(md5v, downloaded[-1]))
                self.set_md5sum("\n".join(md5sums)+"\n")

            self.set_status(STATUS_POSTPROCESS)
            log_info(STATUS[STATUS_POSTPROCESS])

            if unpack:
                fullpath = crashdir / filename
                if self.get_type() in [TASK_VMCORE, TASK_VMCORE_INTERACTIVE]:
                    try:
                        unpack_vmcore(fullpath)
                    except Exception as ex:
                        errors.append((fullpath, str(ex)))
                if self.get_type() in [TASK_RETRACE, TASK_RETRACE_INTERACTIVE]:
                    try:
                        unpack_coredump(fullpath)
                    except Exception as ex:
                        errors.append((fullpath, str(ex)))
                st = crashdir.stat()
                if (st.st_mode & stat.S_IRGRP) == 0 or (st.st_mode & stat.S_IXGRP) == 0:
                    try:
                        crashdir.chmod(st.st_mode | stat.S_IRGRP | stat.S_IXGRP)
                    except Exception:
                        log_warn("Crashdir '%s' is not group readable and chmod"
                                 " failed. The process will continue but if"
                                 " it fails this is the likely cause."
                                 % crashdir)

        if self.get_type() in [TASK_VMCORE, TASK_VMCORE_INTERACTIVE]:
            vmcore_path = self.get_vmcore_path()
            for filename in Path(crashdir).iterdir():
                if filename.is_dir():
                    move_dir_contents(fullpath, crashdir)

            files = list(crashdir.iterdir())
            if not files:
                errors.append(([], "No files found in the tarball"))
            elif len(files) == 1:
                if files[0] != self.VMCORE_FILE:
                    files[0].rename(vmcore_path)
            else:
                vmcores = []
                for filename in files:
                    fname, fext = filename.parent / filename.stem, filename.suffix
                    if self.VMCORE_FILE in fname and fext != ".vmem":
                        vmcores.append(filename)

                # pick the largest file
                if not vmcores:
                    absfiles = [f for f in files if f.suffix != ".vmem"]
                    files_sizes = [(f.stat().st_size, f) for f in absfiles]
                    largest_file = sorted(files_sizes, reverse=True)[0][1]
                    vmcore_path = self.add_vmcore_suffix(vmcore_path, largest_file)
                    largest_file.rename(vmcore_path)
                elif len(vmcores) > 1:
                    files_sizes = [(f.stat().st_size, f) for f in vmcores]
                    largest_file = sorted(files_sizes, reverse=True)[0][1]
                    vmcore_path = self.add_vmcore_suffix(vmcore_path, largest_file)
                    largest_file.rename(vmcore_path)
                else:
                    for filename in files:
                        if filename == vmcores[0] and vmcores[0].name != self.VMCORE_FILE:
                            vmcore_path = self.add_vmcore_suffix(vmcore_path, filename)
                            filename.rename(vmcore_path)

            for filename in Path(crashdir).iterdir():
                suffix = filename.suffix
                # keep vmcore snapshots with suffixes (vmss/vmsn/vmem)
                if filename.stem == self.VMCORE_FILE and (not suffix or suffix in SNAPSHOT_SUFFIXES):
                    continue

                filename.unlink()

        if self.get_type() in [TASK_RETRACE, TASK_RETRACE_INTERACTIVE]:
            coredump = crashdir / self.COREDUMP_FILE
            for filename in Path(crashdir).iterdir():
                if filename.is_dir():
                    move_dir_contents(filename, crashdir)

            files = list(crashdir.iterdir())
            if not files:
                errors.append(([], "No files found in the tarball"))
            elif len(files) == 1:
                if files[0] != self.COREDUMP_FILE:
                    files[0].rename(coredump)
            else:
                coredumps = []
                for filename in files:
                    if self.COREDUMP_FILE in filename:
                        coredumps.append(filename)

                # pick the largest file
                if not coredumps:
                    files_sizes = [(f.stat().st_size, f) for f in files]
                    largest_file = sorted(files_sizes, reverse=True)[0][1]
                    largest_file.rename(coredump)
                elif len(coredumps) > 1:
                    files_sizes = [(f.stat().st_size, f) for f in coredumps]
                    largest_file = sorted(files_sizes, reverse=True)[0][1]
                    largest_file.rename(coredump)
                else:
                    for filename in files:
                        if filename == coredumps[0]:
                            if coredumps[0] != self.COREDUMP_FILE:
                                filename.rename(coredump)

            for filename in Path(crashdir).iterdir():
                if filename.name in REQUIRED_FILES[self.get_type()]+["release", "os_release"]:
                    continue

                filename.unlink()

            if coredump.is_file():
                oldsize = coredump.stat().st_size
                log_info("Coredump size: %s" % human_readable_size(oldsize))

                st = coredump.stat()
                if (st.st_mode & stat.S_IRGRP) == 0:
                    try:
                        coredump.chmod(st.st_mode | stat.S_IRGRP)
                    except Exception:
                        log_warn("File '%s' is not group readable and chmod"
                                 " failed. The process will continue but if"
                                 " it fails this is the likely cause."
                                 % coredump)

        (self._savedir / RetraceTask.REMOTE_FILE).unlink()
        self.set_downloaded(", ".join(downloaded))

        return errors

    def get_results_dir(self):
        """Return the directory of results; handls legacy 'misc' dir"""
        results_dir = self._savedir / RetraceTask.RESULTS_DIR
        if not results_dir.is_dir():
            results_dir = self._savedir / "misc"
        return results_dir

    def has_results(self, name):
        """Verifies whether a file named 'name' is present in RESULTS_DIR."""
        if "/" in name:
            raise Exception("name may not contain the '/' character")

        results_dir = self.get_results_dir()
        results_path = results_dir / name

        return results_dir.is_dir() and results_path.is_file()

    def get_results_list(self):
        """Lists all files in RESULTS_DIR."""
        results_dir = self.get_results_dir()
        if not results_dir.is_dir():
            return []

        return [f.name for f in results_dir.iterdir()]

    def get_results(self, name, mode="rb"):
        """Gets content of a file named 'name' from RESULTS_DIR."""
        if "/" in name:
            raise Exception("name may not contain the '/' character")

        if not self.has_results(name):
            raise Exception("There is no record with such name")

        results_path = self.get_results_dir() / name
        with open(results_path, mode) as results_file:
            result = results_file.read(1 << 24)  # 16MB

        return result

    def add_results(self, name, value, overwrite=False, mode="wb"):
        """Adds a file named 'name' into RESULTS_DIR and writes 'value' into it."""
        if "/" in name:
            raise Exception("name may not contain the '/' character")

        if not overwrite and self.has_results(name):
            raise Exception("The record already exists. Use overwrite=True "
                            "to force overwrite existing records.")

        results_dir = self.get_results_dir()
        if not results_dir.is_dir():
            oldmask = os.umask(0o007)
            results_dir.mkdir(parents=True)
            os.umask(oldmask)

        results_path = results_dir / name
        with open(results_path, mode) as results_file:
            results_file.write(value)

    def del_results(self, name):
        """Deletes the file named 'name' from RESULTS_DIR."""
        if "/" in name:
            raise Exception("name may not contain the '/' character")

        if self.has_results(name):
            (self.get_results_dir() / name).unlink()

    def get_managed(self):
        """Verifies whether the task is under task management control"""
        if not CONFIG["AllowTaskManager"]:
            raise Exception("Task management is disabled")

        return self.has(RetraceTask.MANAGED_FILE)

    def set_managed(self, managed):
        """Puts or removes the task from task management control"""
        if not CONFIG["AllowTaskManager"]:
            raise Exception("Task management is disabled")

        # create the file if it does not exist
        if managed and not self.has(RetraceTask.MANAGED_FILE):
            self.touch(RetraceTask.MANAGED_FILE)
        # unlink the file if it exists
        elif not managed and self.has(RetraceTask.MANAGED_FILE):
            self.delete(RetraceTask.MANAGED_FILE)

    def has_downloaded(self):
        """Verifies whether DOWNLOAD_FILE exists"""
        return self.has(RetraceTask.DOWNLOADED_FILE)

    def get_downloaded(self):
        """Gets contents of DOWNLOADED_FILE"""
        return self.get(RetraceTask.DOWNLOADED_FILE, maxlen=1 << 22)

    def set_downloaded(self, value):
        """Writes (not atomically) content to DOWNLOADED_FILE"""
        self.set(RetraceTask.DOWNLOADED_FILE, value)

    def has_md5sum(self):
        """Verifies whether MD5SUM_FILE exists"""
        return self.has(RetraceTask.MD5SUM_FILE)

    def get_md5sum(self):
        """Gets contents of MD5SUM_FILE"""
        return self.get(RetraceTask.MD5SUM_FILE, maxlen=1 << 22)

    def set_md5sum(self, value):
        """Writes (not atomically) content to MD5SUM_FILE"""
        self.set(RetraceTask.MD5SUM_FILE, value)

    def has_crashrc(self):
        """Verifies whether CRASHRC_FILE exists"""
        return self.has(RetraceTask.CRASHRC_FILE)

    def get_crashrc_path(self):
        """Gets the absolute path of CRASHRC_FILE"""
        return self._get_file_path(RetraceTask.CRASHRC_FILE)

    def get_crashrc(self):
        """Gets the contents of CRASHRC_FILE"""
        return self.get(RetraceTask.CRASHRC_FILE, maxlen=1 << 22)

    def set_crashrc(self, data):
        """Writes data to CRASHRC_FILE"""
        self.set(RetraceTask.CRASHRC_FILE, data)

    def get_crash_cmd(self):
        """Gets the contents of CRASH_CMD_FILE"""
        result = self.get(RetraceTask.CRASH_CMD_FILE, maxlen=1 << 22)
        if result is None:
            self.set_crash_cmd("crash")
            return "crash"
        return result

    def set_crash_cmd(self, data):
        """Writes data to CRASH_CMD_FILE"""
        self.set(RetraceTask.CRASH_CMD_FILE, data)
        try:
            self._get_file_path(RetraceTask.CRASH_CMD_FILE).chmod(stat.S_IRUSR
                                                                  | stat.S_IWUSR
                                                                  | stat.S_IRGRP
                                                                  | stat.S_IWGRP
                                                                  | stat.S_IROTH)
        except OSError:
            pass

    def has_started_time(self):
        """Verifies whether STARTED_FILE exists"""
        return self.has(RetraceTask.STARTED_FILE)

    def get_started_time(self):
        """Gets the unix timestamp from STARTED_FILE"""
        result = self.get(RetraceTask.STARTED_FILE, maxlen=1 << 8)
        if result is None:
            return None

        return int(result)

    def set_started_time(self, value):
        """Writes the unix timestamp to STARTED_FILE"""
        try:
            data = int(value)
        except ValueError:
            raise Exception("set_start_time requires unix timestamp as parameter")

        self.set(RetraceTask.STARTED_FILE, "%d" % data)

    def has_caseno(self):
        """Verifies whether CASENO_FILE exists"""
        return self.has(RetraceTask.CASENO_FILE)

    def get_caseno(self):
        """Gets the case number from CASENO_FILE"""
        result = self.get(RetraceTask.CASENO_FILE, maxlen=1 << 8)
        if result is None:
            return None

        return int(result)

    def set_caseno(self, value):
        """Writes case number into CASENO_FILE"""
        try:
            data = int(value)
        except ValueError:
            raise Exception("set_caseno requires a number as parameter")

        self.set(RetraceTask.CASENO_FILE, "%d" % data)

    def has_bugzillano(self):
        """Verifies whether BUGZILLANO_FILE exists"""
        return self.has(RetraceTask.BUGZILLANO_FILE)

    def get_bugzillano(self):
        """Gets the bugzilla number from BUGZILLANO_FILE"""
        result = self.get(RetraceTask.BUGZILLANO_FILE, maxlen=1 << 8)
        if result is None:
            return None

        return [bz_number for bz_number in set(n.strip() for n in result.split("\n")) if bz_number]

    def set_bugzillano(self, values):
        """Writes bugzilla numbers into BUGZILLANO_FILE"""
        if not isinstance(values, list) or not all([isinstance(v, str) for v in values]):
            raise Exception("values must be a list of integers")

        self.set_atomic(RetraceTask.BUGZILLANO_FILE,
                        "%s\n" % "\n".join(filter(None, set(v.strip().replace("\n", " ") for v in values))))

    def has_finished_time(self):
        """Verifies whether FINISHED_FILE exists"""
        return self.has(RetraceTask.FINISHED_FILE)

    def get_finished_time(self):
        """Gets the unix timestamp from FINISHED_FILE"""
        result = self.get(RetraceTask.FINISHED_FILE, 1 << 8)
        if result is None:
            return None

        return int(result)

    def set_finished_time(self, value):
        """Writes the unix timestamp to FINISHED_FILE"""
        try:
            data = int(value)
        except ValueError:
            raise Exception("set_finished_time requires unix timestamp as parameter")

        self.set(RetraceTask.FINISHED_FILE, "%d" % data)

    def get_default_started_time(self):
        """Get ctime of the task directory"""
        return int(self._savedir.stat().st_ctime)

    def get_default_finished_time(self):
        """Get mtime of the task directory"""
        return int(self._savedir.stat().st_mtime)

    def clean(self):
        """Removes all files and directories others than
        results and logs from the task directory."""
        if (self._savedir / "default.cfg").is_file() and \
           (self._savedir / "site-defaults.cfg").is_file() and \
           (self._savedir / "logging.ini").is_file():
            run(["/usr/bin/mock", "--configdir", self._savedir, "--scrub=all"],
                stdout=DEVNULL)

        if CONFIG["RetraceEnvironment"] == "podman":
            img_cont_id = str(self._taskid)
            run(["/usr/bin/podman", "rmi", "retrace-image:%s" % img_cont_id],
                stdout=DEVNULL)

        for f in Path(self._savedir).iterdir():
            if f.name not in [RetraceTask.REMOTE_FILE, RetraceTask.CASENO_FILE,
                              RetraceTask.BACKTRACE_FILE, RetraceTask.DOWNLOADED_FILE,
                              RetraceTask.FINISHED_FILE, RetraceTask.LOG_FILE,
                              RetraceTask.MANAGED_FILE, RetraceTask.NOTES_FILE,
                              RetraceTask.NOTIFY_FILE, RetraceTask.PASSWORD_FILE,
                              RetraceTask.STARTED_FILE, RetraceTask.STATUS_FILE,
                              RetraceTask.TYPE_FILE, RetraceTask.RESULTS_DIR,
                              RetraceTask.CRASHRC_FILE, RetraceTask.CRASH_CMD_FILE,
                              RetraceTask.URL_FILE, RetraceTask.MOCK_LOG_DIR,
                              RetraceTask.VMLINUX_FILE, RetraceTask.BUGZILLANO_FILE]:

                try:
                    if f.is_dir():
                        shutil.rmtree(f)
                    else:
                        f.unlink()
                except OSError:
                    # clean as much as possible
                    # ToDo advanced handling
                    pass

    def reset(self):
        """Remove all generated files and only keep the raw crash data"""
        for filename in [RetraceTask.BACKTRACE_FILE, RetraceTask.CRASHRC_FILE,
                         RetraceTask.FINISHED_FILE, RetraceTask.LOG_FILE,
                         RetraceTask.PROGRESS_FILE, RetraceTask.STARTED_FILE,
                         RetraceTask.STATUS_FILE, RetraceTask.MOCK_DEFAULT_CFG,
                         RetraceTask.MOCK_SITE_DEFAULTS_CFG, RetraceTask.MOCK_LOGGING_INI,
                         RetraceTask.CRASH_CMD_FILE, RetraceTask.MOCK_LOG_DIR,
                         RetraceTask.VMLINUX_FILE]:
            try:
                (self._savedir / filename).unlink()
            except OSError as ex:
                # ignore 'No such file or directory'
                if ex.errno != errno.ENOENT:
                    raise

        results_dir = self.get_results_dir()
        for filename in Path(results_dir).iterdir():
            filename.unlink()

        kerneldir = Path(CONFIG["SaveDir"], "%d-kernel" % self._taskid)
        if kerneldir.is_dir():
            shutil.rmtree(kerneldir)

    def remove(self):
        """Completely removes the task directory."""
        self.clean()
        kerneldir = Path(CONFIG["SaveDir"], "%d-kernel" % self._taskid)
        if kerneldir.is_dir():
            shutil.rmtree(kerneldir)

        shutil.rmtree(self._savedir)

    def create_worker(self):
        """Get default worker instance for this task"""
        # TODO: let it be configurable
        from .retrace_worker import RetraceWorker
        return RetraceWorker(self)


### create ConfigClass instance on import ###
CONFIG = Config()
