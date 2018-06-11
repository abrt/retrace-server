from __future__ import division
import datetime
import errno
import ftplib
import gettext
import logging
import os
import grp
import re
import random
import shutil
import smtplib
import sqlite3
import stat
import time
import hashlib
from signal import *
from subprocess import *
import magic
import six
from six.moves import range, urllib
from rpmUtils.miscutils import splitFilename
from webob import Request
from .argparser import *
from .config import *
from .plugins import *

GETTEXT_DOMAIN = "retrace-server"

# filename: max_size (<= 0 unlimited)
ALLOWED_FILES = {
    "coredump": 0,
    "executable": 512,
    "package": 128,
    "packages": (1 << 20), # 1MB
    "os_release": 128,
    "os_release_in_rootdir": 128,
    "rootdir": 256,
    "release": 128,
    "vmcore": 0,
}

TASK_RETRACE, TASK_DEBUG, TASK_VMCORE, TASK_RETRACE_INTERACTIVE, \
  TASK_VMCORE_INTERACTIVE = range(5)

TASK_TYPES = [TASK_RETRACE, TASK_DEBUG, TASK_VMCORE,
              TASK_RETRACE_INTERACTIVE, TASK_VMCORE_INTERACTIVE]

ARCHIVE_UNKNOWN, ARCHIVE_GZ, ARCHIVE_ZIP, \
  ARCHIVE_BZ2, ARCHIVE_XZ, ARCHIVE_TAR, \
  ARCHIVE_7Z, ARCHIVE_LZOP = range(8)

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

BUGZILLA_STATUS = ["NEW", "ASSIGNED", "ON_DEV", "POST", "MODIFIED", "ON_QA", "VERIFIED",
                   "RELEASE_PENDING", "CLOSED"]

#characters, numbers, dash (utf-8, iso-8859-2 etc.)
INPUT_CHARSET_PARSER = re.compile("^([a-zA-Z0-9\-]+)(,.*)?$")
#en_GB, sk-SK, cs, fr etc.
INPUT_LANG_PARSER = re.compile("^([a-z]{2}([_\-][A-Z]{2})?)(,.*)?$")
#characters allowed by Fedora Naming Guidelines
INPUT_PACKAGE_PARSER = re.compile("^([1-9][0-9]*:)?[a-zA-Z0-9\-\.\_\+]+$")
#architecture (i386, x86_64, armv7hl, mips4kec)
INPUT_ARCH_PARSER = re.compile("^[a-zA-Z0-9_]+$")
#name-version-arch (fedora-16-x86_64, rhel-6.2-i386, opensuse-12.1-x86_64)
INPUT_RELEASEID_PARSER = re.compile("^[a-zA-Z0-9]+\-[0-9a-zA-Z\.]+\-[a-zA-Z0-9_]+$")

CORE_ARCH_PARSER = re.compile("core file,? .*(x86-64|80386|ARM|aarch64|IBM S/390|64-bit PowerPC)")
PACKAGE_PARSER = re.compile("^(.+)-([0-9]+(\.[0-9]+)*-[0-9]+)\.([^-]+)$")
DF_OUTPUT_PARSER = re.compile("^([^ ^\t]*)[ \t]+([0-9]+)[ \t]+([0-9]+)[ \t]+([0-9]+)[ \t]+([0-9]+%)[ \t]+(.*)$")
DU_OUTPUT_PARSER = re.compile("^([0-9]+)")
URL_PARSER = re.compile("^/([0-9]+)/?")

REPODIR_NAME_PARSER = re.compile("^[^\-]+\-[^\-]+\-[^\-]+$")

KO_DEBUG_PARSER = re.compile("^.*/([a-zA-Z0-9_\-]+)\.ko\.debug$")

DUMP_LEVEL_PARSER = re.compile("^[ \t]*dump_level[ \t]*:[ \t]*([0-9]+).*$")

WORKER_RUNNING_PARSER = re.compile("^[ \t]*([0-9]+)[ \t]+[0-9]+[ \t]+([^ ^\t]+)[ \t]"
                                   "+.*retrace-server-worker ([0-9]+)( .*)?$")

UNITS = ["B", "kB", "MB", "GB", "TB", "PB", "EB"]

HANDLE_ARCHIVE = {
    "application/x-xz-compressed-tar": {
        "unpack": [TAR_BIN, "xJf"],
        "size": ([XZ_BIN, "--list", "--robot"],
                 re.compile("^totals[ \t]+[0-9]+[ \t]+[0-9]+[ \t]+[0-9]+[ \t]+([0-9]+).*")),
        "type": ARCHIVE_XZ,
    },

    "application/x-gzip": {
        "unpack": [TAR_BIN, "xzf"],
        "size": ([GZIP_BIN, "--list"], re.compile("^[^0-9]*[0-9]+[^0-9]+([0-9]+).*$")),
        "type": ARCHIVE_GZ,
    },

    "application/x-tar": {
        "unpack": [TAR_BIN, "xf"],
        "size": (["ls", "-l"],
                 re.compile("^[ \t]*[^ ^\t]+[ \t]+[^ ^\t]+[ \t]+[^ ^\t]+[ \t]+[^ ^\t]+[ \t]+([0-9]+).*$")),
        "type": ARCHIVE_TAR,
    },
}

FTP_SUPPORTED_EXTENSIONS = [".tar.gz", ".tgz", ".tarz", ".tar.bz2", ".tar.xz",
                            ".tar", ".gz", ".bz2", ".xz", ".Z", ".zip"]

REPO_PREFIX = "retrace-"
EXPLOITABLE_PLUGIN_PATH = "/usr/libexec/abrt-gdb-exploitable"
EXPLOITABLE_SEPARATOR = "== EXPLOITABLE ==\n"

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

PYTHON_LABLE_START = "----------PYTHON-START--------"
PYTHON_LABLE_END = "----------PYTHON--END---------"

class RetraceError(Exception):
    pass


class RetraceWorkerError(RetraceError):
    def __init__(self, message=None, errorcode=1):
        super(RetraceWorkerError, self).__init__(message)
        self.errorcode = errorcode


def now():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


logger = logging.getLogger(__name__)


def log_info(msg):
    logger.info("%23s %s" % (now(), msg))

def log_debug(msg):
    logger.debug("%22s %s" % (now(), msg))

def log_warn(msg):
    logger.warn("%20s %s" % (now(), msg))

def log_error(msg):
    logger.error("%22s %s" % (now(), msg))

def lock(lockfile):
    try:
        fd = os.open(lockfile, os.O_CREAT | os.O_EXCL, 0o600)
    except OSError as ex:
        if ex[0] == errno.EEXIST:
            return False
        else:
            raise ex

    os.close(fd)
    return True

def unlock(lockfile):
    try:
        if os.path.getsize(lockfile) == 0:
            os.unlink(lockfile)
    except:
        return False

    return True

def get_canon_arch(arch):
    for canon_arch, derived_archs in ARCH_MAP.items():
        if arch in derived_archs:
            return canon_arch

    return arch

def free_space(path):
    child = Popen([DF_BIN, "-B", "1", path], stdout=PIPE)
    lines = child.communicate()[0].split("\n")
    for line in lines:
        match = DF_OUTPUT_PARSER.match(line)
        if match:
            return int(match.group(4))

    return None

def dir_size(path):
    child = Popen([DU_BIN, "-sb", path], stdout=PIPE)
    lines = child.communicate()[0].split("\n")
    for line in lines:
        match = DU_OUTPUT_PARSER.match(line)
        if match:
            return int(match.group(1))

    return 0

def unpacked_size(archive, mime):
    command, parser = HANDLE_ARCHIVE[mime]["size"]
    child = Popen(command + [archive], stdout=PIPE)
    lines = child.communicate()[0].split("\n")
    for line in lines:
        match = parser.match(line)
        if match:
            return int(match.group(1))

    return None

def guess_arch(coredump_path):
    child = Popen(["file", coredump_path], stdout=PIPE)
    output = child.communicate()[0]
    match = CORE_ARCH_PARSER.search(output)
    if match:
        if match.group(1) == "80386":
            return "i386"
        elif match.group(1) == "x86-64":
            return "x86_64"
        elif match.group(1) == "ARM":
            # hack - There is no reliable way to determine which ARM
            # version the coredump is. At the moment we only support
            # armv7hl / armhfp - let's approximate arm = armhfp
            return "armhfp"
        elif match.group(1) == "aarch64":
            return "aarch64"
        elif match.group(1) == "IBM S/390":
            return "s390x"
        elif match.group(1) == "64-bit PowerPC":
            if "LSB" in output:
                return "ppc64le"

            return "ppc64"

    result = None
    child = Popen(["strings", coredump_path], stdout=PIPE, stderr=STDOUT)
    line = child.stdout.readline()
    while line:
        for canon_arch, derived_archs in ARCH_MAP.items():
            if any(arch in line for arch in derived_archs):
                result = canon_arch
                break

        if result is not None:
            break

        line = child.stdout.readline()

    child.kill()
    child.stdout.close()

    # "ppc64le" matches both ppc64 and ppc64le
    # if file magic says little endian, fix it
    if result == "ppc64" and "LSB" in output:
        result = "ppc64le"

    return result


def get_supported_releases():
    result = []
    files = os.listdir(CONFIG["RepoDir"])
    for f in files:
        fullpath = os.path.join(CONFIG["RepoDir"], f)
        if not os.path.isdir(fullpath):
            continue

        if REPODIR_NAME_PARSER.match(f) and \
           os.path.isdir(os.path.join(fullpath, "repodata")):
            result.append(f)

    return result

def parse_http_gettext(lang, charset):
    result = lambda x: x
    lang_match = INPUT_LANG_PARSER.match(lang)
    charset_match = INPUT_CHARSET_PARSER.match(charset)
    if lang_match and charset_match:
        try:
            result = gettext.translation(GETTEXT_DOMAIN,
                                         languages=[lang_match.group(1)],
                                         codeset=charset_match.group(1)).gettext
        except:
            pass

    return result

def run_gdb(savedir, plugin):
    #exception is caught on the higher level
    exec_file = open(os.path.join(savedir, "crash", "executable"), "r")
    executable = exec_file.read(ALLOWED_FILES["executable"])
    exec_file.close()

    if '"' in executable or "'" in executable:
        raise Exception("Executable contains forbidden characters")

    with open(os.devnull, "w") as null:
        child = Popen(["/usr/bin/mock", "shell", "--configdir", savedir,
                       "--", "ls '%s'" % executable],
                      stdout=PIPE, stderr=null)
        output = child.communicate()[0]
        if output.strip() != executable:
            raise Exception("The appropriate package set could not be installed")

        chmod = call(["/usr/bin/mock", "shell", "--configdir", savedir,
                      "--", "/bin/chmod a+r '%s'" % executable],
                     stdout=null, stderr=null)

        if chmod != 0:
            raise Exception("Unable to chmod the executable")

        child = Popen(["/usr/bin/mock", "shell", "--configdir", savedir,
                       "--", "ls '%s'" % EXPLOITABLE_PLUGIN_PATH],
                      stdout=PIPE, stderr=null)
        add_exploitable = child.communicate()[0].strip() == EXPLOITABLE_PLUGIN_PATH

        batfile = os.path.join(savedir, "gdb.sh")
        with open(batfile, "w") as gdbfile:
            gdbfile.write("%s -batch " % plugin.gdb_executable)
            if add_exploitable:
                gdbfile.write("-ex 'python execfile(\"/usr/libexec/abrt-gdb-exploitable\")' ")
            gdbfile.write("-ex 'file %s' "
                          "-ex 'core-file /var/spool/abrt/crash/coredump' "
                          "-ex 'echo %s\n' "
                          "-ex 'py-bt' "
                          "-ex 'py-list' "
                          "-ex 'py-locals' "
                          "-ex 'echo %s\n' "
                          "-ex 'thread apply all -ascending backtrace 2048 full' "
                          "-ex 'info sharedlib' "
                          "-ex 'print (char*)__abort_msg' "
                          "-ex 'print (char*)__glib_assert_msg' "
                          "-ex 'info registers' "
                          "-ex 'disassemble' " % (executable, PYTHON_LABLE_START, PYTHON_LABLE_END))
            if add_exploitable:
                gdbfile.write("-ex 'echo %s' "
                              "-ex 'abrt-exploitable'" % EXPLOITABLE_SEPARATOR)

        copyin = call(["/usr/bin/mock", "--configdir", savedir, "--copyin",
                       batfile, "/var/spool/abrt/gdb.sh"],
                      stdout=null, stderr=null)
        if copyin:
            raise Exception("Unable to copy GDB launcher into chroot")

        chmod = call(["/usr/bin/mock", "--configdir", savedir, "shell",
                      "--", "/bin/chmod a+rx /var/spool/abrt/gdb.sh"],
                     stdout=null, stderr=null)
        if chmod:
            raise Exception("Unable to chmod GDB launcher")

        child = Popen(["/usr/bin/mock", "shell", "--configdir", savedir,
                       "--", "su mockbuild -c '/bin/sh /var/spool/abrt/gdb.sh'",
                       # redirect GDB's stderr, ignore mock's stderr
                       "2>&1"], stdout=PIPE, stderr=null)

    backtrace = child.communicate()[0].strip()
    if child.wait():
        raise Exception("Running GDB failed")

    exploitable = None
    if EXPLOITABLE_SEPARATOR in backtrace:
        backtrace, exploitable = backtrace.rsplit(EXPLOITABLE_SEPARATOR, 1)

    if not backtrace:
        raise Exception("An unusable backtrace has been generated")

    python_labels = PYTHON_LABLE_START+'\n'+PYTHON_LABLE_END+'\n'
    if python_labels in backtrace:
        backtrace = backtrace.replace(python_labels, "")

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
        else:
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
    for releaseid in releases:
        for derived_archs in ARCH_MAP.values():
            if arch not in derived_archs:
                continue

            for a in derived_archs:
                candidates.append(os.path.join(CONFIG["RepoDir"], releaseid, "Packages",
                                               "%s.%s.rpm" % (package_nvr, a)))
                candidates.append(os.path.join(CONFIG["RepoDir"], releaseid,
                                               "%s.%s.rpm" % (package_nvr, a)))
            break
        else:
            candidates.append(os.path.join(CONFIG["RepoDir"], releaseid, "Packages",
                                           "%s.%s.rpm" % (package_nvr, arch)))
            candidates.append(os.path.join(CONFIG["RepoDir"], releaseid,
                                           "%s.%s.rpm" % (package_nvr, arch)))

    return any([os.path.isfile(f) for f in candidates])


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
# NOTE: We can get "OSRELEASE=%" so we disallow the '%' character after the '='
OSRELEASE_VAR_PARSER = re.compile("OSRELEASE=([^%][^\x00\s]+)")
# 2. Look for "Linux version" string.  Note that this was taken from
# CAS 'fingerprint' database code.  For more info, see
# https://bugzilla.redhat.com/show_bug.cgi?id=1535592#c9 and
# https://github.com/battlemidget/core-analysis-system/blob/master/lib/cas/core.py#L96
# For exmaple:
# Linux version 3.10.0-693.11.1.el7.x86_64 (mockbuild@x86-041.build.eng.bos.redhat.com)
# (gcc version 4.8.5 20150623 (Red Hat 4.8.5-16) (GCC) ) #1 SMP Fri Oct 27 05:39:05 EDT 2017
LINUX_VERSION_PARSER = re.compile('Linux\sversion\s(\S+)\s+(.*20\d{1,2}|#1\s.*20\d{1,2})')
# 3. Look for the actual kernel release. For example:
# 2.6.32-209.el6.x86_64 | 2.6.18-197.el5
KERNEL_RELEASE_PARSER = re.compile('(\d+\.\d+\.\d+)-(\d+\.[^\x00\s]+)')
def get_kernel_release(vmcore, crash_cmd=["crash"]):
    # First use 'crash' to identify the kernel version.
    # set SIGPIPE to default handler for bz 1540253
    save = getsignal(SIGPIPE)
    signal(SIGPIPE, SIG_DFL)
    child = Popen(crash_cmd + ["--osrelease", vmcore], stdout=PIPE, stderr=STDOUT)
    release = child.communicate()[0].strip()
    ret = child.wait()
    signal(SIGPIPE, save)

    # If the crash tool fails, we must try some other method.
    # Read the first small portion of the file and use a few different
    # regex searches on the file.
    if ret != 0 or \
       not release or \
       "\n" in release or \
       release == "unknown":
        try:
            fd = open(vmcore)
            fd.seek(0)
            blksize = 64000000
            b = os.read(fd.fileno(), blksize)
        except OSError as e:
            log_error("Failed to get kernel release - failed open/seek/read of file %s with errno(%d - '%s')"
                      % (vmcore, e.errno, e.strerror()))
            if fd:
                fd.close()
            return None
        release = OSRELEASE_VAR_PARSER.search(b)
        if release:
            release = release.group(1)
        if not release:
            release = LINUX_VERSION_PARSER.search(b)
            if release:
                release = release.group(1)
        if not release:
            release = KERNEL_RELEASE_PARSER.search(b)
            if release:
                release = release.group(0)

        fd.close()

    # Clean up the release before returning or calling KernelVer
    if release is None or release == "unknown":
        log_error("Failed to get kernel release from file %s" % vmcore)
        return None
    else:
        release = release.rstrip('\0 \t\n')

    # check whether architecture is present
    try:
        result = KernelVer(release)
    except Exception as ex:
        log_error("Failed to parse kernel release from file %s, release = %s: %s" % (vmcore, release, str(ex)))
        return None

    if result.arch is None:
        result.arch = guess_arch(vmcore)
        if not result.arch:
            log_error("Unable to determine architecture from file %s, release = %s, arch result = %s"
                      % (vmcore, release, result))
            return None

    return result

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
                else:
                    log_debug("LOB not found {0}".format(p.get_lob_path("package")))

    # search for the debuginfo RPM
    ver = None
    for release in os.listdir(CONFIG["RepoDir"]):
        for ver in vers:
            testfile = os.path.join(CONFIG["RepoDir"], release, "Packages", ver.package_name(debug=True))
            log_debug("Trying debuginfo file: %s" % testfile)
            if os.path.isfile(testfile):
                return testfile

            # should not happen, but anyway...
            testfile = os.path.join(CONFIG["RepoDir"], release, ver.package_name(debug=True))
            log_debug("Trying debuginfo file: %s" % testfile)
            if os.path.isfile(testfile):
                return testfile

    if ver is not None and ver.rt:
        basename = "kernel-rt"
    else:
        basename = "kernel"

    # koji-like root
    for ver in vers:
        testfile = os.path.join(CONFIG["KojiRoot"], "packages", basename, ver.version, ver.release,
                                ver._arch, ver.package_name(debug=True))
        log_debug("Trying debuginfo file: %s" % testfile)
        if os.path.isfile(testfile):
            return testfile

    if CONFIG["WgetKernelDebuginfos"]:
        downloaddir = os.path.join(CONFIG["RepoDir"], "download")
        if not os.path.isdir(downloaddir):
            oldmask = os.umask(0o007)
            os.makedirs(downloaddir)
            os.umask(oldmask)

        for ver in vers:
            pkgname = ver.package_name(debug=True)
            url = CONFIG["KernelDebuginfoURL"].replace("$VERSION", ver.version).replace("$RELEASE", ver.release)\
                  .replace("$ARCH", ver._arch).replace("$BASENAME", basename)
            if not url.endswith("/"):
                url += "/"
            url += pkgname

            log_debug("Trying debuginfo URL: %s" % url)
            with open(os.devnull, "w") as null:
                retcode = call(["wget", "-nv", "-P", downloaddir, url], stdout=null, stderr=null)

            if retcode == 0:
                return os.path.join(downloaddir, pkgname)

    return None

def cache_files_from_debuginfo(debuginfo, basedir, files):
    # important! if empty list is specified, the whole debuginfo would be unpacked
    if not files:
        return

    if not os.path.isfile(debuginfo):
        raise Exception("Given debuginfo file does not exist")

    # prepend absolute path /usr/lib/debug/... with dot, so that cpio can match it
    for i in range(len(files)):
        if files[i][0] == "/":
            files[i] = ".%s" % files[i]

    with open(os.devnull, "w") as null:
        rpm2cpio = Popen(["rpm2cpio", debuginfo], stdout=PIPE, stderr=null)
        cpio = Popen(["cpio", "-id"] + files, stdin=rpm2cpio.stdout, stdout=null, stderr=null, cwd=basedir)
        rpm2cpio.wait()
        cpio.wait()
        rpm2cpio.stdout.close()


def get_vmcore_dump_level(task, vmlinux=None):
    vmcore_path = os.path.join(task.get_savedir(), "crash", "vmcore")
    if not os.path.isfile(vmcore_path):
        return None

    dmesg_path = os.path.join(task.get_savedir(), RetraceTask.MISC_DIR, "dmesg")
    if os.path.isfile(dmesg_path):
        os.unlink(dmesg_path)

    with open(os.devnull, "w") as null:
        cmd = ["makedumpfile", "-D", "--dump-dmesg", vmcore_path, dmesg_path]
        if vmlinux is not None:
            cmd.append("-x")
            cmd.append(vmlinux)

        result = None
        child = Popen(cmd, stdout=PIPE, stderr=null)
        line = child.stdout.readline()
        while line:
            match = DUMP_LEVEL_PARSER.match(line)
            line = child.stdout.readline()
            if match is None:
                continue

            result = int(match.group(1))
            child.terminate()
            break

        child.wait()
        return result

def get_files_sizes(directory):
    result = []

    for f in os.listdir(directory):
        fullpath = os.path.join(directory, f)
        if os.path.isfile(fullpath):
            result.append((fullpath, os.path.getsize(fullpath)))
        elif os.path.isdir(fullpath):
            result += get_files_sizes(fullpath)

    return sorted(result, key=lambda f_s: f_s[1], reverse=True)

def get_archive_type(path):
    ms = magic.open(magic.MAGIC_NONE)
    ms.load()
    filetype = ms.file(path).lower()
    log_debug("File type: %s" % filetype)

    if "bzip2 compressed data" in filetype:
        log_debug("bzip2 detected")
        return ARCHIVE_BZ2
    elif "gzip compressed data" in filetype or \
         "compress'd data" in filetype:
        log_debug("gzip detected")
        return ARCHIVE_GZ
    elif "xz compressed data" in filetype:
        log_debug("xz detected")
        return ARCHIVE_XZ
    elif "7-zip archive data" in filetype:
        log_debug("7-zip detected")
        return ARCHIVE_7Z
    elif "zip archive data" in filetype:
        log_debug("zip detected")
        return ARCHIVE_ZIP
    elif "tar archive" in filetype:
        log_debug("tar detected")
        return ARCHIVE_TAR
    elif "lzop compressed data" in filetype:
        log_debug("lzop detected")
        return ARCHIVE_LZOP

    log_debug("unknown file type, unpacking finished")
    return ARCHIVE_UNKNOWN

def rename_with_suffix(frompath, topath):
    suffix = SUFFIX_MAP[get_archive_type(frompath)]
    if not topath.endswith(suffix):
        topath = "%s%s" % (topath, suffix)

    os.rename(frompath, topath)

    return topath

def unpack_vmcore(path):
    parentdir = os.path.dirname(path)
    archivebase = os.path.join(parentdir, "archive")
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

        if os.path.isfile(archive):
            os.unlink(archive)

        files_sizes = get_files_sizes(parentdir)
        newfiles = [f for (f, s) in files_sizes]
        diff = set(newfiles) - files
        vmcore_candidate = 0
        while vmcore_candidate < len(newfiles) and \
              not newfiles[vmcore_candidate] in diff:
            vmcore_candidate += 1

        if len(diff) > 1:
            archive = rename_with_suffix(newfiles[vmcore_candidate], archivebase)
            for filename in newfiles:
                if not filename in diff or \
                   filename == newfiles[vmcore_candidate]:
                    continue

                os.unlink(filename)

        elif len(diff) == 1:
            archive = rename_with_suffix(diff.pop(), archivebase)

        # just be explicit here - if no file changed, an archive
        # has most probably been unpacked to a file with same name
        else:
            pass

        for filename in os.listdir(parentdir):
            fullpath = os.path.join(parentdir, filename)
            if os.path.isdir(fullpath):
                shutil.rmtree(fullpath)

        filetype = get_archive_type(archive)

    os.rename(archive, os.path.join(parentdir, "vmcore"))


def unpack_coredump(path):
    processed = set()
    parentdir = os.path.dirname(path)
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

        if os.path.isfile(archive) and filetype != ARCHIVE_UNKNOWN:
            os.unlink(archive)
        processed.add(archive)

        files = set(f for (f, s) in get_files_sizes(parentdir))

    # If coredump is not present, the biggest file becomes it
    if "coredump" not in os.listdir(parentdir):
        os.rename(get_files_sizes(parentdir)[0][0],
                  os.path.join(parentdir, "coredump"))

    for filename in os.listdir(parentdir):
        fullpath = os.path.join(parentdir, filename)
        if os.path.isdir(fullpath):
            shutil.rmtree(fullpath)


def get_task_est_time(taskdir):
    return 180

def unpack(archive, mime, targetdir=None):
    cmd = list(HANDLE_ARCHIVE[mime]["unpack"])
    cmd.append(archive)
    if not targetdir is None:
        cmd.append("--directory")
        cmd.append(targetdir)

    retcode = call(cmd)
    return retcode

def response(start_response, status, body="", extra_headers=[]):
    start_response(status, [("Content-Type", "text/plain"), ("Content-Length", "%d" % len(body))] + extra_headers)
    return [body]

def run_ps():
    child = Popen(["ps", "-eo", "pid,ppid,etime,cmd"], stdout=PIPE)
    lines = child.communicate()[0].split("\n")

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

    for filename in os.listdir(CONFIG["SaveDir"]):
        if len(filename) != CONFIG["TaskIdLength"]:
            continue

        try:
            task = RetraceTask(int(filename))
        except:
            continue

        if CONFIG["AllowTaskManager"] and task.get_managed():
            continue

        if not task.has_log():
            tasks.append(task.get_taskid())

    return tasks

def get_md5_tasks():
    tasks = []

    for filename in os.listdir(CONFIG["SaveDir"]):
        if len(filename) != CONFIG["TaskIdLength"]:
            continue

        try:
            task = RetraceTask(int(filename))
        except:
            continue

        if not task.has_status():
            continue
        else:
            status = task.get_status()

        if status != STATUS_SUCCESS and status != STATUS_FAIL:
            continue

        if not task.has_finished_time():
            continue

        if task.has_md5sum():
            tasks.append(task)

    return tasks

def parse_rpm_name(name):
    result = {
        "epoch": 0,
        "name": None,
        "version": "",
        "release": "",
        "arch": "",
    }
    (result["name"],
     result["version"],
     result["release"],
     result["epoch"],
     result["arch"]) = splitFilename(name + ".mockarch.rpm")

    return result

def init_crashstats_db():
    # create the database group-writable and world-readable
    old_umask = os.umask(0o113)
    con = sqlite3.connect(os.path.join(CONFIG["SaveDir"], CONFIG["DBFile"]))
    os.umask(old_umask)

    query = con.cursor()
    query.execute("PRAGMA foreign_keys = ON")
    query.execute("""
      CREATE TABLE IF NOT EXISTS
      tasks(id INTEGER PRIMARY KEY AUTOINCREMENT, taskid, package, version,
      arch, starttime NOT NULL, duration NOT NULL, coresize, status NOT NULL)
    """)
    query.execute("""
      CREATE TABLE IF NOT EXISTS
      success(taskid REFERENCES tasks(id), pre NOT NULL, post NOT NULL,
              rootsize NOT NULL)
    """)
    query.execute("""
      CREATE TABLE IF NOT EXISTS
      packages(id INTEGER PRIMARY KEY AUTOINCREMENT,
               name NOT NULL, version NOT NULL)
    """)
    query.execute("""
      CREATE TABLE IF NOT EXISTS
      packages_tasks(pkgid REFERENCES packages(id),
                     taskid REFERENCES tasks(id))
    """)
    query.execute("""
      CREATE TABLE IF NOT EXISTS
      buildids(taskid REFERENCES tasks(id), soname, buildid NOT NULL)
    """)
    query.execute("""
      CREATE TABLE IF NOT EXISTS
      reportfull(requesttime NOT NULL, ip NOT NULL)
    """)
    con.commit()

    return con

def save_crashstats(stats, con=None):
    close = False
    if con is None:
        con = init_crashstats_db()
        close = True

    query = con.cursor()
    query.execute("""
      INSERT INTO tasks (taskid, package, version, arch,
      starttime, duration, coresize, status)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      """,
                  (stats["taskid"], stats["package"], stats["version"],
                   stats["arch"], stats["starttime"], stats["duration"],
                   stats["coresize"], stats["status"]))

    con.commit()
    if close:
        con.close()

    return query.lastrowid

def save_crashstats_success(statsid, pre, post, rootsize, con=None):
    close = False
    if con is None:
        con = init_crashstats_db()
        close = True

    query = con.cursor()
    query.execute("""
      INSERT INTO success (taskid, pre, post, rootsize)
      VALUES (?, ?, ?, ?)
      """,
                  (statsid, pre, post, rootsize))

    con.commit()
    if close:
        con.close()

def save_crashstats_packages(statsid, packages, con=None):
    close = False
    if con is None:
        con = init_crashstats_db()
        close = True

    query = con.cursor()
    for package in packages:
        pkgdata = parse_rpm_name(package)
        if pkgdata["name"] is None:
            continue

        ver = "%s-%s" % (pkgdata["version"], pkgdata["release"])
        query.execute("SELECT id FROM packages WHERE name = ? AND version = ?",
                      (pkgdata["name"], ver))
        row = query.fetchone()
        if row:
            pkgid = row[0]
        else:
            query.execute("INSERT INTO packages (name, version) VALUES (?, ?)",
                          (pkgdata["name"], ver))
            pkgid = query.lastrowid

        query.execute("""
          INSERT INTO packages_tasks (taskid, pkgid) VALUES (?, ?)
          """, (statsid, pkgid))

    con.commit()
    if close:
        con.close()

def save_crashstats_build_ids(statsid, buildids, con=None):
    close = False
    if con is None:
        con = init_crashstats_db()
        close = True

    query = con.cursor()
    for soname, buildid in buildids:
        query.execute("""
          INSERT INTO buildids (taskid, soname, buildid)
          VALUES (?, ?, ?)
          """,
                      (statsid, soname, buildid))

    con.commit()
    if close:
        con.close()

def save_crashstats_reportfull(ip, con=None):
    close = False
    if con is None:
        con = init_crashstats_db()
        close = True

    query = con.cursor()
    query.execute("""
      INSERT INTO reportfull (requesttime, ip)
      VALUES (?, ?)
      """,
                  (int(time.time()), ip))

    con.commit()
    if close:
        con.close()

def send_email(frm, to, subject, body):
    if isinstance(to, list):
        to = ",".join(to)

    if not isinstance(to, str):
        raise Exception("'to' must be either string or a list of strings")

    msg = "From: %s\n" \
          "To: %s\n" \
          "Subject: %s\n" \
          "\n" \
          "%s" % (frm, to, subject, body)

    smtp = smtplib.SMTP("localhost")
    smtp.sendmail(frm, to, msg)
    smtp.close()

def ftp_init():
    if CONFIG["FTPSSL"]:
        ftp = ftplib.FTP_SSL(CONFIG["FTPHost"])
        ftp.prot_p()
    else:
        ftp = ftplib.FTP(CONFIG["FTPHost"])

    ftp.login(CONFIG["FTPUser"], CONFIG["FTPPass"])
    ftp.cwd(CONFIG["FTPDir"])

    return ftp

def ftp_close(ftp):
    try:
        ftp.quit()
    except:
        ftp.close()

def ftp_list_dir(ftpdir="/", ftp=None):
    close = False
    if ftp is None:
        ftp = ftp_init()
        close = True

    result = [f.lstrip("/") for f in ftp.nlst(ftpdir)]

    if close:
        ftp_close(ftp)

    return result

def cmp_vmcores_first(str1, str2):
    vmcore1 = "vmcore" in str1.lower()
    vmcore2 = "vmcore" in str2.lower()

    if vmcore1 and not vmcore2:
        return -1
    elif not vmcore1 and vmcore2:
        return 1

    return cmp(str1, str2)

def check_run(cmd):
    child = Popen(cmd, stdout=PIPE, stderr=STDOUT)
    stdout = child.communicate()[0]
    if child.wait():
        raise Exception("%s exitted with %d: %s" % (cmd[0], child.returncode, stdout))

def move_dir_contents(source, dest):
    for filename in os.listdir(source):
        path = os.path.join(source, filename)
        if os.path.isdir(path):
            move_dir_contents(path, dest)
        elif os.path.isfile(path):
            destfile = os.path.join(dest, filename)
            if os.path.isfile(destfile):
                i = 0
                newdest = "%s.%d" % (destfile, i)
                while os.path.isfile(newdest):
                    i += 1
                    newdest = "%s.%d" % (destfile, i)

                destfile = newdest

# try?
            os.rename(path, destfile)
# except?

    shutil.rmtree(source)

def human_readable_size(bytes):
    size = float(bytes)
    unit = 0
    while size > 1024.0 and unit < len(UNITS) - 1:
        unit += 1
        size /= 1024.0

    return "%.2f %s" % (size, UNITS[unit])

class KernelVer(object):
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

class RetraceTask:
    """Represents Retrace server's task."""

    BACKTRACE_FILE = "retrace_backtrace"
    CASENO_FILE = "caseno"
    BUGZILLANO_FILE = "bugzillano"
    CRASHRC_FILE = "crashrc"
    CRASH_CMD_FILE = "crash_cmd"
    DOWNLOADED_FILE = "downloaded"
    MD5SUM_FILE = "md5sum"
    FINISHED_FILE = "finished_time"
    KERNELVER_FILE = "kernelver"
    LOG_FILE = "retrace_log"
    MANAGED_FILE = "managed"
    MISC_DIR = "misc"
    MOCK_LOG_DIR = "log"
    NOTES_FILE = "notes"
    NOTIFY_FILE = "notify"
    PASSWORD_FILE = "password"
    PROGRESS_FILE = "progress"
    REMOTE_FILE = "remote"
    STARTED_FILE = "started_time"
    STATUS_FILE = "status"
    TYPE_FILE = "type"
    URL_FILE = "url"
    VMLINUX_FILE = "vmlinux"
    MOCK_DEFAULT_CFG = "default.cfg"
    MOCK_SITE_DEFAULTS_CFG = "site-defaults.cfg"
    MOCK_LOGGING_INI = "logging.ini"

    def __init__(self, taskid=None):
        """Creates a new task if taskid is None,
        loads the task with given ID otherwise."""

        if taskid is None:
            # create a new task
            # create a retrace-group-writable directory
            oldmask = os.umask(0o007)
            self._taskid = None
            generator = random.SystemRandom()
            for i in range(50):
                taskid = generator.randint(pow(10, CONFIG["TaskIdLength"] - 1),
                                           pow(10, CONFIG["TaskIdLength"]) - 1)
                taskdir = os.path.join(CONFIG["SaveDir"], "%d" % taskid)
                try:
                    os.mkdir(taskdir)
                except OSError as ex:
                    # dir exists, try another taskid
                    if ex[0] == errno.EEXIST:
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

            pwdfilepath = os.path.join(self._savedir, RetraceTask.PASSWORD_FILE)
            with open(pwdfilepath, "w") as pwdfile:
                for i in range(CONFIG["TaskPassLength"]):
                    pwdfile.write(generator.choice(TASKPASS_ALPHABET))

            self.set_crash_cmd("crash")
            os.makedirs(os.path.join(self._savedir, RetraceTask.MISC_DIR))
            os.umask(oldmask)
        else:
            # existing task
            self._taskid = int(taskid)
            self._savedir = os.path.join(CONFIG["SaveDir"], "%d" % self._taskid)
            if not os.path.isdir(self._savedir):
                raise Exception("The task %d does not exist" % self._taskid)

    def use_mock(self, kernelver):
        # Only use mock if we're cross arch, and there's no arch-specific crash available
        hostarch = get_canon_arch(os.uname()[4])
        if kernelver.arch == hostarch:
            return False
        elif CONFIG["Crash%s" % kernelver.arch] and os.path.isfile(CONFIG["Crash%s" % kernelver.arch]):
            self.set_crash_cmd(CONFIG["Crash%s" % kernelver.arch])
            return False
        else:
            return True

    def _get_file_path(self, key):
        key_sanitized = key.replace("/", "_").replace(" ", "_")
        return os.path.join(self._savedir, key_sanitized)

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

        return call(cmdline)

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

    def get_savedir(self):
        """Returns task's savedir"""
        return self._savedir

    def start(self, debug=False, kernelver=None, arch=None):
        crashdir = os.path.join(self._savedir, "crash")
        if arch is None:
            if self.get_type() in [TASK_VMCORE, TASK_VMCORE_INTERACTIVE]:
                filename = os.path.join(crashdir, "vmcore")
            else:
                filename = os.path.join(crashdir, "coredump")

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
        except:
            pass

    def chmod(self, key):
        try:
            os.chmod(self._get_file_path(key), stat.S_IRUSR|stat.S_IWUSR|stat.S_IRGRP|stat.S_IROTH)
        except:
            pass

    def set(self, key, value, mode="w"):
        if mode not in ["w", "a"]:
            raise ValueError("mode must be either 'w' or 'a'")

        with open(self._get_file_path(key), mode) as f:
            f.write(value)
            self.chgrp(key)
            self.chmod(key)

    def set_atomic(self, key, value, mode="w"):
        if mode not in ["w", "a"]:
            raise ValueError("mode must be either 'w' or 'a'")

        tmpfilename = self._get_file_path("%s.tmp" % key)
        filename = self._get_file_path(key)
        if mode == "a":
            try:
                shutil.copyfile(filename, tmpfilename)
            except IOError as ex:
                if ex[0] != errno.ENOENT:
                    raise

        with open(tmpfilename, mode) as f:
            f.write(value)

        os.rename(tmpfilename, filename)
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
        return os.path.isfile(self._get_file_path(key))

    def touch(self, key):
        open(self._get_file_path(key), "a").close()

    def delete(self, key):
        if self.has(key):
            os.unlink(self._get_file_path(key))

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
        else:
            return self.has_status() and self.get_status() not in [STATUS_SUCCESS, STATUS_FAIL]

    def get_age(self):
        """Returns the age of the task in hours."""
        return int(time.time() - os.path.getmtime(self._savedir)) // 3600

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
        if not newtype in TASK_TYPES:
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

    def set_backtrace(self, backtrace):
        """Atomically writes given string into BACKTRACE_FILE."""
        self.set_atomic(RetraceTask.BACKTRACE_FILE, backtrace)

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
        self.set_atomic(RetraceTask.KERNELVER_FILE, value)

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
        if not isinstance(values, list) or not all([isinstance(v, six.string_types) for v in values]):
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

    def download_block(self, data):
        self._progress_write_func(data)
        self._progress_current += len(data)
        progress = "%d%% (%s / %s)" % ((100 * self._progress_current) // self._progress_total,
                                       human_readable_size(self._progress_current),
                                       self._progress_total_str)
        self.set_atomic(RetraceTask.PROGRESS_FILE, progress)

    def prepare_debuginfo(self, vmcore, chroot=None, kernelver=None, crash_cmd=["crash"]):
        log_info("Calling prepare_debuginfo with crash_cmd = " + str(crash_cmd))
        if kernelver is None:
            kernelver = get_kernel_release(vmcore, crash_cmd)

        if kernelver is None:
            raise Exception("Unable to determine kernel version")

        self.set_kernelver(str(kernelver))

        debugdir_base = os.path.join(CONFIG["RepoDir"], "kernel", kernelver.arch)
        if not os.path.isdir(debugdir_base):
            os.makedirs(debugdir_base)

        # First look in our cache for vmlinux at the "typical" location which is something like
        # CONFIG["RepoDir"]/kernel/x86_64/usr/lib/debug/lib/modules/2.6.32-504.el6.x86_64
        log_info("Version: '%s'; Release: '%s'; Arch: '%s'; _arch: '%s'; Flavour: '%s'; Realtime: %s"
                 % (kernelver.version, kernelver.release, kernelver.arch,
                    kernelver._arch, kernelver.flavour, kernelver.rt))
        kernel_path = ""
        if kernelver.version is not None:
            kernel_path = kernel_path + str(kernelver.version)
        if kernelver.release is not None:
            kernel_path = kernel_path + "-" + str(kernelver.release)
	# Skip the 'arch' on RHEL5 and RHEL4 due to different kernel-debuginfo path to vmlinux
        if kernelver._arch is not None and "EL" not in kernelver.release and "el5" not in kernelver.release:
            kernel_path = kernel_path + "." + str(kernelver._arch)
        if kernelver.flavour is not None:
            # 'debug' flavours on rhel6 and above require a '.' before the 'debug'
            if "EL" not in kernelver.release and "el5" not in kernelver.release:
                kernel_path = kernel_path + "."
            kernel_path = kernel_path + str(kernelver.flavour)

        vmlinux_cache_path = debugdir_base + "/usr/lib/debug/lib/modules/" + kernel_path + "/vmlinux"
        if os.path.isfile(vmlinux_cache_path):
            log_info("Found cached vmlinux at path: " + vmlinux_cache_path)
            vmlinux = vmlinux_cache_path
            self.set_vmlinux(vmlinux)
        else:
            log_info("Unable to find cached vmlinux at path: " + vmlinux_cache_path)
            vmlinux = None

        # For now, unconditionally search for kernel-debuginfo.  However, if the vmlinux
        # file existed in the cache, don't raise an exception on the task since the vmcore
        # may still be usable, and instead, return early.
        # A second optimization would be to avoid this completely if the modules files
        # all exist in the cache.
        log_info("Searching for kernel-debuginfo package for " + str(kernelver))
        debuginfo = find_kernel_debuginfo(kernelver)
        if not debuginfo:
            if vmlinux is not None:
                return vmlinux
            else:
                raise Exception("Unable to find debuginfo package and no cached vmlinux file")

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
        child = Popen(["rpm", "-qpl", debuginfo], stdout=PIPE)
        lines = child.communicate()[0].splitlines()
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

                if not pattern2 in os.path.dirname(line):
                    continue

            # '-' in file name is transformed to '_' in module name
            debugfiles[match.group(1).replace("-", "_")] = line

        # Only look for the vmlinux file here if it's not already been found above
        # Note the dependency from this code on the debuginfo file list
        if vmlinux is None:
            vmlinux_debuginfo = os.path.join(debugdir_base, vmlinux_path.lstrip("/"))
            cache_files_from_debuginfo(debuginfo, debugdir_base, [vmlinux_path])
            if os.path.isfile(vmlinux_debuginfo):
                log_info("Found cached vmlinux at new debuginfo location: " + vmlinux_debuginfo)
                vmlinux = vmlinux_debuginfo
                self.set_vmlinux(vmlinux)
            else:
                raise Exception("Failed vmlinux caching from debuginfo at location: " + vmlinux_debuginfo)

        # Obtain the list of modules this vmcore requires
        if chroot:
            with open(os.devnull, "w") as null:
                child = Popen(["/usr/bin/mock", "--configdir", chroot, "shell",
                               "--", "crash -s %s %s" % (vmcore, vmlinux)],
                              stdin=PIPE, stdout=PIPE, stderr=null)
        else:
            child = Popen(crash_cmd + ["-s", vmcore, vmlinux], stdin=PIPE, stdout=PIPE, stderr=STDOUT)
        stdout = child.communicate("mod\nquit")[0]
        if child.returncode == 1 and "el5" in kernelver.release:
            log_info("Unable to list modules but el5 detected, trying crash fixup for vmss files")
            crash_cmd.append("--machdep")
            crash_cmd.append("phys_base=0x200000")
            log_info("trying crash_cmd = " + str(crash_cmd))
            child = Popen(crash_cmd + ["-s", vmcore, vmlinux], stdin=PIPE, stdout=PIPE, stderr=STDOUT)
            stdout = child.communicate("mod\nquit")[0]

        # If we fail to get the list of modules, is the vmcore even usable?
        if child.returncode:
            log_warn("Unable to list modules: crash exited with %d:\n%s" % (child.returncode, stdout))
            return vmlinux

        modules = []
        for line in stdout.splitlines():
            # skip header
            if "NAME" in line:
                continue

            if " " in line:
                modules.append(line.split()[1])

        todo = []
        for module in modules:
            if module in debugfiles and \
               not os.path.isfile(os.path.join(debugdir_base, debugfiles[module].lstrip("/"))):
                todo.append(debugfiles[module])

        cache_files_from_debuginfo(debuginfo, debugdir_base, todo)

        return vmlinux

    def strip_vmcore(self, vmcore, kernelver=None, crash_cmd=["crash"]):
        try:
            vmlinux = self.prepare_debuginfo(vmcore, chroot=None, kernelver=kernelver, crash_cmd=crash_cmd)
        except Exception as ex:
            log_warn("prepare_debuginfo failed: %s" % ex)
            return

        newvmcore = "%s.stripped" % vmcore
        retcode = call(["makedumpfile", "-c", "-d", "%d" % CONFIG["VmcoreDumpLevel"],
                        "-x", vmlinux, "--message-level", "0", vmcore, newvmcore])
        if retcode:
            log_warn("makedumpfile exited with %d" % retcode)
            if os.path.isfile(newvmcore):
                os.unlink(newvmcore)
        else:
            os.rename(newvmcore, vmcore)

    def download_remote(self, unpack=True, timeout=0, kernelver=None):
        """Downloads all remote resources and returns a list of errors."""
        md5sums = []
        downloaded = []
        errors = []

        crashdir = os.path.join(self._savedir, "crash")
        if not os.path.isdir(crashdir):
            oldmask = os.umask(0o007)
            os.makedirs(crashdir)
            os.umask(oldmask)

        for url in self.get_remote():
            self.set_status(STATUS_DOWNLOADING)
            log_info(STATUS[STATUS_DOWNLOADING])

            if url.startswith("FTP "):
                filename = url[4:].strip()
                log_info("Retrieving FTP file '%s'" % filename)

                ftp = None
                try:
                    ftp = ftp_init()
                    with open(os.path.join(crashdir, filename), "wb") as target_file:
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
            elif url.startswith("/") or url.startswith("file:///"):
                if url.startswith("file://"):
                    url = url[7:]

                log_info("Retrieving local file '%s'" % url)

                if not os.path.isfile(url):
                    errors.append((url, "File not found"))
                    continue

                filename = os.path.basename(url)
                targetfile = os.path.join(crashdir, filename)

                copy = True
                if get_archive_type(url) == ARCHIVE_UNKNOWN:
                    try:
                        log_debug("Trying hardlink")
                        os.link(url, targetfile)
                        copy = False
                        log_debug("Succeeded")
                    except:
                        log_debug("Failed")

                if copy:
                    try:
                        log_debug("Copying")
                        shutil.copy(url, targetfile)
                    except Exception as ex:
                        errors.append((url, str(ex)))
                        continue

                downloaded.append(url)
            else:
                log_info("Retrieving remote file '%s'" % url)

                if "/" not in url:
                    errors.append((url, "malformed URL"))
                    continue

                child = Popen(["wget", "-nv", "-P", crashdir, url], stdout=PIPE, stderr=STDOUT)
                stdout = child.communicate()[0]
                if child.wait():
                    errors.append((url, "wget exitted with %d: %s" % (child.returncode, stdout)))
                    continue

                filename = url.rsplit("/", 1)[1]
                downloaded.append(url)

            if self.has_md5sum():
                self.set_status(STATUS_CALCULATING_MD5SUM)
                log_info(STATUS[STATUS_CALCULATING_MD5SUM])
                md5v = self.calculate_md5(os.path.join(crashdir, filename))
                md5sums.append("{0} {1}".format(md5v, downloaded[-1]))
                self.set_md5sum("\n".join(md5sums)+"\n")

            self.set_status(STATUS_POSTPROCESS)
            log_info(STATUS[STATUS_POSTPROCESS])

            if unpack:
                fullpath = os.path.join(crashdir, filename)
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
                st = os.stat(crashdir)
                if (st.st_mode & stat.S_IRGRP) == 0 or (st.st_mode & stat.S_IXGRP) == 0:
                    try:
                        os.chmod(crashdir, st.st_mode | stat.S_IRGRP | stat.S_IXGRP)
                    except Exception as ex:
                        log_warn("Crashdir '%s' is not group readable and chmod"
                                 " failed. The process will continue but if"
                                 " it fails this is the likely cause."
                                 % crashdir)

        if self.get_type() in [TASK_VMCORE, TASK_VMCORE_INTERACTIVE]:
            vmcore = os.path.join(crashdir, "vmcore")
            files = os.listdir(crashdir)
            for filename in files:
                fullpath = os.path.join(crashdir, filename)
                if os.path.isdir(fullpath):
                    move_dir_contents(fullpath, crashdir)

            files = os.listdir(crashdir)
            if len(files) < 1:
                errors.append(([], "No files found in the tarball"))
            elif len(files) == 1:
                if files[0] != "vmcore":
                    os.rename(os.path.join(crashdir, files[0]), vmcore)
            else:
                vmcores = []
                for filename in files:
                    if "vmcore" in filename:
                        vmcores.append(filename)

                # pick the largest file
                if len(vmcores) < 1:
                    absfiles = [os.path.join(crashdir, f) for f in files]
                    files_sizes = [(os.path.getsize(f), f) for f in absfiles]
                    largest_file = sorted(files_sizes, reverse=True)[0][1]
                    os.rename(largest_file, vmcore)
                elif len(vmcores) > 1:
                    absfiles = [os.path.join(crashdir, f) for f in vmcores]
                    files_sizes = [(os.path.getsize(f), f) for f in absfiles]
                    largest_file = sorted(files_sizes, reverse=True)[0][1]
                    os.rename(largest_file, vmcore)
                else:
                    for filename in files:
                        if filename == vmcores[0]:
                            if vmcores[0] != "vmcore":
                                os.rename(os.path.join(crashdir, filename), vmcore)

            files = os.listdir(crashdir)
            for filename in files:
                if filename == "vmcore":
                    continue

                os.unlink(os.path.join(crashdir, filename))

            if os.path.isfile(vmcore):
                oldsize = os.path.getsize(vmcore)
                log_info("Vmcore size: %s" % human_readable_size(oldsize))

                dump_level = get_vmcore_dump_level(self)
                if dump_level is None:
                    log_warn("Unable to determine vmcore dump level")
                else:
                    log_debug("Vmcore dump level is %d" % dump_level)

                skip_makedumpfile = CONFIG["VmcoreDumpLevel"] <= 0 or CONFIG["VmcoreDumpLevel"] >= 32
                if (dump_level is not None and
                        (dump_level & CONFIG["VmcoreDumpLevel"]) == CONFIG["VmcoreDumpLevel"]):
                    log_info("Stripping to %d would have no effect" % CONFIG["VmcoreDumpLevel"])
                    skip_makedumpfile = True

                if not skip_makedumpfile:
                    log_debug("Executing makedumpfile")
                    start = time.time()
                    crash_cmd = self.get_crash_cmd().split()
                    self.strip_vmcore(vmcore, kernelver, crash_cmd)
                    self.set_crash_cmd(' '.join(crash_cmd))
                    dur = int(time.time() - start)

                st = os.stat(vmcore)
                if (st.st_mode & stat.S_IRGRP) == 0:
                    try:
                        os.chmod(vmcore, st.st_mode | stat.S_IRGRP)
                    except Exception as ex:
                        log_warn("File '%s' is not group readable and chmod"
                                 " failed. The process will continue but if"
                                 " it fails this is the likely cause."
                                 % vmcore)
                if not skip_makedumpfile:
                    log_info("Stripped size: %s" % human_readable_size(st.st_size))
                    log_info("Makedumpfile took %d seconds and saved %s"
                             % (dur, human_readable_size(oldsize - st.st_size)))

        if self.get_type() in [TASK_RETRACE, TASK_RETRACE_INTERACTIVE]:
            coredump = os.path.join(crashdir, "coredump")
            files = os.listdir(crashdir)
            for filename in files:
                fullpath = os.path.join(crashdir, filename)
                if os.path.isdir(fullpath):
                    move_dir_contents(fullpath, crashdir)

            files = os.listdir(crashdir)
            if len(files) < 1:
                errors.append(([], "No files found in the tarball"))
            elif len(files) == 1:
                if files[0] != "coredump":
                    os.rename(os.path.join(crashdir, files[0]), coredump)
            else:
                coredumps = []
                for filename in files:
                    if "coredump" in filename:
                        coredumps.append(filename)

                # pick the largest file
                if len(coredumps) < 1:
                    absfiles = [os.path.join(crashdir, f) for f in files]
                    files_sizes = [(os.path.getsize(f), f) for f in absfiles]
                    largest_file = sorted(files_sizes, reverse=True)[0][1]
                    os.rename(largest_file, coredump)
                elif len(coredumps) > 1:
                    absfiles = [os.path.join(crashdir, f) for f in coredumps]
                    files_sizes = [(os.path.getsize(f), f) for f in absfiles]
                    largest_file = sorted(files_sizes, reverse=True)[0][1]
                    os.rename(largest_file, coredump)
                else:
                    for filename in files:
                        if filename == coredumps[0]:
                            if coredumps[0] != "coredump":
                                os.rename(os.path.join(crashdir, filename), coredump)

            files = os.listdir(crashdir)
            for filename in files:
                if filename in REQUIRED_FILES[self.get_type()]+["release", "os_release"]:
                    continue

                os.unlink(os.path.join(crashdir, filename))

            if os.path.isfile(coredump):
                oldsize = os.path.getsize(coredump)
                log_info("Coredump size: %s" % human_readable_size(oldsize))

                st = os.stat(coredump)
                if (st.st_mode & stat.S_IRGRP) == 0:
                    try:
                        os.chmod(coredump, st.st_mode | stat.S_IRGRP)
                    except Exception as ex:
                        log_warn("File '%s' is not group readable and chmod"
                                 " failed. The process will continue but if"
                                 " it fails this is the likely cause."
                                 % coredump)

        os.unlink(os.path.join(self._savedir, RetraceTask.REMOTE_FILE))
        self.set_downloaded(", ".join(downloaded))

        return errors

    def has_misc(self, name):
        """Verifies whether a file named 'name' is present in MISC_DIR."""
        if "/" in name:
            raise Exception("name may not contain the '/' character")

        miscdir = os.path.join(self._savedir, RetraceTask.MISC_DIR)
        miscpath = os.path.join(miscdir, name)

        return os.path.isdir(miscdir) and os.path.isfile(miscpath)

    def get_misc_list(self):
        """Lists all files in MISC_DIR."""
        miscdir = os.path.join(self._savedir, RetraceTask.MISC_DIR)
        if not os.path.isdir(miscdir):
            return []

        return os.listdir(miscdir)

    def get_misc(self, name):
        """Gets content of a file named 'name' from MISC_DIR."""
        if "/" in name:
            raise Exception("name may not contain the '/' character")

        if not self.has_misc(name):
            raise Exception("There is no record with such name")

        miscpath = os.path.join(self._savedir, RetraceTask.MISC_DIR, name)
        with open(miscpath, "r") as misc_file:
            result = misc_file.read(1 << 24) # 16MB

        return result

    def add_misc(self, name, value, overwrite=False):
        """Adds a file named 'name' into MISC_DIR and writes 'value' into it."""
        if "/" in name:
            raise Exception("name may not contain the '/' character")

        if not overwrite and self.has_misc(name):
            raise Exception("The record already exists. Use overwrite=True " \
                             "to force overwrite existing records.")

        miscdir = os.path.join(self._savedir, RetraceTask.MISC_DIR)
        if not os.path.isdir(miscdir):
            oldmask = os.umask(0o007)
            os.makedirs(miscdir)
            os.umask(oldmask)

        miscpath = os.path.join(miscdir, name)
        with open(miscpath, "w") as misc_file:
            misc_file.write(value)

    def del_misc(self, name):
        """Deletes the file named 'name' from MISC_DIR."""
        if "/" in name:
            raise Exception("name may not contain the '/' character")

        if self.has_misc(name):
            os.unlink(os.path.join(self._savedir, RetraceTask.MISC_DIR, name))

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
            os.chmod(self._get_file_path(RetraceTask.CRASH_CMD_FILE),
                     stat.S_IRUSR|stat.S_IWUSR|stat.S_IRGRP|stat.S_IWGRP|stat.S_IROTH)
        except:
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
        if not isinstance(values, list) or not all([isinstance(v, basestring) for v in values]):
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

        self.set(RetraceTask.FINISHED_FILE, "%d" % value)

    def get_default_started_time(self):
        """Get ctime of the task directory"""
        return int(os.path.getctime(self._savedir))

    def get_default_finished_time(self):
        """Get mtime of the task directory"""
        return int(os.path.getmtime(self._savedir))

    def clean(self):
        """Removes all files and directories others than
        results and logs from the task directory."""
        with open(os.devnull, "w") as null:
            if os.path.isfile(os.path.join(self._savedir, "default.cfg")) and \
               os.path.isfile(os.path.join(self._savedir, "site-defaults.cfg")) and \
               os.path.isfile(os.path.join(self._savedir, "logging.ini")):
                retcode = call(["/usr/bin/mock", "--configdir", self._savedir, "--scrub=all"],
                               stdout=null, stderr=null)

        for f in os.listdir(self._savedir):
            if not f in [RetraceTask.REMOTE_FILE, RetraceTask.CASENO_FILE,
                         RetraceTask.BACKTRACE_FILE, RetraceTask.DOWNLOADED_FILE,
                         RetraceTask.FINISHED_FILE, RetraceTask.LOG_FILE,
                         RetraceTask.MANAGED_FILE, RetraceTask.NOTES_FILE,
                         RetraceTask.NOTIFY_FILE, RetraceTask.PASSWORD_FILE,
                         RetraceTask.STARTED_FILE, RetraceTask.STATUS_FILE,
                         RetraceTask.TYPE_FILE, RetraceTask.MISC_DIR,
                         RetraceTask.CRASHRC_FILE, RetraceTask.CRASH_CMD_FILE,
                         RetraceTask.URL_FILE, RetraceTask.MOCK_LOG_DIR,
                         RetraceTask.VMLINUX_FILE, RetraceTask.BUGZILLANO_FILE]:

                path = os.path.join(self._savedir, f)
                try:
                    if os.path.isdir(path):
                        shutil.rmtree(path)
                    else:
                        os.remove(path)
                except:
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
                os.unlink(os.path.join(self._savedir, filename))
            except OSError as ex:
                # ignore 'No such file or directory'
                if ex.errno != errno.ENOENT:
                    raise

        miscdir = os.path.join(self._savedir, RetraceTask.MISC_DIR)
        for filename in os.listdir(miscdir):
            os.unlink(os.path.join(miscdir, filename))

        kerneldir = os.path.join(CONFIG["SaveDir"], "%d-kernel" % self._taskid)
        if os.path.isdir(kerneldir):
            shutil.rmtree(kerneldir)

    def remove(self):
        """Completely removes the task directory."""
        self.clean()
        kerneldir = os.path.join(CONFIG["SaveDir"], "%d-kernel" % self._taskid)
        if os.path.isdir(kerneldir):
            shutil.rmtree(kerneldir)

        shutil.rmtree(self._savedir)

    def create_worker(self):
        """Get default worker instance for this task"""
        # TODO: let it be configurable
        from .retrace_worker import RetraceWorker
        return RetraceWorker(self)

### create ConfigClass instance on import ###
CONFIG = Config()
