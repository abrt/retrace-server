import ConfigParser
import errno
import ftplib
import gettext
import magic
import os
import re
import random
import shutil
import sqlite3
import stat
import time
from argparser import *
from webob import Request
from yum import YumBase
from subprocess import *
from config import *

GETTEXT_DOMAIN = "retrace-server"

# filename: max_size (<= 0 unlimited)
ALLOWED_FILES = {
  "coredump": 0,
  "executable": 512,
  "package": 128,
  "os_release": 128,
  "os_release_in_rootdir": 128,
  "rootdir": 256,
  "release": 128,
  "vmcore": 0,
}

TASK_RETRACE, TASK_DEBUG, TASK_VMCORE, TASK_RETRACE_INTERACTIVE, \
  TASK_VMCORE_INTERACTIVE = xrange(5)

TASK_TYPES = [TASK_RETRACE, TASK_DEBUG, TASK_VMCORE,
              TASK_RETRACE_INTERACTIVE, TASK_VMCORE_INTERACTIVE]

ARCHIVE_UNKNOWN, ARCHIVE_GZ, ARCHIVE_ZIP, \
  ARCHIVE_BZ2, ARCHIVE_XZ, ARCHIVE_TAR, ARCHIVE_7Z = xrange(7)

REQUIRED_FILES = {
  TASK_RETRACE:             ["coredump", "executable", "package"],
  TASK_DEBUG:               ["coredump", "executable", "package"],
  TASK_VMCORE:              ["vmcore"],
  TASK_RETRACE_INTERACTIVE: ["coredump", "executable", "package"],
  TASK_VMCORE_INTERACTIVE:  ["vmcore"],
}

#characters, numbers, dash (utf-8, iso-8859-2 etc.)
INPUT_CHARSET_PARSER = re.compile("^([a-zA-Z0-9\-]+)(,.*)?$")
#en_GB, sk-SK, cs, fr etc.
INPUT_LANG_PARSER = re.compile("^([a-z]{2}([_\-][A-Z]{2})?)(,.*)?$")
#characters allowed by Fedora Naming Guidelines
INPUT_PACKAGE_PARSER = re.compile("^[a-zA-Z0-9\-\.\_\+]+$")
#architecture (i386, x86_64, armv7hl, mips4kec)
INPUT_ARCH_PARSER = re.compile("^[a-zA-Z0-9_]+$")
#name-version-arch (fedora-16-x86_64, rhel-6.2-i386, opensuse-12.1-x86_64)
INPUT_RELEASEID_PARSER = re.compile("^[a-zA-Z0-9]+\-[0-9a-zA-Z\.]+\-[a-zA-Z0-9_]+$")

#2.6.32-201.el6.x86_64
KERNEL_RELEASE_PARSER = re.compile("^(.*)\.([^\.]+)$")

CORE_ARCH_PARSER = re.compile("core file .*(x86-64|80386)")
PACKAGE_PARSER = re.compile("^(.+)-([0-9]+(\.[0-9]+)*-[0-9]+)\.([^-]+)$")
DF_OUTPUT_PARSER = re.compile("^([^ ^\t]*)[ \t]+([0-9]+)[ \t]+([0-9]+)[ \t]+([0-9]+)[ \t]+([0-9]+%)[ \t]+(.*)$")
DU_OUTPUT_PARSER = re.compile("^([0-9]+)")
URL_PARSER = re.compile("^/([0-9]+)/?")

REPODIR_NAME_PARSER = re.compile("^[^\-]+\-[^\-]+\-[^\-]+$")

# rpm name parsers
EPOCH_PARSER = re.compile("^(([0-9]+)\:).*$")
ARCH_PARSER = re.compile("^.*(\.([0-9a-zA-Z_]+))$")
RELEASE_PARSER = re.compile("^.*(\-([0-9a-zA-Z\._]+))$")
VERSION_PARSER = re.compile("^.*(\-([0-9a-zA-Z\._\:]+))$")
NAME_PARSER = re.compile("^[a-zA-Z0-9_\.\+\-]+$")

KO_DEBUG_PARSER = re.compile("^.*/([a-zA-Z0-9_\-]+)\.ko\.debug$")

# parsers for vmcore version
# 2.6.32-209.el6.x86_64 | 2.6.18-197.el5
KERNEL_RELEASE_PARSER = re.compile("^([0-9]+\.[0-9]+\.[0-9]+(\.[^\-]+)?\-[0-9]+\..*?)(\.(x86_64|i386|i486|i586|i686|s390|s390x|ppc|ppc64|armv5tel|armv7l|armv7hl|ia64))?$")
# OSRELEASE=2.6.32-209.el6.x86_64
OSRELEASE_VAR_PARSER = re.compile("^OSRELEASE=(.*)$")

WORKER_RUNNING_PARSER = re.compile("^[ \t]*([0-9]+)[ \t]+[0-9]+[ \t]+([^ ^\t]+)[ \t]+.*retrace-server-worker ([0-9]+)( .*)?$")

HANDLE_ARCHIVE = {
  "application/x-xz-compressed-tar": {
    "unpack": [TAR_BIN, "xJf"],
    "size": ([XZ_BIN, "--list", "--robot"], re.compile("^totals[ \t]+[0-9]+[ \t]+[0-9]+[ \t]+[0-9]+[ \t]+([0-9]+).*")),
  },

  "application/x-gzip": {
    "unpack": [TAR_BIN, "xzf"],
    "size": ([GZIP_BIN, "--list"], re.compile("^[^0-9]*[0-9]+[^0-9]+([0-9]+).*$")),
  },

  "application/x-tar": {
    "unpack": [TAR_BIN, "xf"],
    "size": (["ls", "-l"], re.compile("^[ \t]*[^ ^\t]+[ \t]+[^ ^\t]+[ \t]+[^ ^\t]+[ \t]+[^ ^\t]+[ \t]+([0-9]+).*$")),
  },
}

FTP_SUPPORTED_EXTENSIONS = [".tar.gz", ".tgz", ".tarz", ".tar.bz2", ".tar.xz",
                            ".tar", ".gz", ".bz2", ".xz", ".Z", ".zip"]

REPO_PREFIX = "retrace-"

TASKPASS_ALPHABET = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

CONFIG_FILE = "/etc/retrace-server.conf"
CONFIG = {
  "TaskIdLength": 9,
  "TaskPassLength": 32,
  "MaxParallelTasks": 10,
  "MaxPackedSize": 30,
  "MaxUnpackedSize": 600,
  "MinStorageLeft": 10240,
  "DeleteTaskAfter": 120,
  "ArchiveTaskAfter": 0,
  "KeepRawhideLatest": 3,
  "KojiRoot": "/mnt/koji",
  "DropDir": "/srv/retrace/archive",
  "LogDir": "/var/log/retrace-server",
  "RepoDir": "/var/cache/retrace-server",
  "SaveDir": "/var/spool/retrace-server",
  "WorkDir": "/tmp/retrace-server",
  "UseWorkDir": False,
  "RequireHTTPS": True,
  "AllowAPIDelete": False,
  "AllowInteractive": False,
  "AllowTaskManager": False,
  "UseFTPTasks": False,
  "FTPSSL": False,
  "FTPHost": "",
  "FTPUser": "",
  "FTPPass": "",
  "FTPDir": "/",
  "WgetKernelDebuginfos": False,
  "KernelDebuginfoURL": "http://kojipkgs.fedoraproject.org/packages/kernel/$VERSION/$RELEASE/$ARCH/",
  "VmcoreDumpLevel": 0,
  "RequireGPGCheck": True,
  "UseCreaterepoUpdate": False,
  "DBFile": "stats.db",
  "KernelChrootRepo": "http://dl.fedoraproject.org/pub/fedora/linux/releases/16/Everything/$ARCH/os/",
  "UseFafPackages": False,
  "FafLinkDir": "/var/spool/faf/retrace-tmp",
  "AuthGroup": "retrace",
}

STATUS_ANALYZE, STATUS_INIT, STATUS_BACKTRACE, STATUS_CLEANUP, \
STATUS_STATS, STATUS_FINISHING, STATUS_SUCCESS, STATUS_FAIL, \
STATUS_DOWNLOADING = xrange(9)

STATUS = [
  "Analyzing crash data",
  "Initializing virtual root",
  "Generating backtrace",
  "Cleaning up virtual root",
  "Saving crash statistics",
  "Finishing task",
  "Retrace job finished successfully",
  "Retrace job failed",
  "Downloading remote resources",
]

def lock(lockfile):
    try:
        fd = os.open(lockfile, os.O_CREAT | os.O_EXCL, 0600)
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

def read_config():
    parser = ConfigParser.ConfigParser()
    parser.read(CONFIG_FILE)
    for key in CONFIG.keys():
        vartype = type(CONFIG[key])
        if vartype is int:
            get = parser.getint
        elif vartype is bool:
            get = parser.getboolean
        elif vartype is float:
            get = parser.getfloat
        else:
            get = parser.get

        try:
            CONFIG[key] = get("retrace", key)
        except ConfigParser.NoOptionError:
            pass

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

    result = None
    child = Popen(["strings", coredump_path], stdout=PIPE)
    line = child.stdout.readline()
    while line:
        if "x86_64" in line:
            result = "x86_64"
            break

        if "i386" in line or \
           "i486" in line or \
           "i586" in line or \
           "i686" in line:
            result = "i386"
            break

        line = child.stdout.readline()

    child.kill()
    child.stdout.close()

    return result

def guess_release(package, plugins):
    for plugin in plugins:
        match = plugin.guessparser.search(package)
        if match:
            return plugin.distribution, match.group(1)

    return None, None

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

def run_gdb(savedir):
    #exception is caught on the higher level
    exec_file = open(os.path.join(savedir, "crash", "executable"), "r")
    executable = exec_file.read(ALLOWED_FILES["executable"])
    exec_file.close()

    if '"' in executable or "'" in executable:
        raise Exception, "Executable contains forbidden characters"

    with open("/dev/null", "w") as null:
        child = Popen(["/usr/bin/mock", "shell", "--configdir", savedir,
                       "--", "ls", "'%s'" % executable],
                       stdout=PIPE, stderr=null)
        output = child.communicate()[0]
        if output.strip() != executable:
            raise Exception("The appropriate package set could not be installed")

        chmod = call(["/usr/bin/mock", "shell", "--configdir", savedir,
                      "--", "/bin/chmod", "a+r", "'%s'" % executable],
                      stdout=null, stderr=null)

        if chmod != 0:
            raise Exception, "Unable to chmod the executable"

        batfile = os.path.join(savedir, "gdb.sh")
        with open(batfile, "w") as gdbfile:
            gdbfile.write("gdb -batch -ex 'file %s' "
                          "-ex 'core-file /var/spool/abrt/crash/coredump' "
                          "-ex 'thread apply all backtrace 2048 full' "
                          "-ex 'info sharedlib' "
                          "-ex 'print (char*)__abort_msg' "
                          "-ex 'print (char*)__glib_assert_msg' "
                          "-ex 'info registers' "
                          "-ex 'disassemble'" % executable)

        copyin = call(["/usr/bin/mock", "--configdir", savedir, "--copyin",
                       batfile, "/var/spool/abrt/gdb.sh"],
                      stdout=null, stderr=null)
        if copyin:
            raise Exception("Unable to copy GDB launcher into chroot")

        chmod = call(["/usr/bin/mock", "--configdir", savedir, "shell",
                      "--", "/bin/chmod", "a+rx", "/var/spool/abrt/gdb.sh"],
                     stdout=null, stderr=null)
        if chmod:
            raise Exception("Unable to chmod GDB launcher")

        child = Popen(["/usr/bin/mock", "shell", "--configdir", savedir,
                       "--", "su", "mockbuild", "-c", "'/bin/sh /var/spool/abrt/gdb.sh'",
                       # redirect GDB's stderr, ignore mock's stderr
                       "2>&1"], stdout=PIPE, stderr=null)

    backtrace = child.communicate()[0].strip()
    if child.wait():
        raise Exception("Running GDB failed")

    if not backtrace:
        raise Exception("An unusable backtrace has been generated")

    return backtrace

def is_package_known(package_nvr, arch, releaseid=None):
    if releaseid is None:
        releases = get_supported_releases()
    else:
        releases = [releaseid]

    candidates = []
    for releaseid in releases:
        if arch in ["i386", "i486", "i586", "i686"]:
            for a in ["i386", "i486", "i586", "i686"]:
                candidates.append(os.path.join(CONFIG["RepoDir"], releaseid, "Packages",
                                               "%s.%s.rpm" % (package_nvr, a)))
                candidates.append(os.path.join(CONFIG["RepoDir"], releaseid,
                                               "%s.%s.rpm" % (package_nvr, a)))
        else:
            candidates.append(os.path.join(CONFIG["RepoDir"], releaseid, "Packages",
                                           "%s.%s.rpm" % (package_nvr, arch)))
            candidates.append(os.path.join(CONFIG["RepoDir"], releaseid,
                                           "%s.%s.rpm" % (package_nvr, arch)))

    return any([os.path.isfile(f) for f in candidates])

# tricky
# crash is not able to process the vmcore from different arch
# (not even x86_64 and x86). In addition, there are several
# types of vmcores: running 'file' command on el5- vmcore results
# into an expected description (x86-64 or 80386 coredump), while
# el6+ vmcores are just proclaimed 'data'. Another thing is that
# the OSRELEASE in the vmcore sometimes contains architecture
# and sometimes it does not.
def get_kernel_release(vmcore):
    child = Popen(["crash", "--osrelease", vmcore], stdout=PIPE, stderr=STDOUT)
    release = child.communicate()[0].strip()

    if child.wait() != 0 or \
       not release or \
       "\n" in release or \
       release == "unknown":
        # crash error, let's search the vmcore on our own
        vers = {}
        child = Popen(["strings", "-n", "10", vmcore], stdout=PIPE, stderr=STDOUT)
        # lots! of output, do not use .communicate()
        line = child.stdout.readline()
        while line:
            line = line.strip()

            # OSRELEASE variable is defined in the vmcore,
            # but crash was not able to find it (cross-arch)
            match = OSRELEASE_VAR_PARSER.match(line)
            if match:
                release = match.group(1)
                break

            # assuming the kernel version will sooner or later
            # appear in the list of strings contained in the
            # vmcore
            # paranoia - something else can match the pattern,
            # or another version may be present. assuming that
            # the correct version is repeated several times
            match = KERNEL_RELEASE_PARSER.match(line)
            if match:
                release = line
                break

            line = child.stdout.readline()

        # much more output is available, but we don't need any more
        child.stdout.close()
        child.kill()

    # check whether architecture is present
    match = KERNEL_RELEASE_PARSER.match(release)
    if not match:
        return None

    if match.group(4) is None:
        arch = guess_arch(vmcore)
        if not arch:
            return None

        release += ".%s" % arch

    return release

def find_kernel_debuginfo(kernelver):
    vers = [kernelver]
    v, tail = kernelver.split("-", 1)
    r, a = tail.rsplit(".", 1)

    if a == "i386":
        vers.append("%s-%s.i486" % (v, r))
        vers.append("%s-%s.i586" % (v, r))
        vers.append("%s-%s.i686" % (v, r))

    # search for the debuginfo RPM
    for release in os.listdir(CONFIG["RepoDir"]):
        for ver in vers:
            testfile = os.path.join(CONFIG["RepoDir"], release, "Packages", "kernel-debuginfo-%s.rpm" % ver)
            if os.path.isfile(testfile):
                return testfile

            # should not happen, but anyway...
            testfile = os.path.join(CONFIG["RepoDir"], release, "kernel-debuginfo-%s.rpm" % ver)
            if os.path.isfile(testfile):
                return testfile

    # koji-like root
    for ver in vers:
        testfile = os.path.join(CONFIG["KojiRoot"], "packages", "kernel", v, r, a, "kernel-debuginfo-%s.rpm" % ver)
        if os.path.isfile(testfile):
            return testfile

    if CONFIG["WgetKernelDebuginfos"]:
        downloaddir = os.path.join(CONFIG["RepoDir"], "download")
        if not os.path.isdir(downloaddir):
            os.makedirs(downloaddir)

        for ver in vers:
            pkgname = "kernel-debuginfo-%s.rpm" % ver
            url = CONFIG["KernelDebuginfoURL"].replace("$VERSION", v).replace("$RELEASE", r).replace("$ARCH", a)
            if not url.endswith("/"):
                url += "/"
            url += pkgname

            with open("/dev/null", "w") as null:
                retcode = call(["wget", "-nv", "-P", downloaddir, url], stdout=null, stderr=null)

            if retcode == 0:
                return os.path.join(downloaddir, pkgname)

    return None

def cache_files_from_debuginfo(debuginfo, basedir, files):
    # important! if empty list is specified, the whole debuginfo would be unpacked
    if not files:
        return

    if not os.path.isfile(debuginfo):
        raise Exception, "Given debuginfo file does not exist"

    # prepend absolute path /usr/lib/debug/... with dot, so that cpio can match it
    for i in xrange(len(files)):
        if files[i][0] == "/":
            files[i] = ".%s" % files[i]

    with open("/dev/null", "w") as null:
        rpm2cpio = Popen(["rpm2cpio", debuginfo], stdout=PIPE, stderr=null)
        cpio = Popen(["cpio", "-id"] + files, stdin=rpm2cpio.stdout, stdout=null, stderr=null, cwd=basedir)
        rpm2cpio.wait()
        cpio.wait()
        rpm2cpio.stdout.close()

def prepare_debuginfo(vmcore, chroot=None):
    kernelver = get_kernel_release(vmcore)
    match = KERNEL_RELEASE_PARSER.match(kernelver)
    if not match:
        raise Exception, "Unable to parse kernel version"

    kernelver_noarch = match.group(1)
    arch = match.group(4)

    debuginfo = find_kernel_debuginfo(kernelver)
    if not debuginfo:
        raise Exception, "Unable to find debuginfo package"

    vmlinux_path = None
    debugfiles = {}
    child = Popen(["rpm", "-qpl", debuginfo], stdout=PIPE)
    lines = child.communicate()[0].splitlines()
    for line in lines:
        if line.endswith("/vmlinux"):
            vmlinux_path = line
            continue

        match = KO_DEBUG_PARSER.match(line)
        if not match:
            continue

        # '-' in file name is transformed to '_' in module name
        debugfiles[match.group(1).replace("-", "_")] = line

    debugdir_base = os.path.join(CONFIG["RepoDir"], "kernel", arch)
    if not os.path.isdir(debugdir_base):
        os.makedirs(debugdir_base)

    vmlinux = os.path.join(debugdir_base, vmlinux_path.lstrip("/"))
    if not os.path.isfile(vmlinux):
        cache_files_from_debuginfo(debuginfo, debugdir_base, [vmlinux_path])
        if not os.path.isfile(vmlinux):
            raise Exception, "Caching vmlinux failed"

    if chroot:
        with open("/dev/null", "w") as null:
            child = Popen(["/usr/bin/mock", "--configdir", chroot, "shell",
                           "--", "crash", "-s", vmcore, vmlinux],
                           stdin=PIPE, stdout=PIPE, stderr=null)
    else:
        child = Popen(["crash", "-s", vmcore, vmlinux], stdin=PIPE, stdout=PIPE, stderr=STDOUT)
    stdout = child.communicate("mod\nquit")[0]
    if child.returncode:
        raise Exception, "crash exitted with %d:\n%s" % (child.returncode, stdout)

    modules = []
    for line in stdout.splitlines():
        # skip header
        if "NAME" in line:
            continue

        modules.append(line.split()[1])

    todo = []
    for module in modules:
        if module in debugfiles and \
           not os.path.isfile(os.path.join(debugdir_base, debugfiles[module].lstrip("/"))):
            todo.append(debugfiles[module])

    cache_files_from_debuginfo(debuginfo, debugdir_base, todo)

    return vmlinux

def get_files_sizes(directory):
    result = []

    for f in os.listdir(directory):
        fullpath = os.path.join(directory, f)
        if os.path.isfile(fullpath):
            result.append((fullpath, os.path.getsize(fullpath)))
        elif os.path.isdir(fullpath):
            result += get_files_sizes(fullpath)

    return sorted(result, key=lambda (f, s): s, reverse=True)

def get_archive_type(path):
    ms = magic.open(magic.MAGIC_NONE)
    ms.load()
    filetype = ms.file(path).lower()
    logging.debug("File type: %s" % filetype)

    if "bzip2 compressed data" in filetype:
        logging.debug("bzip2 detected")
        return ARCHIVE_BZ2
    elif "gzip compressed data" in filetype or \
         "compress'd data" in filetype:
        logging.debug("gzip detected")
        return ARCHIVE_GZ
    elif "xz compressed data" in filetype:
        logging.debug("xz detected")
        return ARCHIVE_XZ
    elif "7-zip archive data" in filetype:
        logging.debug("7-zip detected")
        return ARCHIVE_7Z
    elif "zip archive data" in filetype:
        logging.debug("zip detected")
        return ARCHIVE_ZIP
    elif "tar archive" in filetype:
        logging.debug("tar detected")
        return ARCHIVE_TAR

    logging.debug("unknown file type, unpacking finished")
    return ARCHIVE_UNKNOWN

def unpack_vmcore(path):
    parentdir = path.rsplit("/", 1)[0]
    vmcore = os.path.join(parentdir, "vmcore")
    if path != vmcore and os.path.isfile(vmcore):
        raise Exception, "'vmcore' already exists"

    os.rename(path, vmcore)
    filetype = get_archive_type(vmcore)
    while filetype != ARCHIVE_UNKNOWN:
        files = set(f for (f, s) in get_files_sizes(parentdir))
        if filetype == ARCHIVE_GZ:
            vmcoregz = "%s.gz" % vmcore
            os.rename(vmcore, vmcoregz)
            check_run(["gunzip", vmcoregz])

            if not os.path.isfile(vmcore):
                logging.warn("expected file not present, maybe gunzip failed?")
        elif filetype == ARCHIVE_BZ2:
            check_run(["bunzip2", vmcore])
        elif filetype == ARCHIVE_XZ:
            check_run(["unxz", vmcore])
        elif filetype == ARCHIVE_ZIP:
            check_run(["unzip", vmcore, "-d", parentdir])
        elif filetype == ARCHIVE_7Z:
            check_run(["7za", "e", "-o%s" % parentdir, vmcore])
        elif filetype == ARCHIVE_TAR:
            check_run(["tar", "-C", parentdir, "-xf", vmcore])
        else:
            raise Exception, "Unknown archive type"

        files_sizes = get_files_sizes(parentdir)
        newfiles = [f for (f, s) in files_sizes]
        diff = set(newfiles) - files
        vmcore_candidate = 0
        while vmcore_candidate < len(newfiles) and \
              not newfiles[vmcore_candidate] in diff:
            vmcore_candidate += 1

        if len(diff) > 1:
            os.rename(newfiles[vmcore_candidate], vmcore)
            for filename in newfiles:
                if not filename in diff or \
                   filename == newfiles[vmcore_candidate]:
                    continue

                os.unlink(filename)

        elif len(diff) == 1:
            os.rename(diff.pop(), vmcore)

        # just be explicit here - if no file changed, an archive
        # has most probably been unpacked to a file with same name
        else:
            pass

        for filename in os.listdir(parentdir):
            fullpath = os.path.join(parentdir, filename)
            if os.path.isdir(fullpath):
                shutil.rmtree(fullpath)

        filetype = get_archive_type(vmcore)

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

        if task.get_managed():
            continue

        if not task.has_log():
            tasks.append(task.get_taskid())

    return tasks

def parse_rpm_name(name):
    result = {
      "epoch": 0,
      "name": None,
      "version": "",
      "release": "",
      "arch": "",
    }

    # cut off rpm suffix
    if name.endswith(".rpm"):
        name = name[:-4]

    # arch
    match = ARCH_PARSER.match(name)
    if match and match.group(2) in ["i386", "i586", "i686", "x86_64", "noarch"]:
        result["arch"] = match.group(2)
        name = name[:-len(match.group(1))]

    # release
    match = RELEASE_PARSER.match(name)
    if match:
        result["release"] = match.group(2)
        name = name[:-len(match.group(1))]

    # version
    match = VERSION_PARSER.match(name)
    if match:
        result["version"] = match.group(2)
        name = name[:-len(match.group(1))]
    else:
        result["version"] = result["release"]
        result["release"] = None

    # epoch
    match = EPOCH_PARSER.match(name)
    if match:
        result["epoch"] = int(match.group(2))
        name = name[len(match.group(1)):]
    else:
        match = EPOCH_PARSER.match(result["version"])
        if match:
            result["epoch"] = int(match.group(2))
            result["version"] = result["version"][len(match.group(1)):]

    # raw name - verify allowed characters
    match = NAME_PARSER.match(name)
    if match:
        result["name"] = name

    return result

def init_crashstats_db():
    con = sqlite3.connect(os.path.join(CONFIG["SaveDir"], CONFIG["DBFile"]))
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
        raise Exception, "%s exitted with %d: %s" % (cmd[0], child.returncode, stdout)

def strip_vmcore(vmcore):
    vmlinux = None
    try:
        vmlinux = prepare_debuginfo(vmcore)
    except:
        pass

    if vmlinux:
        newvmcore = "%s.stripped" % vmcore
        retcode = call(["makedumpfile", "-c", "-d", "%d" % CONFIG["VmcoreDumpLevel"],
                        "-x", vmlinux, "--message-level", "0", vmcore, newvmcore])
        if retcode:
            os.unlink(newvmcore)
        else:
            os.rename(newvmcore, vmcore)

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

class RetraceTask:
    """Represents Retrace server's task."""

    BACKTRACE_FILE = "retrace_backtrace"
    CRASHRC_FILE = "crashrc"
    DOWNLOADED_FILE = "downloaded"
    FINISHED_FILE = "finished_time"
    LOG_FILE = "retrace_log"
    MANAGED_FILE = "managed"
    MISC_DIR = "misc"
    PASSWORD_FILE = "password"
    REMOTE_FILE = "remote"
    STARTED_FILE = "started_time"
    STATUS_FILE = "status"
    TYPE_FILE = "type"

    def __init__(self, taskid=None):
        """Creates a new task if taskid is None,
        loads the task with given ID otherwise."""

        if taskid is None:
            # create a new task
            # create a retrace-group-writable directory
            oldmask = os.umask(0002)
            self._taskid = None
            generator = random.SystemRandom()
            for i in xrange(50):
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
                raise Exception, "Unable to create new task"

            pwdfilepath = os.path.join(self._savedir, RetraceTask.PASSWORD_FILE)
            with open(pwdfilepath, "w") as pwdfile:
                for i in xrange(CONFIG["TaskPassLength"]):
                    pwdfile.write(generator.choice(TASKPASS_ALPHABET))

            os.makedirs(os.path.join(self._savedir, RetraceTask.MISC_DIR))
            os.umask(oldmask)
        else:
            # existing task
            self._taskid = int(taskid)
            self._savedir = os.path.join(CONFIG["SaveDir"], "%d" % self._taskid)
            if not os.path.isdir(self._savedir):
                raise Exception, "The task %d does not exist" % self._taskid

    def get_taskid(self):
        """Returns task's ID"""
        return self._taskid

    def get_savedir(self):
        """Returns task's savedir"""
        return self._savedir

    def get_password(self):
        """Returns task's password"""
        pwdfilename = os.path.join(self._savedir, RetraceTask.PASSWORD_FILE)
        with open(pwdfilename, "r") as pwdfile:
            pwd = pwdfile.read(CONFIG["TaskPassLength"])

        return pwd

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
            return self.has_status() and not self.get_status() in [STATUS_SUCCESS, STATUS_FAIL]

    def get_age(self):
        """Returns the age of the task in hours."""
        return int(time.time() - os.path.getatime(self._savedir)) / 3600

    def get_type(self):
        """Returns task type. If TYPE_FILE is missing,
        task is considered standard TASK_RETRACE."""
        typefilename = os.path.join(self._savedir, RetraceTask.TYPE_FILE)
        if not os.path.isfile(typefilename):
            return TASK_RETRACE

        with open(typefilename, "r") as typefile:
            # typicaly one digit, max 8B
            result = typefile.read(8)

        return int(result)

    def set_type(self, newtype):
        """Atomically writes given type into TYPE_FILE."""
        tmpfilename = os.path.join(self._savedir,
                                   "%s.tmp" % RetraceTask.TYPE_FILE)
        typefilename = os.path.join(self._savedir, RetraceTask.TYPE_FILE)
        with open(tmpfilename, "w") as tmpfile:
            if newtype in TASK_TYPES:
                tmpfile.write("%d" % newtype)
            else:
                tmpfile.write("%d" % TASK_RETRACE)

        os.rename(tmpfilename, typefilename)

    def has_backtrace(self):
        """Verifies whether BACKTRACE_FILE is present in the task directory."""
        return os.path.isfile(os.path.join(self._savedir,
                                           RetraceTask.BACKTRACE_FILE))

    def get_backtrace(self):
        """Returns None if there is no BACKTRACE_FILE in the task directory,
        BACKTRACE_FILE's contents otherwise."""
        if not self.has_backtrace():
            return None

        btfilename = os.path.join(self._savedir, RetraceTask.BACKTRACE_FILE)
        with open(btfilename, "r") as btfile:
            # max 4 MB
            bt = btfile.read(1 << 22)

        return bt

    def set_backtrace(self, backtrace):
        """Atomically writes given string into BACKTRACE_FILE."""
        tmpfilename = os.path.join(self._savedir,
                                   "%s.tmp" % RetraceTask.BACKTRACE_FILE)
        btfilename = os.path.join(self._savedir,
                                   RetraceTask.BACKTRACE_FILE)

        with open(tmpfilename, "w") as tmpfile:
            tmpfile.write(backtrace)

        os.rename(tmpfilename, btfilename)

    def has_log(self):
        """Verifies whether LOG_FILE is present in the task directory."""
        return os.path.isfile(os.path.join(self._savedir,
                                           RetraceTask.LOG_FILE))

    def get_log(self):
        """Returns None if there is no LOG_FILE in the task directory,
        LOG_FILE's contents otherwise."""
        if not self.has_log():
            return None

        logfilename = os.path.join(self._savedir, RetraceTask.LOG_FILE)
        with open(logfilename, "r") as logfile:
            # max 4 MB
            log = logfile.read(1 << 22)

        return log

    def set_log(self, log, append=False):
        """Atomically writes or appends given string into LOG_FILE."""
        tmpfilename = os.path.join(self._savedir,
                                   "%s.tmp" % RetraceTask.LOG_FILE)
        logfilename = os.path.join(self._savedir,
                                   RetraceTask.LOG_FILE)

        if append:
            if os.path.isfile(logfilename):
                shutil.copyfile(logfilename, tmpfilename)

            with open(tmpfilename, "a") as tmpfile:
                tmpfile.write(log)
        else:
            with open(tmpfilename, "w") as tmpfile:
                tmpfile.write(log)

        os.rename(tmpfilename, logfilename)

    def has_status(self):
        """Verifies whether STATUS_FILE is present in the task directory."""
        return os.path.isfile(os.path.join(self._savedir,
                                           RetraceTask.STATUS_FILE))

    def get_status(self):
        """Returns None if there is no STATUS_FILE in the task directory,
        an integer status code otherwise."""
        if not self.has_status():
            return None

        statusfilename = os.path.join(self._savedir, RetraceTask.STATUS_FILE)
        with open(statusfilename, "r") as statusfile:
            # typically one digit, max 8B
            status = statusfile.read(8)

        return int(status)

    def set_status(self, statuscode):
        """Atomically writes given statuscode into STATUS_FILE."""
        tmpfilename = os.path.join(self._savedir,
                                   "%s.tmp" % RetraceTask.STATUS_FILE)
        statusfilename = os.path.join(self._savedir,
                                      RetraceTask.STATUS_FILE)

        with open(tmpfilename, "w") as tmpfile:
            tmpfile.write("%d" % statuscode)

        os.rename(tmpfilename, statusfilename)

    def has_remote(self):
        """Verifies whether REMOTE_FILE is present in the task directory."""
        return os.path.isfile(os.path.join(self._savedir,
                                           RetraceTask.REMOTE_FILE))

    def add_remote(self, url):
        """Appends a remote resource to REMOTE_FILE."""
        if "\n" in url:
            url = url.split("\n")[0]

        with open(os.path.join(self._savedir, RetraceTask.REMOTE_FILE), "a") as remote_file:
            remote_file.write("%s\n" % url)

    def get_remote(self):
        """Returns the list of remote resources."""
        if not self.has_remote():
            return []

        with open(os.path.join(self._savedir, RetraceTask.REMOTE_FILE), "r") as remote_file:
            result = [line.strip() for line in remote_file.readlines()]

        return result

    def download_remote(self, unpack=True):
        """Downloads all remote resources and returns a list of errors."""
        downloaded = []
        errors = []

        crashdir = os.path.join(self._savedir, "crash")
        if not os.path.isdir(crashdir):
            os.makedirs(crashdir)

        for url in self.get_remote():
            if url.startswith("FTP "):
                filename = url[4:].strip()

                ftp = None
                try:
                    ftp = ftp_init()
                    with open(os.path.join(crashdir, filename), "wb") as target_file:
                        ftp.retrbinary("RETR %s" % filename, target_file.write)

                    downloaded.append(filename)
                except Exception as ex:
                    errors.append((url, str(ex)))
                    continue
                finally:
                    if ftp:
                        ftp_close(ftp)
            else:
                child = Popen(["wget", "-nv", "-P", crashdir, url], stdout=PIPE, stderr=STDOUT)
                stdout = child.communicate()[0]
                if child.wait():
                    errors.append((url, "wget exitted with %d: %s" % (child.returncode, stdout)))
                    continue

                filename = url.rsplit("/", 1)[1]
                downloaded.append(url)

            if unpack:
                fullpath = os.path.join(crashdir, filename)
                try:
                    unpack_vmcore(fullpath)
                except Exception as ex:
                    errors.append((fullpath, str(ex)))

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

            if CONFIG["VmcoreDumpLevel"] > 0 and CONFIG["VmcoreDumpLevel"] < 32 and \
               os.path.isfile(vmcore):
                strip_vmcore(vmcore)
                st = os.stat(vmcore)
                os.chmod(vmcore, st.st_mode | stat.S_IRGRP)

        os.unlink(os.path.join(self._savedir, RetraceTask.REMOTE_FILE))
        self.set_downloaded(", ".join(downloaded))

        return errors

    def has_misc(self, name):
        """Verifies whether a file named 'name' is present in MISC_DIR."""
        if "/" in name:
            raise Exception, "name may not contain the '/' character"

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
            raise Exception, "name may not contain the '/' character"

        if not self.has_misc(name):
            raise Exception, "There is no record with such name"

        miscpath = os.path.join(self._savedir, RetraceTask.MISC_DIR, name)
        with open(miscpath, "r") as misc_file:
            result = misc_file.read(1 << 24) # 16MB

        return result

    def add_misc(self, name, value, overwrite=False):
        """Adds a file named 'name' into MISC_DIR and writes 'value' into it."""
        if "/" in name:
            raise Exception, "name may not contain the '/' character"

        if not overwrite and self.has_misc(name):
            raise Exception, "The record already exists. Use overwrite=True " \
                             "to force overwrite existing records."

        miscdir = os.path.join(self._savedir, RetraceTask.MISC_DIR)
        if not os.path.isdir(miscdir):
            os.makedirs(miscdir)

        miscpath = os.path.join(miscdir, name)
        with open(miscpath, "w") as misc_file:
            misc_file.write(value)

    def del_misc(self, name):
        """Deletes the file named 'name' from MISC_DIR."""
        if "/" in name:
            raise Exception, "name may not contain the '/' character"

        if self.has_misc(name):
            os.unlink(os.path.join(self._savedir, RetraceTask.MISC_DIR, name))

    def get_managed(self):
        """Verifies whether the task is under task management control"""
        if not CONFIG["AllowTaskManager"]:
            raise Exception, "Task management is disabled"

        filename = os.path.join(self._savedir, RetraceTask.MANAGED_FILE)
        return os.path.isfile(filename)

    def set_managed(self, managed):
        """Puts or removes the task from task management control"""
        if not CONFIG["AllowTaskManager"]:
            raise Exception, "Task management is disabled"

        filename = os.path.join(self._savedir, RetraceTask.MANAGED_FILE)
        # create the file if it does not exist
        if managed and not os.path.isfile(filename):
            open(filename, "w").close()
        # unlink the file if it exists
        elif not managed and os.path.isfile(filename):
            os.unlink(filename)

    def has_downloaded(self):
        """Verifies whether DOWNLOAD_FILE exists"""
        return os.path.isfile(os.path.join(self._savedir,
                                           RetraceTask.DOWNLOADED_FILE))

    def get_downloaded(self):
        """Gets contents of DOWNLOADED_FILE"""
        if not self.has_downloaded():
            return None

        downloaded_file_name = os.path.join(self._savedir,
                                            RetraceTask.DOWNLOADED_FILE)
        with open(downloaded_file_name, "r") as f:
            result = f.read(1 << 22)

        return result

    def set_downloaded(self, value):
        """Writes (not atomically) content to DOWNLOADED_FILE"""
        downloaded_file_name = os.path.join(self._savedir,
                                            RetraceTask.DOWNLOADED_FILE)

        with open(downloaded_file_name, "w") as f:
            result = f.write(value)

        return result

    def has_crashrc(self):
        """Verifies whether CRASHRC_FILE exists"""
        return os.path.isfile(os.path.join(self._savedir,
                                           RetraceTask.CRASHRC_FILE))

    def get_crashrc_path(self):
        """Gets the absolute path of CRASHRC_FILE"""
        return os.path.join(self._savedir, RetraceTask.CRASHRC_FILE)

    def get_crashrc(self):
        """Gets the unix timestamp from CRASHRC_FILE"""
        if not self.has_started_time():
            return None

        crashrc_file_name = os.path.join(self._savedir, RetraceTask.CRASHRC_FILE)
        with open(crashrc_file_name, "r") as f:
            result = f.read(1 << 22)

        return result

    def set_crashrc(self, data):
        """Writes data to CRASHRC_FILE"""
        crashrc_file_name = os.path.join(self._savedir, RetraceTask.CRASHRC_FILE)
        with open(crashrc_file_name, "w") as f:
            result = f.write(data)

    def has_started_time(self):
        """Verifies whether STARTED_FILE exists"""
        return os.path.isfile(os.path.join(self._savedir,
                                           RetraceTask.STARTED_FILE))

    def get_started_time(self):
        """Gets the unix timestamp from STARTED_FILE"""
        if not self.has_started_time():
            return None

        start_file_name = os.path.join(self._savedir, RetraceTask.STARTED_FILE)
        with open(start_file_name, "r") as f:
            result = f.read(1 << 8)

        return int(result)

    def set_started_time(self, value):
        """Writes the unix timestamp to STARTED_FILE"""
        try:
            data = int(value)
        except ValueError:
            raise Exception, "set_start_time requires unix timestamp as parameter"

        start_file_name = os.path.join(self._savedir, RetraceTask.STARTED_FILE)
        with open(start_file_name, "w") as f:
            result = f.write("%d" % data)

    def has_finished_time(self):
        """Verifies whether FINISHED_FILE exists"""
        return os.path.isfile(os.path.join(self._savedir,
                                           RetraceTask.FINISHED_FILE))

    def get_finished_time(self):
        """Gets the unix timestamp from FINISHED_FILE"""
        if not self.has_finished_time():
            return None

        finished_file_name = os.path.join(self._savedir, RetraceTask.FINISHED_FILE)
        with open(finished_file_name, "r") as f:
            result = f.read(1 << 8)

        return int(result)

    def set_finished_time(self, value):
        """Writes the unix timestamp to FINISHED_FILE"""
        try:
            data = int(value)
        except ValueError:
            raise Exception, "set_finished_time requires unix timestamp as parameter"

        finished_file_name = os.path.join(self._savedir, RetraceTask.FINISHED_FILE)
        with open(finished_file_name, "w") as f:
            result = f.write("%d" % data)

    def clean(self):
        """Removes all files and directories others than
        results and logs from the task directory."""
        with open("/dev/null", "w") as null:
            if os.path.isfile(os.path.join(self._savedir, "default.cfg")) and \
               os.path.isfile(os.path.join(self._savedir, "site-defaults.cfg")) and \
               os.path.isfile(os.path.join(self._savedir, "logging.ini")):
                retcode = call(["/usr/bin/mock", "--configdir", self._savedir, "--scrub=all"],
                               stdout=null, stderr=null)

        for f in os.listdir(self._savedir):
            if f != RetraceTask.BACKTRACE_FILE and \
               f != RetraceTask.DOWNLOADED_FILE and \
               f != RetraceTask.FINISHED_FILE and \
               f != RetraceTask.LOG_FILE and \
               f != RetraceTask.MANAGED_FILE and \
               f != RetraceTask.PASSWORD_FILE and \
               f != RetraceTask.STARTED_FILE and \
               f != RetraceTask.STATUS_FILE and \
               f != RetraceTask.TYPE_FILE and \
               f != RetraceTask.MISC_DIR:
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

    def remove(self):
        """Completely removes the task directory."""
        self.clean()
        shutil.rmtree(self._savedir)

### read config on import ###
read_config()
