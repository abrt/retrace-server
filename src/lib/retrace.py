import ConfigParser
import datetime
import errno
import ftplib
import gettext
import logging
import magic
import os
import re
import random
import shutil
import smtplib
import sqlite3
import stat
import time
import urllib
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
  "packages": (1 << 20), # 1MB
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
  ARCHIVE_BZ2, ARCHIVE_XZ, ARCHIVE_TAR, \
  ARCHIVE_7Z, ARCHIVE_LZOP = xrange(8)

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

CORE_ARCH_PARSER = re.compile("core file,? .*(x86-64|80386|ARM|IBM S/390|64-bit PowerPC)")
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
KERNEL_RELEASE_PARSER = re.compile("^([0-9]+\.[0-9]+\.[0-9]+)-([0-9]+\.[^ \t]*)$")
# OSRELEASE=2.6.32-209.el6.x86_64
OSRELEASE_VAR_PARSER = re.compile("^OSRELEASE=([^%]*)$")

DUMP_LEVEL_PARSER = re.compile("^[ \t]*dump_level[ \t]*:[ \t]*([0-9]+).*$")

WORKER_RUNNING_PARSER = re.compile("^[ \t]*([0-9]+)[ \t]+[0-9]+[ \t]+([^ ^\t]+)[ \t]+.*retrace-server-worker ([0-9]+)( .*)?$")

UNITS = ["B", "kB", "MB", "GB", "TB", "PB", "EB"]

HANDLE_ARCHIVE = {
  "application/x-xz-compressed-tar": {
    "unpack": [TAR_BIN, "xJf"],
    "size": ([XZ_BIN, "--list", "--robot"], re.compile("^totals[ \t]+[0-9]+[ \t]+[0-9]+[ \t]+[0-9]+[ \t]+([0-9]+).*")),
    "type": ARCHIVE_XZ,
  },

  "application/x-gzip": {
    "unpack": [TAR_BIN, "xzf"],
    "size": ([GZIP_BIN, "--list"], re.compile("^[^0-9]*[0-9]+[^0-9]+([0-9]+).*$")),
    "type": ARCHIVE_GZ,
  },

  "application/x-tar": {
    "unpack": [TAR_BIN, "xf"],
    "size": (["ls", "-l"], re.compile("^[ \t]*[^ ^\t]+[ \t]+[^ ^\t]+[ \t]+[^ ^\t]+[ \t]+[^ ^\t]+[ \t]+([0-9]+).*$")),
    "type": ARCHIVE_TAR,
  },
}

FTP_SUPPORTED_EXTENSIONS = [".tar.gz", ".tgz", ".tarz", ".tar.bz2", ".tar.xz",
                            ".tar", ".gz", ".bz2", ".xz", ".Z", ".zip"]

REPO_PREFIX = "retrace-"
EXPLOITABLE_PLUGIN_PATH = "/usr/libexec/abrt-gdb-exploitable"
EXPLOITABLE_SEPARATOR = "== EXPLOITABLE ==\n"

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
  "DeleteFailedTaskAfter": 24,
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
  "AllowExternalDir": False,
  "AllowInteractive": False,
  "AllowTaskManager": False,
  "TaskManagerAuthDelete": False,
  "TaskManagerDeleteUsers": [],
  "UseFTPTasks": False,
  "FTPSSL": False,
  "FTPHost": "",
  "FTPUser": "",
  "FTPPass": "",
  "FTPDir": "/",
  "FTPBufferSize": 16,
  "WgetKernelDebuginfos": False,
  "KernelDebuginfoURL": "http://kojipkgs.fedoraproject.org/packages/kernel/$VERSION/$RELEASE/$ARCH/",
  "VmcoreDumpLevel": 0,
  "VmcoreRunKmem": 0,
  "RequireGPGCheck": True,
  "UseCreaterepoUpdate": False,
  "DBFile": "stats.db",
  "KernelChrootRepo": "http://dl.fedoraproject.org/pub/fedora/linux/releases/16/Everything/$ARCH/os/",
  "UseFafPackages": False,
  "FafLinkDir": "/var/spool/faf/retrace-tmp",
  "AuthGroup": "retrace",
  "EmailNotify": False,
  "EmailNotifyFrom": "retrace@localhost",
  "CaseNumberURL": "",
}

ARCH_HOSTS = {}

STATUS_ANALYZE, STATUS_INIT, STATUS_BACKTRACE, STATUS_CLEANUP, \
STATUS_STATS, STATUS_FINISHING, STATUS_SUCCESS, STATUS_FAIL, \
STATUS_DOWNLOADING, STATUS_POSTPROCESS = xrange(10)

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
]

ARCHITECTURES = set(["src", "noarch", "i386", "i486", "i586", "i686", "x86_64",
                     "s390", "s390x", "ppc", "ppc64",  "ppc64iseries",
                     "armel", "armhfp", "armv5tel", "armv7l", "armv7hl",
                     "armv7hnl", "sparc", "sparc64", "mips4kec", "ia64"])

# armhfp is not correct, but there is no way to distinguish armv5/armv6/armv7 coredumps
# as armhfp (RPM armv7hl) is the only supported now, let's approximate arm = armhfp

# "arm" has been intentionally removed - when guessing architecture, it matches
# "alarm" or "hdparm" and thus leads to wrong results.
# As soon as plain "arm" needs to be supported, this needs to be solved properly.
ARCH_MAP = {
    "i386": set(["i386", "i486", "i586", "i686"]),
    "armhfp": set(["armhfp", "armel", "armv5tel", "armv7l", "armv7hl", "armv7hnl"]),
    "x86_64": set(["x86_64"]),
    "s390x": set(["s390x"]),
    "ppc64": set(["ppc64"]),
}

def now():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def log_info(msg):
    logging.info("%23s %s" % (now(), msg))

def log_debug(msg):
    logging.debug("%22s %s" % (now(), msg))

def log_warn(msg):
    logging.warn("%20s %s" % (now(), msg))

def log_error(msg):
    logging.error("%22s %s" % (now(), msg))

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

def get_canon_arch(arch):
    for canon_arch, derived_archs in ARCH_MAP.items():
        if arch in derived_archs:
            return canon_arch

    return arch

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
        elif vartype is list:
            get = lambda sect, key: parser.get(sect, key).split()
        else:
            get = parser.get

        try:
            CONFIG[key] = get("retrace", key)
        except ConfigParser.NoOptionError:
            pass

    if "archhosts" in parser.sections():
        for arch, host in parser.items("archhosts"):
            host = host.strip()
            if host:
                ARCH_HOSTS[arch] = host

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
        elif match.group(1) == "IBM S/390":
            return "s390x"
        elif match.group(1) == "64-bit PowerPC":
            return "ppc64"

    result = None
    child = Popen(["strings", coredump_path], stdout=PIPE)
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

    with open(os.devnull, "w") as null:
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

        child = Popen(["/usr/bin/mock", "shell", "--configdir", savedir,
                       "--", "ls", "'%s'" % EXPLOITABLE_PLUGIN_PATH],
                       stdout=PIPE, stderr=null)
        add_exploitable = child.communicate()[0].strip() == EXPLOITABLE_PLUGIN_PATH

        batfile = os.path.join(savedir, "gdb.sh")
        with open(batfile, "w") as gdbfile:
            gdbfile.write("gdb -batch ")
            if add_exploitable:
                gdbfile.write("-ex 'python execfile(\"/usr/libexec/abrt-gdb-exploitable\")' ")
            gdbfile.write("-ex 'file %s' "
                          "-ex 'core-file /var/spool/abrt/crash/coredump' "
                          "-ex 'thread apply all backtrace 2048 full' "
                          "-ex 'info sharedlib' "
                          "-ex 'print (char*)__abort_msg' "
                          "-ex 'print (char*)__glib_assert_msg' "
                          "-ex 'info registers' "
                          "-ex 'disassemble' " % executable)
            if add_exploitable:
                gdbfile.write("-ex 'echo %s' "
                              "-ex 'abrt-exploitable'" % EXPLOITABLE_SEPARATOR)

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

    exploitable = None
    if EXPLOITABLE_SEPARATOR in backtrace:
        backtrace, exploitable = backtrace.rsplit(EXPLOITABLE_SEPARATOR, 1)

    if not backtrace:
        raise Exception("An unusable backtrace has been generated")

    return backtrace, exploitable

def is_package_known(package_nvr, arch, releaseid=None):
    if releaseid is None:
        releases = get_supported_releases()
    else:
        releases = [releaseid]

    candidates = []
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
        release = None
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
            match = KERNEL_RELEASE_PARSER.match(line)
            if match:
                release = line
                break

            line = child.stdout.readline()

        # much more output is available, but we don't need any more
        child.stdout.close()
        child.kill()

    if release is None or release == "unknown":
        return None

    # check whether architecture is present
    try:
        result = KernelVer(release)
    except Exception as ex:
        log_error(str(ex))
        return None

    if result.arch is None:
        result.arch = guess_arch(vmcore)
        if not result.arch:
            log_error("Unable to determine architecture")
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

    # search for the debuginfo RPM
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

    if ver.rt:
        basename = "kernel-rt"
    else:
        basename = "kernel"

    # koji-like root
    for ver in vers:
        testfile = os.path.join(CONFIG["KojiRoot"], "packages", basename, ver.version, ver.release, ver._arch, ver.package_name(debug=True))
        log_debug("Trying debuginfo file: %s" % testfile)
        if os.path.isfile(testfile):
            return testfile

    if CONFIG["WgetKernelDebuginfos"]:
        downloaddir = os.path.join(CONFIG["RepoDir"], "download")
        if not os.path.isdir(downloaddir):
            oldmask = os.umask(0007)
            os.makedirs(downloaddir)
            os.umask(oldmask)

        for ver in vers:
            pkgname = ver.package_name(debug=True)
            url = CONFIG["KernelDebuginfoURL"].replace("$VERSION", ver.version).replace("$RELEASE", ver.release).replace("$ARCH", ver._arch).replace("$BASENAME", basename)
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
        raise Exception, "Given debuginfo file does not exist"

    # prepend absolute path /usr/lib/debug/... with dot, so that cpio can match it
    for i in xrange(len(files)):
        if files[i][0] == "/":
            files[i] = ".%s" % files[i]

    with open(os.devnull, "w") as null:
        rpm2cpio = Popen(["rpm2cpio", debuginfo], stdout=PIPE, stderr=null)
        cpio = Popen(["cpio", "-id"] + files, stdin=rpm2cpio.stdout, stdout=null, stderr=null, cwd=basedir)
        rpm2cpio.wait()
        cpio.wait()
        rpm2cpio.stdout.close()

def prepare_debuginfo(vmcore, chroot=None, kernelver=None):
    if kernelver is None:
        kernelver = get_kernel_release(vmcore)

    if kernelver is None:
        raise Exception, "Unable to determine kernel version"

    debuginfo = find_kernel_debuginfo(kernelver)
    if not debuginfo:
        raise Exception, "Unable to find debuginfo package"

    if "EL" in kernelver.release:
        if kernelver.flavour is None:
            pattern = "EL/vmlinux"
        else:
            pattern = "EL%s/vmlinux" % kernelver.flavour
    else:
        pattern = "/vmlinux"

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

    debugdir_base = os.path.join(CONFIG["RepoDir"], "kernel", kernelver.arch)
    if not os.path.isdir(debugdir_base):
        os.makedirs(debugdir_base)

    vmlinux = os.path.join(debugdir_base, vmlinux_path.lstrip("/"))
    if not os.path.isfile(vmlinux):
        cache_files_from_debuginfo(debuginfo, debugdir_base, [vmlinux_path])
        if not os.path.isfile(vmlinux):
            raise Exception, "Caching vmlinux failed"

    if chroot:
        with open(os.devnull, "w") as null:
            child = Popen(["/usr/bin/mock", "--configdir", chroot, "shell",
                           "--", "crash", "-s", vmcore, vmlinux],
                           stdin=PIPE, stdout=PIPE, stderr=null)
    else:
        child = Popen(["crash", "-s", vmcore, vmlinux], stdin=PIPE, stdout=PIPE, stderr=STDOUT)
    stdout = child.communicate("mod\nquit")[0]
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

    return sorted(result, key=lambda (f, s): s, reverse=True)

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
            raise Exception, "Unknown archive type"

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
    if match and match.group(2) in ARCHITECTURES:
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
    # create the database group-writable and world-readable
    old_umask = os.umask(0113)
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
        raise Exception, "'to' must be either string or a list of strings"

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
        raise Exception, "%s exitted with %d: %s" % (cmd[0], child.returncode, stdout)

def strip_vmcore(vmcore, kernelver=None):
    try:
        vmlinux = prepare_debuginfo(vmcore, kernelver=kernelver)
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
    FLAVOUR =  [ "debug", "highbank", "hugemem",
                 "kirkwood", "largesmp", "PAE", "omap",
                 "smp", "tegra", "xen", "xenU" ]

    ARCH = ARCHITECTURES

    @property
    def arch(self):
        return get_canon_arch(self._arch)

    @arch.setter
    def arch(self, value):
        self._arch = value

    def __init__(self, kernelver_str):
        log_debug("Parsing kernel version '%s'" % kernelver_str)
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

        self.rt = self.release.endswith("rt")

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

    def package_name(self, debug=False):
        if self._arch is None:
            raise Exception, "Architecture is required for building package name"

        base = "kernel"
        if self.rt:
            base = "%s-rt" % base

        if self.flavour and not (debug and ".EL" in self.release):
            base = "%s-%s" % (base, self.flavour)

        if debug:
            base = "%s-debuginfo" % base

        return "%s-%s-%s.%s.rpm" % (base, self.version, self.release, self._arch)

    def needs_arch(self):
        return self._arch is None

class RetraceTask:
    """Represents Retrace server's task."""

    BACKTRACE_FILE = "retrace_backtrace"
    CASENO_FILE = "caseno"
    CRASHRC_FILE = "crashrc"
    DOWNLOADED_FILE = "downloaded"
    FINISHED_FILE = "finished_time"
    KERNELVER_FILE = "kernelver"
    LOG_FILE = "retrace_log"
    MANAGED_FILE = "managed"
    MISC_DIR = "misc"
    NOTES_FILE = "notes"
    NOTIFY_FILE = "notify"
    PASSWORD_FILE = "password"
    PROGRESS_FILE = "progress"
    REMOTE_FILE = "remote"
    STARTED_FILE = "started_time"
    STATUS_FILE = "status"
    TYPE_FILE = "type"
    URL_FILE = "url"

    def __init__(self, taskid=None):
        """Creates a new task if taskid is None,
        loads the task with given ID otherwise."""

        if taskid is None:
            # create a new task
            # create a retrace-group-writable directory
            oldmask = os.umask(0007)
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

        qs_text = urllib.urlencode(qs)

        if qs_text:
            starturl = "%s?%s" % (starturl, qs_text)

        url = urllib.urlopen(starturl)
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

        if task_arch in ARCH_HOSTS:
            return self._start_remote(ARCH_HOSTS[task_arch], debug=debug,
                                      kernelver=kernelver, arch=arch)

        return self._start_local(debug=debug, kernelver=kernelver, arch=arch)

    def set(self, key, value, mode="w"):
        if not mode in ["w", "a"]:
            raise ValueError, "mode must be either 'w' or 'a'"

        with open(self._get_file_path(key), mode) as f:
            f.write(value)

    def set_atomic(self, key, value, mode="w"):
        if not mode in ["w", "a"]:
            raise ValueError, "mode must be either 'w' or 'a'"

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
            return self.has_status() and not self.get_status() in [STATUS_SUCCESS, STATUS_FAIL]

    def get_age(self):
        """Returns the age of the task in hours."""
        return int(time.time() - os.path.getmtime(self._savedir)) / 3600

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
        return filter(None, set(n.strip() for n in result.split("\n")))

    def set_notify(self, values):
        if not isinstance(values, list) or not all([isinstance(v, basestring) for v in values]):
            raise Exception, "values must be a list of strings"

        self.set_atomic(RetraceTask.NOTIFY_FILE,
                        "%s\n" % "\n".join(filter(None, set(v.strip().replace("\n", " ") for v in values))))

    def has_url(self):
        return self.has(RetraceTask.URL_FILE)

    def get_url(self):
        return self.get(RetraceTask.URL_FILE, maxlen=1 << 14)

    def set_url(self, value):
        self.set(RetraceTask.URL_FILE, value)

    def download_block(self, data):
        self._progress_write_func(data)
        self._progress_current += len(data)
        progress = "%d%% (%s / %s)" % ((100 * self._progress_current) / self._progress_total,
                                       human_readable_size(self._progress_current),
                                       self._progress_total_str)
        self.set_atomic(RetraceTask.PROGRESS_FILE, progress)

    def download_remote(self, unpack=True, timeout=0, kernelver=None):
        """Downloads all remote resources and returns a list of errors."""
        downloaded = []
        errors = []

        crashdir = os.path.join(self._savedir, "crash")
        if not os.path.isdir(crashdir):
            oldmask = os.umask(0007)
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

            self.set_status(STATUS_POSTPROCESS)
            log_info(STATUS[STATUS_POSTPROCESS])

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
                    strip_vmcore(vmcore, kernelver)
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
                    log_info("Makedumpfile took %d seconds and saved %s" % (dur, human_readable_size(oldsize - st.st_size)))

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
            oldmask = os.umask(0007)
            os.makedirs(miscdir)
            os.umask(oldmask)

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

        return self.has(RetraceTask.MANAGED_FILE)

    def set_managed(self, managed):
        """Puts or removes the task from task management control"""
        if not CONFIG["AllowTaskManager"]:
            raise Exception, "Task management is disabled"

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
            raise Exception, "set_start_time requires unix timestamp as parameter"

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
            raise Exception, "set_caseno requires a number as parameter"

        self.set(RetraceTask.CASENO_FILE, "%d" % data)

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
            raise Exception, "set_finished_time requires unix timestamp as parameter"

        self.set(RetraceTask.FINISHED_FILE, "%d" % value)

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
            if not f in [ RetraceTask.REMOTE_FILE, RetraceTask.CASENO_FILE,
              RetraceTask.BACKTRACE_FILE, RetraceTask.DOWNLOADED_FILE,
              RetraceTask.FINISHED_FILE, RetraceTask.LOG_FILE,
              RetraceTask.MANAGED_FILE, RetraceTask.NOTES_FILE,
              RetraceTask.NOTIFY_FILE, RetraceTask.PASSWORD_FILE,
              RetraceTask.STARTED_FILE, RetraceTask.STATUS_FILE,
              RetraceTask.TYPE_FILE, RetraceTask.MISC_DIR,
              RetraceTask.CRASHRC_FILE, RetraceTask.URL_FILE ]:

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
                         RetraceTask.STATUS_FILE]:
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

### read config on import ###
read_config()
