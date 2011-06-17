import sys
from retrace import *

sys.path.insert(0, "/usr/share/retrace-server/")
from plugins import *

log = None
task = None

def fail(exitcode):
    "Kills script with given exitcode"
    global task, log
    task.set_status(STATUS_FAIL)
    task.set_log(log)
    task.clean()
    sys.exit(exitcode)

def retrace_run(errorcode, cmd):
    "Runs cmd using subprocess.Popen and kills script with errorcode on failure"
    try:
        child = Popen(cmd, stdout=PIPE, stderr=STDOUT)
        output = child.communicate()[0]
    except Exception as ex:
        child = None
        output = "An unhandled exception occured: %s" % ex

    if not child or child.returncode != 0:
        global log
        log += "Error %d:\n=== OUTPUT ===\n%s\n" % (errorcode, output)
        fail(errorcode)

    return output

if __name__ == "__main__":
    starttime = time.time()
    log = ""

    if len(sys.argv) != 2:
        sys.stderr.write("Usage: %s task_id\n" % sys.argv[0])
        sys.exit(11)

    try:
        taskid = int(sys.argv[1])
    except:
        sys.stderr.write("Task ID may only contain digits.\n")
        sys.exit(12)

    try:
        task = RetraceTask(taskid)
    except:
        sys.stderr.write("Task '%s' does not exist.\n" % taskid)
        sys.exit(13)

    task.set_status(STATUS_ANALYZE)
    log += "%s " % STATUS[STATUS_ANALYZE]

    crashdir = os.path.join(task.get_savedir(), "crash")

    # check the crash directory for required files
    for required_file in REQUIRED_FILES:
        if not os.path.isfile(os.path.join(crashdir, required_file)):
            log += "Error\nCrash directory does not contain required file '%s'.\n" % required_file
            fail(15)

    # read architecture from coredump
    arch = guess_arch(os.path.join(crashdir, "coredump"))

    if not arch:
        log += "Error\nUnable to read architecture from 'coredump' file.\n"
        fail(16)

    # read package file
    try:
        with open(os.path.join(crashdir, "package"), "r") as package_file:
            crash_package = package_file.read()
    except Exception as ex:
        log += "Error\nUnable to read crash package from 'package' file: %s.\n" % ex
        fail(17)

    # read package file
    if not INPUT_PACKAGE_PARSER.match(crash_package):
        log += "Error\nInvalid package name: %s.\n" % crash_package
        fail(19)

    # read release, distribution and version from release file
    release_path = os.path.join(crashdir, "os_release")
    if not os.path.isfile(release_path):
        release_path = os.path.join(crashdir, "release")

    try:
        with open(release_path, "r") as release_file:
            release = release_file.read()

        version = distribution = None
        for plugin in PLUGINS:
            match = plugin.abrtparser.match(release)
            if match:
                version = match.group(1)
                distribution = plugin.distribution
                break

        if not version or not distribution:
            raise Exception, "Release '%s' is not supported.\n" % release

    except Exception as ex:
        log += "Error\nUnable to read distribution and version from 'release' file: %s.\n" % ex
        log += "Trying to guess distribution and version "
        distribution, version = guess_release(crash_package, PLUGINS)
        if distribution and version:
            log += "%s-%s\n" % (distribution, version)
        else:
            log += "Failure\n"
            fail(18)

    packages = crash_package

    # read required packages from coredump
    try:
        # ToDo: deal with not found build-ids
        child = Popen(["coredump2packages", os.path.join(crashdir, "coredump"),
                       "--repos=retrace-%s-%s-%s*" % (distribution, version, arch)],
                      stdout=PIPE)
        section = 0
        crash_package_or_component = None
        lines = child.communicate()[0].split("\n")
        for line in lines:
            if line == "":
                section += 1
                continue
            elif 0 == section:
                crash_package_or_component = line.strip()
            elif 1 == section:
                packages += " %s" % line.rstrip("\n")
            elif 2 == section:
                # Missing build ids
                pass
    except Exception as ex:
        log += "Error\nUnable to obtain packages from 'coredump' file: %s.\n" % ex
        fail(20)

    # create mock config file
    try:
        with open(os.path.join(task.get_savedir(), "default.cfg"), "w") as mockcfg:
            mockcfg.write("config_opts['root'] = '%s'\n" % taskid)
            mockcfg.write("config_opts['target_arch'] = '%s'\n" % arch)
            mockcfg.write("config_opts['chroot_setup_cmd'] = '--skip-broken install %s shadow-utils gdb rpm'\n" % packages)
            mockcfg.write("config_opts['plugin_conf']['ccache_enable'] = False\n")
            mockcfg.write("config_opts['plugin_conf']['yum_cache_enable'] = False\n")
            mockcfg.write("config_opts['plugin_conf']['root_cache_enable'] = False\n")
            mockcfg.write("\n")
            mockcfg.write("config_opts['yum.conf'] = \"\"\"\n")
            mockcfg.write("[main]\n")
            mockcfg.write("cachedir=/var/cache/yum\n")
            mockcfg.write("debuglevel=1\n")
            mockcfg.write("reposdir=/dev/null\n")
            mockcfg.write("logfile=/var/log/yum.log\n")
            mockcfg.write("retries=20\n")
            mockcfg.write("obsoletes=1\n")
            mockcfg.write("gpgcheck=1\n")
            mockcfg.write("assumeyes=1\n")
            mockcfg.write("syslog_ident=mock\n")
            mockcfg.write("syslog_device=\n")
            mockcfg.write("\n")
            mockcfg.write("#repos\n")
            mockcfg.write("\n")
            mockcfg.write("[%s]\n" % distribution)
            mockcfg.write("name=%s\n" % distribution)
            mockcfg.write("baseurl=file://%s/%s-%s-%s/\n" % (CONFIG["RepoDir"], distribution, version, arch))
            mockcfg.write("failovermethod=priority\n")
            mockcfg.write("gpgkey=file:///usr/share/retrace-server/gpg/%s-%s\n" % (distribution, version))
            mockcfg.write("\"\"\"\n")

        # symlink defaults from /etc/mock
        os.symlink("/etc/mock/site-defaults.cfg", os.path.join(task.get_savedir(), "site-defaults.cfg"))
        os.symlink("/etc/mock/logging.ini", os.path.join(task.get_savedir(), "logging.ini"))
    except Exception as ex:
        log += "Error\nUnable to create mock config file: %s.\n" % ex
        fail(21)

    log += "OK\n"

    # get count of tasks running before starting
    prerunning = len(get_active_tasks()) - 1

    # run retrace
    task.set_status(STATUS_INIT)
    log += "%s " % STATUS[STATUS_INIT]

    retrace_run(25, ["mock", "init", "--configdir", task.get_savedir()])
    retrace_run(26, ["mock", "--configdir", task.get_savedir(), "--copyin",
                     crashdir, "/var/spool/abrt/crash"])
    retrace_run(27, ["mock", "--configdir", task.get_savedir(), "shell",
                     "--", "chgrp", "-R", "mockbuild", "/var/spool/abrt/crash"])

    log += "OK\n"

    # generate backtrace
    task.set_status(STATUS_BACKTRACE)
    log += "%s " % STATUS[STATUS_BACKTRACE]

    try:
        backtrace = run_gdb(task.get_savedir())
    except Exception as ex:
        log += "Error\n%s\n" % ex
        fail(29)

    try:
        task.set_backtrace(backtrace)
    except Exception as ex:
        log += "Error\n%s\n" % ex
        fail(30)

    log += "OK\n"

    # does not work at the moment
    chroot_size = 0

    # clean up temporary data
    task.set_status(STATUS_CLEANUP)
    log += "%s " % STATUS[STATUS_CLEANUP]

    task.clean()

    # ignore error: workdir = savedir => workdir is not empty
    if CONFIG["UseWorkDir"]:
        try:
            os.rmdir(workdir)
        except:
            pass

    log += "OK\n"

    # save crash statistics
    task.set_status(STATUS_STATS)
    log += "%s " % STATUS[STATUS_STATS]

    duration = int(time.time() - starttime)

    package_match = PACKAGE_PARSER.match(crash_package)
    if not package_match:
        package = crash_package
        version = "unknown"
        release = "unknown"
    else:
        package = package_match.group(1)
        version = package_match.group(2)
        release = package_match.group(4)

    crashstats = {
      "taskid": task.get_taskid(),
      "package": package,
      "version": version,
      "release": release,
      "arch": arch,
      "starttime": int(starttime),
      "duration": duration,
      "prerunning": prerunning,
      "postrunning": len(get_active_tasks()) - 1,
      "chrootsize": chroot_size
    }

    if not init_crashstats_db() or not save_crashstats(crashstats):
        log += "Error\n%s\n" % crashstats
    else:
        log += "OK\n"

    # publish log => finish task
    log += "Retrace took %d seconds.\n" % duration
    log += STATUS[STATUS_SUCCESS]

    task.set_log(log)
    task.set_status(STATUS_SUCCESS)
