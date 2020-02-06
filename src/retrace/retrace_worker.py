import os
import sys
import datetime
import errno
import time
import grp
import logging
import shutil
import stat
from subprocess import PIPE, DEVNULL, STDOUT, run

from retrace.hooks.hooks import RetraceHook
from .retrace import (ALLOWED_FILES, REPO_PREFIX, REQUIRED_FILES,
                      STATUS, STATUS_ANALYZE, STATUS_BACKTRACE, STATUS_CLEANUP,
                      STATUS_FAIL, STATUS_INIT, STATUS_STATS, STATUS_SUCCESS,
                      TASK_DEBUG, TASK_RETRACE, TASK_RETRACE_INTERACTIVE, TASK_VMCORE,
                      TASK_VMCORE_INTERACTIVE, RETRACE_GPG_KEYS,
                      get_active_tasks,
                      get_supported_releases,
                      guess_arch,
                      is_package_known,
                      KernelVMcore,
                      log_debug,
                      log_error,
                      log_info,
                      log_warn,
                      logger,
                      run_gdb,
                      RetraceTask,
                      RetraceWorkerError)
from .config import Config
from .plugins import Plugins
from .stats import (init_crashstats_db,
                    save_crashstats,
                    save_crashstats_build_ids,
                    save_crashstats_packages,
                    save_crashstats_success)
from .util import (INPUT_PACKAGE_PARSER,
                   human_readable_size,
                   parse_rpm_name,
                   send_email)

sys.path.insert(0, "/usr/share/retrace-server/")

CONFIG = Config()


class RetraceWorker():
    def __init__(self, task):
        self.plugins = Plugins()
        self.task = task
        self.logging_handler = None
        self.hook = RetraceHook(task)

    def begin_logging(self):
        if self.logging_handler is None:
            self.logging_handler = logging.FileHandler(
                self.task._get_file_path(RetraceTask.LOG_FILE))

        formatter = logging.Formatter(fmt="[%(asctime)s] [%(levelname)-.1s] %(message)s",
                                      datefmt="%Y-%m-%d %H:%M:%S")
        self.logging_handler.setFormatter(formatter)
        logger.addHandler(self.logging_handler)

    def end_logging(self):
        if self.logging_handler is not None:
            logger.removeHandler(self.logging_handler)


    def notify_email(self):
        task = self.task
        if not CONFIG["EmailNotify"] or not task.has_notify():
            return
        if task.get_status() == STATUS_SUCCESS:
            disposition = "succeeded"
        else:
            disposition = "failed"

        try:
            log_info("Sending e-mail to %s" % ", ".join(task.get_notify()))

            message = "The task #%d started on %s %s\n\n" % (task.get_taskid(), os.uname()[1], disposition)

            if task.has_url():
                message += "URL: %s\n" % task.get_url()

            message += "Task directory: %s\n" % task.get_savedir()

            if task.has_started_time():
                message += "Started: %s\n" % datetime.datetime.fromtimestamp(task.get_started_time())

            if task.has_finished_time():
                message += "Finished: %s\n" % datetime.datetime.fromtimestamp(task.get_finished_time())

            if task.has_md5sum():
                message += "MD5sum: %s" % task.get_md5sum()

            if task.has_kernelver():
                message += "Kernelver: %s\n" % task.get_kernelver()

            if task.has_remote() or task.has_downloaded():
                files = ""
                if task.has_remote():
                    remote = [x[4:] if x.startswith("FTP ") else x for x in task.get_remote()]
                    files = ", ".join(remote)

                if task.has_downloaded():
                    files = ", ".join(filter(None, [task.get_downloaded(), files]))

                message += "Remote file(s): %s\n" % files

            if task.get_type() in [TASK_VMCORE, TASK_VMCORE_INTERACTIVE] and task.get_status() == STATUS_FAIL:
                message += "\nIf kernel version detection failed (the log shows 'Unable to determine kernel " \
                           "version'), and you know the kernel version, you may try re-starting the task " \
                           "with the 'retrace-server-worker --restart' command.  Please check the log below " \
                           "for more information on why the task failed.  The following example assumes " \
                           "the vmcore's kernel version is 2.6.32-358.el6 on x86_64 arch: \n" \
                           "$ retrace-server-worker --restart --kernelver 2.6.32-358.el6.x86_64 --arch x86_64 %d\n" \
                           % task.get_taskid()
                message += "\nIf this is a test kernel with a non-errata kernel version, or for some reason " \
                           "the kernel-debuginfo repository is unavailable, you can place the kernel-debuginfo RPM " \
                           "at %s/download/ and restart the task with: \n$ retrace-server-worker --restart %d\n" \
                           % (CONFIG["RepoDir"], task.get_taskid())
                message += "\nIf the retrace-log contains a message similar to 'Failing task due to crash " \
                           "exiting with non-zero status and small kernellog size' then the vmcore may be " \
                           "truncated or incomplete and not useable.  Check the md5sum on the manager page " \
                           "and compare with the expected value, and possibly re-upload and resubmit the vmcore.\n"

            if task.has_log():
                message += "\nLog:\n%s\n" % task.get_log()

            send_email("Retrace Server <%s>" % CONFIG["EmailNotifyFrom"],
                       task.get_notify(),
                       "Retrace Task #%d on %s %s" % (task.get_taskid(), os.uname()[1], disposition),
                       message)

        except Exception as ex:
            log_error("Failed to send e-mail: %s" % ex)

    def _symlink_log(self):
        if self.task.has_log():
            # add a symlink to log to results directory
            # use underscore so that the log is first in the list
            try:
                os.symlink(self.task._get_file_path(RetraceTask.LOG_FILE),
                           os.path.join(self.task.get_results_dir(), "retrace-log"))
            except OSError as ex:
                if ex.errno != errno.EEXIST:
                    raise

    def _fail(self, errorcode=1):
        task = self.task
        task.set_status(STATUS_FAIL)
        task.set_finished_time(int(time.time()))
        self.notify_email()

        self._symlink_log()

        self.stats["duration"] = int(time.time()) - self.stats["starttime"]
        try:
            save_crashstats(self.stats)
        except Exception as ex:
            log_warn("Failed to save crash statistics: %s" % str(ex))

        if not task.get_type() in [TASK_DEBUG, TASK_RETRACE_INTERACTIVE, TASK_VMCORE_INTERACTIVE]:
            self.clean_task()

        self.hook.run("fail")

        raise RetraceWorkerError(errorcode=errorcode)

    def _retrace_run(self, errorcode, cmd):
        "Runs cmd using subprocess.Popen and kills script with errorcode on failure"
        try:
            child = run(cmd, stdout=PIPE, stderr=STDOUT, encoding='utf-8')
            output = child.stdout
        except Exception as ex:
            child = None
            log_error("An unhandled exception occured: %s" % ex)

        if not child or child.returncode != 0:
            log_error("%s exited with %d\n=== OUTPUT ===\n%s" % (" ".join(cmd), child.returncode, output))
            self._fail(errorcode)

        return output

    def guess_release(self, package, plugins):
        for plugin in plugins:
            match = plugin.guessparser.search(package)
            if match:
                self.plugin = plugin
                return plugin.distribution, match.group(1)

        return None, None

    def read_architecture(self, custom_arch, corepath):
        if custom_arch:
            log_debug("Using custom architecture: %s" % custom_arch)
            arch = custom_arch
        else:
            # read architecture from coredump
            arch = guess_arch(corepath)

            if not arch:
                log_error("Unable to determine architecture from coredump")
                self._fail()

            log_debug("Determined architecture: %s" % arch)
        return arch

    def read_package_file(self, crashdir):
        # read package file
        try:
            with open(os.path.join(crashdir, "package"), "r") as package_file:
                crash_package = package_file.read(ALLOWED_FILES["package"])
        except Exception as ex:
            log_error("Unable to read crash package from 'package' file: %s" % ex)
            self._fail()
        # read package file
        if not INPUT_PACKAGE_PARSER.match(crash_package):
            log_error("Invalid package name: %s" % crash_package)
            self._fail()

        pkgdata = parse_rpm_name(crash_package)
        if not pkgdata["name"]:
            log_error("Unable to parse package name: %s" % crash_package)
            self._fail()
        return (crash_package, pkgdata)

    def read_release_file(self, crashdir, crash_package):
        # read release, distribution and version from release file
        release_path = None
        rootdir = None
        rootdir_path = os.path.join(crashdir, "rootdir")
        if os.path.isfile(rootdir_path):
            with open(rootdir_path, "r") as rootdir_file:
                rootdir = rootdir_file.read(ALLOWED_FILES["rootdir"])

            exec_path = os.path.join(crashdir, "executable")
            with open(exec_path, "r") as exec_file:
                executable = exec_file.read(ALLOWED_FILES["executable"])

            if executable.startswith(rootdir):
                with open(exec_path, "w") as exec_file:
                    exec_file.write(executable[len(rootdir):])

            rel_path = os.path.join(crashdir, "os_release_in_rootdir")
            if os.path.isfile(rel_path):
                release_path = rel_path

        if not release_path:
            release_path = os.path.join(crashdir, "os_release")
            if not os.path.isfile(release_path):
                release_path = os.path.join(crashdir, "release")

        release = "Unknown Release"
        try:
            with open(release_path, "r") as release_file:
                release = release_file.read(ALLOWED_FILES["os_release"])

            version = distribution = None
            for plugin in self.plugins.all():
                match = plugin.abrtparser.match(release)
                if match:
                    version = match.group(1)
                    distribution = plugin.distribution
                    self.plugin = plugin
                    break

            if not version or not distribution:
                raise Exception("Unknown release '%s'" % release)

        except Exception as ex:
            log_error("Unable to read distribution and version from 'release' file: %s" % ex)
            log_info("Trying to guess distribution and version")
            distribution, version = self.guess_release(crash_package, self.plugins.all())
            if distribution and version:
                log_info("%s-%s" % (distribution, version))
            else:
                log_error("Failure")
                self._fail()

        if "rawhide" in release.lower():
            version = "rawhide"
        return (release, distribution, version)

    def read_packages(self, crashdir, releaseid, crash_package, distribution):
        packages = [crash_package]
        missing = []

        packagesfile = os.path.join(crashdir, "packages")
        if os.path.isfile(packagesfile):
            with open(packagesfile, "r") as f:
                packages = f.read.split()
        else:
            # read required packages from coredump
            try:
                repoid = "%s%s" % (REPO_PREFIX, releaseid)
                dnfcfgpath = os.path.join(self.task.get_savedir(), "dnf.conf")
                with open(dnfcfgpath, "w") as dnfcfg:
                    dnfcfg.write("[%s]\n" % repoid)
                    dnfcfg.write("name=%s\n" % releaseid)
                    dnfcfg.write("baseurl=file://%s/%s/\n" % (CONFIG["RepoDir"], releaseid))
                    dnfcfg.write("failovermethod=priority\n")

                child = run(["coredump2packages", os.path.join(crashdir, "coredump"),
                             "--repos=%s" % repoid, "--config=%s" % dnfcfgpath,
                             "--log=%s" % os.path.join(self.task.get_savedir(), "c2p_log")],
                            stdout=PIPE, stderr=PIPE, encoding='utf-8')
                section = 0
                lines = child.stdout.split("\n")
                libdb = False
                for line in lines:
                    if line == "":
                        section += 1
                        continue
                    elif section == 1:
                        stripped = line.strip()

                        # hack - help to depsolver, yum would fail otherwise
                        # unknow for DNF
                        if distribution == "fedora" and stripped.startswith("gnome"):
                            packages.append("desktop-backgrounds-gnome")

                        # hack - libdb-debuginfo and db4-debuginfo are conflicting
                        if distribution == "fedora" and \
                           (stripped.startswith("db4-debuginfo") or stripped.startswith("libdb-debuginfo")):
                            if libdb:
                                continue
                            else:
                                libdb = True

                        packages.append(stripped)
                    elif section == 2:
                        soname, buildid = line.strip().split(" ", 1)
                        if not soname or soname == "-":
                            soname = None
                        missing.append((soname, buildid))

                if child.stderr:
                    log_warn(child.stderr)

            except Exception as ex:
                log_error("Unable to obtain packages from 'coredump' file: %s" % ex)
                self._fail()
        return (packages, missing)

    def construct_gpg_keys(self, version, pre_rawhide_version=None, scheme="file://"):
        final_result = ""

        for key in self.plugin.gpg_keys:
            final_result += "%s%s " % (scheme, key.format(release=version))

        if pre_rawhide_version and self.plugin.gpg_keys:
            final_result += "%s%s " % (scheme, self.plugin.gpg_keys[0].format(release=pre_rawhide_version))

        return final_result

    def start_retrace(self, custom_arch=None):
        self.hook.run("start")

        task = self.task
        crashdir = os.path.join(task.get_savedir(), "crash")
        corepath = os.path.join(crashdir, "coredump")

        try:
            self.stats["coresize"] = os.path.getsize(corepath)
        except OSError:
            pass

        arch = self.read_architecture(custom_arch, corepath)
        self.stats["arch"] = arch

        crash_package, pkgdata = self.read_package_file(crashdir)
        self.stats["package"] = pkgdata["name"]
        if pkgdata["epoch"] != 0:
            self.stats["version"] = "%s:%s-%s" % (pkgdata["epoch"], pkgdata["version"], pkgdata["release"])
        else:
            self.stats["version"] = "%s-%s" % (pkgdata["version"], pkgdata["release"])

        release, distribution, version = self.read_release_file(crashdir, crash_package)

        releaseid = "%s-%s-%s" % (distribution, version, arch)
        if releaseid not in get_supported_releases():
            log_error("Release '%s' is not supported" % releaseid)
            self._fail()

        if not is_package_known(crash_package, arch, releaseid):
            log_error("Package '%s.%s' was not recognized.\nIs it a part of "
                      "official %s repositories?" % (crash_package, arch, release))
            self._fail()
        self.hook.run("pre_prepare_debuginfo")

        packages, missing = self.read_packages(crashdir, releaseid, crash_package, distribution)

        self.hook.run("post_prepare_debuginfo")
        self.hook.run("pre_prepare_environment")

        repopath = os.path.join(CONFIG["RepoDir"], releaseid)

        if CONFIG["RetraceEnvironment"] == "mock":
        # create mock config file
            try:
                with open(os.path.join(task.get_savedir(), RetraceTask.MOCK_DEFAULT_CFG), "w") as mockcfg:
                    mockcfg.write("config_opts['root'] = '%d'\n" % task.get_taskid())
                    mockcfg.write("config_opts['target_arch'] = '%s'\n" % arch)
                    mockcfg.write("config_opts['chroot_setup_cmd'] = '")
                    mockcfg.write(" install %s abrt-addon-ccpp shadow-utils %s rpm'\n" % (" ".join(packages),
                                                                                          self.plugin.gdb_package))
                    mockcfg.write("config_opts['releasever'] = '%s'\n" % version)
                    mockcfg.write("config_opts['package_manager'] = 'dnf'\n")
                    mockcfg.write("config_opts['plugin_conf']['ccache_enable'] = False\n")
                    mockcfg.write("config_opts['plugin_conf']['yum_cache_enable'] = False\n")
                    mockcfg.write("config_opts['plugin_conf']['root_cache_enable'] = False\n")
                    mockcfg.write("config_opts['plugin_conf']['bind_mount_enable'] = True\n")
                    mockcfg.write("config_opts['plugin_conf']['bind_mount_opts'] = { 'create_dirs': True,\n")
                    mockcfg.write("    'dirs': [\n")
                    mockcfg.write("              ('%s', '%s'),\n" % (repopath, repopath))
                    if CONFIG["RequireGPGCheck"]:
                        mockcfg.write("              ('%s', '%s'),\n" % (RETRACE_GPG_KEYS, RETRACE_GPG_KEYS))
                    mockcfg.write("              ('%s', '/var/spool/abrt/crash'),\n" % crashdir)
                    mockcfg.write("            ] }\n")
                    mockcfg.write("\n")
                    mockcfg.write("config_opts['yum.conf'] = \"\"\"\n")
                    mockcfg.write("[main]\n")
                    mockcfg.write("cachedir=/var/cache/yum\n")
                    mockcfg.write("debuglevel=1\n")
                    mockcfg.write("reposdir=%s\n" % os.devnull)
                    mockcfg.write("logfile=/var/log/yum.log\n")
                    mockcfg.write("retries=20\n")
                    mockcfg.write("obsoletes=1\n")
                    mockcfg.write("gpgcheck=%s\n" % CONFIG["RequireGPGCheck"])
                    mockcfg.write("assumeyes=1\n")
                    mockcfg.write("syslog_ident=mock\n")
                    mockcfg.write("syslog_device=\n")
                    mockcfg.write("\n")
                    mockcfg.write("#repos\n")
                    mockcfg.write("\n")
                    mockcfg.write("[%s]\n" % distribution)
                    mockcfg.write("name=%s\n" % releaseid)
                    mockcfg.write("baseurl=file://%s/\n" % repopath)
                    mockcfg.write("gpgkey=%s\n" % self.construct_gpg_keys(version))
                    mockcfg.write("failovermethod=priority\n")
                    mockcfg.write("\"\"\"\n")

                # symlink defaults from /etc/mock
                os.symlink("/etc/mock/site-defaults.cfg",
                           os.path.join(task.get_savedir(), RetraceTask.MOCK_SITE_DEFAULTS_CFG))
                os.symlink("/etc/mock/logging.ini",
                           os.path.join(task.get_savedir(), RetraceTask.MOCK_LOGGING_INI))
            except Exception as ex:
                log_error("Unable to create mock config file: %s" % ex)
                self._fail()

        # run retrace
        task.set_status(STATUS_INIT)
        log_info(STATUS[STATUS_INIT])

        if CONFIG["RetraceEnvironment"] == "mock":
            self._retrace_run(25, ["/usr/bin/mock", "init", "--resultdir",
                                   task.get_savedir() + "/log", "--configdir",
                                   task.get_savedir()])

            self.hook.run("post_prepare_environment")
            self.hook.run("pre_retrace")

            self._retrace_run(27, ["/usr/bin/mock", "--configdir", task.get_savedir(), "shell",
                                   "--", "chgrp -R mock /var/spool/abrt/crash"])

        # generate backtrace
        task.set_status(STATUS_BACKTRACE)
        log_info(STATUS[STATUS_BACKTRACE])

        if CONFIG["RetraceEnvironment"] == "podman":
            try:
                with open(os.path.join(task.get_savedir(),
                                       "podman_repo.repo"), "w") as podman_repo:
                    podman_repo.write("[podman-%s]\n" % distribution)
                    podman_repo.write("name=podman-%s\n" % releaseid)
                    podman_repo.write("baseurl=file://%s/\n" % repopath)
                    podman_repo.write("gpgcheck=%s" % CONFIG["RequireGPGCheck"])
                    podman_repo.write("gpgkey=%s" % self.construct_gpg_keys(version))
            except Exception as ex:
                log_error("Unable to create podman repo file: %s" % ex)
                self._fail()

            try:
                with open(os.path.join(task.get_savedir(),
                                       RetraceTask.DOCKERFILE), "w") as dockerfile:
                    dockerfile.write('FROM %s:%s\n\n' % (distribution, version))
                    dockerfile.write('RUN useradd -l retrace && \\ \n')
                    dockerfile.write('    mkdir -p /var/spool/abrt/crash\n')
                    dockerfile.write('COPY --chown=retrace gdb.sh /var/spool/abrt/\n')
                    dockerfile.write('COPY --chown=retrace %s /var/spool/abrt/crash/\n'
                                     % RetraceTask.COREDUMP_FILE)
                    dockerfile.write('COPY podman_repo.repo /etc/yum.repos.d/\n')
                    dockerfile.write('RUN ')
                    if CONFIG["RequireGPGCheck"]:
                        dockerfile.write('rpm --import %s && \\ \n' % self.construct_gpg_keys(version, scheme=""))
                    dockerfile.write('dnf --assumeyes --skip-broken --allowerasing --setopt=tsflags=nodocs ')
                    dockerfile.write('--releasever=%s ' % version)
                    dockerfile.write('--repo="podman-%s" ' % distribution)
                    dockerfile.write('install abrt-addon-ccpp %s %s && \\ \n'
                                     % (" \\ \n".join(packages), self.plugin.gdb_package))
                    dockerfile.write('dnf clean all\n\n')
                    dockerfile.write('USER retrace\n')
                    dockerfile.write('ENTRYPOINT ["bash", "/var/spool/abrt/gdb.sh"]')
            except Exception as ex:
                log_error("Unable to create Dockerfile: %s" % ex)
                self._fail()

            self.hook.run("post_prepare_environment")
            self.hook.run("pre_retrace")

        try:
            backtrace, exploitable = run_gdb(task.get_savedir(), self.plugin, repopath, task.get_taskid())
        except Exception as ex:
            log_error(str(ex))
            self._fail()

        task.set_backtrace(backtrace)
        if exploitable is not None:
            task.add_results("exploitable", exploitable, mode="w")

        self.hook.run("post_retrace")

        # does not work at the moment
        rootsize = 0

        if not task.get_type() in [TASK_DEBUG, TASK_RETRACE_INTERACTIVE]:
            # clean up temporary data
            task.set_status(STATUS_CLEANUP)
            log_info(STATUS[STATUS_CLEANUP])

            self.clean_task()

        # save crash statistics
        task.set_status(STATUS_STATS)
        log_info(STATUS[STATUS_STATS])

        task.set_finished_time(int(time.time()))
        self.stats["duration"] = int(time.time()) - self.stats["starttime"]
        self.stats["status"] = STATUS_SUCCESS

        try:
            con = init_crashstats_db()
            statsid = save_crashstats(self.stats, con)
            save_crashstats_success(statsid, self.prerunning, len(get_active_tasks()), rootsize, con)
            save_crashstats_packages(statsid, packages[1:], con)
            if missing:
                save_crashstats_build_ids(statsid, missing, con)
            con.close()
        except Exception as ex:
            log_warn(str(ex))

        # publish log => finish task
        log_info("Retrace took %d seconds" % self.stats["duration"])

        log_info(STATUS[STATUS_SUCCESS])
        task.set_status(STATUS_SUCCESS)

        self.hook.run("success")

        return True

    # de-dup self.task's vmcore with md5_tasks's vmcore
    def dedup_vmcore(self, md5_task):
        task1 = md5_task   # primary
        task2 = self.task  # one we are going to try to hardlink and the one that gets logged to
        v1 = CONFIG["SaveDir"] + "/" + str(task1.get_taskid()) + "/crash/vmcore"
        v2 = CONFIG["SaveDir"] + "/" + str(task2.get_taskid()) + "/crash/vmcore"
        try:
            s1 = os.stat(v1)
            s2 = os.stat(v2)
        except OSError:
            log_warn("Attempt to dedup %s and %s but 'stat' failed on one of the paths" % (v1, v2))
            return 0

        if s1.st_ino == s2.st_ino:
            return 0
        if s1.st_size != s2.st_size:
            log_warn("Attempt to dedup %s and %s but sizes differ - size1 = %d size2 = %d"
                     % (v1, v2, s1.st_size, s2.st_size))
            return 0
        v1_md5 = str.split(task1.get_md5sum())[0]
        v2_md5 = str.split(task2.get_md5sum())[0]
        if len(v1_md5) != 32 or len(v2_md5) != 32:
            return 0
        if v1_md5 != v2_md5:
            log_warn("Attempted to dedup %s and %s but md5sums are different - v1 = %s v2 = %s)"
                     % (v1, v2, v1_md5, v2_md5))
            return 0

        v2_link = v2 + "-link"
        try:
            os.link(v1, v2_link)
        except OSError:
            log_warn("Failed to dedup %s and %s - failed to create hard link from %s to %s" % (v1, v2, v2_link, v1))
            return 0
        try:
            os.unlink(v2)
        except OSError:
            log_warn("Failed to dedup %s and %s - unlink of %s failed" % (v1, v2, v2))
            os.unlink(v2_link)
            return 0
        try:
            os.rename(v2_link, v2)
        except OSError:
            log_error("ERROR: Failed to dedup %s and %s - rename hardlink %s to %s failed" % (v1, v2, v2_link, v2))
            return 0

        log_warn("Successful dedup - created hardlink from %s to %s saving %d MB"
                 % (v2, v1, s1.st_size // 1024 // 1024))

        return s1.st_size

    def start_vmcore(self, custom_kernelver=None):
        self.hook.run("start")

        task = self.task
        vmcore_path = os.path.join(task.get_savedir(), "crash", "vmcore")

        try:
            self.stats["coresize"] = os.path.getsize(vmcore_path)
        except OSError:
            pass

        vmcore = KernelVMcore(vmcore_path)
        oldsize = os.path.getsize(vmcore_path)
        log_info("Vmcore size: %s" % human_readable_size(oldsize))
        if vmcore.is_flattened_format():
            start = time.time()
            log_info("Executing makedumpfile to convert flattened format")
            # NOTE: We do not need to know the kernelver or vmlinux path here
            vmcore.convert_flattened_format()
            dur = int(time.time() - start)
            newsize = os.path.getsize(vmcore_path)
            log_info("Converted size: %s" % human_readable_size(newsize))
            log_info("Makedumpfile took %d seconds and saved %s"
                     % (dur, human_readable_size(oldsize - newsize)))
            oldsize = newsize

        if custom_kernelver is not None:
            kernelver = custom_kernelver
        else:
            kernelver = vmcore.get_kernel_release(task.get_crash_cmd().split())
            if not kernelver:
                raise Exception("Unable to determine kernel version")

            log_debug("Determined kernel version: %s" % kernelver)

        task.set_kernelver(kernelver)
        kernelver_str = kernelver.kernelver_str

        self.stats["package"] = "kernel"
        self.stats["version"] = kernelver_str
        self.stats["arch"] = kernelver.arch

        log_info(STATUS[STATUS_INIT])
        task.set_status(STATUS_INIT)
        vmlinux = ""

        if task.get_mock():
            if CONFIG["RetraceEnvironment"] == "mock":
                self.hook.run("post_prepare_environment")

                # we don't save config into task.get_savedir() because it is only
                # readable by user/group retrace/CONFIG["AuthGroup"].
                # if a non-retrace user in group mock executes
                # setgid /usr/bin/mock, he gets permission denied.
                # this is not a security thing - using mock gives you root anyway
                cfgdir = os.path.join(CONFIG["SaveDir"], "%d-kernel" % task.get_taskid())

                # if the directory exists, it is orphaned - nuke it
                if os.path.isdir(cfgdir):
                    shutil.rmtree(cfgdir)

                mockgid = grp.getgrnam("mock").gr_gid
                old_umask = os.umask(0o027)
                os.mkdir(cfgdir)
                os.chown(cfgdir, -1, mockgid)

                try:
                    cfgfile = os.path.join(cfgdir, RetraceTask.MOCK_DEFAULT_CFG)
                    with open(cfgfile, "w") as mockcfg:
                        mockcfg.write("config_opts['root'] = '%d-kernel'\n" % task.get_taskid())
                        mockcfg.write("config_opts['target_arch'] = '%s'\n" % kernelver.arch)
                        mockcfg.write("config_opts['chroot_setup_cmd'] = 'install bash coreutils cpio "
                                      "crash findutils rpm shadow-utils'\n")
                        mockcfg.write("config_opts['releasever'] = '%s'\n" % kernelver_str)
                        mockcfg.write("config_opts['package_manager'] = 'dnf'\n")
                        mockcfg.write("config_opts['plugin_conf']['ccache_enable'] = False\n")
                        mockcfg.write("config_opts['plugin_conf']['yum_cache_enable'] = False\n")
                        mockcfg.write("config_opts['plugin_conf']['root_cache_enable'] = False\n")
                        mockcfg.write("config_opts['plugin_conf']['bind_mount_enable'] = True\n")
                        mockcfg.write("config_opts['plugin_conf']['bind_mount_opts'] = { \n")
                        mockcfg.write("    'dirs': [('%s', '%s'),\n" % (CONFIG["RepoDir"], CONFIG["RepoDir"]))
                        mockcfg.write("             ('%s', '%s'),],\n" % (task.get_savedir(), task.get_savedir()))
                        mockcfg.write("    'create_dirs': True, }\n")
                        mockcfg.write("\n")
                        mockcfg.write("config_opts['yum.conf'] = \"\"\"\n")
                        mockcfg.write("[main]\n")
                        mockcfg.write("cachedir=/var/cache/yum\n")
                        mockcfg.write("debuglevel=1\n")
                        mockcfg.write("reposdir=%s\n" % os.devnull)
                        mockcfg.write("logfile=/var/log/yum.log\n")
                        mockcfg.write("retries=20\n")
                        mockcfg.write("obsoletes=1\n")
                        mockcfg.write("assumeyes=1\n")
                        mockcfg.write("syslog_ident=mock\n")
                        mockcfg.write("syslog_device=\n")
                        mockcfg.write("\n")
                        mockcfg.write("#repos\n")
                        mockcfg.write("\n")
                        mockcfg.write("[kernel-%s]\n" % kernelver.arch)
                        mockcfg.write("name=kernel-%s\n" % kernelver.arch)
                        mockcfg.write("baseurl=%s\n" % CONFIG["KernelChrootRepo"].replace("$ARCH", kernelver.arch))
                        mockcfg.write("failovermethod=priority\n")
                        mockcfg.write("\"\"\"\n")

                    os.chown(cfgfile, -1, mockgid)

                    # symlink defaults from /etc/mock
                    os.symlink("/etc/mock/site-defaults.cfg",
                               os.path.join(task.get_savedir(), RetraceTask.MOCK_SITE_DEFAULTS_CFG))
                    os.symlink("/etc/mock/logging.ini",
                               os.path.join(task.get_savedir(), RetraceTask.MOCK_LOGGING_INI))
                except Exception as ex:
                    raise Exception("Unable to create mock config file: %s" % ex)
                finally:
                    os.umask(old_umask)

                child = run(["/usr/bin/mock", "--configdir", cfgdir, "init"],
                            stdout=PIPE, stderr=PIPE, encoding='utf-8')
                stderr = child.stderr
                if child.returncode:
                    raise Exception("mock exited with %d:\n%s" % (child.returncode, stderr))

                self.hook.run("post_prepare_environment")

                # no locks required, mock locks itself
                try:
                    self.hook.run("pre_prepare_debuginfo")
                    vmlinux = vmcore.prepare_debuginfo(task, cfgdir, kernelver=kernelver)
                    self.hook.run("post_prepare_debuginfo")
                except Exception as ex:
                    raise Exception("prepare_debuginfo failed: %s" % str(ex))

                self.hook.run("pre_retrace")
                crash_normal = ["/usr/bin/mock", "--configdir", cfgdir, "shell", "--",
                                task.get_crash_cmd() + " -s %s %s" % (vmcore_path, vmlinux)]
                crash_minimal = ["/usr/bin/mock", "--configdir", cfgdir, "shell", "--",
                                 task.get_crash_cmd() + " -s --minimal %s %s" % (vmcore_path, vmlinux)]

            elif CONFIG["RetraceEnvironment"] == "podman":

                savedir = task.get_savedir()
                crashdir = os.path.join(savedir, "crash")
                release, distribution, version = self.read_release_file(crashdir, None)
                try:
                    with open(os.path.join(savedir, RetraceTask.DOCKERFILE), "w") as dockerfile:
                        dockerfile.write('FROM %s:%s\n\n' % (distribution, version))
                        dockerfile.write('RUN mkdir -p /var/spool/abrt/crash\n\n')
                        dockerfile.write('RUN dnf ' \
                                         '--releasever=%s ' \
                                         '--assumeyes ' \
                                         '--skip-broken ' \
                                         'install bash coreutils cpio crash findutils rpm ' \
                                         'shadow-utils && dnf clean all\n' % kernelver_str)
                        dockerfile.write('RUN dnf ' \
                                         '--assumeyes ' \
                                         '--enablerepo=*debuginfo* ' \
                                         'install kernel-debuginfo\n\n')
                        dockerfile.write('COPY %s /var/spool/abrt/crash/\n\n'
                                         % RetraceTask.VMCORE_FILE)
                        dockerfile.write('RUN useradd -m retrace\n')
                        dockerfile.write('RUN chown retrace /var/spool/abrt/%s\n'
                                         % RetraceTask.VMCORE_FILE)
                        dockerfile.write('USER retrace\n\n')
                        dockerfile.write('CMD ["/usr/bin/bash"]')
                except Exception as ex:
                    log_error("Unable to create Dockerfile: %s" % ex)
                    self._fail()

                img_cont_id = str(task.get_taskid())

                child = run(["/usr/bin/podman",
                             "build",
                             "--file",
                             os.path.join(savedir, RetraceTask.DOCKERFILE),
                             "--tag",
                             "retrace-image:%s" % img_cont_id],
                            stdout=DEVNULL, stderr=DEVNULL)
                if child.returncode:
                    raise Exception("Unable to build podman container")

                vmlinux = vmcore.prepare_debuginfo(task, kernelver=kernelver)
                child = run(["/usr/bin/podman", "run", "--detach", "-it", "--rm",
                             "retrace-image:%s" % img_cont_id],
                            stdout=PIPE, stderr=PIPE, encoding='utf-8')
                if child.stderr:
                    log_error(child.stderr)
                    raise Exception("Unable to run podman container")

                crash_normal = ["/usr/bin/podman", "exec", img_cont_id,
                                task.get_crash_cmd()
                                + " -s /var/spool/abrt/crash/vmcore %s" % vmlinux]
                crash_minimal = ["/usr/bin/podman", "exec", img_cont_id,
                                 task.get_crash_cmd()
                                 + " -s --minimal /var/spool/abrt/crash/vmcore %s" % vmlinux]

            else:
                raise Exception("RetraceEnvironment set to invalid value")

        else:
            try:
                self.hook.run("pre_prepare_debuginfo")
                vmlinux = vmcore.prepare_debuginfo(task, kernelver=kernelver)
                self.hook.run("post_prepare_debuginfo")
            except Exception as ex:
                raise Exception("prepare_debuginfo failed: %s" % str(ex))

            self.hook.run("pre_retrace")
            task.set_status(STATUS_BACKTRACE)
            log_info(STATUS[STATUS_BACKTRACE])

            crash_normal = task.get_crash_cmd().split() + ["-s", vmcore_path, vmlinux]
            crash_minimal = task.get_crash_cmd().split() + ["--minimal", "-s", vmcore_path, vmlinux]

        if vmcore.has_extra_pages(task):
            log_info("Executing makedumpfile to strip extra pages")
            start = time.time()
            # NOTE: We need to know the kernelver and vmlinux path here
            vmcore.strip_extra_pages()
            dur = int(time.time() - start)
            newsize = os.path.getsize(vmcore_path)
            log_info("Stripped size: %s" % human_readable_size(newsize))
            log_info("Makedumpfile took %d seconds and saved %s"
                     % (dur, human_readable_size(oldsize - newsize)))

        if os.path.isfile(vmcore_path):
            st = os.stat(vmcore_path)
            if (st.st_mode & stat.S_IRGRP) == 0:
                try:
                    os.chmod(vmcore_path, st.st_mode | stat.S_IRGRP)
                except Exception:
                    log_warn("File '%s' is not group readable and chmod"
                             " failed. The process will continue but if"
                             " it fails this is the likely cause."
                             % vmcore_path)

        # Generate the kernel log and run other crash commands
        kernellog, ret = task.run_crash_cmdline(crash_minimal, "log\nquit\n")

        task.set_backtrace(kernellog, "wb")
        # If crash sys command exited with non-zero status,
        # we likely have a semi-useful vmcore
        crash_sys, ret = task.run_crash_cmdline(crash_normal, "sys\nquit\n")

        if ret == 0 and crash_sys:
            task.add_results("sys", crash_sys)
        else:
            # FIXME: Probably a better hueristic can be done here
            if len(kernellog) < 1024:
                # If log < 1024 bytes, probably it is not useful so fail task
                raise Exception("Failing task due to crash exiting with non-zero status and "
                                "small kernellog size = %d bytes" % len(kernellog))
            # If log is 1024 bytes or above, try 'crash --minimal'
            task.set_crash_cmd("crash --minimal")

        crashrc_lines = []

        if "/" in vmlinux:
            crashrc_lines.append("mod -S %s > %s" % (vmlinux.rsplit("/", 1)[0], os.devnull))

        results_dir = task.get_results_dir()
        crashrc_lines.append("cd %s" % results_dir)

        if crashrc_lines:
            task.set_crashrc("%s\n" % "\n".join(crashrc_lines))

        self.hook.run("post_retrace")

        task.set_finished_time(int(time.time()))
        self.stats["duration"] = int(time.time()) - self.stats["starttime"]
        self.stats["status"] = STATUS_SUCCESS

        log_info(STATUS[STATUS_STATS])

        try:
            save_crashstats(self.stats)
        except Exception as ex:
            log_error(str(ex))

        # clean up temporary data
        task.set_status(STATUS_CLEANUP)
        log_info(STATUS[STATUS_CLEANUP])

        if not task.get_type() in [TASK_VMCORE_INTERACTIVE]:
            self.clean_task()

        log_info("Retrace took %d seconds" % self.stats["duration"])
        log_info(STATUS[STATUS_SUCCESS])

        self._symlink_log()

        task.set_status(STATUS_SUCCESS)
        self.notify_email()
        self.hook.run("success")

    def start(self, kernelver=None, arch=None):
        self.hook.run("pre_start")
        self.stats = {
            "taskid": self.task.get_taskid(),
            "package": None,
            "version": None,
            "arch": None,
            "starttime": int(time.time()),
            "duration": None,
            "coresize": None,
            "status": STATUS_FAIL,
        }
        self.prerunning = len(get_active_tasks()) - 1
        try:
            task = self.task

            task.set_started_time(int(time.time()))

            if task.has_remote():
                errors = task.download_remote(kernelver=kernelver)
                if errors:
                    for error in errors:
                        log_warn(error)

            task.set_status(STATUS_ANALYZE)
            log_info(STATUS[STATUS_ANALYZE])

            crashdir = os.path.join(task.get_savedir(), "crash")

            tasktype = task.get_type()

            if task.has("custom_executable"):
                shutil.copyfile(task._get_file_path("custom_executable"),
                                os.path.join(crashdir, "executable"))
            if task.has("custom_package"):
                shutil.copyfile(task._get_file_path("custom_package"),
                                os.path.join(crashdir, "package"))
            if task.has("custom_os_release"):
                shutil.copyfile(task._get_file_path("custom_os_release"),
                                os.path.join(crashdir, "os_release"))

            for required_file in REQUIRED_FILES[tasktype]:
                if not os.path.isfile(os.path.join(crashdir, required_file)):
                    raise Exception("Crash directory does not contain required file '%s'" % required_file)

            if tasktype in [TASK_RETRACE, TASK_DEBUG, TASK_RETRACE_INTERACTIVE]:
                self.start_retrace(custom_arch=arch)
            elif tasktype in [TASK_VMCORE, TASK_VMCORE_INTERACTIVE]:
                self.start_vmcore(custom_kernelver=kernelver)
            else:
                raise Exception("Unsupported task type")
        except Exception as ex:
            log_error(str(ex))
            self._fail()

    def clean_task(self):
        self.hook.run("pre_clean_task")
        ret = self.task.clean()
        self.hook.run("post_clean_task")
        return ret

    def remove_task(self):
        self.hook.run("pre_remove_task")
        ret = self.task.remove()
        self.hook.run("post_remove_task")
        return ret
