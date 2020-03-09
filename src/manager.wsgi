#!/usr/bin/python3
import os
import datetime
import fnmatch
import re
import time
import urllib
from webob import Request

from retrace.retrace import (STATUS, STATUS_DOWNLOADING, STATUS_FAIL,
                             STATUS_SUCCESS, TASK_DEBUG, TASK_RETRACE, TASK_RETRACE_INTERACTIVE,
                             TASK_VMCORE, TASK_VMCORE_INTERACTIVE,
                             KernelVer,
                             RetraceTask)
from retrace.config import Config
from retrace.util import (free_space,
                          ftp_close,
                          ftp_init,
                          ftp_list_dir,
                          human_readable_size,
                          parse_http_gettext,
                          response)

CONFIG = Config()

FTP_SUPPORTED_EXTENSIONS = [".tar.gz", ".tgz", ".tarz", ".tar.bz2", ".tar.xz",
                            ".tar", ".gz", ".bz2", ".xz", ".Z", ".zip"]


MANAGER_URL_PARSER = re.compile(r"^(.*/manager)(/(([^/]+)(/(__custom__|start|backtrace|savenotes|caseno|"
                                r"bugzillano|notify|delete(/(sure/?)?)?|results/([^/]+)/?)?)?)?)?$")

LONG_TYPES = {TASK_RETRACE: "Coredump retrace",
              TASK_DEBUG: "Coredump retrace - debug",
              TASK_VMCORE: "VMcore retrace",
              TASK_RETRACE_INTERACTIVE: "Coredump retrace - interactive",
              TASK_VMCORE_INTERACTIVE: "VMcore retrace - interactive"}


def is_local_task(taskid):
    try:
        RetraceTask(taskid)
    except:
        return False

    return True

def get_status_for_task_manager(task, _=lambda x: x):
    status = _(STATUS[task.get_status()])
    if task.get_status() == STATUS_DOWNLOADING and task.has(RetraceTask.PROGRESS_FILE):
        status += " %s" % task.get(RetraceTask.PROGRESS_FILE)

    return status

def application(environ, start_response):
    request = Request(environ)

    _ = parse_http_gettext("%s" % request.accept_language,
                           "%s" % request.accept_charset)

    ftpcallback = """
        <script>
        $.ajax({
          type: "GET",
          <URL>
          success: function( returnedData ) {
            $( '#available' ).html( returnedData );
            $( '#ftploading' ).hide();
            $( '#available' ).show();
          }
         });
        </script>
    """

    if not CONFIG["AllowTaskManager"]:
        return response(start_response, "403 Forbidden", _("Task manager was disabled by the server administrator"))

    match = MANAGER_URL_PARSER.match(request.path_url)
    if not match:
        return response(start_response, "404 Not Found")

    filename = match.group(4)
    if filename:
        filename = urllib.parse.unquote(match.group(4))

    space = free_space(CONFIG["SaveDir"])
    if space is None:
        return response(start_response, "500 Internal Server Error", _("Unable to obtain free space"))

    if match.group(6) and match.group(6).startswith("results") and match.group(9):
        try:
            task = RetraceTask(filename)
        except:
            return response(start_response, "404 Not Found", _("There is no such task"))

        if not task.has_results(match.group(9)):
            return response(start_response, "404 Not Found", _("There is no such record"))

        return response(start_response, "200 OK", task.get_results(match.group(9)).decode('utf-8','ignore'))

    elif match.group(6) and match.group(6) == "start":
        # start
        GET = request.GET
        ftptask = False
        try:
            task = RetraceTask(filename)
        except:
            if CONFIG["UseFTPTasks"]:
                ftp = ftp_init()
                files = ftp_list_dir(CONFIG["FTPDir"], ftp)
                if filename not in files:
                    ftp_close(ftp)
                    return response(start_response, "404 Not Found", _("There is no such task"))

                try:
                    size = ftp.size(filename)
                except:
                    size = 0

                ftp_close(ftp)

                if space - size < (CONFIG["MinStorageLeft"] << 20):
                    return response(start_response, "507 Insufficient Storage",
                                    _("There is not enough free space on the server"))

                ftptask = True
            else:
                return response(start_response, "404 Not Found", _("There is no such task"))

        if ftptask:
            try:
                task = RetraceTask()
                task.set_managed(True)
                # ToDo: determine?
                task.set_type(TASK_VMCORE_INTERACTIVE)
                task.add_remote("FTP %s" % filename)
                task.set_url("%s/%d" % (match.group(1), task.get_taskid()))
            except:
                return response(start_response, "500 Internal Server Error", _("Unable to create a new task"))

            if "caseno" in GET:
                try:
                    task.set_caseno(int(GET["caseno"]))
                except:
                    # caseno is invalid number - do nothing, it can be set later
                    pass

            if "bugzillano" in GET:
                try:
                    bugzillano = list(filter(int, set(n.strip() for n in GET["bugzillano"].
                                                      replace(";", ",").split(","))))
                    task.set_bugzillano(bugzillano)
                except Exception:
                    # bugzillano is invalid number - do nothing, it can be set later
                    pass

        if not task.get_managed():
            return response(start_response, "403 Forbidden", _("Task does not belong to task manager"))

        debug = "debug" in GET
        kernelver = None
        arch = None
        if "kernelver" in GET:
            try:
                kernelver = KernelVer(GET["kernelver"])
                if kernelver.arch is None:
                    raise Exception
            except Exception as ex:
                return response(start_response, "403 Forbidden",
                                _("Please use VRA format for kernel version (e.g. 2.6.32-287.el6.x86_64)"))

            arch = kernelver.arch
            kernelver = str(kernelver)

        if "notify" in GET:
            task.set_notify([email for email in set(n.strip() for n in GET["notify"].
                                                    replace(";", ",").split(",")) if email])

        if "md5sum" in GET:
            task.set_md5sum("Enabled")

        task.start(debug=debug, kernelver=kernelver, arch=arch)

        # ugly, ugly, ugly! retrace-server-worker double-forks and needs a while to spawn
        time.sleep(2)

        return response(start_response, "303 See Other", "",
                        [("Location", "%s/%d" % (match.group(1), task.get_taskid()))])

    elif match.group(6) and match.group(6) == "savenotes":
        POST = request.POST
        try:
            task = RetraceTask(filename)
        except:
            return response(start_response, "404 Not Found", _("There is no such task"))

        if "notes" in POST and len(POST["notes"]) > 0:
            task.set_notes(POST["notes"])

        return response(start_response, "302 Found", "", [("Location", "%s/%d" % (match.group(1), task.get_taskid()))])

    elif match.group(6) and match.group(6) == "notify":
        POST = request.POST
        try:
            task = RetraceTask(filename)
        except:
            return response(start_response, "404 Not Found", _("There is no such task"))

        if "notify" in POST and len(POST["notify"]) > 0:
            task.set_notify([email for email in set(n.strip() for n in POST["notify"]
                                                    .replace(";", ",").split(",")) if email])

        return response(start_response, "302 Found", "", [("Location", "%s/%d" % (match.group(1), task.get_taskid()))])

    elif match.group(6) and match.group(6) == "caseno":
        POST = request.POST
        try:
            task = RetraceTask(filename)
        except:
            return response(start_response, "404 Not Found", _("There is no such task"))

        if "caseno" in POST and len(POST["caseno"]) > 0:
            if not POST["caseno"]:
                task.delete(RetraceTask.CASENO_FILE)
            else:
                try:
                    caseno = int(POST["caseno"])
                except Exception as ex:
                    return response(start_response, "404 Not Found", _("Case number must be an integer; %s" % ex))

                task.set_caseno(caseno)

        return response(start_response, "302 Found", "", [("Location", "%s/%d" % (match.group(1), task.get_taskid()))])

    elif match.group(6) and match.group(6) == "bugzillano":
        POST = request.POST
        try:
            task = RetraceTask(filename)
        except Exception:
            return response(start_response, "404 Not Found", _("There is no such task"))

        if "bugzillano" in POST and len(POST["bugzillano"]) > 0:
            if not POST["bugzillano"]:
                task.delete(RetraceTask.BUGZILLANO_FILE)
            else:
                try:
                    bugzillano = list(filter(int, set(n.strip() for n in POST["bugzillano"]
                                                      .replace(";", ",").split(","))))
                except ValueError as ex:
                    return response(start_response, "404 Not Found", _("Bugzilla numbers must be integers; %s" % ex))

                task.set_bugzillano(bugzillano)

        return response(start_response, "302 Found", "", [("Location", "%s/%d" % (match.group(1), task.get_taskid()))])

    elif match.group(6) and match.group(6) == "backtrace":
        try:
            task = RetraceTask(filename)
        except:
            return response(start_response, "404 Not Found", _("There is no such task"))

        if not task.get_managed():
            return response(start_response, "403 Forbidden", _("Task does not belong to task manager"))

        if not task.has_backtrace():
            return response(start_response, "404 Forbidden", _("There is no backtrace for the specified task"))

        return response(start_response, "200 OK", task.get_backtrace())

    elif match.group(6) and match.group(6).startswith("delete") and \
         match.group(8) and match.group(8).startswith("sure"):
        try:
            task = RetraceTask(filename)
        except:
            return response(start_response, "404 Not Found", _("There is no such task"))

        if not task.get_managed():
            return response(start_response, "403 Forbidden", _("Task does not belong to task manager"))

        if CONFIG["TaskManagerAuthDelete"]:
            return response(start_response, "403 Forbidden", _("Authorization required to delete tasks"))

        task.remove()

        return response(start_response, "302 Found", "", [("Location", match.group(1))])
    elif filename and filename == "__custom__":
        POST = request.POST

        qs_base = []
        if "md5sum" in POST and POST["md5sum"] == "on":
            qs_base.append("md5sum=md5sum")

        if "debug" in POST and POST["debug"] == "on":
            qs_base.append("debug=debug")

        if "vra" in POST:
            vra = POST["vra"]

            if len(vra.strip()) > 0:
                try:
                    kver = KernelVer(vra)
                    if kver.arch is None:
                        raise Exception
                except:
                    return response(start_response, "403 Forbidden",
                                    _("Please use VRA format for kernel version (e.g. 2.6.32-287.el6.x86_64)"))

                qs_base.append("kernelver=%s" % urllib.parse.quote(vra))

        try:
            task = RetraceTask()
        except Exception as ex:
            return response(start_response, "500 Internal Server Error", _("Unable to create a new task"))

        if "task_type" in POST and POST["task_type"] == "coredump":
            task.set_type(TASK_RETRACE_INTERACTIVE)
            if "package" in POST and POST["package"]:
                task.set("custom_package", POST["package"])
            if "executable" in POST and POST["executable"]:
                task.set("custom_executable", POST["executable"])
            if "os_release" in POST and POST["os_release"]:
                task.set("custom_os_release", POST["os_release"])
        else:
            task.set_type(TASK_VMCORE_INTERACTIVE)
        task.add_remote(POST["custom_url"])
        task.set_managed(True)
        task.set_url("%s/%d" % (match.group(1), task.get_taskid()))

        starturl = "%s/%d/start" % (match.group(1), task.get_taskid())
        if len(qs_base) > 0:
            starturl = "%s?%s" % (starturl, "&".join(qs_base))

        return response(start_response, "302 Found", "", [("Location", starturl)])

    elif filename:
        # info
        ftptask = False
        filesize = None
        try:
            task = RetraceTask(filename)
        except:
            if CONFIG["UseFTPTasks"]:
                ftp = ftp_init()
                files = ftp_list_dir(CONFIG["FTPDir"], ftp)
                if filename not in files:
                    ftp_close(ftp)
                    return response(start_response, "404 Not Found", _("There is no such task"))

                ftptask = True
                try:
                    filesize = ftp.size(filename)
                except:
                    pass
                ftp_close(ftp)
            else:
                return response(start_response, "404 Not Found", _("There is no such task"))

        with open("/usr/share/retrace-server/managertask.xhtml", "r") as f:
            output = f.read(1 << 20) # 1MB

        start = ""
        if not ftptask and task.has_status():
            status = get_status_for_task_manager(task, _=_)
        else:
            md5sum_enabled = ""
            if CONFIG["CalculateMd5"]:
                md5sum_enabled = "checked=\"checked\""

            startcontent = "    <form method=\"get\" action=\"%s/start\">" \
                           "      Kernel version (empty to autodetect): <input name=\"kernelver\" " \
                           "type=\"text\" id=\"kernelver\" /> e.g. <code>2.6.32-287.el6.x86_64</code><br />" \
                           "      Case no.: <input name=\"caseno\" type=\"text\" id=\"caseno\" /><br />" \
                           "      Bugzilla no.: <input name=\"bugzillano\" type=\"text\" id=\"bugzillano\" /><br />" \
                           "      E-mail notification: <input name=\"notify\" type=\"text\" id=\"notify\" /><br />" \
                           "      <input type=\"checkbox\" name=\"debug\" id=\"debug\" checked=\"checked\" />" \
                           "Be more verbose in case of error<br />" \
                           "      <input type=\"checkbox\" name=\"md5sum\" id=\"md5sum\" %s />" \
                           "Calculate md5 checksum for all downloaded resources<br />" \
                           "      <input type=\"submit\" value=\"%s\" id=\"start\" class=\"button\" />" \
                           "    </form>" % (request.path_url.rstrip("/"), md5sum_enabled, _("Start task"))

            if ftptask:
                status = _("On remote FTP server")
                if filesize:
                    status += " (%s)" % human_readable_size(filesize)

                if space - filesize < (CONFIG["MinStorageLeft"] << 20):
                    startcontent = _("You can not start the task because there is not enough free space on the server")
            else:
                status = _("Not started")

            start = "<tr>" \
                    "  <td colspan=\"2\">" \
                    "%s" \
                    "  </td>" \
                    "</tr>" % startcontent

        interactive = ""
        backtrace = ""
        backtracewindow = ""
        if not ftptask:
            if task.has_backtrace():
                backtrace = "<tr><td colspan=\"2\"><a href=\"%s/backtrace\">%s</a></td></tr>" \
                            % (request.path_url.rstrip("/"), _("Show raw backtrace"))
                backtracewindow = "<h2>Backtrace</h2><textarea class=\"backtrace\">%s</textarea>" % task.get_backtrace()
                if task.get_type() in [TASK_RETRACE_INTERACTIVE, TASK_VMCORE_INTERACTIVE]:
                    if task.get_type() == TASK_VMCORE_INTERACTIVE:
                        debugger = "crash"
                    else:
                        debugger = "gdb"

                    interactive = "<tr><td colspan=\"2\">%s</td></tr>" \
                                  "<tr><td colspan=\"2\">%s <code>retrace-server-interact %s shell</code></td></tr>" \
                                  "<tr><td colspan=\"2\">%s <code>retrace-server-interact %s %s</code></td></tr>" \
                                  "<tr><td colspan=\"2\">%s <code>man retrace-server-interact</code> %s</td></tr>" \
                                  % (_("This is an interactive task"), _("You can jump to the chrooted shell with:"),
                                     filename, _("You can jump directly to the debugger with:"), filename, debugger,
                                     _("see"), _("for further information about cmdline flags"))
            elif task.has_log():
                backtracewindow = "<h2>Log:</h2><textarea class=\"backtrace\">%s</textarea>" % task.get_log()

        if ftptask or task.is_running(readproc=True) or CONFIG["TaskManagerAuthDelete"]:
            delete = ""
        else:
            delete = "<tr><td colspan=\"2\"><a href=\"%s/delete\">%s</a></td></tr>" \
                     % (request.path_url.rstrip("/"), _("Delete task"))

        if ftptask:
            # ToDo: determine?
            tasktype = _(LONG_TYPES[TASK_VMCORE_INTERACTIVE])
            title = "%s '%s' - %s" % (_("Remote file"), filename, _("Retrace Server Task Manager"))
            taskno = "%s '%s'" % (_("Remote file"), filename)
        else:
            tasktype = _(LONG_TYPES[task.get_type()])
            title = "%s #%s - %s" % (_("Task"), filename, _("Retrace Server Task Manager"))
            taskno = "%s #%s" % (_("Task"), filename)

        results = ""
        if not ftptask:
            results_list = sorted(task.get_results_list())
            if results_list:
                links = []
                for name in results_list:
                    links.append("<a href=\"%s/results/%s\">%s</a>" % (request.path_url.rstrip("/"), name, name))
                results = "<tr><th>%s</th><td>%s</td></tr>" % (_("Additional results:"), ", ".join(links))

        if match.group(6) and match.group(6).startswith("delete") and not CONFIG["TaskManagerAuthDelete"]:
            delete_yesno = "<tr><td colspan=\"2\">%s <a href=\"%s/sure\">Yes</a> - <a href=\"%s/%s\">No</a></td></tr>" \
                           % (_("Are you sure you want to delete the task?"), request.path_url.rstrip("/"),
                              match.group(1), filename)
        else:
            delete_yesno = ""

        unknownext = ""
        if ftptask:
            known = any(filename.endswith(ext) for ext in FTP_SUPPORTED_EXTENSIONS)
            if not known:
                unknownext = "<tr><td colspan=\"2\">%s %s</td></tr>" % \
                             (_("The file extension was not recognized, thus the file will be "
                                "considered a raw vmcore. Known extensions are:"),
                              ", ".join(FTP_SUPPORTED_EXTENSIONS))

        downloaded = ""
        if not ftptask and task.has_downloaded():
            downloaded = "<tr><th>Downloaded resources:</th><td>%s</td></tr>" % task.get_downloaded()

        starttime_str = ""
        if not ftptask:
            if task.has_started_time():
                starttime = task.get_started_time()
            else:
                starttime = task.get_default_started_time()

            starttime_str = "<tr><th>Started:</th><td>%s</td></tr>" % datetime.datetime.fromtimestamp(starttime)

        md5sum = ""
        if not ftptask and task.has_md5sum():
            md5sum = "<tr><th>Md5sum:</th><td>%s</td></tr>" % task.get_md5sum()

        finishtime_str = ""
        if not ftptask:
            if task.has_finished_time():
                finishtime = task.get_finished_time()
            else:
                finishtime = task.get_default_finished_time()


            finishtime_str = "<tr><th>Finished:</th><td>%s</td></tr>" % datetime.datetime.fromtimestamp(finishtime)

        caseno = ""
        if not ftptask:
            currentcaseno = ""
            if task.has_caseno():
                currentcaseno = "value=\"%d\" " % task.get_caseno()

            caseno = "<tr>" \
                     "  <th>Case no.:</th>" \
                     "  <td>" \
                     "    <form method=\"post\" action=\"%s/caseno\">" \
                     "      <input type=\"text\" name=\"caseno\" %s/>" \
                     "      <input type=\"submit\" value=\"Update case no.\" class=\"button\" />" \
                     "    </form>" \
                     "  </td>" \
                     "</tr>" % (request.path_url.rstrip("/"), currentcaseno)

        bugzillano = ""
        if not ftptask:
            currentbugzillano = ""
            if task.has_bugzillano():
                currentbugzillano = "value=\"%s\"" % ", ".join(task.get_bugzillano())

            bugzillano = "<tr>" \
                     "  <th>Bugzilla no.:</th>" \
                     "  <td>" \
                     "    <form method=\"post\" action=\"%s/bugzillano\">" \
                     "      <input type=\"text\" name=\"bugzillano\" %s/>" \
                     "      <input type=\"submit\" value=\"Update bugzilla no.\" class=\"button\" />" \
                     "    </form>" \
                     "  </td>" \
                     "</tr>" % (request.path_url.rstrip("/"), currentbugzillano)

        back = "<tr><td colspan=\"2\"><a href=\"%s\">%s</a></td></tr>" % (match.group(1), _("Back to task manager"))

        notes = ""
        if not ftptask:
            notes_quoted = ""
            if task.has_notes():
                notes_quoted = task.get_notes().replace("<", "&lt;") \
                                               .replace(">", "&gt;") \
                                               .replace("\"", "&quot;") \
                                               .replace("'", "&apos;")

            notes = "<form method=\"post\" action=\"%s/savenotes\" class=\"notes\">" \
                    "  <h2>Notes</h2>" \
                    "  <textarea class=\"notes\" name=\"notes\">%s</textarea>" \
                    "  <input type=\"submit\" value=\"Update notes\" class=\"button\" />" \
                    "</form>" % (request.path_url.rstrip("/"), notes_quoted)

        notify = ""
        if not ftptask:
            currentnotify = ""
            if task.has_notify():
                currentnotify = "value=\"%s\"" % ", ".join(task.get_notify())

            notify = "<tr>" \
                     "  <th>E-mail notification:</th>" \
                     "  <td>" \
                     "    <form method=\"post\" action=\"%s/notify\">" \
                     "      <input type=\"text\" name=\"notify\" %s/>" \
                     "      <input type=\"submit\" value=\"Update e-mail(s)\" class=\"button\" />" \
                     "    </form>" \
                     "  </td>" \
                     "</tr>" % (request.path_url.rstrip("/"), currentnotify)

        output = output.replace("{title}", title)
        output = output.replace("{taskno}", taskno)
        output = output.replace("{str_type}", _("Type:"))
        output = output.replace("{type}", tasktype)
        output = output.replace("{str_status}", _("Status:"))
        output = output.replace("{status}", status)
        output = output.replace("{start}", start)
        output = output.replace("{back}", back)
        output = output.replace("{backtrace}", backtrace)
        output = output.replace("{backtracewindow}", backtracewindow)
        output = output.replace("{caseno}", caseno)
        output = output.replace("{bugzillano}", bugzillano)
        output = output.replace("{notify}", notify)
        output = output.replace("{delete}", delete)
        output = output.replace("{delete_yesno}", delete_yesno)
        output = output.replace("{interactive}", interactive)
        output = output.replace("{results}", results)
        output = output.replace("{notes}", notes)
        output = output.replace("{md5sum}", md5sum)
        output = output.replace("{unknownext}", unknownext)
        output = output.replace("{downloaded}", downloaded)
        output = output.replace("{starttime}", starttime_str)
        output = output.replace("{finishtime}", finishtime_str)
        return response(start_response, "200 OK", output, [("Content-Type", "text/html")])

    # menu
    with open("/usr/share/retrace-server/manager.xhtml") as f:
        output = f.read(1 << 20) # 1MB

    title = _("Retrace Server Task Manager")
    sitename = _("Retrace Server Task Manager")

    baseurl = request.path_url
    if not baseurl.endswith("/"):
        baseurl += "/"

    try:
        filterexp = request.GET.getone("filter")
    except:
        filterexp = None

    available = []
    running = []
    finished = []
    for taskid in sorted(os.listdir(CONFIG["SaveDir"])):
        if not os.path.isdir(os.path.join(CONFIG["SaveDir"], taskid)):
            continue

        try:
            task = RetraceTask(taskid)
        except:
            continue

        if not task.get_managed():
            continue

        if task.has_status():
            statuscode = task.get_status()
            if statuscode in [STATUS_SUCCESS, STATUS_FAIL]:
                status = ""
                if statuscode == STATUS_SUCCESS:
                    status = " class=\"success\""
                elif statuscode == STATUS_FAIL:
                    status = " class=\"fail\""

                finishtime = task.get_default_finished_time()
                if task.has_finished_time():
                    finishtime = task.get_finished_time()

                finishtime_str = datetime.datetime.fromtimestamp(finishtime)

                caseno = ""
                if task.has_caseno():
                    caseno = str(task.get_caseno())

                    url = CONFIG["CaseNumberURL"].strip()
                    if len(url) > 0:
                        try:
                            link = url % task.get_caseno()
                            caseno = "<a href=\"%s\">%d</a>" % (link, task.get_caseno())
                        except:
                            pass

                bugzillano = ""
                if task.has_bugzillano():
                    bugzillano = min(task.get_bugzillano(), key=int)

                    bzurl = CONFIG["BugzillaURL"].strip()
                    if bzurl:
                        bugzillano = "<a href={0}/{1}>{1}</a>".format(bzurl, bugzillano)

                files = ""
                if task.has_downloaded():
                    files = task.get_downloaded()

                row = "<tr%s>" \
                      "  <td class=\"taskid\">" \
                      "    <a href=\"%s%s\">%s</a>" \
                      "  </td>" \
                      "  <td>%s</td>" \
                      "  <td>%s</td>" \
                      "  <td>%s</td>" \
                      "  <td>%s</td>" \
                      "</tr>" % (status, baseurl, taskid, taskid, caseno, bugzillano, files,
                                 finishtime_str)

                if filterexp and not fnmatch.fnmatch(row, filterexp):
                    continue

                finished.append((finishtime_str, row))
            else:
                status = get_status_for_task_manager(task, _=_)

                starttime = task.get_default_started_time()
                if task.has_started_time():
                    starttime = task.get_started_time()

                starttime_str = datetime.datetime.fromtimestamp(starttime)

                caseno = ""
                if task.has_caseno():
                    caseno = str(task.get_caseno())

                    url = CONFIG["CaseNumberURL"].strip()
                    if len(url) > 0:
                        try:
                            link = url % task.get_caseno()
                            caseno = "<a href=\"%s\">%d</a>" % (link, task.get_caseno())
                        except:
                            pass

                bugzillano = ""
                if task.has_bugzillano():
                    bugzillano = min(task.get_bugzillano(), key=int)

                    bzurl = CONFIG["BugzillaURL"].strip()
                    if bzurl:
                        bugzillano = "<a href={0}/{1}>{1}</a>".format(bzurl, bugzillano)

                files = ""
                if task.has_remote():
                    remote = [x[4:] if x.startswith("FTP ") else x for x in task.get_remote()]
                    files = ", ".join(remote)

                if task.has_downloaded():
                    files = ", ".join(filter(None, [task.get_downloaded(), files]))

                row = "<tr>" \
                      "  <td class=\"taskid\">" \
                      "    <a href=\"%s%s\">%s</a>" \
                      "  </td>" \
                      "  <td>%s</td>" \
                      "  <td>%s</td>" \
                      "  <td>%s</td>" \
                      "  <td>%s</td>" \
                      "  <td>%s</td>" \
                      "</tr>" % (baseurl, taskid, taskid, caseno, bugzillano, files, starttime_str,
                                 status)

                if filterexp and not fnmatch.fnmatch(row, filterexp):
                    continue

                running.append((starttime_str, row))
        else:
            row = "<tr>" \
                  "  <td>" \
                  "    <a href=\"%s%s\">%s</a>" \
                  "  </td>" \
                  "</tr>" % (baseurl, taskid, taskid)

            if filterexp and not fnmatch.fnmatch(row, filterexp):
                continue

            available.append(row)

    finished = [f[1] for f in sorted(finished, key=lambda x: x[0], reverse=True)]
    running = [r[1] for r in sorted(running, key=lambda x: x[0], reverse=True)]

    available_str = _("Available tasks")
    running_str = _("Running tasks")
    finished_str = _("Finished tasks")
    taskid_str = _("Task ID")
    caseno_str = _("Case no.")
    bugzillano_str = _("Bugzilla no.")
    files_str = _("File(s)")
    starttime_str = _("Started")
    finishtime_str = _("Finished")
    status_str = _("Status")

    md5_enabled = ""
    if CONFIG["CalculateMd5"]:
        md5_enabled = 'checked="checked"'

    if CONFIG["UseFTPTasks"]:
        starturl = "ftp"
        qs = {}
        if filterexp:
            qs["filterexp"] = filterexp

        qs_text = urllib.parse.urlencode(qs)

        if qs_text:
            starturl = "\"%s?%s\"" % (starturl, qs_text)
        else:
            starturl = "\"" + starturl + "\""

        ftpcallback = ftpcallback.replace("<URL>", "url: %s," %(starturl))
        output = output.replace("{ftpscript}", ftpcallback)
    else:
        output = output.replace("{ftpscript}", "")
        available_str = _("FTP files")

    custom_url = "%s/__custom__" % match.group(1)

    vmcore_form = ""
    if CONFIG["AllowVMCoreTask"]:
        with open("/usr/share/retrace-server/manager_vmcore_task_form.xhtml") as f:
            vmcore_form = f.read(1 << 20) # 1MB
    output = output.replace("{vmcore_task_form}", vmcore_form)

    usrcore_form = ""
    if CONFIG["AllowUsrCoreTask"]:
        with open("/usr/share/retrace-server/manager_usrcore_task_form.xhtml") as f:
            usrcore_form = f.read(1 << 20) # 1MB
    output = output.replace("{usrcore_task_form}", usrcore_form)

    output = output.replace("{title}", title)
    output = output.replace("{sitename}", sitename)
    output = output.replace("{available_str}", available_str)
    output = output.replace("{running_str}", running_str)
    output = output.replace("{finished_str}", finished_str)
    output = output.replace("{taskid_str}", taskid_str)
    output = output.replace("{caseno_str}", caseno_str)
    output = output.replace("{bugzillano_str}", bugzillano_str)
    output = output.replace("{files_str}", files_str)
    output = output.replace("{starttime_str}", starttime_str)
    output = output.replace("{finishtime_str}", finishtime_str)
    output = output.replace("{status_str}", status_str)
    output = output.replace("{create_custom_url}", custom_url)
    # spaces to keep the XML nicely aligned
    output = output.replace("{running}", "\n            ".join(running))
    output = output.replace("{finished}", "\n            ".join(finished))
    output = output.replace("{md5_enabled}", md5_enabled)


    return response(start_response, "200 OK", output, [("Content-Type", "text/html")])
