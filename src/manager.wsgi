#!/usr/bin/python
import datetime
import fnmatch
import re
import urllib
import urlparse
from retrace import *

MANAGER_URL_PARSER = re.compile("^(.*/manager)(/(([^/]+)(/(start|backtrace|savenotes|caseno|delete(/(sure/?)?)?|misc/([^/]+)/?)?)?)?)?$")

LONG_TYPES = { TASK_RETRACE: "Coredump retrace",
               TASK_DEBUG: "Coredump retrace - debug",
               TASK_VMCORE: "VMcore retrace",
               TASK_RETRACE_INTERACTIVE: "Coredump retrace - interactive",
               TASK_VMCORE_INTERACTIVE: "VMcore retrace - interactive" }

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

    if not CONFIG["AllowTaskManager"]:
        return response(start_response, "403 Forbidden", _("Task manager was disabled by the server administrator"))

    match = MANAGER_URL_PARSER.match(request.path_url)
    if not match:
        return response(start_response, "404 Not Found")

    filename = match.group(4)
    if filename:
        filename = urllib.unquote(match.group(4))

    space = free_space(CONFIG["SaveDir"])
    if space is None:
        return response(start_response, "500 Internal Server Error", _("Unable to obtain free space"))

    if match.group(6) and match.group(6).startswith("misc") and match.group(9):
        try:
            task = RetraceTask(filename)
        except:
            return response(start_response, "404 Not Found", _("There is no such task"))

        if not task.has_misc(match.group(9)):
            return response(start_response, "404 Not Found", _("There is no such record"))

        return response(start_response, "200 OK", task.get_misc(match.group(9)))
    elif match.group(6) and match.group(6) == "start":
        # start
        get = urlparse.parse_qs(request.query_string)
        ftptask = False
        try:
            task = RetraceTask(filename)
        except:
            if CONFIG["UseFTPTasks"]:
                ftp = ftp_init()
                files = ftp_list_dir(CONFIG["FTPDir"], ftp)
                if not filename in files:
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
            except:
                return response(start_response, "500 Internal Server Error", _("Unable to create a new task"))

        if not task.get_managed():
            return response(start_response, "403 Forbidden", _("Task does not belong to task manager"))

        cmdline = ["/usr/bin/retrace-server-worker", str(task.get_taskid())]
        if "debug" in get:
            cmdline.append("-v")

        if "kernelver" in get:
            kmatch = KERNEL_RELEASE_PARSER.match(get["kernelver"][0])
            if not kmatch or not kmatch.group(4):
                return response(start_response, "403 Forbidden", _("Please use VRA format for kernel version (eg. 2.6.32-287.el6.x86_64)"))

            cmdline.append("--kernelver")
            cmdline.append(kmatch.group(1))
            cmdline.append("--arch")
            cmdline.append(kmatch.group(4))

        call(cmdline)

        # ugly, ugly, ugly! retrace-server-worker double-forks and needs a while to spawn
        time.sleep(2)

        return response(start_response, "303 See Other", "", [("Location", "%s/%d" % (match.group(1), task.get_taskid()))])
    elif match.group(6) and match.group(6) == "savenotes":
        POST = urlparse.parse_qs(request.body, keep_blank_values=1)
        try:
            task = RetraceTask(filename)
        except:
            return response(start_response, "404 Not Found", _("There is no such task"))

        if "notes" in POST and len(POST["notes"]) > 0:
            task.set_notes(POST["notes"][0])

        return response(start_response, "302 Found", "", [("Location", "%s/%d" % (match.group(1), task.get_taskid()))])
    elif match.group(6) and match.group(6) == "caseno":
        POST = urlparse.parse_qs(request.body, keep_blank_values=1)
        try:
            task = RetraceTask(filename)
        except:
            return response(start_response, "404 Not Found", _("There is no such task"))

        if "caseno" in POST and len(POST["caseno"]) > 0:
            if not POST["caseno"][0]:
                task.delete(RetraceTask.CASENO_FILE)
            else:
                try:
                    caseno = int(POST["caseno"][0])
                except Exception as ex:
                    return response(start_response, "404 Not Found", _("Case number must be an integer; %s" % ex))

                task.set_caseno(caseno)

        return response(start_response, "302 Found", "", [("Location", "%s/%d" % (match.group(1), task.get_taskid()))])
    elif match.group(6) and match.group(6) == "backtrace":
        try:
            task = RetraceTask(filename)
        except:
            return response(start_response, "404 Not Found", _("There is no such task"))

        if not task.get_managed():
            return response(start_response, "403 Forbidden", _("Task does not belong to task manager"))

        if not task.has_backtrace():
            return response(start_response, "404 Forbidden", _("Task does not have a backtrace"))

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
                if not filename in files:
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
            startcontent = "    <form method=\"get\" action=\"%s/start\">" \
                           "      Kernel VRA (empty to autodetect): <input name=\"kernelver\" type=\"text\" id=\"kernelver\" /><br />" \
                           "      <input type=\"checkbox\" name=\"debug\" id=\"debug\" />Be more verbose in case of error<br />" \
                           "      <input type=\"submit\" value=\"%s\" id=\"start\" class=\"button\" />" \
                           "    </form>" % (request.path_url.rstrip("/"), _("Start task"))

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
                backtrace = "<tr><td colspan=\"2\"><a href=\"%s/backtrace\">%s</a></td></tr>" % (request.path_url.rstrip("/"), _("Show raw backtrace"))
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
                              % (_("This is an interactive task"), _("You can jump to the chrooted shell with:"), filename,
                                 _("You can jump directly to the debugger with:"), filename, debugger,
                                 _("see"), _("for further information about cmdline flags"))
            elif task.has_log():
                backtracewindow = "<h2>Log:</h2><textarea class=\"backtrace\">%s</textarea>" % task.get_log()

        if ftptask or task.is_running(readproc=True) or CONFIG["TaskManagerAuthDelete"]:
            delete = ""
        else:
            delete = "<tr><td colspan=\"2\"><a href=\"%s/delete\">%s</a></td></tr>" % (request.path_url.rstrip("/"), _("Delete task"))

        if ftptask:
            # ToDo: determine?
            tasktype = _(LONG_TYPES[TASK_VMCORE_INTERACTIVE])
            title = "%s '%s' - %s" % (_("Remote file"), filename, _("Retrace Server Task Manager"))
            taskno = "%s '%s'" % (_("Remote file"), filename)
        else:
            tasktype = _(LONG_TYPES[task.get_type()])
            title = "%s #%s - %s" % (_("Task"), filename, _("Retrace Server Task Manager"))
            taskno = "%s #%s" % (_("Task"), filename)

        misc = ""
        if not ftptask:
            misclist = sorted(task.get_misc_list())
            if misclist:
                links = []
                for name in misclist:
                    links.append("<a href=\"%s/misc/%s\">%s</a>" % (request.path_url.rstrip("/"), name, name))
                misc = "<tr><th>%s</th><td>%s</td></tr>" % (_("Additional results:"), ", ".join(links))

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

        starttime = ""
        if not ftptask and task.has_started_time():
            starttime = "<tr><th>Started:</th><td>%s</td></tr>" % datetime.datetime.fromtimestamp(task.get_started_time())

        finishtime = ""
        if not ftptask and task.has_finished_time():
            finishtime = "<tr><th>Finished:</th><td>%s</td></tr>" % datetime.datetime.fromtimestamp(task.get_finished_time())

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
        output = output.replace("{delete}", delete)
        output = output.replace("{delete_yesno}", delete_yesno)
        output = output.replace("{interactive}", interactive)
        output = output.replace("{misc}", misc)
        output = output.replace("{notes}", notes)
        output = output.replace("{unknownext}", unknownext)
        output = output.replace("{downloaded}", downloaded)
        output = output.replace("{starttime}", starttime)
        output = output.replace("{finishtime}", finishtime)
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

        if task.get_managed():
            if task.has_status():
                status = get_status_for_task_manager(task, _=_)
            else:
                status = ""

            if task.has_downloaded():
                downloaded = task.get_downloaded()
            else:
                downloaded = ""

            if task.has_remote() and task.get_remote():
                remotes = []
                for remote in task.get_remote():
                    if remote.startswith("FTP "):
                        remotes.append(remote[4:])
                    else:
                        remotes.append(remote)

                downloaded = "%s %s" % (", ".join(remotes), downloaded)

            row = "<tr><td class=\"taskid\"><a href=\"%s%s\">%s</a></td><td>%s</td><td class=\"status\">%s</td></tr>" \
                  % (baseurl, taskid, taskid, downloaded, status)

            if filterexp and not fnmatch.fnmatch(row, filterexp):
                continue

            if not task.has_status():
                available.append(row)
                continue

            if task.get_status() == STATUS_SUCCESS:
                finished.append(row.replace("<tr>", "<tr class=\"success\">"))
                continue

            if task.get_status() == STATUS_FAIL:
                finished.append(row.replace("<tr>", "<tr class=\"fail\">"))
                continue

            running.append(row)

    available_str = _("Available tasks")
    running_str = _("Running tasks")
    finished_str = _("Finished tasks")

    if CONFIG["UseFTPTasks"]:
        available = []
        rawtasklist = ftp_list_dir(CONFIG["FTPDir"])
        if filterexp:
            tasklist = sorted(fnmatch.filter(rawtasklist, filterexp))
        else:
            tasklist = sorted(rawtasklist, cmp=cmp_vmcores_first)

        for fname in tasklist:
            available.append("<tr><td><a href=\"%s/%s\">%s</a></td></tr>" \
                             % (match.group(1), urllib.quote_plus(fname), fname))
        available_str = _("FTP files")

    output = output.replace("{title}", title)
    output = output.replace("{sitename}", sitename)
    output = output.replace("{available_str}", available_str)
    output = output.replace("{running_str}", running_str)
    output = output.replace("{finished_str}", finished_str)
    # spaces to keep the XML nicely aligned
    output = output.replace("{available}", "\n        ".join(available))
    output = output.replace("{running}", "\n        ".join(running))
    output = output.replace("{finished}", "\n        ".join(finished))

    return response(start_response, "200 OK", output, [("Content-Type", "text/html")])
