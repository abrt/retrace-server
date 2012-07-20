import re
from retrace import *

MANAGER_URL_PARSER = re.compile("^(.*/manager)(/(([^/]+)(/(start|backtrace|delete|misc/([^/]+)/?)?)?)?)?$")

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

def application(environ, start_response):
    request = Request(environ)

    _ = parse_http_gettext("%s" % request.accept_language,
                           "%s" % request.accept_charset)

    if not CONFIG["AllowTaskManager"]:
        return response(start_response, "403 Forbidden", _("Task manager was disabled by the server administrator"))

    match = MANAGER_URL_PARSER.match(request.url)
    if not match:
        return response(start_response, "404 Not Found")

    if match.group(6) and match.group(6).startswith("misc") and match.group(7):
        try:
            task = RetraceTask(match.group(4))
        except:
            return response(start_response, "404 Not Found", _("There is no such task"))

        if not task.has_misc(match.group(7)):
            return response(start_response, "404 Not Found", _("There is no such record"))

        return response(start_response, "200 OK", task.get_misc(match.group(7)))
    elif match.group(6) and match.group(6) == "start":
        # start
        ftptask = False
        try:
            task = RetraceTask(match.group(4))
        except:
            if CONFIG["UseFTPTasks"]:
                files = ftp_list_dir(CONFIG["FTPDir"])
                if not match.group(4) in files:
                    return response(start_response, "404 Not Found", _("There is no such task"))

                ftptask = True
            else:
                return response(start_response, "404 Not Found", _("There is no such task"))

        if ftptask:
            try:
                task = RetraceTask()
                task.set_managed(True)
                # ToDo: determine?
                task.set_type(TASK_VMCORE_INTERACTIVE)
                task.add_remote("FTP %s" % match.group(4))
            except:
                return response(start_response, "500 Internal Server Error", _("Unable to create a new task"))

        if not task.get_managed():
            return response(start_response, "403 Forbidden", _("Task does not belong to task manager"))

        call(["/usr/bin/retrace-server-worker", str(task.get_taskid())])

        # ugly, ugly, ugly! retrace-server-worker double-forks and needs a while to spawn
        time.sleep(2)

        return response(start_response, "303 See Other", "", [("Location", "%s/%d" % (match.group(1), task.get_taskid()))])
    elif match.group(6) and match.group(6) == "backtrace":
        try:
            task = RetraceTask(match.group(4))
        except:
            return response(start_response, "404 Not Found", _("There is no such task"))

        if not task.get_managed():
            return response(start_response, "403 Forbidden", _("Task does not belong to task manager"))

        if not task.has_backtrace():
            return response(start_response, "404 Forbidden", _("Task does not have a backtrace"))

        return response(start_response, "200 OK", task.get_backtrace())
    elif match.group(6) and match.group(6) == "delete":
        try:
            task = RetraceTask(match.group(4))
        except:
            return response(start_response, "404 Not Found", _("There is no such task"))

        if not task.get_managed():
            return response(start_response, "403 Forbidden", _("Task does not belong to task manager"))

        task.remove()

        return response(start_response, "302 Found", "", [("Location", match.group(1))])
    elif match.group(4):
        # info
        ftptask = False
        try:
            task = RetraceTask(match.group(4))
        except:
            if CONFIG["UseFTPTasks"]:
                files = ftp_list_dir(CONFIG["FTPDir"])
                if not match.group(4) in files:
                    return response(start_response, "404 Not Found", _("There is no such task"))

                ftptask = True
            else:
                return response(start_response, "404 Not Found", _("There is no such task"))

        with open("/usr/share/retrace-server/managertask.xhtml", "r") as f:
            output = f.read(1 << 20) # 1MB

        start = ""
        if ftptask:
            status = _("On remote FTP server")
            start = "<tr><td colspan=\"2\" id=\"highrow\"><a href=\"%s/start\" id=\"start\">%s</a></td></tr>" % (request.url.rstrip("/"), _("Start task"))
        elif task.has_status():
            status = _(STATUS[task.get_status()])
        else:
            status = _("Not started")
            start = "<tr><td colspan=\"2\" id=\"highrow\"><a href=\"%s/start\" id=\"start\">%s</a></td></tr>" % (request.url.rstrip("/"), _("Start task"))

        interactive = ""
        if not ftptask and task.has_backtrace():
            backtrace = "<tr><td colspan=\"2\"><a href=\"%s/backtrace\">%s</a></td></tr>" % (request.url.rstrip("/"), _("Show raw backtrace"))
            backtracewindow = "<h2>Backtrace</h2><textarea>%s</textarea>" % task.get_backtrace()
            if task.get_type() in [TASK_RETRACE_INTERACTIVE, TASK_VMCORE_INTERACTIVE]:
                if task.get_type() == TASK_VMCORE_INTERACTIVE:
                    debugger = "crash"
                else:
                    debugger = "gdb"

                interactive = "<tr><td colspan=\"2\">%s</td></tr>" \
                              "<tr><td colspan=\"2\">%s <code>retrace-server-interact %s shell</code></td></tr>" \
                              "<tr><td colspan=\"2\">%s <code>retrace-server-interact %s %s</code></td></tr>" \
                              "<tr><td colspan=\"2\">%s <code>man retrace-server-interact</code> %s</td></tr>" \
                              % (_("This is an interactive task"), _("You can jump to the chrooted shell with:"), match.group(4),
                                 _("You can jump directly to the debugger with:"), match.group(4), debugger,
                                 _("see"), _("for further information about cmdline flags"))
        else:
            backtrace = ""
            backtracewindow = ""

        if ftptask or task.is_running():
            delete = ""
        else:
            delete = "<tr><td colspan=\"2\"><a href=\"%s/delete\">%s</a></td></tr>" % (request.url.rstrip("/"), _("Delete task"))

        if ftptask:
            # ToDo: determine?
            tasktype = _(LONG_TYPES[TASK_VMCORE_INTERACTIVE])
            title = "%s '%s' - %s" % (_("Remote file"), match.group(4), _("Retrace Server Task Manager"))
            taskno = "%s '%s'" % (_("Remote file"), match.group(4))
        else:
            tasktype = _(LONG_TYPES[task.get_type()])
            title = "%s #%s - %s" % (_("Task"), match.group(4), _("Retrace Server Task Manager"))
            taskno = "%s #%s" % (_("Task"), match.group(4))

        misc = ""
        if not ftptask:
            misclist = sorted(task.get_misc_list())
            if misclist:
                links = []
                for name in misclist:
                    links.append("<a href=\"%s/misc/%s\">%s</a>" % (request.url.rstrip("/"), name, name))
                misc = "<tr><th>Additional results:</th><td>%s</td></tr>" % ", ".join(links)

        back = "<tr><td colspan=\"2\"><a href=\"%s\">%s</a></td></tr>" % (match.group(1), _("Back to task manager"))

        output = output.replace("{title}", _("Task #%s - Retrace Server Task Manager") % match.group(4))
        output = output.replace("{taskno}", _("Task #%s") % match.group(4))
        output = output.replace("{str_type}", _("Type:"))
        output = output.replace("{type}", tasktype)
        output = output.replace("{str_status}", _("Status:"))
        output = output.replace("{status}", status)
        output = output.replace("{start}", start)
        output = output.replace("{back}", back)
        output = output.replace("{backtrace}", backtrace)
        output = output.replace("{backtracewindow}", backtracewindow)
        output = output.replace("{delete}", delete)
        output = output.replace("{interactive}", interactive)
        output = output.replace("{misc}", misc)
        return response(start_response, "200 OK", output, [("Content-Type", "text/html")])

    # menu
    with open("/usr/share/retrace-server/manager.xhtml") as f:
        output = f.read(1 << 20) # 1MB

    title = _("Retrace Server Task Manager")
    sitename = _("Retrace Server Task Manager")

    baseurl = request.url
    if not baseurl.endswith("/"):
        baseurl += "/"

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
            row = "<tr><td><a href=\"%s%s\">%s</a> (%s)</td></tr>" \
                  % (baseurl, taskid, taskid, LONG_TYPES[task.get_type()])

            if not task.has_status():
                available.append(row)
                continue

            if task.get_status() in [STATUS_SUCCESS, STATUS_FAIL]:
                finished.append(row)
                continue

            running.append(row)

    if CONFIG["UseFTPTasks"]:
        available = []
        for filename in sorted(ftp_list_dir(CONFIG["FTPDir"]), cmp=cmp_vmcores_first):
            available.append("<tr><td><a href=\"%s/%s\">%s</a></td></tr>" \
                             % (match.group(1), filename, filename))

    output = output.replace("{title}", title)
    output = output.replace("{sitename}", sitename)
    # spaces to keep the XML nicely aligned
    output = output.replace("{available}", "\n        ".join(available))
    output = output.replace("{running}", "\n        ".join(running))
    output = output.replace("{finished}", "\n        ".join(finished))

    return response(start_response, "200 OK", output, [("Content-Type", "text/html")])
