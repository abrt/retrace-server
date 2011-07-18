from retrace import *
from tempfile import *

def application(environ, start_response):
    request = Request(environ)

    _ = parse_http_gettext("%s" % request.accept_language,
                           "%s" % request.accept_charset)

    if CONFIG["RequireHTTPS"] and request.scheme != "https":
        return response(start_response, "403 Forbidden",
                        _("You must use HTTPS"))

    if len(get_active_tasks()) >= CONFIG["MaxParallelTasks"]:
        return response(start_response, "503 Service Unavailable",
                        _("Retrace server is fully loaded at the moment"))

    if request.method != "POST":
        return response(start_response, "405 Method Not Allowed",
                        _("You must use POST method"))

    if not request.content_type in HANDLE_ARCHIVE.keys():
        return response(start_response, "415 Unsupported Media Type",
                        _("Specified archive format is not supported"))

    if not request.content_length:
        return response(start_response, "411 Length Required",
                        _("You need to set Content-Length header properly"))

    if request.content_length > CONFIG["MaxPackedSize"] * 1048576:
        return response(start_response, "413 Request Entity Too Large",
                        _("Specified archive is too large"))

    if CONFIG["UseWorkDir"]:
        workdir = CONFIG["WorkDir"]
    else:
        workdir = CONFIG["SaveDir"]

    if not os.path.isdir(workdir):
        try:
            os.makedirs(workdir)
        except:
            return response(start_response, "500 Internal Server Error",
                            _("Unable to create working directory"))

    space = free_space(workdir)

    if not space:
        return response(start_response, "500 Internal Server Error",
                        _("Unable to obtain disk free space"))

    if space - request.content_length < CONFIG["MinStorageLeft"] * 1048576:
        return response(start_response, "507 Insufficient Storage",
                        _("There is not enough storage space on the server"))

    try:
        task = RetraceTask()
    except:
        return response(start_response, "500 Internal Server Error",
                        _("Unable to create new task"))

    if len(get_active_tasks()) > CONFIG["MaxParallelTasks"]:
        os.unlink(archive.name)
        task.remove()
        return response(start_response, "503 Service Unavailable",
                        _("Retrace server is fully loaded at the moment"))

    try:
        archive = NamedTemporaryFile(mode="wb", suffix=".tar.xz",
                                     delete=False, dir=task.get_savedir())
        archive.write(request.body)
        archive.close()
    except:
        task.remove()
        return response(start_response, "500 Internal Server Error",
                        _("Unable to save archive"))

    size = unpacked_size(archive.name, request.content_type)
    if not size:
        task.remove()
        return response(start_response, "500 Internal Server Error",
                        _("Unable to obtain unpacked size"))

    if size > CONFIG["MaxUnpackedSize"] * 1048576:
        task.remove()
        return response(start_response, "413 Request Entity Too Large",
                        _("Specified archive's content is too large"))

    if space - size < CONFIG["MinStorageLeft"] * 1048576:
        task.remove()
        return response(start_response, "507 Insufficient Storage",
                        _("There is not enough storage space on the server"))

    try:
        crashdir = os.path.join(task.get_savedir(), "crash")
        os.mkdir(crashdir)
        unpack_retcode = unpack(archive.name, request.content_type, crashdir)

        if unpack_retcode != 0:
            raise Exception
    except:
        task.remove()
        return response(start_response, "500 Internal Server Error",
                        _("Unable to unpack archive"))

    os.unlink(archive.name)

    files = os.listdir(crashdir)

    for f in files:
        filepath = os.path.join(crashdir, f)

        if os.path.islink(filepath):
            task.remove()
            return response(start_response, "403 Forbidden",
                            _("Symlinks are not allowed to be in" \
                              " the archive"))

        allowed = False
        for filename in ALLOWED_FILES.keys():
            if f != filename:
                continue

            allowed = True
            maxsize = ALLOWED_FILES[filename]

            if maxsize > 0 and os.path.getsize(filepath) > maxsize:
                task.remove()
                return response(start_response, "403 Forbidden",
                                _("The '%s' file is larger than expected") % f)

        if not allowed:
            task.remove()
            return response(start_response, "403 Forbidden",
                            _("File '%s' is not allowed to be in" \
                              " the archive") % f)

    for required_file in REQUIRED_FILES:
        if not required_file in files:
            task.remove()
            return response(start_response, "403 Forbidden",
                            _("Required file '%s' is missing") % required_file)

    if "X-Task-Type" in request.headers:
        task.set_type(request.headers["X-Task-Type"])
    else:
        task.set_type(TASK_RETRACE)

    call(["/usr/bin/retrace-server-worker", "%d" % task.get_taskid()])

    return response(start_response, "201 Created", "",
                    [("X-Task-Id", "%d" % task.get_taskid()),
                     ("X-Task-Password", task.get_password())])
