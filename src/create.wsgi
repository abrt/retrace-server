from retrace import *
from tempfile import *

def application(environ, start_response):
    request = Request(environ)

    try:
        _ = gettext.translation(GETTEXT_DOMAIN, languages=["%s" % request.accept_language],
                                codeset="%s" % request.accept_charset).gettext
    except:
        _ = lambda x: x

    if request.scheme != "https":
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
        archive = NamedTemporaryFile(mode="wb", delete=False, suffix=".tar.xz")
        archive.write(request.body)
        archive.close()
    except:
        return response(start_response, "500 Internal Server Error",
                        _("Unable to save archive"))

    size = unpacked_size(archive.name, request.content_type)
    if not size:
        os.unlink(archive.name)
        return response(start_response, "500 Internal Server Error",
                        _("Unable to obtain unpacked size"))

    if size > CONFIG["MaxUnpackedSize"] * 1048576:
        os.unlink(archive.name)
        return response(start_response, "413 Request Entity Too Large",
                        _("Specified archive's content is too large"))

    if space - size < CONFIG["MinStorageLeft"] * 1048576:
        os.unlink(archive.name)
        return response(start_response, "507 Insufficient Storage",
                        _("There is not enough storage space on the server"))

    taskid, taskpass, taskdir = new_task()
    if not taskid or not taskpass or not taskdir:
        return response(start_response, "500 Internal Server Error",
                        _("Unable to create new task"))

    try:
        os.mkdir("%s/crash/" % taskdir)
        os.chdir("%s/crash/" % taskdir)
        unpack_retcode = unpack(archive.name, request.content_type)
        os.unlink(archive.name)

        if unpack_retcode != 0:
            raise Exception
    except:
        os.chdir("/")
        shutil.rmtree(taskdir)
        return response(start_response, "500 Internal Server Error",
                        _("Unable to unpack archive"))

    files = os.listdir(".")

    for required_file in REQUIRED_FILES:
        if not required_file in files:
            os.chdir("/")
            shutil.rmtree(taskdir)
            return response(start_response, "403 Forbidden",
                            _("Required file \"%s\" is missing") % required_file)

    call(["/usr/bin/retrace-server-worker", "%d" % taskid])

    return response(start_response, "201 Created", "",
                    [("X-Task-Id", "%d" % taskid),
                     ("X-Task-Password", taskpass)])
