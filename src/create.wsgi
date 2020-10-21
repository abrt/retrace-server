import os
import sys
from typing import List

from pathlib import Path
from webob import Request
from tempfile import NamedTemporaryFile

from retrace.retrace import (ALLOWED_FILES,
                             REQUIRED_FILES,
                             SNAPSHOT_SUFFIXES,
                             TASK_RETRACE,
                             TASK_RETRACE_INTERACTIVE,
                             TASK_TYPES,
                             TASK_VMCORE,
                             TASK_VMCORE_INTERACTIVE,
                             get_active_tasks,
                             get_archive_type,
                             KernelVMcore,
                             RetraceTask)

from retrace.config import Config
from retrace.stats import save_crashstats_reportfull
from retrace.util import (HANDLE_ARCHIVE,
                          free_space,
                          parse_http_gettext,
                          response,
                          unpack,
                          unpacked_size)

CONFIG = Config()
BUFSIZE = 1 << 20  # 1 MB


def check_required_file(filelist: List[str], required: str) -> bool:
    if required in filelist:
        return True

    if required == "vmcore":
        for suffix in SNAPSHOT_SUFFIXES:
            with_suffix = required + suffix
            if with_suffix in filelist:
                return True

    return False


def application(environ, start_response):
    request = Request(environ)

    _ = parse_http_gettext("%s" % request.accept_language,
                           "%s" % request.accept_charset)

    if CONFIG["RequireHTTPS"] and request.scheme != "https":
        return response(start_response, "403 Forbidden",
                        _("You must use HTTPS"))

    if len(get_active_tasks()) >= CONFIG["MaxParallelTasks"]:
        save_crashstats_reportfull(environ["REMOTE_ADDR"])
        return response(start_response, "503 Service Unavailable",
                        _("Retrace server is fully loaded at the moment"))

    if request.method != "POST":
        return response(start_response, "405 Method Not Allowed",
                        _("You must use POST method"))

    if request.content_type not in HANDLE_ARCHIVE.keys():
        return response(start_response, "415 Unsupported Media Type",
                        _("Specified archive format is not supported"))

    if request.content_length is None:
        return response(start_response, "411 Length Required",
                        _("You need to set Content-Length header properly"))

    if request.content_length > CONFIG["MaxPackedSize"] * 1048576:
        return response(start_response, "413 Request Entity Too Large",
                        _("Specified archive is too large"))

    if (not CONFIG["AllowExternalDir"] and
            "X-CoreFileDirectory" in request.headers):
        return response(start_response, "403 Forbidden",
                        _("X-CoreFileDirectory header has been disabled "
                          "by server administrator"))

    workdir = Path(CONFIG["SaveDir"])

    if not workdir.is_dir():
        try:
            workdir.mkdir(parents=True)
        except OSError:
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
        # do not make the task world-readable
        os.umask(0o027)
        task = RetraceTask()
    except Exception:
        return response(start_response, "500 Internal Server Error",
                        _("Unable to create new task"))

    if len(get_active_tasks()) > CONFIG["MaxParallelTasks"]:
        save_crashstats_reportfull(environ["REMOTE_ADDR"])
        Path(archive.name).unlink()
        task.remove()
        return response(start_response, "503 Service Unavailable",
                        _("Retrace server is fully loaded at the moment"))

    if "X-CoreFileDirectory" in request.headers:
        coredir = Path(request.headers["X-CoreFileDirectory"])
        if not coredir.is_dir():
            return response(start_response, "404 Not Found", _("The directory "
                                                               "specified in 'X-CoreFileDirectory' does not exist"))

        files = list(coredir.iterdir())
        if len(files) != 1:
            return response(start_response, "501 Not Implemented",
                            _("There are %d files in the '%s' directory. Only "
                              "a single archive is supported at the moment") %
                            (len(files), coredir))

        filepath = files[0]
        archive_meta = HANDLE_ARCHIVE[request.content_type]
        if ("type" in archive_meta and
                get_archive_type(filepath) != archive_meta["type"]):
            return response(start_response, "409 Conflict",
                            _("You header specifies '%s' type, but the file "
                              "type does not match") % request.content_type)

        body_file = open(filepath, "rb")
    else:
        body_file = request.body_file

    try:
        archive = NamedTemporaryFile(mode="wb", suffix=".tar.xz",
                                     delete=False, dir=task.get_savedir())
        buf = body_file.read(BUFSIZE)
        while buf:
            archive.write(buf)
            buf = body_file.read(BUFSIZE)
        archive.close()
    except Exception:
        task.remove()
        return response(start_response, "500 Internal Server Error",
                        _("Unable to save archive"))
    finally:
        body_file.close()

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
        crashdir = task.get_crashdir()
        crashdir.mkdir()
        unpack_retcode = unpack(archive.name, request.content_type, crashdir)

        if unpack_retcode != 0:
            raise Exception
    except Exception:
        task.remove()
        return response(start_response, "500 Internal Server Error",
                        _("Unable to unpack archive"))

    Path(archive.name).unlink()

    files = list(crashdir.iterdir())

    for f in files:
        filename, suffix = f.stem, f.suffix

        if f.is_symlink():
            task.remove()
            return response(start_response, "403 Forbidden",
                            _("Symlinks are not allowed to be in the archive"))

        if filename in ALLOWED_FILES and (not suffix or suffix in SNAPSHOT_SUFFIXES):
            maxsize = ALLOWED_FILES[filename]
            if maxsize > 0 and f.stat().st_size > maxsize:
                task.remove()
                return response(start_response, "403 Forbidden",
                                _("The '%s' file is larger than expected") % f)
        else:
            task.remove()
            return response(start_response, "403 Forbidden",
                            _("File '%s' is not allowed to be in the archive") % f)

    if "X-Task-Type" in request.headers:
        try:
            tasktype = int(request.headers["X-Task-Type"])
        except TypeError:
            tasktype = TASK_RETRACE

        if tasktype not in TASK_TYPES:
            tasktype = TASK_RETRACE

        if tasktype in [TASK_RETRACE_INTERACTIVE, TASK_VMCORE_INTERACTIVE] \
           and not CONFIG["AllowInteractive"]:
            task.remove()
            return response(start_response, "409 Conflict",
                            _("Interactive tasks were disabled by server administrator"))
        task.set_type(tasktype)
    else:
        task.set_type(TASK_RETRACE)

    present_files = [f.name for f in files]
    for required_file in REQUIRED_FILES[task.get_type()]:
        if not check_required_file(present_files, required_file):
            task.remove()
            return response(start_response, "403 Forbidden",
                            _("Required file '%s' is missing") % required_file)

    if task.get_type() in [TASK_VMCORE, TASK_VMCORE_INTERACTIVE]:
        task.find_vmcore_file(crashdir)
        vmcore = KernelVMcore(task.get_vmcore_path())
        vmcore.prepare_debuginfo(task)
        vmcore.strip_extra_pages()

    retcode = task.start()
    if retcode != 0:
        sys.stderr.write("Task {0} failed to start: {1}\n".format(
            task.get_taskid(), retcode))

    return response(start_response, "201 Created", "",
                    [("X-Task-Id", "%d" % task.get_taskid()),
                     ("X-Task-Password", task.get_password())])
