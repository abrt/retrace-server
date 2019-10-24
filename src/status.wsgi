#!/usr/bin/python3
from webob import Request

from retrace.retrace import (STATUS,
                             URL_PARSER,
                             parse_http_gettext,
                             response,
                             RetraceTask)
from retrace.config import Config

CONFIG = Config()

def application(environ, start_response):
    request = Request(environ)

    _ = parse_http_gettext("%s" % request.accept_language,
                           "%s" % request.accept_charset)

    if CONFIG["RequireHTTPS"] and request.scheme != "https":
        return response(start_response, "403 Forbidden",
                        _("You must use HTTPS"))

    match = URL_PARSER.match(request.script_name)
    if not match:
        return response(start_response, "404 Not Found",
                        _("Invalid URL"))

    try:
        task = RetraceTask(int(match.group(1)))
    except:
        return response(start_response, "404 Not Found",
                        _("There is no such task"))

    if "X-Task-Password" not in request.headers or \
       not task.verify_password(request.headers["X-Task-Password"]):
        return response(start_response, "403 Forbidden",
                        _("Invalid password"))

    status = "PENDING"
    if task.has_finished_time():
        if task.has_backtrace():
            status = "FINISHED_SUCCESS"
        else:
            status = "FINISHED_FAILURE"

    statusmsg = status
    try:
        statusmsg = _(STATUS[task.get_status()])
    except:
        pass

    return response(start_response, "200 OK",
                    statusmsg, [("X-Task-Status", status)])
