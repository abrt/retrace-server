from retrace import *

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

    if not CONFIG["AllowAPIDelete"]:
        return response(start_response, "403 Forbidden",
                        _("Manual deleting is disabled"))

    try:
        task = RetraceTask(int(match.group(1)))
    except:
        return response(start_response, "404 Not Found",
                        _("There is no such task"))

    if not "X-Task-Password" in request.headers or \
       not task.verify_password(request.headers["X-Task-Password"]):
        return response(start_response, "403 Forbidden",
                        _("Invalid password"))

    try:
        task.remove()
    except:
        return reponse(start_response, "500 Internal Server Error",
                       _("An error occured while deleting task data"))

    return response(start_response, "200 OK",
                    _("All task data were deleted successfully"))
