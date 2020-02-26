#!/usr/bin/python3

import urllib
from webob import Request

from retrace.retrace import RetraceTask
from retrace.config import Config
from retrace.util import URL_PARSER, parse_http_gettext, response

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
    except Exception:
        return response(start_response, "404 Not Found",
                        _("There is no such task"))

    qs = urllib.parse.parse_qs(request.query_string, keep_blank_values=True)

    debug = "debug" in qs

    kernelver = None
    if "kernelver" in qs:
        kernelver = qs["kernelver"][0]

    arch = None
    if "arch" in qs:
        arch = qs["arch"][0]

    task.start(debug=debug, kernelver=kernelver, arch=arch)

    return response(start_response, "201 Created")
