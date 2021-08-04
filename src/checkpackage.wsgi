from webob import Request

from retrace.retrace import is_package_known
from retrace.util import (INPUT_ARCH_PARSER,
                          INPUT_PACKAGE_PARSER,
                          INPUT_RELEASEID_PARSER,
                          parse_http_gettext,
                          response)


def application(environ, start_response):
    request = Request(environ)

    _ = parse_http_gettext("%s" % request.accept_language,
                           "%s" % request.accept_charset)

    if "X-Package-NVR" not in request.headers:
        return response(start_response, "403 Forbidden",
                        _("Required header 'X-Package-NVR' not found"))

    if not INPUT_PACKAGE_PARSER.match(request.headers["X-Package-NVR"]):
        return response(start_response, "403 Forbidden",
                        _("Package NVR contains illegal characters"))

    if "X-Package-Arch" not in request.headers:
        return response(start_response, "403 Forbidden",
                        _("Required header 'X-Package-Arch' not found"))

    if not INPUT_ARCH_PARSER.match(request.headers["X-Package-Arch"]):
        return response(start_response, "403 Forbidden",
                        _("Architecture contains illegal characters"))

    if "X-OS-Release" not in request.headers:
        request.headers["X-OS-Release"] = None
    elif not INPUT_RELEASEID_PARSER.match(request.headers["X-OS-Release"]):
        return response(start_response, "403 Forbidden",
                        _("OS release contains illegal characters"))

    # TODO: How to check if a package is supported when using debuginfod?
    if is_package_known(request.headers["X-Package-NVR"],
                        request.headers["X-Package-Arch"],
                        request.headers["X-OS-Release"]):
        return response(start_response, "302 Found")

    return response(start_response, "404 Not Found")
