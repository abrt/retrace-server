from webob import Request

from retrace.config import Config
from retrace.metrics import generate_latest_metrics

CONFIG = Config()


def application(environ, start_response):
    request = Request(environ)

    _ = parse_http_gettext("%s" % request.accept_language,
                           "%s" % request.accept_charset)

    if CONFIG["RequireHTTPS"] and request.scheme != "https":
        return response(start_response, "403 Forbidden",
                        _("You must use HTTPS"))

    if not CONFIG["AllowMetrics"]:
        return response(start_response, "403 Forbidden",
                        _("Metrics are not enabled for this server"))

    body = generate_latest_metrics()

    return response(start_response, "200 OK", body)
