from retrace import *

def application(environ, start_response):
    request = Request(environ)

    _ = parse_http_gettext("%s" % request.accept_language,
                           "%s" % request.accept_charset)

    with open("/usr/share/retrace-server/index.xhtml") as f:
        output = f.read(1 << 20) # 1MB

    title = _("Retrace Server")
    welcome = _("Welcome to Retrace Server")
    host = environ["HTTP_HOST"]
    about = "%s %s" % (_("Retrace Server is a service that provides the possibility to analyze "
                         "coredump and generate backtrace over network. "
                         "You can find further information at Retrace Server&apos;s wiki:"),
                         "<a href=\"https://fedorahosted.org/abrt/wiki/AbrtRetraceServer\">"
                         "https://fedorahosted.org/abrt/wiki/AbrtRetraceServer</a>")
    if CONFIG["RequireHTTPS"]:
        https = _("Only the secure HTTPS connection is now allowed by the server. HTTP requests will be denied.")
    else:
        https = _("Both HTTP and HTTPS are allowed. Using HTTPS is strictly recommended because of security reasons.")
    releases = _("The following releases are supported: %s" % ", ".join(sorted(get_supported_releases())))
    active = len(get_active_tasks())
    running = _("At the moment the server is loaded for %d%% (running %d out of %d jobs)." % (100 * active / CONFIG["MaxParallelTasks"], active, CONFIG["MaxParallelTasks"]))
    disclaimer1 = _("Your coredump is only kept on the server while the retrace job is running. "
                    "Once the job is finished, the server keeps retrace log and backtrace. "
                    "All the other data (including coredump) are deleted. "
                    "The retrace log and backtrace are only accessible via unique task ID and password, thus no one (except the author) is allowed to view it. "
                    "All the crash information (including backtrace) is deleted after %d hours of inactivity. "
                    "No possibly private data are kept on the server any longer." % CONFIG["DeleteTaskAfter"])
    disclaimer2 = _("Your coredump is only used for retrace purposes. "
                    "Server administrators are not trying to get your private data from coredumps or backtraces. "
                    "Using a secure communication channel (HTTPS) is strictly recommended. "
                    "Server administrators are not responsible for the problems related to the usage of an insecure channel (such as HTTP).")

    output = output.replace("{title}", title)
    output = output.replace("{welcome}", welcome)
    output = output.replace("{host}", host)
    output = output.replace("{about}", about)
    output = output.replace("{https}", https)
    output = output.replace("{releases}", releases)
    output = output.replace("{running}", running)
    output = output.replace("{disclaimer1}", disclaimer1)
    output = output.replace("{disclaimer2}", disclaimer2)

    return response(start_response, "200 OK", output, [("Content-Type", "text/html")])

