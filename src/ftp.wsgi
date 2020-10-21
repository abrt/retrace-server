import fnmatch
import re
import urllib
from webob import Request

from retrace.config import Config
from retrace.util import ftp_list_dir, parse_http_gettext, response

CONFIG = Config()

MANAGER_URL_PARSER = re.compile(r"^(.*/manager)(/(([^/]+)(/(__custom__|start|backtrace|savenotes|"
                                r"caseno|notify|delete(/(sure/?)?)?|results/([^/]+)/?)?)?)?)?$")
tableheader = """
          <table>
            <tr>
              <th class="tablename">FTP files</th>
            </tr>
"""
tablefooter = """
          </table>
"""

def async_ftp_list_dir(filterexp):
    available = []
    rawtasklist = ftp_list_dir(CONFIG["FTPDir"])

    if filterexp:
        tasklist = sorted(fnmatch.filter(rawtasklist, filterexp))
    else:
        tasklist = sorted(rawtasklist)

    for fname in tasklist:
        available.append("<tr><td><a href=\"manager/%s\">%s</a></td></tr>" \
                         % (urllib.parse.quote(fname), fname))

    available.append(tablefooter)
    return "\n            ".join(available)

def application(environ, start_response):
    request = Request(environ)

    _ = parse_http_gettext("%s" % request.accept_language,
                           "%s" % request.accept_charset)

    get = urllib.parse.parse_qs(request.query_string)
    filterexp = None
    if "filterexp" in get:
        filterexp = get["filterexp"][0]

    output = ""
    output += tableheader
    output += async_ftp_list_dir(filterexp)
    output += tablefooter

    return response(start_response, "200 OK", output, [("Content-Type", "text/html")])
