#!/usr/bin/python3
import sys
import time

from webob import Request

from retrace.retrace import (STATUS_FAIL,
                             STATUS_SUCCESS,
                             init_crashstats_db,
                             parse_http_gettext,
                             response)
from retrace.plugins import Plugins

sys.path.insert(0, "/usr/share/retrace-server/")

status_queries = {"SELECT COUNT(*) FROM tasks": "{total}",
                  "SELECT COUNT(*) FROM tasks WHERE status = {0}".format(STATUS_SUCCESS): "{success}",
                  "SELECT COUNT(*) FROM tasks WHERE status = {0}".format(STATUS_FAIL): "{fail}",
                  "SELECT COUNT(*) FROM reportfull": "{denied}",
                 }

def replace_by_count(input, q, key, query):
    query.execute(q)
    row = query.fetchone()
    return input.replace(key, str(row[0]))

plugins = Plugins()
def application(environ, start_response):

    con = init_crashstats_db()
    query = con.cursor()

    request = Request(environ)
    _ = parse_http_gettext("%s" % request.accept_language,
                           "%s" % request.accept_charset)

    strings = {
        "{_Architecture}": _("Architecture"),
        "{_Architectures}": _("Architectures"),
        "{_Build-id}": _("Build-id"),
        "{_Count}": _("Count"),
        "{_Denied_jobs}": _("Denied jobs"),
        "{_Failed}": _("Failed"),
        "{_First_retrace}": _("First retrace"),
        "{_Global_statistics}": _("Global statistics"),
        "{_Missing_build-ids}": _("Missing build-ids"),
        "{_Name}": _("Name"),
        "{_Release}": _("Release"),
        "{_Releases}": _("Releases"),
        "{_Required_packages}": _("Required packages"),
        "{_Retraced_packages}": _("Retraced packages"),
        "{_Retrace_Server_statistics}": _("Retrace Server statistics"),
        "{_Shared_object_name}": _("Shared object name"),
        "{_Successful}": _("Successful"),
        "{_Total}": _("Total"),
        "{_Versions}": _("Versions"),
        }

    with open("/usr/share/retrace-server/stats.xhtml") as f:
        output = f.read(1 << 20) # 1 MB

    for key in strings:
        output = output.replace(key, strings[key])

    output = output.replace("{host}", environ["HTTP_HOST"])

    # fill in statuses
    for key in status_queries.keys():
        output = replace_by_count(output, key, status_queries[key], query)

    # first retrace
    query.execute("SELECT starttime FROM tasks \
                   ORDER BY starttime ASC LIMIT 0,1")
    row = query.fetchone()
    if row:
        date = time.localtime(int(row[0]))
        output = output.replace("{first}", "%04d-%02d-%02d %02d:%02d" % \
                                           (date.tm_year, date.tm_mon, \
                                            date.tm_mday, date.tm_hour, \
                                            date.tm_min))
    else:
        output = output.replace("{first}", "No retrace yet")


    # by architecture
    query.execute("SELECT arch, COUNT(*) FROM tasks WHERE arch IS NOT NULL \
                   GROUP BY arch")
    tablerows = []
    i = 1
    row = query.fetchone()
    while row:
        if i % 2:
            style = "odd"
        else:
            style = "even"

        tablerows.append("<tr class=\"%s\">" % style)
        tablerows.append("  <td>%s</td>" % str(row[0]))
        tablerows.append("  <td>%s</td>" % str(row[1]))
        tablerows.append("</tr>")

        row = query.fetchone()
        i += 1
    # spaces to keep the xml nicely indented
    output = output.replace("{arch_rows}", "\n            ".join(tablerows))

    # by release
    versions = {}
    for entry in plugins.all():
        for key in entry.versionlist:
            versions[key] = entry.displayrelease

    tablerows = []
    i = 1
    for key in versions.keys():
        query.execute("SELECT COUNT(*) FROM tasks WHERE version LIKE '%"+key+"'")
        row = query.fetchone()
        retstr = str(versions[key]) + " " + str(key[2:])

        if i % 2:
            style = "odd"
        else:
            style = "even"

        if row[0] > 0:
            tablerows.append("<tr class=\"%s\">" % style)
            tablerows.append("  <td>%s</td>" % retstr)
            tablerows.append("  <td>%s</td>" % str(row[0]))
            tablerows.append("</tr>")
            i += 1

    output = output.replace("{release_rows}", "\n            ".join(tablerows))

    # most retraced
    query.execute("SELECT package, COUNT(*) as c FROM tasks GROUP BY package \
                   ORDER BY c DESC LIMIT 0,37")
    tablerows = []
    i = 1
    row = query.fetchone()
    while row:
        if i % 2:
            style = "odd"
        else:
            style = "even"

        tablerows.append("<tr class=\"%s\">" % style)
        tablerows.append("  <td>%s</td>" % str(row[0]))
        tablerows.append("  <td>%s</td>" % str(row[1]))
        tablerows.append("</tr>")

        row = query.fetchone()
        i += 1
    # spaces to keep the xml nicely indented
    output = output.replace("{retraced_rows}", "\n            ".join(tablerows))

    # most required
    query.execute("SELECT name, COUNT(*) AS cnt, SUM(c) AS s FROM \
                  (SELECT pkgid, COUNT(*) AS c FROM packages_tasks \
                  GROUP BY pkgid) AS sub, packages WHERE \
                  NOT packages.name LIKE '%-debuginfo' AND \
                  packages.id = sub.pkgid GROUP BY packages.name \
                  ORDER BY s DESC LIMIT 0,32")
    tablerows = []
    i = 1
    row = query.fetchone()
    while row:
        if i % 2:
            style = "odd"
        else:
            style = "even"

        tablerows.append("<tr class=\"%s\">" % style)
        tablerows.append("  <td>%s</td>" % str(row[0]))
        tablerows.append("  <td>%s</td>" % str(row[1]))
        tablerows.append("  <td>%s</td>" % str(row[2]))
        tablerows.append("</tr>")

        row = query.fetchone()
        i += 1
    # spaces to keep the xml nicely indented
    output = output.replace("{required_rows}", "\n            ".join(tablerows))

    # most missing build-ids
    query.execute("SELECT * FROM (SELECT buildid, soname, COUNT(*) as c \
                   FROM buildids WHERE buildid = '-' OR buildid IS NULL \
                   GROUP BY soname UNION SELECT buildid, soname, COUNT(*) as c \
                   FROM buildids WHERE buildid != '-' AND buildid IS NOT NULL \
                   GROUP BY buildid) ORDER BY c DESC LIMIT 0,20")
    tablerows = []
    i = 1
    row = query.fetchone()
    while row:
        if i % 2:
            style = "odd"
        else:
            style = "even"

        tablerows.append("<tr class=\"%s\">" % style)
        tablerows.append("  <td>%s</td>" % str(row[0]))
        tablerows.append("  <td>%s</td>" % str(row[1]))
        tablerows.append("  <td>%s</td>" % str(row[2]))
        tablerows.append("</tr>")

        row = query.fetchone()
        i += 1
    # spaces to keep the xml nicely indented
    output = output.replace("{buildids_rows}", "\n          ".join(tablerows))

    con.close()
    return response(start_response, "200 OK", output,
                    [("Content-Type", "text/xml")])
