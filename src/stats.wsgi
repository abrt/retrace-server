#!/usr/bin/python
from retrace import *

def application(environ, start_response):
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

    con = init_crashstats_db()
    query = con.cursor()

    # total
    query.execute("SELECT COUNT(*) FROM tasks")
    row = query.fetchone()
    output = output.replace("{total}", str(row[0]))

    # by status
    query.execute("SELECT status, COUNT(*) FROM tasks GROUP BY status")
    row = query.fetchone()
    while row:
        if int(row[0]) == STATUS_SUCCESS:
            output = output.replace("{success}", str(row[1]))
        elif int(row[0]) == STATUS_FAIL:
            output = output.replace("{fail}", str(row[1]))
        row = query.fetchone()

    # denied
    query.execute("SELECT COUNT(*) FROM reportfull")
    row = query.fetchone()
    output = output.replace("{denied}", str(row[0]))

    # first retrace
    query.execute("SELECT starttime FROM tasks \
                   ORDER BY starttime ASC LIMIT 0,1")
    row = query.fetchone()
    date = time.localtime(int(row[0]))
    output = output.replace("{first}", "%04d-%02d-%02d %02d:%02d" % \
                                       (date.tm_year, date.tm_mon, \
                                        date.tm_mday, date.tm_hour, \
                                        date.tm_min))

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
    # tricky - no simple way to group by .fcXY
    query.execute("SELECT COUNT(*) FROM tasks WHERE version LIKE '%.fc15'")
    row = query.fetchone()
    output = output.replace("{f15}", str(row[0]))
    query.execute("SELECT COUNT(*) FROM tasks WHERE version LIKE '%.fc16'")
    row = query.fetchone()
    output = output.replace("{f16}", str(row[0]))
    query.execute("SELECT COUNT(*) FROM tasks WHERE version LIKE '%.fc17'")
    row = query.fetchone()
    output = output.replace("{f17}", str(row[0]))

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
