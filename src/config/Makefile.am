SUBDIRS = hooks

retraceconf_DATA = retrace-server.conf \
                   retrace-server-hooks.conf

retraceconfdir = ${sysconfdir}/retrace-server

httpdconf_DATA = retrace-server-httpd.conf
httpdconfdir = ${sysconfdir}/httpd/conf.d

logrotate_DATA = retrace-server
logrotatedir = ${sysconfdir}/logrotate.d

EXTRA_DIST = retrace-server.conf \
             retrace-server-hooks.conf \
             retrace-server-httpd.conf \
             retrace-server
