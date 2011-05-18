SUBDIRS = plugins

bin_PROGRAMS = retrace-server-worker
retrace_server_worker_SOURCES = worker.c

dist_bin_SCRIPTS = retrace-server-cleanup retrace-server-reposync coredump2packages

python_PYTHON = retrace.py

worker_PYTHON = worker.py
workerdir = $(datadir)/retrace-server

interface_PYTHON = backtrace.wsgi create.wsgi log.wsgi settings.wsgi status.wsgi
# interfacedir should probably be $$(pkgdatadir)/retrace
interfacedir =  $(datadir)/retrace-server

repo_DATA = retrace-server.repo
repodir = ${sysconfdir}/yum.repos.d

retraceconf_DATA = retrace-server.conf
retraceconfdir = ${sysconfdir}

httpdconf_DATA = retrace-server-httpd.conf
httpdconfdir = ${sysconfdir}/httpd/conf.d

EXTRA_DIST = retrace-server.conf retrace-server-httpd.conf retrace-server.repo

# Apache config files can be owned by root, httpd just needs read
# access.
#install-data-hook:
#       chown apache:apache $(DESTDIR)$(httpdconfdir)/retrace_httpd.conf
