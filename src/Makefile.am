SUBDIRS = gpg plugins

MAN_TXT = \
    retrace-server-cleanup.txt \
    retrace-server-reposync.txt \
    retrace-server-worker.txt

#Manual pages are generated from .txt via Docbook
man1_MANS = ${MAN_TXT:%.txt=%.1}

%.1 %.5 %.7: %.xml
	$(XMLTO_SILENT) xmlto man $< 2>&1 | sed '/Note/d'

%.xml: %.txt ../asciidoc.conf
	$(ASCIIDOC_SILENT) asciidoc --backend=docbook --doctype=manpage --conf-file ../asciidoc.conf -a rs_version=$(PACKAGE_VERSION) -o $@ $<

CLEANFILES = $(man1_MANS)

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

logrotate_DATA = retrace-server
logrotatedir = ${sysconfdir}/logrotate.d

EXTRA_DIST = $(man1_MANS) retrace-server.conf retrace-server-httpd.conf retrace-server.repo retrace-server

# Apache config files can be owned by root, httpd just needs read
# access.
#install-data-hook:
#       chown apache:apache $(DESTDIR)$(httpdconfdir)/retrace_httpd.conf
