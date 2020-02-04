SUBDIRS = config retrace plugins

MAN_TXT = \
    retrace-server-cleanup.txt \
    retrace-server-interact.txt \
    retrace-server-reposync.txt \
    retrace-server-worker.txt \
    retrace-server-task.txt

#Manual pages are generated from .txt via Docbook
man1_MANS = ${MAN_TXT:%.txt=%.1}

%.1 %.5 %.7: %.xml
	$(XMLTO_SILENT) xmlto man $< 2>&1 | sed '/Note/d'

%.xml: %.txt ../asciidoc.conf
	$(ASCIIDOC_SILENT) asciidoc --backend=docbook --doctype=manpage --conf-file ../asciidoc.conf -a rs_version=$(PACKAGE_VERSION) -o $@ $<

CLEANFILES = $(man1_MANS)

dist_bin_SCRIPTS = coredump2packages \
                   retrace-server-cleanup \
                   retrace-server-reposync \
                   retrace-server-reposync-faf \
                   retrace-server-worker \
                   retrace-server-interact\
                   retrace-server-plugin-checker\
                   retrace-server-task \
                   retrace-server-bugzilla-refresh \
                   retrace-server-bugzilla-query

interface_PYTHON = backtrace.wsgi \
                   create.wsgi \
                   checkpackage.wsgi \
                   delete.wsgi \
                   exploitable.wsgi \
                   index.wsgi \
                   log.wsgi \
                   manager.wsgi \
                   ftp.wsgi \
                   settings.wsgi \
                   start.wsgi \
                   stats.wsgi \
                   status.wsgi

interface_DATA = index.xhtml \
                 manager.xhtml \
                 manager_vmcore_task_form.xhtml \
                 manager_usrcore_task_form.xhtml \
                 managertask.xhtml \
                 stats.xhtml
# interfacedir should probably be $$(pkgdatadir)/retrace
interfacedir =  $(datadir)/retrace-server

EXTRA_DIST = $(man1_MANS) $(interface_DATA)
