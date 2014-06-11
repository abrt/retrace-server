SUBDIRS = config gpg lib plugins

MAN_TXT = \
    retrace-server-cleanup.txt \
    retrace-server-interact.txt \
    retrace-server-reposync.txt \
    retrace-server-worker.txt

#Manual pages are generated from .txt via Docbook
man1_MANS = ${MAN_TXT:%.txt=%.1}

%.1 %.5 %.7: %.xml
	$(XMLTO_SILENT) xmlto man $< 2>&1 | sed '/Note/d'

%.xml: %.txt ../asciidoc.conf
	$(ASCIIDOC_SILENT) asciidoc --backend=docbook --doctype=manpage --conf-file ../asciidoc.conf -a rs_version=$(PACKAGE_VERSION) -o $@ $<

CLEANFILES = $(man1_MANS)

dist_bin_SCRIPTS = bt_filter \
                   coredump2packages \
                   retrace-server-cleanup \
                   retrace-server-reposync \
                   retrace-server-worker \
                   retrace-server-interact

interface_PYTHON = backtrace.wsgi \
                   create.wsgi \
                   checkpackage.wsgi \
                   delete.wsgi \
                   exploitable.wsgi \
                   index.wsgi \
                   log.wsgi \
                   manager.wsgi \
                   settings.wsgi \
                   start.wsgi \
                   stats.wsgi \
                   status.wsgi

interface_DATA = index.xhtml \
                 manager.xhtml \
                 managertask.xhtml \
                 stats.xhtml
# interfacedir should probably be $$(pkgdatadir)/retrace
interfacedir =  $(datadir)/retrace-server

EXTRA_DIST = $(man1_MANS) $(interface_DATA)
