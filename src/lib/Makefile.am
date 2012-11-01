retracelib_PYTHON = __init__.py argparser.py config.py retrace.py
retracelibdir = $(pythondir)/retrace

EXTRA_DIST = config.py.in

config.py: config.py.in
	sed -e "s|@DF_BIN@|$(DF)|g" \
	    -e "s|@DU_BIN@|$(DU)|g" \
	    -e "s|@GZIP_BIN@|$(GZIP)|g" \
	    -e "s|@TAR_BIN@|$(TAR)|g" \
	    -e "s|@XZ_BIN@|$(XZ)|g" \
	    $< > $@
