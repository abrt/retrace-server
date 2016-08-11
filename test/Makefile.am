check-local:
	$(MAKE) -C ${abs_top_srcdir}/src/retrace config.py
	PYTHONPATH=${abs_top_srcdir}/src PATH=${abs_top_srcdir}/src:$(PATH) RETRACE_SERVER_PLUGIN_DIR=${abs_top_srcdir}/src/plugins RETRACE_SERVER_CONFIG_PATH=${abs_top_srcdir}/src/config/retrace-server.conf $(PYTHON) run_test.py $(ARGS)
