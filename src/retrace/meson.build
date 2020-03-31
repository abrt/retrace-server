configuration = configuration_data()

configuration.set('DF_BIN', df.path())
configuration.set('GZIP_BIN', gzip.path())
configuration.set('TAR_BIN', tar.path())
configuration.set('XZ_BIN', xz.path())
configuration.set('LSOF_BIN', lsof.path())

python_installation.install_sources([
    '__init__.py',
    'argparser.py',
    configure_file(
      configuration: configuration,
      input: 'config.py.in',
      output: 'config.py',
    ),
    'plugins.py',
    'retrace.py',
    'retrace_worker.py',
    'stats.py',
    'util.py',
  ],
  subdir: 'retrace',
  pure: true,
)
python_installation.install_sources([
    'hooks/__init__.py',
    'hooks/config.py',
    'hooks/hooks.py',
  ],
  subdir: join_paths('retrace', 'hooks'),
  pure: true,
)
