subdir('hooks')

configuration = configuration_data()

configuration.set('DF_BIN', df.path())
configuration.set('GZIP_BIN', gzip.path())
configuration.set('TAR_BIN', tar.path())
configuration.set('XZ_BIN', xz.path())
configuration.set('LSOF_BIN', lsof.path())

sources = [
  '__init__.py',
  'argparser.py',
  'plugins.py',
  'retrace.py',
  'retrace_worker.py',
  'stats.py',
  'util.py',
]

foreach file: sources
  configure_file(
    copy: true,
    input: file,
    output: file,
  )
endforeach

python_installation.install_sources([
    configure_file(
      configuration: configuration,
      input: 'config.py.in',
      output: 'config.py',
    ),
    sources,
  ],
  subdir: 'retrace',
  pure: true,
)
