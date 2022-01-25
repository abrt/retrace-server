subdir('backends')
subdir('hooks')

configuration = configuration_data()

configuration.set('CREATEREPO_BIN', createrepo.full_path())
configuration.set('DF_BIN', df.full_path())
configuration.set('GZIP_BIN', gzip.full_path())
configuration.set('LSOF_BIN', lsof.full_path())
configuration.set('PODMAN_BIN', podman.full_path())
configuration.set('PS_BIN', ps.full_path())
configuration.set('TAR_BIN', tar.full_path())
configuration.set('XZ_BIN', xz.full_path())

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
