sources = [
  '__init__.py',
  'centos.py',
  'fedora.py',
  'rhel.py',
]

foreach file: sources
  configure_file(
    copy: true,
    input: file,
    output: file,
  )
endforeach

install_data(sources,
  install_dir: join_paths(datadir, meson.project_name(), 'plugins'),
)
