sources = [
  '__init__.py',
  'config.py',
  'hooks.py',
]

foreach file: sources
  configure_file(
    copy: true,
    input: file,
    output: file,
  )
endforeach

python_installation.install_sources(sources,
  subdir: join_paths('retrace', 'hooks'),
  pure: true,
)
