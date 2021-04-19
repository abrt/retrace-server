sources = [
  '__init__.py',
  'podman.py',
]

foreach file: sources
  configure_file(
    copy: true,
    input: file,
    output: file,
  )
endforeach

python_installation.install_sources(sources,
  subdir: join_paths('retrace', 'backends'),
  pure: true,
)
