custom_target('retrace-server.info',
  build_by_default: true,
  command: [
    makeinfo,
    # Can be removed when Autotools support is nuked: it’s the inclusion of version.texi.
    '--force',
    '--output=@OUTPUT@',
    '-D', 'VERSION @0@'.format(meson.project_version()),
    '-D', 'UPDATED @0@"'.format(run_command(date, '--iso-8601').stdout()),
    '@INPUT@',
  ],
  input: 'retrace-server.texi',
  install: true,
  install_dir: get_option('infodir'),
  output: 'retrace-server.info',
)
