templates = [
    'retrace-server-cleanup.txt',
    'retrace-server-interact.txt',
    'retrace-server-reposync.txt',
    'retrace-server-worker.txt',
    'retrace-server-task.txt',
]

foreach template : templates
    base_name = template.split('.')[0]
    xml_output = base_name + '.xml'
    docbook = custom_target(xml_output,
      command: [
        asciidoc,
        '--backend=docbook',
        '--doctype=manpage',
        '--conf-file=@0@'.format(join_paths(meson.current_source_dir(), 'asciidoc.conf')),
        '--attribute=rs_version=' + meson.project_version(),
        '--out-file=@OUTPUT@',
        '@INPUT@',
      ],
      input: template,
      output: xml_output,
    )
    custom_target(base_name + '.1',
      build_by_default: true,
      command: [
        xmlto,
        '-o', '@OUTDIR@',
        'man',
        '@INPUT@'
      ],
      depends: docbook,
      input: docbook,
      install: true,
      install_dir: join_paths(get_option('mandir'), 'man1'),
      output: base_name + '.1',
    )
endforeach
