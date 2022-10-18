project('retrace-server', license : 'GPL2+', meson_version : '>= 0.49.0', version : '1.24.2')

bindir = get_option('bindir')
datadir = get_option('datadir')
mandir = get_option('mandir')
sysconfdir = get_option('sysconfdir')

spec_name = '@0@.spec'.format(meson.project_name())

i18n = import('i18n')
python = import('python')

python_installation = python.find_installation('python3')

asciidoc = find_program('asciidoc',
  required: get_option('docs'),
  disabler: true,
)
createrepo = find_program('createrepo')
date = find_program('date',
  required: get_option('docs'),
  disabler: true,
)
df = find_program('df')
gzip = find_program('gzip')
lsof = find_program('lsof')
makeinfo = find_program('makeinfo',
  required: get_option('docs'),
  disabler: true,
)
podman = find_program('podman',
  required: false,
  disabler: true,
)
pytest = find_program('pytest-3')
ps = find_program('ps')
tar = find_program('tar')
tito = find_program('tito',
  required: false,
  disabler: true,
)
unar = find_program('unar',
  required: false,
  disabler: true,
)
xmlto = find_program('xmlto',
  required: get_option('docs'),
  disabler: true,
)
xz = find_program('xz')

subdir('doc')
subdir('man')
subdir('po')
subdir('src')
subdir('test')

# Copy the spec file to the build directory so that Tito can run inside it to build
# the rpm and srpm targets (below).
configure_file(
  copy: true,
  input: spec_name,
  output: spec_name,
)

configure_file(
  copy: true,
  input: 'pylintrc',
  output: 'pylintrc',
)

# This will, naturally, fail if the build directory is outside the git repo,
# since Tito does not provide a way to specify the working directory or the spec
# file using the CLI.
run_target('rpm',
  command: [
    tito,
    'build',
    '--offline',
    '--output=@0@/rpm'.format(meson.current_build_dir()),
    '--rpm',
    '--test'
  ],
)
run_target('srpm',
  command: [
    tito,
    'build',
    '--offline',
    '--output=@0@/rpm'.format(meson.current_build_dir()),
    '--srpm',
    '--test'
  ],
)
