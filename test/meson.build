createrepo = find_program('createrepo')
dnf = find_program('dnf')
gcore = find_program('gcore')
rpm = find_program('rpm')

configuration = configuration_data()

configuration.set('CREATEREPO_BIN', createrepo.path())
configuration.set('DNF_BIN', dnf.path())
configuration.set('GCORE_BIN', gcore.path())
configuration.set('RPM_BIN', rpm.path())

configure_file(
  configuration: configuration,
  input: 'run_test.py.in',
  output: 'run_test.py'
)

# TODO: build_root() is deprecated since Meson 0.56.0. Port to
# project_build_root() once the version lands in all supported
# releases.
build_dir = meson.build_root()
# TODO: source_root() is deprecated since Meson 0.56.0. Port to
# project_source_root() once the version lands in all supported
# releases.
source_dir = meson.source_root()

test_env = environment()
test_env.set('PYTHONPATH',
  join_paths(build_dir, 'src')
)
test_env.prepend('PATH',
  join_paths(build_dir, 'src')
)
test_env.set('RETRACE_SERVER_CONFIG_PATH',
  join_paths(source_dir, 'src', 'config', 'retrace-server.conf')
)
test_env.set('RETRACE_SERVER_PLUGIN_DIR',
  join_paths(build_dir, 'src', 'plugins')
)
test_env.set('RETRACE_SERVER_TESTING', '1')

run_test_py = join_paths(build_dir, 'test', 'run_test.py')

test('basic test',
  python_installation,
  args: [run_test_py, '--delete-repo'],
  env: test_env,
  timeout: 300 # 5 minutes
)
