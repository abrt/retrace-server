dnf = find_program('dnf')
gcore = find_program('gcore')
podman = find_program('podman')
rpm = find_program('rpm')

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
test_env.append('PATH',
  join_paths(build_dir, 'src')
)
test_env.set('RETRACE_SERVER_CONFIG_PATH',
  join_paths(source_dir, 'src', 'config', 'retrace-server.conf')
)
test_env.set('RETRACE_SERVER_PLUGIN_DIR',
  join_paths(build_dir, 'src', 'plugins')
)
test_env.set('RETRACE_SERVER_TESTING', '1')

test('basic test',
  python_installation,
  args: [files('run_test.py'), '--delete-repo'],
  env: test_env,
  timeout: 300 # 5 minutes
)
