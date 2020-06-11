subdir('plugins')
subdir('retrace')

scripts = [
  'coredump2packages',
  'retrace-server-cleanup',
  'retrace-server-reposync',
  'retrace-server-reposync-faf',
  'retrace-server-worker',
  'retrace-server-interact',
  'retrace-server-plugin-checker',
  'retrace-server-task',
  'retrace-server-bugzilla-refresh',
  'retrace-server-bugzilla-query',
]

foreach file: scripts
  configure_file(
    copy: true,
    input: file,
    output: file,
  )
endforeach
install_data(scripts,
  install_dir: bindir,
)

install_data([
    'backtrace.wsgi',
    'create.wsgi',
    'checkpackage.wsgi',
    'delete.wsgi',
    'exploitable.wsgi',
    'index.wsgi',
    'log.wsgi',
    'manager.wsgi',
    'ftp.wsgi',
    'settings.wsgi',
    'start.wsgi',
    'stats.wsgi',
    'status.wsgi',
    'index.xhtml',
    'manager.xhtml',
    'manager_vmcore_task_form.xhtml',
    'manager_usrcore_task_form.xhtml',
    'managertask.xhtml',
    'stats.xhtml',
  ],
  install_dir: join_paths(datadir, meson.project_name())
)

install_data([
    'config/retrace-server.conf',
    'config/retrace-server-hooks.conf',
  ],
  install_dir: join_paths(sysconfdir, meson.project_name())
)
install_data([
    'config/hooks/debuginfo.conf',
    'config/hooks/fail.conf',
    'config/hooks/environment.conf',
    'config/hooks/retrace.conf',
    'config/hooks/start.conf',
    'config/hooks/success.conf',
    'config/hooks/task.conf',
  ],
  install_dir: join_paths(sysconfdir, meson.project_name(), 'hooks')
)
install_data('config/retrace-server-httpd.conf',
  install_dir: join_paths(sysconfdir, 'httpd', 'conf.d')
)
install_data('config/retrace-server',
  install_dir: join_paths(sysconfdir, 'logrotate.d')
)
