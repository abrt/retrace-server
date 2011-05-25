#include <config.h>
#include <stdio.h>
#include <ctype.h>
#include <pwd.h>
#include <stdlib.h>
#include <unistd.h>

/*
 * Launches Retrace Server worker (worker.py) with root permissions.
 */

int main(int argc, char **argv)
{
  if (argc != 2)
  {
    fprintf(stderr, "Usage: %s task_id\n", argv[0]);
    return 1;
  }

  if (setuid(0) != 0)
  {
    fprintf(stderr, "You must run %s with root permissions.\n", argv[0]);
    return 2;
  }

  int i;
  for (i = 0; argv[1][i]; ++i)
    if (!isdigit(argv[1][i]))
    {
      fputs("Task ID may only contain digits.", stderr);
      return 3;
    }

  const char *apache_username = "apache";
  struct passwd *apache_user = getpwnam(apache_username);
  if (!apache_user)
  {
    fprintf(stderr, "User \"%s\" not found.\n", apache_username);
    return 4;
  }

  char uid[16];
  sprintf(uid, "%d", apache_user->pw_uid);

  setenv("SUDO_USER", apache_username, 1);
  setenv("SUDO_UID", uid, 1);
  /* required by mock to be able to write into result directory */
  setenv("SUDO_GID", "0", 1);

  /* fork and launch worker.py */
  pid_t pid = fork();

  if (pid < 0)
  {
    fputs("Unable to fork.", stderr);
    return 6;
  }

  /* parent - exit */
  if (pid > 0)
      return 0;

  /* child - execute worker.py */
  execlp("/usr/bin/python", "/usr/bin/python", "/usr/share/retrace-server/worker.py", argv[1], NULL);

  /* execlp failed */
  fputs("execlp failed.", stderr);
  return 5;
}
