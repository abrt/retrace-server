# Retrace Server

[![Translation status](https://translate.fedoraproject.org/widgets/abrt/-/retrace-server/svg-badge.svg)](https://translate.fedoraproject.org/engage/abrt/)
[![Language grade: Python](https://img.shields.io/lgtm/grade/python/g/abrt/retrace-server.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/abrt/retrace-server/context:python)
[![Total alerts](https://img.shields.io/lgtm/alerts/g/abrt/retrace-server.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/abrt/retrace-server/alerts/)
[![codecov](https://codecov.io/gh/abrt/retrace-server/branch/master/graph/badge.svg?token=AHUkZe3dV6)](https://codecov.io/gh/abrt/retrace-server)

---

Remote service for generating backtraces from coredumps of crashes. Supports
user space coredumps as well as a kernel coredumps. All communication with
server can be over a simple HTTP API or via Web UI.

## About
For generating a backtrace from a coredump following files are needed:
* Source (binary) of the crashed application (or kernel)
* Source (binary) of all libraries involved in the crash
* Debuginfo of the source
* Debuginfo of all libraries involved in the crash

All of these files must be in the same version in which the crash happened.
That can be a problem after update, since the older packages can be removed
from repositories after a newer version is available (and they usually are).
Another problem is having debuginfos - normally user does not need them and
they take a lot of space.

All of these problems are solved by Retrace Server. In conclusion Retrace Server's
benefits are:
* Less disk space and processing time needed for generating backtrace
* Possibility to generate backtrace from older/random crash
* Higher quality of backtraces (always the correct debuginfo files)

These benefits are crucial when reporting bugs via ABRT.

## Development and Deployment
* [Bug Reports and RFEs](https://github.com/abrt/retrace-server/issues)
* IRC Channel: #abrt on [irc.libera.chat](https://libera.chat/)
* [Contributing to Retrace Server](CONTRIBUTING.md)
* [Deploying Retrace Server](DEPLOYING.md)

## How it works
Retrace server consists of three parts:
* [HTTP API](#http-api) handles communication with client
* [Analyzer](#analysis) takes coredump and returns backtrace
* [Repository synchronization](#repository-synchronization) downloads and
stores all versions of packages

### HTTP API
The HTTP API is one of two ways how to communicate with Retrace Server (another
 is via Web UI). Communication is based on sanding standard HTTP POST and GET methods.

There is a plugin in ABRT called [abrt-retrace-client](https://github.com/abrt/abrt/blob/master/src/plugins/abrt-retrace-client.c)
 which wraps the API and makes communication for end-user easier.

In the following text the API is described.

**Creating task**

A client might create a new task by sending an HTTP request to the
https://server/create URL providing an archive as the request content.
The archive must contain crash data files. The crash data files are a subset
of the local /var/spool/abrt/ccpp-time-pid/ directory contents, so the client
must only pack and upload them. The HTTP request for a new task must use the
POST method. It must contain a proper 'Content-Length' and 'Content-Type'
fields.

If the creation was successful and all checks on server passed, the server
HTTP response is "201 Created" HTTP code. The response includes the following
HTTP header fields:
* "X-Task-Id" containing a new server-unique numerical task id
* "X-Task-Password" containing a newly generated password, required to access
the result

**Task status**

A client might request a task status by sending a HTTP GET request to the
https://server/\<id\> URL, where \<id\> is the numerical task id returned in the
"X-Task-Id" field by https://server/create.

The client request must contain the "X-Task-Password" field, and its content
must match the password sent in response after creating task.

The server returns the "200 OK" HTTP code, and includes a field
"X-Task-Status" containing one of the following values:
* FINISHED_SUCCESS - retrace finished successfully and backtrace is ready
* FINISHED_FAILURE - retrace finished unsuccessfully
* PENDING - retracing is in progress

**Requesting a backtrace**

A client might request a backtrace by sending a HTTP GET request to the
https://server/\<id\>/backtrace URL, where \<id\> is the numerical task id
returned in the "X-Task-Id" field by https://server/create.

The client request must contain the "X-Task-Password" field, and its
content must match the password sent in response after creating task.

If the backtrace does not exist, the server returns the "404 Not Found" HTTP
error code.  Otherwise it returns the backtrace.

**Requesting a log**

A client might request a task log by sending a HTTP GET request to the
https://server/\<id\>/log URL, where \<id\> is the numerical task id
returned in the "X-Task-Id" field by https://server/create.

The client request must contain the "X-Task-Password" field, and its
content must match the password sent in response after creating task.

The server returns a text representation of the log.

### Analysis

The server prepares a new chroot environment by using mock. This means that
a new folder is created, most likely with path like `/var/lib/mock/\<id\>/root/'.
Content of this directory looks very similiar to the `\` directory. All important
programs are installed into appropriate destination - so if we would found
gdb in `/usr/bin/gdb`, it would be installed into `/var/lib/mock/\<id\>/root/usr/lib/gdb`.

After the directory is prepared, the coredump is moved there and
root is changed (using the chroot system function). In this chrooted environment
gdb is run on the coredump. In this environment the gdb sees the corresponding
crashy binary, all debuginfos and all the proper versions of libraries on
right places.

When the gdb run is finished, a backtrace is saved into
`SaveDir/\<id\>/backtrace` file as well as a log from the whole
chroot process is saved to the retrace-log file in the same directory. SaveDir
is a variable in configuration file.

### Repository-synchronization
Since older versions of packages are deleted from public repositories,
Retrace Server needs to maintain local copies of repositories containing all
versions of all packages. This job is realized by retrace-server-reposync tool
by running 'retrace-server-reposync distribution version architecture' where
'distribution' is a plugin name (see [Plugins](#plugins)). The
retrace-server-reposync tool should be set up in retrace's crontab.

### Plugins

Each supported distribution needs to have its proper plugin. The plugin
itself consists of 2 parts:

**1. Plugin file**

A python file dropped in /usr/share/retrace-server/plugins containing the
following elements:

        distribution:   String considered plugin name and identifier.

        abrtparser:     Parser able to get release from ABRT's os_release file.

        guessparser:    Parser able to guess release from package's name. Can not
                        be relied on (e.g. el6 does not give enough information).

        dnfcfg:         A string that will be appended to dnf config file for all
                        repositories

        displayrelease: Name of release for displaying in statistics page

        versionlist:    List of all versions that can be shown in statistics page

        gdb_package:    Name of package, from which the gdb comes from

        gdb_executable: Path to the gdb executable

        repos:          An array of public repositories and their mirrors.
                        The synchronization is realized using rsync or dnf, so
                        repository path is either a directory in the filesystem,
                        rsync:// URL, http:// URL or ftp:// URL. $ARCH and $VER
                        meta-variables are expanded to appropriate strings.
                        The repo is either defined as list of mirrors or
                        a two-member tuple where the first member is the same
                        list of mirrors and second is a part of dnf config file
                        that will only be appended to the repo.
                        Example:
                        repos = [
                          [ #repo1
                            /srv/repos/repo1_mirror1,
                            rsync://repo1/mirror2,
                          ],
                          [ #repo2
                            ftp://repo2/repo2_mirror1,
                            /srv/repos/repo2_mirror2,
                          ],
                          [ #repo3
                            rsync://repo3/mirror1,
                          ],
                          ( #repo4
                            [
                              "rsync://repo4/mirror1",
                              "http://repo4/mirror2",
                            ],
                            "gpgcheck = 0", # local dnf config
                          ),
                        ]

