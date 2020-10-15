**If you want to deploy retrace server for testing purposes, please skip to
[Deploying Testing Retrace Server](DEPLOYING.md#deploying-testing-retrace-server)**

# Deploying Retrace Server
1. Install dependencies

    First you should install all dependent packages.

    Dependencies can be listed by:

        $ ./autogen.sh sysdeps

    or installed by:

        $ ./autogen.sh sysdeps --install

    The dependency installer gets the data from [the rpm spec file](retrace-server.spec.in)

2. Build from source

    When you have all dependencies installed you can now build a rpm package by these commands:

        $ ./autogen.sh
        $ make rpm

    Now in the `noarch` folder you can find a rpm package. You can install it by:

        $ rpm -ivh noarch/retrace-server-*.rpm

3. Deploy

    After installing the retrace server, before having a functional retrace server you need
    do a few things:
    1. Add repositories
        If you need to add another distribution, another repository or new url for
        mirror do it in /usr/share/retrace-server/plugins/distribution.py. To
        learn more about writing plugins please read
        [Plugin section in README](README.md#plugins)
   2. Run reposync
        To download packages from repository run (must run as `retrace` user):

            $ sudo -u retrace retrace-server-reposync distribution version architecture

        Don't forget to substitute the last three arguments. You want to run
        this command on all combinations of distribution version and architecture
        always when new packages or new versions are releases. Therefore it is
        recommended to set this into cron.
   3. Open port 443

        To enable communication via https you have to open port 443. You can do so
        by running these commands:

        Open port 443 in the firewall

            # firewall-cmd --permanent --zone=public --add-service=https

        Reload the firewall

            # firewall-cmd --reload

        Make sure that the port is listed

            # firewall-cmd --zone=public --list-ports

   4. Restart httpd

            # service httpd restart

   5. Disable SELinux

            # setenforce 0

   6. Set `subuid` and `subgid` for user `retrace` (optional)
        If you want to use podman as your retrace environment, the user `retrace`
        needs to have `subuid` and `subgid` set in `/etc/subuid` and `/etc/subgid`
        respectively. See `man 5 /etc/subuid` and the `SUB_UID_...` section in `man useradd`.

   7. Set up your system to use cgroups v1 (optional)
        You might need to do this if you want to use podman. For example:

            # grubby --update-kernel=ALL --args="systemd.unified_cgroup_hierarchy=0"

        followed by a reboot.

   8. Make sure the `retrace` user's home directory is set to `/var/lib/retrace`
        when updating from an older version of retrace-server.


4. Test your server

    There are two ways how to test if your server is running:

    * Abrt Plugin

        There is
        [plugin](https://github.com/abrt/abrt/blob/master/src/plugins/abrt-retrace-client.c)
        in ABRT that should be available in your system if you have ABRT installed.
        See `abrt-retrace-client -h` to learn more.

    * Web UI

        You should be able to see front page by visiting https://my_server

        There also exist a Web UI for assigning retrace task. It can be found
        under `\manager`, but firstly must be enabled in configuration file.

            open /etc/retrace-server/retrace-server.conf

            set `AllowTaskManager = 1`

        Mind that this a security risk and should not be enabled in production servers.


# Deploying testing Retrace Server
When deploying retrace server only for testing purposes, you don't want to
have all packages from all repositories. You only need some packages, so you
can retrace one or two coredumps. In this section a simple tutorial is written
how to deploy such a server. Each point corresponds with point from section
[Deploying Retrace Server](DEPLOYING.md#deploying-retrace-server).

1. Install dependencies

    There is no change when deploying real and testing retrace server.

2. Build from source

    There is no change when deploying real and testing retrace server.

3. Deploy

    1. Add repositories

        This is **the main difference**. Since you don't want to have all
        packages from fedora, you should **NOT** run commands like

            $ retrace-server-reposync fedora version architecture

        You only need a few packages (and their dependencies). Therefore you should
        create a local repository, download only necessary packages there and
        tell retrace-server that this is your repository. Here is how you can do it.

        1. Create a new folder and call it for example `local_repo`

            `$ mkdir /var/tmp/local_repo`

        2. Now you have to download packages into that folder. If you have yours
        coredump, find out which package it comes from - it will be later marked
        as *my-packages*.

        Run this:

            # dnf --releasever=25 --enablerepo=\*debuginfo\* -y --installroot=/var/tmp/local_repo/ \
            download --resolve --destdir /var/tmp/local_repo/ abrt-addon-ccpp shadow-utils \
            gdb rpm *my-packages*

        Then if you look into `/var/tmp/local_repo` you should see a few packages.

        It is your own local repository. Now you need to create a plugin for it.
        Easiest way is to copy existing plugin and create changes in it.

            $ cd /usr/share/retrace-server/plugins/
            # cp fedora.py local.py

        Now open `/usr/share/retrace-server/plugins/local.py` in your favourite
        text editor and do the following changes:
            All occurances of word `Fedora` replace by `Local`, all `fedora` by
            `local` and you only want one repository with one mirror, so your
            `repos` part should look like this:

               repos = [
                   [
                       "/var/tmp/local_repo"
                   ]
               ]
   2. Run reposync

        `$ sudo -u retrace retrace-server-reposync local 25 x86_64`

   3. Open port 443

        There is no change when deploying real and testing retrace server.

   4. Restart httpd

        There is no change when deploying real and testing retrace server.

   5. Disable SELinux

        There is no change when deploying real and testing retrace server.

   6. Set `subuid` and `subgid` for user `retrace` (optional)

        There is no change when deploying real and testing retrace server.

   7. Set up your system to use cgroups v1 (optional)

        There is no change when deploying real and testing retrace server.

   8. Make sure the `retrace` user's home directory is set to `/var/lib/retrace`

        There is no change when deploying real and testing retrace server.


4. Test your server

    You should be able to test your server the same way as when server deployed
    normally. Only difference would be, that you cannot update just any coredump.
    The package from which the crashing app comes must be in your repository.
    You can download it later and run `reposync` again and you should be good
    to go. And do not forget, your release is now called `Local release 25 (Twenty five)`.


##Most often problems mainly when testing retrace server deployed

* Submitting coredump via manager from local folder and retrace server cannot find it

    Create tarball of the coredump `tar -cf coredump.tar coredump` and put it
    into /var or /var/spool. Then put path as `file:///var/(spool/)coredump.tar`

* Task fails on running mock (last command starts with /usr/bin/mock init --resultdir...)

    There is a lot of possibilites, but most often it is one of two:

      * You have not enough space in `/usr/lib/mock`

      * A gpg check failed. Set `RequireGPGCheck = 0` in `/etc/retrace-server/retrace-server.conf`
        and restart httpd.
