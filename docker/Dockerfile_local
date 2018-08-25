FROM abrt/retrace-server-image
MAINTAINER mmarusak@redhat.com
ARG fedoraversion=28

USER root

# Copy sources to the docker image
COPY . /retrace-server

# From not on work from retrace-server directory
WORKDIR '/retrace-server'

# Change owner of /retrace-server, clean git and install dependences
RUN chown -R --silent retrace /retrace-server && \
    chmod -R --silent g=u /retrace-server && \
    dnf -y install rpm-build sudo git &&  \
    git clean -dfx && \
    eval dnf -y --setopt=strict=0 --setopt=tsflags=nodocs install $(./autogen.sh sysdeps)

# Build as non root
USER retrace

ENV HOME /retrace-server

# Build retrace-server
RUN ./autogen.sh && \
    ./configure && \
    make rpm

#And continue as root
USER 0

# Update FAF
RUN rpm -Uvh noarch/retrace-server-* && \
    /usr/libexec/fix-permissions /retrace-server && \
    /usr/libexec/fix-permissions /var/log/retrace-server && \
    /usr/libexec/fix-permissions /var/spool/retrace-server && \
    sed -i -e"s/AllowTaskManager\s*=\s*0/AllowTaskManager = 1/i" /etc/retrace-server.conf && \
    sed -i -e"s/RequireGPGCheck\s*=\s*1/RequireGPGCheck = 0/i" /etc/retrace-server.conf && \
    mkdir /var/tmp/local_repo && \
    dnf --releasever=$fedoraversion --enablerepo=\*debuginfo\* -y --installroot=/var/tmp/local_repo/ \
    download --resolve --destdir /var/tmp/local_repo/ abrt-addon-ccpp shadow-utils \
    gdb rpm will-crash

COPY docker/files/plugins /usr/share/retrace-server/plugins

RUN sudo -u retrace retrace-server-reposync fedora $fedoraversion x86_64

#Switch workdir back to /
WORKDIR '/'
