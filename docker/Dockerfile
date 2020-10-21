FROM fedora:32
USER root
RUN dnf --assumeyes install git-core tito && \
    git clone --quiet https://github.com/abrt/retrace-server.git /src && \
    dnf --assumeyes builddep --spec /src/retrace-server.spec && \
    useradd --no-create-home builder && \
    chown --recursive --quiet builder:builder /src
USER builder
WORKDIR /src
RUN tito build --output=rpm --rpm --test

FROM fedora:32 as build
USER root
COPY --from=0 /src/rpm/noarch/retrace-server-*.rpm rpm/
RUN \
    dnf --assumeyes install mod_ssl uwsgi rpm/retrace-server-*.rpm && \
    dnf clean all

FROM build

ENV NAME="Retrace Server" \
    SUMMARY="Application for remote coredump analysis " \
    DESCRIPTION=" Remote service for generating backtraces from coredumps of crashes. \
Supports user space coredumps as well as a kernel coredumps. \
All communication with server can be over a simple HTTP API or via Web UI."

LABEL summary="$SUMMARY" \
      description="$DESCRIPTION" \
      io.openshift.tags="retrace-server,crash,abrt" \
      io.k8s.description="$DESCRIPTION" \
      io.k8s.display-name="Retrace Server" \
      io.openshift.expose-services="8181:TCP" \
      name="$NAME" \
      usage="docker run -d --name retrace-server" \
      maintainer="ABRT devel team <abrt-devel-list@redhat.com>"

# Copy main run script
COPY docker/files/usr/bin /usr/bin
COPY docker/files/usr/libexec /usr/libexec

RUN rm -rf /run/httpd && mkdir /run/httpd && chmod -R a+rwx /run/httpd && \
    sed -i -e"s/Listen\s*80/Listen 8181/i" /etc/httpd/conf/httpd.conf && \
    sed -i -e"s/ErrorLog\s*\"logs\/error_log\"/ErrorLog \"\/var\/log\/retrace-server\/httpd_error_log\"/i" /etc/httpd/conf/httpd.conf && \
    sed -i -e"s/CustomLog\s*\"logs\/access_log\"/CustomLog \"\/var\/log\/retrace-server\/httpd_access_log\"/i" /etc/httpd/conf/httpd.conf && \
    sed -i -e"s/RequireHTTPS\s*=\s*1/RequireHTTPS = 0/i" /etc/retrace-server/retrace-server.conf && \
    echo "cron =  0 -5 -1 -1 -1 /usr/bin/retrace-server-reposync fedora 28 x86_64" >> /etc/uwsgi.ini && \
    chmod g=u /etc/passwd && \
    mkdir -p /run/uwsgi && \
    /usr/libexec/httpd-ssl-gencerts && \
    chmod 644 /etc/pki/tls/private/localhost.key && \
    /usr/libexec/fix-permissions /run/uwsgi && \
    /usr/libexec/fix-permissions /var/log/retrace-server && \
    /usr/libexec/fix-permissions /var/spool/retrace-server

VOLUME /var/spool/retrace-server

EXPOSE 8181
RUN mkdir -p /usr/share/retrace-server/.mock && \
    echo "config_opts['use_nspawn'] = False" > /usr/share/retrace-server/.mock/user.cfg

ENTRYPOINT ["retrace-server-entrypoint"]
CMD ["run_retrace_server"]
