FROM quay.io/centos/centos:stream8

RUN dnf install -y dnf-plugins-core epel-release
RUN dnf config-manager --set-enabled powertools

WORKDIR /src

RUN dnf -y --setopt=tsflags=nodocs install \
    koji \
    python3-coverage \
    python3

### END OF COMMON PART

# enable installation of gettext message objects
RUN rm /etc/rpm/macros.image-language-conf

RUN dnf -y --setopt=tsflags=nodocs install \
    /usr/bin/pg_isready \
    csdiff \
    gzip \
    python3-bugzilla \
    python3-csdiff \
    python3-django3 \
    python3-gssapi \
    python3-jira \
    python3-psycopg2 \
    python3-qpid-proton \
    xz

RUN dnf copr enable -y packit/openscanhub-openscanhub-168

RUN dnf install -y osh-hub openssl

# Setup OpenScanHub settings
COPY osh/hub/settings_local.ci.py /usr/lib/python3.6/site-packages/osh/hub/settings_local.py

RUN cd /etc/httpd/conf && openssl req -newkey rsa:4096 -nodes -keyout localhost.key -x509 -sha256 -days 365 -addext "subjectAltName = DNS:localhost, DNS:localhost, DNS:127.0.0.1" -subj "/C=CZ/ST=/L=/O=Red Hat/OU=Plumbers/CN=localhost" -out localhost.crt

RUN cp /etc/httpd/conf/localhost.crt /etc/pki/ca-trust/source/anchors/ && update-ca-trust

RUN touch /var/log/osh/hub/hub.log && chown apache:apache /var/log/osh/hub/hub.log

EXPOSE 80
EXPOSE 443

RUN sed -i 's#/etc/pki/tls/certs/localhost#/etc/httpd/conf/localhost#g' /etc/httpd/conf.d/ssl.conf
RUN sed -i 's#/etc/pki/tls/private/localhost#/etc/httpd/conf/localhost#g' /etc/httpd/conf.d/ssl.conf

# CMD while true; do sleep 1; done
RUN /usr/lib/python3.6/site-packages/osh/hub/manage.py collectstatic --noinput
CMD containers/hub/run_in_openshift.sh
