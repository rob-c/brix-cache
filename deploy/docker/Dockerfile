# deploy/docker/Dockerfile — the published BriX-Cache server image.
#
# One image, every deployment mode: nginx 1.28.x with the brix module compiled
# in (stream + http planes), the native client tools (xrdcp, xrdfs, ...) for
# in-container smoke tests, and a demo-PKI minter so a compose stack can run
# TLS/GSI paths with no external material. Built FROM THE REPO ROOT (the
# .dockerignore whitelists the needed trees):
#
#   docker build -t ghcr.io/<org>/brix-cache:dev -f deploy/docker/Dockerfile .
#
# CI publishes it from .github/workflows/image.yml; deploy/compose/* consume it.
# The RPM/deb in packaging/ remain the host-install path — this image is the
# container path and compiles the same sources with the same configure flags.
ARG BRIX_BASE_IMAGE=almalinux:9
ARG BRIX_RUNTIME_IMAGE=almalinux:9

# ---------------------------------------------------------------- builder --
FROM ${BRIX_BASE_IMAGE} AS builder
ARG NGINX_VERSION=1.28.3
ARG NGINX_TARBALL_URL=https://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz

# jansson-devel/liburing-devel live in CRB; voms-devel, fuse3-devel in EPEL.
RUN dnf -y install 'dnf-command(config-manager)' \
    && dnf config-manager --set-enabled crb \
    && dnf -y install epel-release \
    && dnf -y install gcc make perl tar gzip curl pkgconf-pkg-config \
        pcre2-devel zlib-devel openssl-devel krb5-devel libxml2-devel \
        libcurl-devel jansson-devel sqlite-devel libzstd-devel \
    && (dnf -y install voms-devel liburing-devel fuse3-devel || true) \
    && dnf clean all

WORKDIR /build
RUN curl -fsSL "$NGINX_TARBALL_URL" -o nginx.tar.gz \
    && tar -xzf nginx.tar.gz && rm nginx.tar.gz

COPY config /build/brix/config
COPY src    /build/brix/src
COPY shared /build/brix/shared
COPY client /build/brix/client

# Same flag set as .github/workflows/build.yml and the RPM spec's
# %nginx_modconfigure (minus =dynamic: the container links statically).
RUN cd "nginx-${NGINX_VERSION}" \
    && ./configure \
        --prefix=/opt/brix \
        --with-stream --with-stream_ssl_module \
        --with-http_ssl_module --with-http_dav_module \
        --with-http_auth_request_module --with-threads \
        --add-module=/build/brix \
    && make -j"$(nproc)" \
    && make install

# Native client tools (xrdcp, xrdfs, xrdcksum, ...) for the smoke clients.
RUN make -C /build/brix/client -j"$(nproc)" \
    && make -C /build/brix/client install-bin PREFIX=/opt/brix

# ---------------------------------------------------------------- runtime --
FROM ${BRIX_RUNTIME_IMAGE}
RUN dnf -y install 'dnf-command(config-manager)' \
    && dnf config-manager --set-enabled crb \
    && dnf -y install epel-release \
    && dnf -y install pcre2 zlib openssl krb5-libs libxml2 libcurl jansson \
        sqlite-libs libzstd curl procps-ng iproute \
    && (dnf -y install voms liburing fuse3-libs || true) \
    && dnf clean all

COPY --from=builder /opt/brix /opt/brix
COPY deploy/compose/common/pki-init.sh /usr/local/bin/brix-pki-init
COPY deploy/docker/entrypoint.sh       /usr/local/bin/brix-entrypoint
RUN chmod +x /usr/local/bin/brix-pki-init /usr/local/bin/brix-entrypoint \
    && ln -s /opt/brix/sbin/nginx /usr/local/bin/nginx \
    && for b in /opt/brix/bin/*; do ln -sf "$b" /usr/local/bin/; done \
    && mkdir -p /etc/brix/pki /data /var/cache/brix /var/lib/brix/creds \
                /var/lib/brix/state /var/log/brix /run/brix

# 1094 root://   2811 gsiftp://   8443 davs://+httpg   9000 S3   9100 metrics
EXPOSE 1094 1213 2811 8443 9000 9100
VOLUME ["/data", "/var/cache/brix", "/etc/brix/pki"]
ENV BRIX_CONF=/etc/brix/nginx.conf
ENTRYPOINT ["/usr/local/bin/brix-entrypoint"]
CMD ["nginx"]
