# deploy/cvmfs/docker/Dockerfile — self-contained CVMFS site-cache demo.
#
# One CentOS Stream 9 container proving the whole phase-68 stack coexists in
# a single nginx config:
#   :3128  cvmfs:// site cache, forward-proxy mode (CVMFS_HTTP_PROXY target)
#          with the bad-actor guard active on the listener
#   :3129  built-in operator dashboard
#   :3130  Prometheus /metrics + /healthz
#   fail2ban inside the container consuming the cvmfs-reject + guard audit logs
#
# Build FROM THE REPO ROOT (the .dockerignore whitelists config/ + src/):
#   docker build -t nginx-xrootd-cvmfs -f deploy/cvmfs/docker/Dockerfile .
# Run (NET_ADMIN lets fail2ban install real nftables bans):
#   docker run -d --name cvmfs-demo --cap-add=NET_ADMIN \
#       -p 3128:3128 -p 3129:3129 -p 3130:3130 nginx-xrootd-cvmfs
#
# See README.md in this directory for client configuration.

# ---------------------------------------------------------------- builder --
FROM quay.io/centos/centos:stream9 AS builder

ARG NGINX_VERSION=1.28.3
ARG NGINX_TARBALL_URL=https://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz

# jansson-devel lives in CRB on EL9
RUN dnf -y install dnf-plugins-core \
    && dnf config-manager --set-enabled crb \
    && dnf -y install gcc make pcre2-devel zlib-devel openssl-devel tar gzip \
        libxml2-devel jansson-devel libcurl-devel \
    && dnf clean all

COPY config /src/nginx-xrootd/config
COPY src    /src/nginx-xrootd/src

RUN curl -fsSL "$NGINX_TARBALL_URL" -o /tmp/nginx.tar.gz \
    && tar -xzf /tmp/nginx.tar.gz -C /tmp \
    && cd "/tmp/nginx-${NGINX_VERSION}" \
    && ./configure \
        --prefix=/opt/nginx-xrootd \
        --with-stream \
        --with-stream_ssl_module \
        --with-http_ssl_module \
        --with-http_dav_module \
        --with-threads \
        --add-module=/src/nginx-xrootd \
    && make -j"$(nproc)" \
    && make install

# ---------------------------------------------------------------- runtime --
FROM quay.io/centos/centos:stream9

# fail2ban lives in EPEL; nftables backs the ban action; python3 runs the
# optional offline mock Stratum-1 (MOCK_STRATUM1=1).
RUN dnf -y install epel-release \
    && dnf -y install fail2ban-server nftables python3 procps-ng iproute \
        libxml2 jansson \
    && dnf clean all
    # (libcurl-minimal in the base image provides libcurl.so.4 for the module)

COPY --from=builder /opt/nginx-xrootd /opt/nginx-xrootd

# fail2ban: the committed filters + the demo jail template (entrypoint picks
# the ban action based on the container's actual capabilities).
COPY deploy/fail2ban/filter.d/ /etc/fail2ban/filter.d/
COPY deploy/cvmfs/docker/jail.local.in /etc/fail2ban/jail-nginx-xrootd.local.in

COPY deploy/cvmfs/docker/nginx.conf.in /opt/nginx-xrootd/conf/nginx.conf.in
COPY tests/cvmfs/mock_stratum1.py      /opt/demo/mock_stratum1.py
COPY deploy/cvmfs/docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 3128 3129 3130
VOLUME /var/cache/nginx-cvmfs

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
    CMD curl -fsS http://127.0.0.1:3130/healthz || exit 1

ENTRYPOINT ["/entrypoint.sh"]
