# server — the real nginx-xrootd (brix) module compiled against nginx 1.28.3.
# Strategy A: self-contained in-image compile (no external RPM dependency).
ARG BRIX_BASE_IMAGE=almalinux:9
ARG BRIX_RUNTIME_IMAGE=almalinux:9
FROM ${BRIX_BASE_IMAGE} AS build
ARG BRIX_OS_TARGET=alma9
ARG BRIX_ENABLE_CEPH_SIG=0
ARG BRIX_CEPH_SIG_RELEASE=tentacle
COPY k8s-tests/lib/el-target.sh /tmp/el-target.sh
RUN bash /tmp/el-target.sh \
    && dnf install -y --allowerasing gcc make perl tar gzip which curl \
                      pcre2-devel zlib-devel openssl-devel krb5-devel \
                      libxml2-devel libcurl-devel jansson-devel \
    && (dnf install -y voms-devel || true) \
    && dnf clean all
ARG NGINX_VER=1.28.3
WORKDIR /src
RUN curl -fsSL "https://nginx.org/download/nginx-${NGINX_VER}.tar.gz" | tar xz
COPY . /src/brix
RUN cd "nginx-${NGINX_VER}" \
    && ./configure --with-stream --with-stream_ssl_module --with-http_ssl_module \
        --with-http_dav_module --with-threads --add-module=/src/brix \
    && make -j"$(nproc)" \
    && make install

FROM ${BRIX_RUNTIME_IMAGE}
ARG BRIX_OS_TARGET=alma9
ARG BRIX_ENABLE_CEPH_SIG=0
ARG BRIX_CEPH_SIG_RELEASE=tentacle
COPY k8s-tests/lib/el-target.sh /tmp/el-target.sh
RUN bash /tmp/el-target.sh \
    && dnf install -y --allowerasing pcre2 zlib openssl krb5-libs libxml2 libcurl jansson \
                      xrootd-client \
    && (dnf install -y voms-libs || true) \
    && dnf clean all
COPY --from=build /usr/local/nginx /usr/local/nginx
COPY k8s-tests/images/server/entrypoint.sh /entrypoint.sh
RUN ln -s /usr/local/nginx/sbin/nginx /usr/local/bin/nginx \
    && chmod +x /entrypoint.sh \
    && mkdir -p /data/xrootd /etc/brix
EXPOSE 1094 1095 8443 8080 9100 1096
ENTRYPOINT ["/entrypoint.sh"]
CMD ["nginx", "-g", "daemon off;"]
