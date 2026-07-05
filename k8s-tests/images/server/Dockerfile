# server — the real nginx-xrootd (brix) module compiled against nginx 1.28.3.
# Strategy A: self-contained in-image compile (no external RPM dependency).
FROM almalinux:9 AS build
RUN dnf install -y epel-release dnf-plugins-core \
    && dnf config-manager --set-enabled crb \
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

FROM almalinux:9
RUN dnf install -y epel-release \
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
