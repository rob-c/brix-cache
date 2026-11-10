# authority — provisioning tools + static HTTP distributor for the auth plane.
ARG BRIX_BASE_IMAGE=almalinux:9
FROM ${BRIX_BASE_IMAGE}
ARG TARGETARCH
ARG BRIX_OS_TARGET=alma9
ARG BRIX_ENABLE_CEPH_SIG=0
ARG BRIX_CEPH_SIG_RELEASE=tentacle
COPY k8s-tests/lib/el-target.sh /tmp/el-target.sh
RUN bash /tmp/el-target.sh \
    && dnf install -y python3.12 python3.12-pip openssl nginx \
                      krb5-server krb5-workstation \
    && alternatives --install /usr/bin/python3 python3 /usr/bin/python3.12 1 \
    && (dnf install -y voms-clients || true) \
    && dnf clean all
RUN python3 -m pip install --no-cache-dir cryptography pyjwt
RUN curl -fsSLo /usr/local/bin/kubectl \
        "https://dl.k8s.io/release/v1.37.2/bin/linux/${TARGETARCH}/kubectl" \
    && chmod +x /usr/local/bin/kubectl
WORKDIR /opt/brix
COPY tests/ /opt/brix/tests/
COPY utils/ /opt/brix/utils/
COPY brixtest/ /opt/brix/brixtest/
RUN python3 -m pip install --no-cache-dir /opt/brix/brixtest
COPY k8s-tests/images/authority/serve.conf /etc/nginx/nginx.conf
RUN mkdir -p /srv/dist/crl /srv/dist/certs /srv/dist/voms
EXPOSE 8080
CMD ["nginx", "-g", "daemon off;"]
