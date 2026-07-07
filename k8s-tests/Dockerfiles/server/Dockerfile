# Server — nginx-xrootd deployment image with full PKI tooling
ARG BRIX_RUNTIME_IMAGE=almalinux:9-minimal
FROM ${BRIX_RUNTIME_IMAGE} AS base

ARG BRIX_OS_TARGET=alma9
ARG BRIX_ENABLE_CEPH_SIG=0
ARG BRIX_CEPH_SIG_RELEASE=tentacle
COPY k8s-tests/lib/el-target.sh /tmp/el-target.sh

RUN bash /tmp/el-target.sh \
    && dnf install -y \
        nginx curl openssl voms-libs xrootd-client \
        && dnf clean all

ARG RPM_FILE
COPY k8s-tests/rpms/${RPM_FILE} /tmp/ngx-xrootd.rpm

RUN rpm -ivh /tmp/ngx-xrootd.rpm --nodeps 2>/dev/null || true

# Create default data directory and PKI structure
RUN mkdir -p /data/xrootd \
    && mkdir -p /etc/grid-security/certificates \
    && mkdir -p /etc/grid-security/vomsdir

COPY k8s-tests/Dockerfiles/server/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 1094 1095 8443 8080 9100

ENTRYPOINT ["/entrypoint.sh"]
CMD ["nginx", "-g", "daemon off;"]
