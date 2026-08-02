# Server — nginx-xrootd deployment image with full PKI tooling.
# Needs a dnf-capable base: el-target.sh + the runtime install below both drive
# `dnf` (config-manager, crb, epel — xrootd-client lives in EPEL). almalinux:9
# ships dnf; the :9-minimal variant ships only microdnf (no config-manager /
# dnf-command plugin), so el-target.sh exits 127 there. The rpm-builder uses
# minimal only for its artifact-copy final stage, which never runs dnf.
ARG BRIX_RUNTIME_IMAGE=almalinux:9
FROM ${BRIX_RUNTIME_IMAGE} AS base

ARG BRIX_OS_TARGET=alma9
# The brix module hard-links librados / libradosstriper (ceph backend), so the
# runtime image MUST carry those libs — they live only in the CentOS Storage SIG
# Ceph repo, hence SIG on by default. Pin to squid: it is the release the module
# RPM is built against (rpm-builder) and is mirror-published; the default
# `tentacle` (ceph 20) is not yet on the SIG mirror.
ARG BRIX_ENABLE_CEPH_SIG=1
ARG BRIX_CEPH_SIG_RELEASE=squid
COPY k8s-tests/lib/el-target.sh /tmp/el-target.sh

# Runtime shared libs the module NEEDs (readelf -d ngx_stream_brix_module.so):
# jansson (libjansson.so.4), libbrotli (libbrotli{enc,dec}.so.1), liburing
# (liburing.so.2), and the ceph client libs librados2 / libradosstriper1. Without
# these the module dlopen fails at `load_module` (libjansson.so.4: not found).
RUN bash /tmp/el-target.sh \
    && dnf install -y --allowerasing \
        nginx nginx-mod-stream curl openssl voms xrootd-client \
        jansson libbrotli liburing librados2 libradosstriper1 \
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
