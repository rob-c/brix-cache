# Client — XRootD client tools (xrdcp, xrdfs) for running tests against servers
ARG BRIX_RUNTIME_IMAGE=almalinux:9-minimal
FROM ${BRIX_RUNTIME_IMAGE}

ARG BRIX_OS_TARGET=alma9
ARG BRIX_ENABLE_CEPH_SIG=0
ARG BRIX_CEPH_SIG_RELEASE=tentacle
COPY k8s-tests/lib/el-target.sh /tmp/el-target.sh

RUN bash /tmp/el-target.sh \
    && dnf install -y \
        xrootd-client voms-libs curl openssl \
        && dnf clean all

WORKDIR /test
COPY k8s-tests/test-runner/conftest.py ./conftest.py 2>/dev/null || true

CMD ["xrdcp", "--help"]
