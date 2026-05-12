# Client — XRootD client tools (xrdcp, xrdfs) for running tests against servers
FROM almalinux:9-minimal

RUN dnf install -y \
        xrootd-client voms-libs curl openssl \
        && dnf clean all

WORKDIR /test
COPY k8s-tests/test-runner/conftest.py ./conftest.py 2>/dev/null || true

CMD ["xrdcp", "--help"]
