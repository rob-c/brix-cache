# test-runner — pytest + the repo tests tree + xrootd clients, run against the
# deployed lab via TEST_* env pointed at cluster Service DNS.
ARG BRIX_BASE_IMAGE=almalinux:9
FROM ${BRIX_BASE_IMAGE}
ARG BRIX_OS_TARGET=alma9
ARG BRIX_ENABLE_CEPH_SIG=0
ARG BRIX_CEPH_SIG_RELEASE=tentacle
# The suite uses 3.10+ typing (X | None), so ship Python 3.12 as python3.
COPY k8s-tests/lib/el-target.sh /tmp/el-target.sh
RUN bash /tmp/el-target.sh \
    && dnf install -y --allowerasing python3.12 python3.12-pip xrootd-client openssl krb5-workstation \
    && alternatives --install /usr/bin/python3 python3 /usr/bin/python3.12 1 \
    && dnf clean all
RUN python3.12 -m pip install --no-cache-dir pytest pytest-timeout requests cryptography pyjwt
WORKDIR /opt/brix
COPY tests/ /opt/brix/tests/
COPY utils/ /opt/brix/utils/
# client-PKI init: lays out $TEST_ROOT/pki + tokens from the mounted authority
# material so gsi/token tests find client certs, a proxy, CA trust, and JWKS.
COPY k8s-tests/tools/client-pki-init.sh /opt/brix/client-pki-init.sh
ENV PYTHONPATH=/opt/brix/tests
CMD ["/bin/bash"]
