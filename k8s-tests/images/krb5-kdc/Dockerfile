# krb5-kdc — MIT KDC running the repo's kdc_helpers.py realm, publishing its
# krb5.conf + service keytab into the release namespace on startup.
ARG BRIX_BASE_IMAGE=almalinux:9
FROM ${BRIX_BASE_IMAGE}
ARG TARGETARCH
ARG BRIX_OS_TARGET=alma9
ARG BRIX_ENABLE_CEPH_SIG=0
ARG BRIX_CEPH_SIG_RELEASE=tentacle
COPY k8s-tests/lib/el-target.sh /tmp/el-target.sh
RUN bash /tmp/el-target.sh \
    && dnf install -y krb5-server krb5-workstation python3.12 python3.12-pip \
    && alternatives --install /usr/bin/python3 python3 /usr/bin/python3.12 1 \
    && dnf clean all
RUN curl -fsSLo /usr/local/bin/kubectl \
        "https://dl.k8s.io/release/v1.37.2/bin/linux/${TARGETARCH}/kubectl" \
    && chmod +x /usr/local/bin/kubectl
COPY tests/ /opt/brix/tests/
COPY brixtest/ /opt/brix/brixtest/
RUN python3 -m pip install --no-cache-dir /opt/brix/brixtest
WORKDIR /opt/brix
CMD ["/bin/bash","-lc","\
    export TEST_ROOT=${TEST_ROOT:-/work} && mkdir -p \"$TEST_ROOT\" && \
    python3 tests/kdc_helpers.py up && \
    KRB5_CONF=$(python3 -c 'import sys;sys.path.insert(0,\"tests\");import kdc_helpers as k;print(k.KRB5_CONF)') && \
    KRB5_KEYTAB=$(python3 -c 'import sys;sys.path.insert(0,\"tests\");import kdc_helpers as k;print(k.KRB5_KEYTAB)') && \
    kubectl create configmap \"$REL-krb5\" -n \"$NS\" --from-file=krb5.conf=\"$KRB5_CONF\" --dry-run=client -o yaml | kubectl apply -f - && \
    kubectl create secret generic \"$REL-pki\" -n \"$NS\" --from-file=brix.keytab=\"$KRB5_KEYTAB\" --dry-run=client -o yaml | kubectl apply -f - || true && \
    sleep infinity"]
