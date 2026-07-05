# brix-client — runs the copied suite against a remote server, with real pyxrootd.
# pytest runs on python3.12 (the suite uses 3.10+ typing); the XrdCl worker runs
# on python3.9 (where EPEL's python3-xrootd C extension is installed).
FROM almalinux:9
RUN dnf install -y epel-release \
    && dnf install -y --allowerasing python3.12 python3.12-pip \
                      python3-xrootd xrootd-client openssl krb5-workstation \
    && alternatives --install /usr/bin/python3 python3 /usr/bin/python3.12 1 \
    && curl -fsSLo /usr/local/bin/kubectl "https://dl.k8s.io/release/v1.31.4/bin/linux/amd64/kubectl" \
    && chmod +x /usr/local/bin/kubectl \
    && dnf clean all
# kubernetes: the rewritten klib.py reaches server-side files via the k8s client
# (in-cluster config) instead of shelling out to kubectl.
RUN python3.12 -m pip install --no-cache-dir pytest pytest-timeout requests cryptography pyjwt kubernetes
WORKDIR /opt/brix
COPY k8s-tests/remote-suite/ /opt/brix/
COPY k8s-tests/tools/client-pki-init.sh /opt/brix/client-pki-init.sh
COPY k8s-tests/images/client/client-entry.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh /opt/brix/client-pki-init.sh
ENV PYTHONPATH=/opt/brix/tests \
    TEST_ROOT=/tmp/tr \
    XRDCL_WORKER_PYTHON=/usr/bin/python3.9 \
    XrdSecGSISRVNAMES=*
ENTRYPOINT ["/entrypoint.sh"]
CMD ["/bin/bash"]
