# GridFTP interop client — a real Globus GridFTP client (globus-url-copy) plus
# gfal2 and the VOMS proxy tools, for driving the brix gsiftp:// gateway from
# outside brix's own client code.  Used by
# k8s-tests/remote-suite/tests/test_gridftp_interop.py (container tier).
#
# The point of this image is cross-implementation interop: brix's gateway is
# proven against the *reference* GridFTP client, not against xrdcp, so a framing
# or GSI regression that both sides of brix would agree on still gets caught.
#
# Base is the FULL almalinux:9, not :9-minimal — this is a single-stage image
# that must run `dnf` (via el-target.sh) to install the grid client RPMs, and
# the -minimal base ships only `microdnf` (`dnf: command not found`, build fails
# at el-target.sh). The multi-stage rpm-builder image can use -minimal for its
# runtime stage because its el-target.sh/dnf work happens in the full builder.
ARG BRIX_RUNTIME_IMAGE=almalinux:9
FROM ${BRIX_RUNTIME_IMAGE}

ARG BRIX_OS_TARGET=alma9
COPY k8s-tests/lib/el-target.sh /tmp/el-target.sh

# globus-gass-copy-progs provides globus-url-copy; gfal2-all + gfal2-plugin-
# gridftp + gfal2-util-scripts (EL9 name for the CLI — /usr/bin/gfal-copy, NOT
# gfal2-util) give gfal-copy/gfal-ls a second, independent GridFTP client stack;
# voms-clients mints the VOMS proxy the GSI control channel authenticates with.
RUN bash /tmp/el-target.sh \
    && dnf install -y epel-release \
    && dnf install -y \
        globus-gass-copy-progs \
        gfal2-all gfal2-plugin-gridftp gfal2-util-scripts \
        voms-clients-cpp \
        python3 python3-pip \
        openssl \
    && dnf clean all

# Ship the pytest runtime so the same image hosts the interop suite.
RUN python3 -m pip install --no-cache-dir pytest

# Assemble the /opt/brix runner layout the test-runner chart's job.yaml expects
# (workingDir /opt/brix; runs client-pki-init.sh then `pytest tests/...`):
#   /opt/brix/tests   — remote-suite test tree (conftest.py + settings.py +
#                       test_gridftp_interop.py and helpers)
#   /opt/brix/utils   — make_proxy.py etc. (client-pki-init.sh's UTILS default)
#   /opt/brix/client-pki-init.sh — rebuilds the client PKI/CA trust from the
#                       chart-mounted gridftp-pki Secret at /auth/pki.
COPY k8s-tests/remote-suite/tests/ /opt/brix/tests/
COPY k8s-tests/remote-suite/utils/ /opt/brix/utils/
COPY k8s-tests/tools/client-pki-init.sh /opt/brix/client-pki-init.sh

WORKDIR /opt/brix
# X509_CERT_DIR is overridden by the runner to the CA trust client-pki-init.sh
# rebuilds under $TEST_ROOT/pki/ca; this default keeps the bare image usable.
ENV X509_CERT_DIR=/etc/grid-security/certificates
CMD ["globus-url-copy", "-version"]
