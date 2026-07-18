# GridFTP interop client — a real Globus GridFTP client (globus-url-copy) plus
# gfal2 and the VOMS proxy tools, for driving the brix gsiftp:// gateway from
# outside brix's own client code.  Used by
# k8s-tests/remote-suite/tests/test_gridftp_interop.py (container tier).
#
# The point of this image is cross-implementation interop: brix's gateway is
# proven against the *reference* GridFTP client, not against xrdcp, so a framing
# or GSI regression that both sides of brix would agree on still gets caught.
ARG BRIX_RUNTIME_IMAGE=almalinux:9-minimal
FROM ${BRIX_RUNTIME_IMAGE}

ARG BRIX_OS_TARGET=alma9
COPY k8s-tests/lib/el-target.sh /tmp/el-target.sh

# globus-gass-copy-progs provides globus-url-copy; gfal2-all + gfal2-plugin-file
# give gfal-copy/gfal-ls a second, independent GridFTP client stack; voms-clients
# mints the VOMS proxy the GSI control channel authenticates with.
RUN bash /tmp/el-target.sh \
    && dnf install -y epel-release \
    && dnf install -y \
        globus-gass-copy-progs \
        gfal2-all gfal2-plugin-gridftp gfal2-util \
        voms-clients-cpp \
        python3 python3-pip \
        openssl curl \
    && dnf clean all

# The interop driver is copied in at test time or mounted; ship the pytest
# runtime so the same image can host it.
RUN python3 -m pip install --no-cache-dir pytest

WORKDIR /test
ENV X509_CERT_DIR=/etc/grid-security/certificates
CMD ["globus-url-copy", "-version"]
