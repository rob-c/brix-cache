# Official XRootD reference server for integration testing.
#
# Supports three auth modes selected at runtime via AUTH_MODE env var:
#   anonymous  — no authentication (default)
#   gsi        — x509 proxy certificate (GSI) via XrdSecgsi.so
#   token      — WLCG JWT / SciTokens via XrdAccSciTokens.so
#   both       — GSI and token accepted in parallel
#
# PKI material is mounted via Kubernetes Secrets at /etc/grid-security/.
# See k8s-tests/k8s-manifests/xrootd-reference/ for deployment manifests.
FROM almalinux:9 AS base

# Install EPEL first so xrootd packages are available.
RUN dnf install -y epel-release && dnf clean all

RUN dnf install -y \
        xrootd-server \
        xrootd-secsss \
        xrootd-scitokens \
        voms-libs \
        openssl \
        ca-certificates \
        python3 \
        python3-pip \
        jq \
        && dnf clean all

# SciTokens Python library is needed by some xrootd token validation paths.
RUN pip3 install --no-cache-dir scitokens cryptography

# Data directory that will be exposed over XRootD.
RUN mkdir -p /data/xrootd && chmod 1777 /data/xrootd

# Grid-security layout expected by GSI:
#   /etc/grid-security/certificates/   — CA bundle + hash symlinks
#   /etc/grid-security/hostcert.pem    — server EE certificate
#   /etc/grid-security/hostkey.pem     — server private key (0400, root)
#   /etc/grid-security/vomsdir/        — VOMS LS files (optional)
RUN mkdir -p \
        /etc/grid-security/certificates \
        /etc/grid-security/vomsdir \
        /etc/xrootd \
        /var/run/xrootd \
        /var/spool/xrootd/admin

COPY Dockerfiles/xrootd-reference/xrootd-anon.cf   /etc/xrootd/xrootd-anon.cf
COPY Dockerfiles/xrootd-reference/xrootd-gsi.cf    /etc/xrootd/xrootd-gsi.cf
COPY Dockerfiles/xrootd-reference/xrootd-token.cf  /etc/xrootd/xrootd-token.cf
COPY Dockerfiles/xrootd-reference/xrootd-both.cf   /etc/xrootd/xrootd-both.cf
COPY Dockerfiles/xrootd-reference/entrypoint.sh    /entrypoint.sh

RUN chmod +x /entrypoint.sh

# 1094: cleartext XRootD  1095: TLS XRootD  9100: Prometheus metrics (optional)
EXPOSE 1094 1095 9100

ENV AUTH_MODE=anonymous \
    DATA_DIR=/data/xrootd \
    XROOTD_PORT=1094

ENTRYPOINT ["/entrypoint.sh"]
