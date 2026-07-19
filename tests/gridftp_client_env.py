"""Shared GSI client-environment helper for the globus-url-copy gridftp tests.

Centralises one subtle, easy-to-reintroduce gotcha: how globus-url-copy selects
its client credential when the test fleet runs as root on a real grid node.
"""
import os


def gsi_client_env(cert_dir, proxy, base=None):
    """Build a subprocess env that presents *proxy* as the GSI client credential.

    globus-url-copy honours ``X509_USER_PROXY`` only for a non-root caller.
    Running as uid 0 — which the test fleet does on a real grid worker node — it
    silently IGNORES the proxy and falls back to the host credential at
    ``/etc/grid-security/hostcert.pem``.  On a production grid host that cert is
    issued by a real IGTF CA that is (correctly) absent from the ephemeral test
    trust store, so the gateway rejects it with "unable to get local issuer
    certificate" and every LIST/RETR/STOR fails with ``535 GSSAPI
    authentication failed`` — even though the intended proxy is perfectly valid.

    Pinning ``X509_USER_CERT``/``X509_USER_KEY`` to the same proxy file (which
    carries cert + chain + key) forces globus to present it regardless of uid.
    For a non-root caller the proxy already wins, so the extra vars are inert.
    Security-negative callers pass their forged proxy here too, so CERT/KEY
    always track whatever credential the test deliberately selected.
    """
    env = dict(os.environ if base is None else base)
    env["X509_CERT_DIR"] = str(cert_dir)
    env["X509_USER_PROXY"] = str(proxy)
    if os.geteuid() == 0:
        env["X509_USER_CERT"] = env["X509_USER_PROXY"]
        env["X509_USER_KEY"] = env["X509_USER_PROXY"]
    return env
