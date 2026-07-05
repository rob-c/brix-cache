"""
Client-conformance: xrdgsiproxy (differential vs stock).

xrdgsiproxy is a LOCAL credential tool (no server), so it sits outside the
endpoint matrix.  We compare our tool to stock on the operations that have a
stable, byte-comparable surface: ``info`` on a known proxy (subject/issuer/
timeleft presence + rc) and error handling for a missing proxy.  Help text is
our own (a registered divergence), so only its rc is asserted.
"""

import os

import pytest

from clientconf.diffcore import OURS, STOCK, binary, normalize
from settings import CA_DIR, PROXY_STD

TOOL = "xrdgsiproxy"


def _have_both():
    return binary(STOCK, TOOL) is not None and binary(OURS, TOOL) is not None


pytestmark = [
    pytest.mark.timeout(60),
    pytest.mark.skipif(not _have_both(), reason="stock or our xrdgsiproxy absent"),
]


def _run(which, args, env_extra=None):
    import subprocess
    env = {k: v for k, v in os.environ.items()}
    env.pop("X509_USER_PROXY", None)
    if env_extra:
        env.update(env_extra)
    proc = subprocess.run([binary(which, TOOL), *args], env=env,
                          capture_output=True, text=True, timeout=45)
    return proc


@pytest.mark.skipif(not os.path.exists(PROXY_STD), reason="no test proxy present")
def test_info_reports_subject():
    env = {"X509_USER_PROXY": PROXY_STD, "X509_CERT_DIR": CA_DIR}
    s = _run(STOCK, ["info"], env)
    o = _run(OURS, ["info"], env)
    # Both must succeed and report an identity ("subject"/"identity"/DN).
    assert s.returncode == 0 and o.returncode == 0, \
        "info rc: stock=%s ours=%s" % (s.returncode, o.returncode)
    blob_s = normalize(s.stdout + s.stderr).lower()
    blob_o = normalize(o.stdout + o.stderr).lower()
    for token in ("subject", "/cn="):
        if token in blob_s:
            assert token in blob_o, \
                "ours info missing %r that stock reports" % token


def test_info_missing_proxy_handled():
    # A genuinely missing proxy. Use ``-file`` (which stock honors, unlike the
    # X509_USER_PROXY env which stock's `info` ignores) so this is a true
    # differential. Stock prints a plain "proxy file: <path> not found" notice
    # and exits 1 -- it does NOT treat the absence as a usage error. Ours must
    # mirror that: a soft "not found" notice and the same low rc, never the
    # usage-error exit code (50).
    args = ["info", "-file", "/nonexistent/proxy.pem"]
    s = _run(STOCK, args)
    o = _run(OURS, args)
    assert s.returncode < 128 and o.returncode < 128, \
        "info crashed: stock=%s ours=%s" % (s.returncode, o.returncode)
    # Stock returns 1 here; match it (and in particular do not return 50).
    assert o.returncode == s.returncode, \
        "info rc on missing proxy: stock=%s ours=%s" % (s.returncode, o.returncode)
    blob = (o.stdout + o.stderr).lower()
    assert "not found" in blob or "proxy" in blob, \
        "ours gave no clear signal about the missing proxy"


def test_help_runs():
    # Our help is our own text (registered divergence); just prove it runs.
    o = _run(OURS, ["--help"])
    assert "xrdgsiproxy" in (o.stdout + o.stderr).lower()
