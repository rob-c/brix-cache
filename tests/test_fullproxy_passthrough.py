"""
GSI full-proxy passthrough (phase-70 §5.1a, verified/hardened as P90-70.5).

The native client's round-2 kXGC_cert builder (shared kernel
src/auth/gsi/gsi_core_cresp_util.c::gsi_add_fullproxy_bucket) can append the
user's FULL proxy — cert chain + private key PEM — as a kXRS_x509_fullproxy
bucket inside the AES-encrypted inner buffer, so a delegation-enabled server
can present the user's own credential upstream.  The server captures it in
src/auth/gsi/parse_x509.c and promotes it in auth_cert.c only when (a) the
connection is TLS, (b) the PEM parses as chain + key, and (c) the supplied
leaf's identity matches the authenticated DN.

3-test ritual:
  success      — opt-in (XRD_DELEGATEFULLPROXY=1) over roots:// → copy works
                 AND the server logs "full-proxy passthrough accepted".
  error        — default-off: without the env var the same copy works and NO
                 passthrough happens (stock behaviour byte-identical).
  security-neg — opt-in over cleartext root:// → the server REJECTS the login
                 (a private key must never ride a cleartext session), and the
                 kernel's proxy-file read refuses symlinks / foreign-owned
                 files (source contract: the predictable /tmp/x509up_u<uid>
                 path must not be hijackable).
"""

import os
import subprocess
from pathlib import Path

import pytest
from settings import (
    CA_DIR,
    DATA_ROOT,
    LOG_DIR,
    NGINX_GSI_PORT,
    NGINX_GSI_TLS_PORT,
    PROXY_STD,
    SERVER_HOST,
)

ROOT = Path(__file__).resolve().parents[1]
NATIVE_XRDCP = ROOT / "client" / "bin" / "xrdcp"

GSI_TLS_URL = f"roots://{SERVER_HOST}:{NGINX_GSI_TLS_PORT}"
GSI_URL = f"root://{SERVER_HOST}:{NGINX_GSI_PORT}"

ACCEPT_LINE = "full-proxy passthrough accepted"
CLEARTEXT_LINE = "supplied over cleartext"

# The subprocess env is built from a scrubbed copy so an operator's own
# X509_*/XRD_* settings can't leak into the assertions.
_CLEAN_ENV = dict(os.environ)
for _k in ("X509_USER_PROXY", "X509_CERT_DIR", "XRD_DELEGATEFULLPROXY"):
    _CLEAN_ENV.pop(_k, None)


def _gsi_env(optin=False):
    env = dict(_CLEAN_ENV)
    env["X509_USER_PROXY"] = PROXY_STD
    env["X509_CERT_DIR"] = CA_DIR
    if optin:
        env["XRD_DELEGATEFULLPROXY"] = "1"
    return env


@pytest.fixture(scope="module")
def native_xrdcp():
    if not NATIVE_XRDCP.exists():
        pytest.skip("native xrdcp not built (make -C client)")
    if not os.path.exists(PROXY_STD) or not os.path.isdir(CA_DIR):
        pytest.skip("test PKI not provisioned")
    return str(NATIVE_XRDCP)


class _ErrorLogTail:
    """Offset-based scrape of the main fleet instance's error.log."""

    def __init__(self):
        self.path = os.path.join(LOG_DIR, "error.log")
        self._start = os.path.getsize(self.path) if os.path.exists(self.path) else 0

    def text(self):
        if not os.path.exists(self.path):
            return ""
        with open(self.path, errors="replace") as fh:
            fh.seek(self._start)
            return fh.read()


def _copy(native_xrdcp, url, dest, env):
    return subprocess.run(
        [native_xrdcp, "-f", f"{url}//test.txt", dest],
        capture_output=True, text=True, env=env, timeout=60,
    )


def test_fullproxy_optin_accepted_over_tls(native_xrdcp, tmp_path):
    """Opt-in over roots://: transfer succeeds AND the server promotes the
    pushed proxy (identity-verified) for backend delegation."""
    tail = _ErrorLogTail()
    proc = _copy(native_xrdcp, GSI_TLS_URL, str(tmp_path / "out.txt"),
                 _gsi_env(optin=True))
    assert proc.returncode == 0, f"GSI+TLS copy failed: {proc.stderr}"
    with open(os.path.join(DATA_ROOT, "test.txt"), "rb") as fh:
        assert (tmp_path / "out.txt").read_bytes() == fh.read()
    assert ACCEPT_LINE in tail.text(), (
        "server never logged the passthrough-accepted line — the "
        "kXRS_x509_fullproxy bucket was not sent or not promoted")


def test_default_off_sends_no_fullproxy(native_xrdcp, tmp_path):
    """Without XRD_DELEGATEFULLPROXY the copy works and nothing is pushed —
    stock GSI behaviour is unchanged."""
    tail = _ErrorLogTail()
    proc = _copy(native_xrdcp, GSI_TLS_URL, str(tmp_path / "out.txt"),
                 _gsi_env(optin=False))
    assert proc.returncode == 0, f"GSI+TLS copy failed: {proc.stderr}"
    text = tail.text()
    assert ACCEPT_LINE not in text
    assert "fullproxy" not in text


def test_fullproxy_over_cleartext_rejected(native_xrdcp, tmp_path):
    """Opt-in over plain root://: the server must reject the login — a full
    proxy (private key) may never be accepted from a cleartext session."""
    tail = _ErrorLogTail()
    proc = _copy(native_xrdcp, GSI_URL, str(tmp_path / "out.txt"),
                 _gsi_env(optin=True))
    assert proc.returncode != 0, (
        "cleartext full-proxy push must fail the login, but the copy succeeded")
    assert CLEARTEXT_LINE in tail.text()


class TestKernelSourceContract:
    """The shared-kernel sender must stay opt-in, symlink-safe, and
    default-path aware (P90-70.5 hardening)."""

    def _src(self):
        return (ROOT / "src/auth/gsi/gsi_core_cresp_util.c").read_text()

    def test_env_gate_precedes_any_file_io(self):
        src = self._src()
        fn = src.index("gsi_add_fullproxy_bucket(brix_gbuf *inner)")
        gate = src.index('getenv("XRD_DELEGATEFULLPROXY")', fn)
        assert gate < src.index("open(proxy", fn)

    def test_open_refuses_symlinks_and_foreign_files(self):
        src = self._src()
        assert "O_RDONLY | O_NOFOLLOW | O_CLOEXEC" in src
        assert "S_ISREG(sb.st_mode)" in src
        assert "sb.st_uid != geteuid()" in src

    def test_default_proxy_path_fallback(self):
        # Opt-in must work with the standard /tmp/x509up_u<uid> proxy, not
        # only when X509_USER_PROXY is exported.
        assert '"/tmp/x509up_u%u"' in self._src()

    def test_key_bytes_are_cleansed(self):
        src = self._src()
        fn = src.index("gsi_add_fullproxy_bucket(brix_gbuf *inner)")
        assert "OPENSSL_cleanse(buf, sizeof(buf))" in src[fn:]

    def test_server_promote_is_tls_and_identity_gated(self):
        srv = (ROOT / "src/auth/gsi/auth_cert.c").read_text()
        fn = srv.index("gsi_promote_fullproxy(brix_ctx_t *ctx")
        block = srv[fn:fn + 3500]
        assert "c->ssl == NULL" in block
        assert CLEARTEXT_LINE in block
        assert "does not match authenticated DN" in block
