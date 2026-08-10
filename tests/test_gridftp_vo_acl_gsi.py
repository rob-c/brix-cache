"""
GridFTP gsiftp:// gateway — VO-ACL *allow* edge via VOMS attribute carry
(phase-92, audit item :605 RESIDUAL closure).

test_gridftp_vo_acl.py proves the deny edges over a *cleartext* control channel
(a session with no VO is refused on a VO-gated prefix).  This suite proves the
missing *allow* edge that needs a real GSI/VOMS handshake: a client proxy whose
VOMS FQAN names the required VO is ADMITTED to the gated prefix, because the
gateway lifts the proxy's VOMS FQANs into the session identity
(``ev_gss_carry_voms`` in ``ftp_ev_sec.c``, mirroring the HTTPS plane's
``webdav_extract_and_set_voms_identity``) before ``brix_ftp_ev_resolve`` runs the
shared ``brix_check_vo_acl_identity`` gate.

Gateway (nginx_gridftp_vo_gsi.conf): event-engine GSI gsiftp with
``brix_require_vo /vodata atlas`` + ``brix_vomsdir`` /
``brix_voms_cert_dir``.  Three edges (success + error/deny + security-neg):

  * allow        -- an /atlas VOMS proxy RETRs a file under /vodata (VO carried,
                    rule satisfied).
  * deny         -- a plain GSI proxy (no VOMS AC) is refused under /vodata
                    (deny-until-VOMS-carry — carry is fail-closed, never a
                    bypass), yet is served normally outside the gated prefix.
  * security-neg -- a /cms VOMS proxy (wrong VO) is refused under /vodata: the
                    carry admits only the FQAN the rule names.

Requirements (any missing one skips): globus-url-copy, the brix nginx build, the
test PKI, and voms_proxy_fake.py (pure-Python VOMS AC generator in utils/).

Run:
    PYTHONPATH=tests python3 -m pytest tests/test_gridftp_vo_acl_gsi.py -v -p no:xdist
"""

import os
import shutil
import subprocess
import sys

import pytest

from settings import (
    BIND_HOST,
    CA_DIR,
    NGINX_BIN,
    PKI_DIR,
    PROXY_STD,
    SERVER_CERT,
    SERVER_HOST,
    SERVER_KEY,
    USER_CERT,
    USER_KEY,
    VOMSDIR,
)
from server_launcher import LifecycleHarness
from server_registry import NginxInstanceSpec
from gridftp_client_env import gsi_client_env

def _guard_require_1():
    if GUC is None:
        pytest.skip("globus-url-copy not on PATH")

def _guard_require_2():
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx not executable: {NGINX_BIN}")

def _guard_require_3():
    if not os.path.isfile(_VOMS_PROXY_FAKE):
        pytest.skip("voms_proxy_fake.py not found")

def _guard_require_4(p):
    if not os.path.exists(p):
        pytest.skip(f"test PKI incomplete: missing {p}")


pytestmark = [pytest.mark.slow, pytest.mark.serial,
              pytest.mark.timeout(300), pytest.mark.uses_lifecycle_harness]

GUC = shutil.which("globus-url-copy")

# The same pure-Python VOMS AC generator the rest of the suite uses; it supersedes
# the AKID-broken system voms-proxy-fake (see docs/refactor/phase-92 item :605).
_VOMS_PROXY_FAKE = os.path.join(os.path.dirname(__file__), "..", "utils",
                                "voms_proxy_fake.py")
VOMS_CERT = os.path.join(PKI_DIR, "voms", "voms_cert.pem")
VOMS_KEY = os.path.join(PKI_DIR, "voms", "voms_key.pem")
PROXY_ATLAS = os.path.join(PKI_DIR, "user", "proxy_vo_atlas.pem")
PROXY_CMS = os.path.join(PKI_DIR, "user", "proxy_vo_cms.pem")


def _require():
    _guard_require_1()
    _guard_require_2()
    _guard_require_3()
    for p in (SERVER_CERT, SERVER_KEY, CA_DIR, USER_CERT, USER_KEY):
        _guard_require_4(p)


# ---------------------------------------------------------------------------
# VOMS infrastructure — signing cert, per-VO LSC vomsdir, VOMS proxies.
# Mirrors test_vo_acl.py's helpers; shares the main test PKI (the gateway's
# brix_trusted_ca already trusts {CA_DIR}, so no separate trust root).
# ---------------------------------------------------------------------------

def _voms_dn(pem, field):
    r = subprocess.run(
        ["openssl", "x509", "-in", pem, "-noout", f"-{field}", "-nameopt", "compat"],
        check=True, capture_output=True, text=True)
    return r.stdout.strip().split("=", 1)[1].strip()


def _make_voms_signing_cert():
    os.makedirs(os.path.dirname(VOMS_CERT), exist_ok=True)
    if os.path.exists(VOMS_CERT) and os.path.exists(VOMS_KEY):
        return
    subprocess.run(["openssl", "genrsa", "-out", VOMS_KEY, "2048"],
                   check=True, capture_output=True)
    csr = VOMS_CERT.replace(".pem", ".csr")
    subprocess.run(["openssl", "req", "-new", "-key", VOMS_KEY,
                    "-subj", "/DC=test/DC=xrootd/CN=voms.test.local", "-out", csr],
                   check=True, capture_output=True)
    ext = VOMS_CERT.replace(".pem", "_ext.conf")
    with open(ext, "w") as f:
        f.write("[voms_ext]\nsubjectKeyIdentifier = hash\n"
                "authorityKeyIdentifier = keyid:always\nbasicConstraints = CA:FALSE\n")
    subprocess.run(["openssl", "x509", "-req", "-in", csr,
                    "-CA", f"{CA_DIR}/ca.pem", "-CAkey", f"{CA_DIR}/ca.key",
                    "-CAcreateserial", "-out", VOMS_CERT, "-days", "365",
                    "-extensions", "voms_ext", "-extfile", ext],
                   check=True, capture_output=True)


def _make_vomsdir():
    lsc = f"{_voms_dn(VOMS_CERT, 'subject')}\n{_voms_dn(VOMS_CERT, 'issuer')}\n"
    for vo in ("atlas", "cms"):
        vo_dir = os.path.join(VOMSDIR, vo)
        os.makedirs(vo_dir, exist_ok=True)
        with open(os.path.join(vo_dir, "voms.test.local.lsc"), "w") as f:
            f.write(lsc)


def _make_voms_proxy(vo, out):
    subprocess.run(
        [sys.executable, _VOMS_PROXY_FAKE,
         "-cert", USER_CERT, "-key", USER_KEY, "-certdir", CA_DIR,
         "-hostcert", VOMS_CERT, "-hostkey", VOMS_KEY, "-voms", vo,
         "-fqan", f"/{vo}/Role=NULL/Capability=NULL",
         "-uri", "voms.test.local:15000", "-out", out, "-hours", "24"],
        check=True, capture_output=True)


class _Gateway:
    def __init__(self, harness):
        endpoint = harness.start(NginxInstanceSpec(
            name="gridftp-vo-gsi",
            template="nginx_gridftp_vo_gsi.conf",
            protocol="root",
            readiness="tcp",
            template_values={
                "BIND_HOST": BIND_HOST,
                "SERVER_CERT": SERVER_CERT,
                "SERVER_KEY": SERVER_KEY,
                "CA_DIR": CA_DIR,
                "VOMSDIR": VOMSDIR,
            },
        ))
        self.harness = harness
        self.port = endpoint.port
        self.export = endpoint.data_root
        self._log = os.path.join(endpoint.prefix, "logs", "error.log")

    def error_log(self):
        try:
            with open(self._log) as fh:
                return fh.read()
        except FileNotFoundError:
            return ""

    def close(self):
        self.harness.close()


@pytest.fixture(scope="module")
def gateway():
    _require()
    _make_voms_signing_cert()
    _make_vomsdir()
    _make_voms_proxy("atlas", PROXY_ATLAS)
    _make_voms_proxy("cms", PROXY_CMS)
    gw = _Gateway(LifecycleHarness())
    os.makedirs(os.path.join(gw.export, "vodata"), exist_ok=True)
    os.makedirs(os.path.join(gw.export, "open"), exist_ok=True)
    with open(os.path.join(gw.export, "vodata", "secret.txt"), "wb") as fh:
        fh.write(b"vo-gated-payload")
    with open(os.path.join(gw.export, "open", "pub.txt"), "wb") as fh:
        fh.write(b"public-payload")
    yield gw
    gw.close()


def _get(gw, proxy, rel, dst):
    """RETR gsiftp://.../rel to dst with *proxy* as the GSI credential."""
    env = gsi_client_env(CA_DIR, proxy)
    return subprocess.run(
        [GUC, "-nodcau", f"gsiftp://{SERVER_HOST}:{gw.port}/{rel}",
         f"file://{dst}"],
        capture_output=True, text=True, env=env, timeout=60)


# ---- allow: /atlas VOMS proxy is admitted to the /vodata prefix ------------

def test_atlas_voms_proxy_allowed_on_gated_prefix(gateway, tmp_path):
    """An /atlas VOMS proxy carries the required VO into the identity, so the
    gate admits the RETR under /vodata — the allow edge."""
    dst = os.path.join(str(tmp_path), "got.bin")
    r = _get(gateway, PROXY_ATLAS, "vodata/secret.txt", dst)
    assert r.returncode == 0, (
        f"atlas proxy must be admitted to /vodata rc={r.returncode}\n"
        f"{r.stderr}\n{gateway.error_log()}")
    with open(dst, "rb") as fh:
        assert fh.read() == b"vo-gated-payload"


# ---- deny: plain GSI proxy (no VOMS) refused under the gated prefix ---------

def test_plain_proxy_denied_on_gated_prefix(gateway, tmp_path):
    """A plain GSI proxy carries no VOMS AC, so the carry sets no VO and the gate
    refuses /vodata (deny-until-VOMS-carry — fail-closed, never a bypass)."""
    dst = os.path.join(str(tmp_path), "denied.bin")
    r = _get(gateway, PROXY_STD, "vodata/secret.txt", dst)
    assert r.returncode != 0, (
        f"plain proxy must be refused under /vodata\n{r.stdout}\n{gateway.error_log()}")
    assert not (os.path.exists(dst) and os.path.getsize(dst) > 0)


def test_plain_proxy_allowed_outside_gated_prefix(gateway, tmp_path):
    """The gate only covers the rule prefix: a plain GSI proxy still reads
    /open normally, proving the carry adds no over-denial elsewhere."""
    dst = os.path.join(str(tmp_path), "pub.bin")
    r = _get(gateway, PROXY_STD, "open/pub.txt", dst)
    assert r.returncode == 0, (
        f"plain proxy must read the uncovered /open path rc={r.returncode}\n"
        f"{r.stderr}\n{gateway.error_log()}")
    with open(dst, "rb") as fh:
        assert fh.read() == b"public-payload"


# ---- security-neg: wrong-VO proxy refused under the gated prefix ------------

def test_wrong_vo_proxy_denied_on_gated_prefix(gateway, tmp_path):
    """A /cms VOMS proxy carries a VO, but not the one the rule names, so the
    gate refuses /vodata: the carry admits only the required FQAN."""
    dst = os.path.join(str(tmp_path), "wrongvo.bin")
    r = _get(gateway, PROXY_CMS, "vodata/secret.txt", dst)
    assert r.returncode != 0, (
        f"cms proxy (wrong VO) must be refused under /vodata (atlas)\n"
        f"{r.stdout}\n{gateway.error_log()}")
    assert not (os.path.exists(dst) and os.path.getsize(dst) > 0)
