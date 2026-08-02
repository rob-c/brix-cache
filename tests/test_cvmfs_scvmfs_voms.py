"""phase-92 — scvmfs:// VOMS client authz (`brix_scvmfs_authz voms`).

``brix_scvmfs_authz voms`` layers a VOMS-VO authorisation gate on top of the
x509 mode: the TLS-verified peer is authenticated by its end-entity (EEC) DN
exactly as x509, then the scvmfs preamble lifts+verifies the client proxy's
VOMS attribute certificate (per-VO LSC ``brix_scvmfs_vomsdir`` + VOMS signing-CA
``brix_scvmfs_voms_cert_dir``) and gates the carried VO name(s) against the
optional ``brix_scvmfs_voms`` allow-glob list.  Because a GSI proxy chain is
what carries the AC, the cvmfs postconfig hook sets X509_V_FLAG_ALLOW_PROXY_CERTS
on the server's TLS context so the proxy chain VERIFIES under ssl_verify_client.
Contract (fail-closed):

* an /atlas VOMS proxy whose VO matches the allow-glob → served exactly as an
  open repo, EEC DN recorded as the F9 QoS subject (the allow edge);
* a plain GSI proxy carrying no VOMS AC → 403 (voms mode requires a VO — the
  carry is never a bypass);
* a /cms VOMS proxy (wrong VO) → 403 (the gate admits only the named VO);
* with no allow-glob list, any verified client carrying at least one VO is
  accepted (403 becomes 200);
* no client cert presented → 401 (the preamble fails closed).

Requirements (any missing one skips): openssl, the brix VOMS build, the test PKI
(settings USER_CERT/USER_KEY/CA_DIR + PROXY_STD), and voms_proxy_fake.py.
Port block srv_scvmfs_voms (13540-13559).

Run:
    PYTHONPATH=tests python3 -m pytest tests/test_cvmfs_scvmfs_voms.py -v
"""

import os
import shutil
import ssl
import subprocess
import sys
import urllib.error
import urllib.request
from contextlib import contextmanager
from pathlib import Path

import pytest

# conftest chdir()s into a scratch dir — anchor imports on this file's dir.
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "cvmfs"))

from conformance_common import NGINX_BIN, PortBlock, srv_instance
from settings import CA_DIR, HOST, PROXY_STD, USER_CERT, USER_KEY

requires_openssl = pytest.mark.skipif(shutil.which("openssl") is None,
                                      reason="openssl not installed")

_VOMS_PROXY_FAKE = os.path.join(os.path.dirname(__file__), "..", "utils",
                                "voms_proxy_fake.py")

pytestmark = [
    pytest.mark.skipif(not os.path.exists(NGINX_BIN),
                       reason=f"nginx binary not found: {NGINX_BIN}"),
    pytest.mark.skipif(not os.path.isfile(_VOMS_PROXY_FAKE),
                       reason="voms_proxy_fake.py not found"),
    pytest.mark.skipif(not (os.path.exists(USER_CERT) and os.path.exists(USER_KEY)
                            and os.path.exists(f"{CA_DIR}/ca.pem")),
                       reason="test PKI incomplete"),
    requires_openssl,
]


def _run(*argv):
    subprocess.run(argv, check=True, capture_output=True)


def _dn(pem, field):
    r = subprocess.run(
        ["openssl", "x509", "-in", str(pem), "-noout", f"-{field}",
         "-nameopt", "compat"],
        check=True, capture_output=True, text=True)
    return r.stdout.strip().split("=", 1)[1].strip()


def _voms_signing_cert(d: Path):
    """A VOMS signing cert signed by the test CA (so voms_cert_dir=CA_DIR trusts
    it) with subjectKeyIdentifier/authorityKeyIdentifier — the AC the fake mints
    references this cert's AKID, so the extractor can locate the signer."""
    key, crt = d / "voms.key", d / "voms.crt"
    csr = d / "voms.csr"
    _run("openssl", "genrsa", "-out", str(key), "2048")
    _run("openssl", "req", "-new", "-key", str(key),
         "-subj", "/DC=test/DC=xrootd/CN=voms.test.local", "-out", str(csr))
    ext = d / "voms_ext.conf"
    ext.write_text("[v]\nsubjectKeyIdentifier = hash\n"
                   "authorityKeyIdentifier = keyid:always\n"
                   "basicConstraints = CA:FALSE\n")
    _run("openssl", "x509", "-req", "-in", str(csr),
         "-CA", f"{CA_DIR}/ca.pem", "-CAkey", f"{CA_DIR}/ca.key",
         "-CAcreateserial", "-out", str(crt), "-days", "1",
         "-extensions", "v", "-extfile", str(ext))
    return crt, key


def _vomsdir(d: Path, voms_crt: Path):
    """Per-VO LSC trust: each VO dir names the signer's subject+issuer DN."""
    vd = d / "vomsdir"
    lsc = f"{_dn(voms_crt, 'subject')}\n{_dn(voms_crt, 'issuer')}\n"
    for vo in ("atlas", "cms"):
        (vd / vo).mkdir(parents=True, exist_ok=True)
        (vd / vo / "voms.test.local.lsc").write_text(lsc)
    return vd


def _voms_proxy(d: Path, vo: str, voms_crt: Path, voms_key: Path):
    out = d / f"proxy_{vo}.pem"
    _run(sys.executable, _VOMS_PROXY_FAKE,
         "-cert", USER_CERT, "-key", USER_KEY, "-certdir", CA_DIR,
         "-hostcert", str(voms_crt), "-hostkey", str(voms_key), "-voms", vo,
         "-fqan", f"/{vo}/Role=NULL/Capability=NULL",
         "-uri", "voms.test.local:15000", "-out", str(out), "-hours", "24")
    return out


def _split(proxy: Path, d: Path, stem: str):
    """load_cert_chain wants a cert(-chain) file and a key file; a proxy PEM
    interleaves proxy-cert / key / EEC-cert.  Split into a certs-only file
    (proxy leaf first, then EEC chain) and a key-only file."""
    blob = proxy.read_text()
    certs, key, cur, in_key = [], [], [], False
    for line in blob.splitlines(keepends=True):
        cur.append(line)
        if "BEGIN" in line and "PRIVATE KEY" in line:
            in_key = True
        if "END" in line:
            (key if in_key else certs).append("".join(cur))
            cur, in_key = [], False
    cfile, kfile = d / f"{stem}.certs", d / f"{stem}.key"
    cfile.write_text("".join(certs))
    kfile.write_text("".join(key))
    return cfile, kfile


@pytest.fixture(scope="module")
def voms(tmp_path_factory):
    d = tmp_path_factory.mktemp("scvmfs_voms")
    # throwaway server TLS cert; the client trusts nothing (unverified ctx).
    _run("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
         "-subj", "/CN=localhost", "-keyout", str(d / "server.key"),
         "-out", str(d / "server.crt"))
    voms_crt, voms_key = _voms_signing_cert(d)
    vd = _vomsdir(d, voms_crt)
    proxies = {
        "atlas": _split(_voms_proxy(d, "atlas", voms_crt, voms_key), d, "atlas"),
        "cms": _split(_voms_proxy(d, "cms", voms_crt, voms_key), d, "cms"),
        "plain": _split(Path(PROXY_STD), d, "plain")
                 if os.path.exists(PROXY_STD) else None,
    }
    return {"dir": d, "server": (d / "server.crt", d / "server.key"),
            "vomsdir": vd, "proxies": proxies}


@contextmanager
def _srv(voms, *, vo_glob=None):
    extra = ("brix_scvmfs_authz voms;"
             f" brix_scvmfs_vomsdir {voms['vomsdir']};"
             f" brix_scvmfs_voms_cert_dir {CA_DIR};")
    if vo_glob is not None:
        extra += f' brix_scvmfs_voms "{vo_glob}";'
    with srv_instance(PortBlock("srv_scvmfs_voms"), objects=4, scvmfs=True,
                      ssl_cert=voms["server"][0], ssl_key=voms["server"][1],
                      ssl_verify_client="optional", ssl_client_ca=f"{CA_DIR}/ca.pem",
                      extra_directives=extra) as srv:
        yield srv


def _fetch(port, path, *, client=None):
    ctx = ssl._create_unverified_context()   # server cert is throwaway
    if client is not None:
        ctx.load_cert_chain(str(client[0]), str(client[1]))
    req = urllib.request.Request(f"https://{HOST}:{port}{path}")
    try:
        with urllib.request.urlopen(req, timeout=15, context=ctx) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


# ---- success ---------------------------------------------------------------

def test_matching_vo_served(voms):
    """An /atlas VOMS proxy whose VO matches the allow-glob is admitted — the
    proxy chain verifies (ALLOW_PROXY_CERTS) and the carried VO satisfies the
    gate, so the repo is served."""
    with _srv(voms, vo_glob="atlas") as srv:
        st, body = _fetch(srv.nginx_port, srv.objects()[0],
                          client=voms["proxies"]["atlas"])
        assert st == 200 and body


def test_no_vo_list_accepts_any_carried_vo(voms):
    """With no brix_scvmfs_voms glob, any verified client carrying at least one
    VO is accepted — the cms proxy has a VO, just not a named one to satisfy."""
    with _srv(voms, vo_glob=None) as srv:
        st, body = _fetch(srv.nginx_port, srv.objects()[0],
                          client=voms["proxies"]["cms"])
        assert st == 200 and body


# ---- error -----------------------------------------------------------------

def test_no_client_cert_401(voms):
    with _srv(voms, vo_glob="atlas") as srv:
        st, _ = _fetch(srv.nginx_port, srv.objects()[0], client=None)
        assert st == 401


def test_plain_proxy_no_voms_403(voms):
    """A plain GSI proxy carries no VOMS AC, so the carry sets no VO and voms
    mode refuses it (403) — the VO requirement is fail-closed, never bypassed by
    a merely-authenticated peer."""
    if voms["proxies"]["plain"] is None:
        pytest.skip("no plain proxy fixture (settings.PROXY_STD)")
    with _srv(voms, vo_glob="atlas") as srv:
        st, _ = _fetch(srv.nginx_port, srv.objects()[0],
                       client=voms["proxies"]["plain"])
        assert st == 403


# ---- security-negative -----------------------------------------------------

def test_wrong_vo_403(voms):
    """A /cms VOMS proxy carries a VO, but not the one the allow-glob names, so
    the gate refuses it (403) — a valid VO is not a wildcard."""
    with _srv(voms, vo_glob="atlas") as srv:
        st, _ = _fetch(srv.nginx_port, srv.objects()[0],
                       client=voms["proxies"]["cms"])
        assert st == 403
