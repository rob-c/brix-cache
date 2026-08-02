"""phase-92 — scvmfs:// X.509 client-cert authz (`brix_scvmfs_authz x509`).

``brix_scvmfs_authz x509`` authenticates the TLS-verified peer by its
end-entity (EEC) subject DN — nginx's own ssl_verify_client chain does the
crypto; the scvmfs preamble reads the verified peer, skips RFC 3820 proxy certs
so a GSI proxy authenticates as its issuing EEC, and gates the DN against an
optional ``brix_scvmfs_x509_dn`` allow-glob list. Contract:

* verified client cert whose EEC DN matches the allow-glob → served exactly as
  an open repo, DN recorded as the F9 QoS subject;
* no client cert presented → 401 (our preamble fails closed);
* a client cert signed by an UNtrusted CA → rejected (nginx core 400s a cert
  that fails chain verify under ssl_verify_client, before our DN handler — the
  handler's own X509_V_OK guard is the second line of defence);
* a verified cert whose DN is NOT in the allow-glob → 403 (authenticated but
  out of policy);
* with no allow-glob list, ANY verified client is accepted (403 becomes 200).

VOMS-FQAN authorisation rides on top of this and is deferred (no VOMS-AC test
fixture yet). Port block srv_scvmfs_x509 (13520-13539).
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
from settings import HOST

requires_openssl = pytest.mark.skipif(shutil.which("openssl") is None,
                                      reason="openssl not installed")

pytestmark = [
    pytest.mark.skipif(not os.path.exists(NGINX_BIN),
                       reason=f"nginx binary not found: {NGINX_BIN}"),
    requires_openssl,
]


def _run(*argv):
    subprocess.run(argv, check=True, capture_output=True)


def _self_signed(d: Path, cn: str, stem: str):
    _run("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
         "-subj", f"/CN={cn}", "-keyout", str(d / f"{stem}.key"),
         "-out", str(d / f"{stem}.crt"))
    return d / f"{stem}.crt", d / f"{stem}.key"


def _leaf(d: Path, cn: str, ca_crt: Path, ca_key: Path, stem: str):
    """A client leaf cert with subject /CN=<cn>, signed by the given CA."""
    _run("openssl", "req", "-newkey", "rsa:2048", "-nodes",
         "-subj", f"/CN={cn}", "-keyout", str(d / f"{stem}.key"),
         "-out", str(d / f"{stem}.csr"))
    _run("openssl", "x509", "-req", "-in", str(d / f"{stem}.csr"),
         "-CA", str(ca_crt), "-CAkey", str(ca_key), "-CAcreateserial",
         "-days", "1", "-out", str(d / f"{stem}.crt"))
    return d / f"{stem}.crt", d / f"{stem}.key"


@pytest.fixture(scope="module")
def pki(tmp_path_factory):
    """A trust root that signs alice+bob, a throwaway server TLS cert, and a
    rogue CA+leaf outside the server's trust store."""
    d = tmp_path_factory.mktemp("scvmfs_x509")
    ca_crt, ca_key = _self_signed(d, "BriX Test CA", "ca")
    srv_crt, srv_key = _self_signed(d, "localhost", "server")
    alice = _leaf(d, "alice", ca_crt, ca_key, "alice")
    bob = _leaf(d, "bob", ca_crt, ca_key, "bob")
    rogue_ca_crt, rogue_ca_key = _self_signed(d, "Rogue CA", "rogue_ca")
    rogue = _leaf(d, "alice", rogue_ca_crt, rogue_ca_key, "rogue")
    return {
        "ca": ca_crt, "server": (srv_crt, srv_key),
        "alice": alice, "bob": bob, "rogue": rogue,
    }


@contextmanager
def _srv(pki, *, dn_glob=None):
    """An scvmfs x509 instance: TLS + ssl_verify_client optional against the
    test CA + brix_scvmfs_authz x509 (with an optional DN allow-glob)."""
    extra = "brix_scvmfs_authz x509;"
    if dn_glob is not None:
        extra += f' brix_scvmfs_x509_dn "{dn_glob}";'
    with srv_instance(PortBlock("srv_scvmfs_x509"), objects=4, scvmfs=True,
                      ssl_cert=pki["server"][0], ssl_key=pki["server"][1],
                      ssl_verify_client="optional", ssl_client_ca=pki["ca"],
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

def test_matching_dn_served(pki):
    with _srv(pki, dn_glob="*CN=alice*") as srv:
        st, body = _fetch(srv.nginx_port, srv.objects()[0], client=pki["alice"])
        assert st == 200 and body
        st, _ = _fetch(srv.nginx_port, f"/cvmfs/{srv.repo}/.cvmfspublished",
                       client=pki["alice"])
        assert st == 200


def test_no_dn_list_accepts_any_verified(pki):
    """With no brix_scvmfs_x509_dn, any cert that chains to the trusted CA is
    accepted — bob has no matching glob to satisfy, only a valid chain."""
    with _srv(pki, dn_glob=None) as srv:
        st, body = _fetch(srv.nginx_port, srv.objects()[0], client=pki["bob"])
        assert st == 200 and body


# ---- error -----------------------------------------------------------------

def test_no_client_cert_401(pki):
    with _srv(pki, dn_glob="*CN=alice*") as srv:
        st, _ = _fetch(srv.nginx_port, srv.objects()[0], client=None)
        assert st == 401


# ---- security-negative -----------------------------------------------------

def test_untrusted_ca_rejected(pki):
    """A cert with the RIGHT DN but signed by a CA outside the server trust
    store fails chain verification — DN spoofing must not open the repo. nginx
    core 400s the unverifiable cert under ssl_verify_client before our handler;
    either way the repo is never served."""
    with _srv(pki, dn_glob="*CN=alice*") as srv:
        st, _ = _fetch(srv.nginx_port, srv.objects()[0], client=pki["rogue"])
        assert st in (400, 401) and st != 200


def test_verified_but_dn_not_allowed_403(pki):
    """bob's chain verifies, but his DN is outside the allow-glob — a valid
    client is still refused when policy does not name it (403, not 401)."""
    with _srv(pki, dn_glob="*CN=alice*") as srv:
        st, _ = _fetch(srv.nginx_port, srv.objects()[0], client=pki["bob"])
        assert st == 403
