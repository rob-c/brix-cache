"""Phase-96 S14 — scvmfs-gated Stratum-0: securing the published repo is
pure configuration.

`brix_scvmfs on` + an authz mode composes with `brix_cvmfs_stratum0_root`
unchanged: the scvmfs preamble runs before the gate, so EVERY Stratum-0
answer — `.cvmfspublished`, `.cvmfswhitelist`, CAS objects, and the
`.cvmfs_master_replica` marker — is behind the credential wall.

  success:      an x509 client whose EEC DN matches the allow-glob (and a
                VOMS proxy whose VO matches) fetches manifest / CAS / marker
                byte-identical to the published tree.
  error:        no client credential → 401 fail-closed on every class,
                INCLUDING `.cvmfspublished` (no manifest leak around the
                preamble) and the replication marker.
  security-neg: a verified-but-unlisted DN and a wrong-VO proxy → 403; a
                matching DN minted by an untrusted CA → rejected before the
                repo is ever served.

x509 leg is self-contained (throwaway openssl PKI); the VOMS leg reuses the
test-PKI + voms_proxy_fake fixtures and skips when they are absent.
Port block srv_s0_scvmfs (13580-13599).
"""

import os
import shutil
import ssl
import sys
import urllib.error
import urllib.request

import pytest

# conftest chdir()s into a scratch dir — anchor imports on this file's dir.
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "cvmfs"))

from conformance_common import NGINX_BIN, PortBlock
from cmdscripts.cvmfs_publish_txn import _upper, cas_path, parse_manifest, repotool
from cmdscripts.cvmfs_repo_cli import _build_repotool
from cmdscripts.live_common import LiveRun
from settings import BIND_HOST, CA_DIR, HOST, USER_CERT, USER_KEY
from config_templates import render_config
from test_cvmfs_scvmfs_voms import (_VOMS_PROXY_FAKE, _split, _voms_proxy,
                                    _voms_signing_cert, _vomsdir)
from test_cvmfs_scvmfs_x509 import _leaf, _self_signed

FQRN = "s0sec.brix.io"
FILES = {"payload.txt": b"gated stratum-zero payload\n"}

pytestmark = [
    pytest.mark.skipif(not os.path.exists(NGINX_BIN),
                       reason=f"nginx binary not found: {NGINX_BIN}"),
    pytest.mark.skipif(shutil.which("openssl") is None,
                       reason="openssl not installed"),
]

_BLOCK = PortBlock("srv_s0_scvmfs")


def _nginx_conf(run: LiveRun, port: int, ssl_lines: str, loc_lines: str):
    return run.write(
        run.root / f"nginx.{port}.conf",
        render_config(
            "nginx_cvmfs_stratum0_lab.conf",
            USER_LINE="user root;\n" if os.geteuid() == 0 else "",
            LOG_FILE=f"{run.root}/logs/e.{port}.log",
            PID_FILE=f"{run.root}/nginx.{port}.pid",
            BIND_HOST=BIND_HOST, PORT=port,
            LISTEN_SSL=" ssl", SSL_LINES=ssl_lines,
            LOCATION_LINES=loc_lines))


@pytest.fixture(scope="module")
def s0(tmp_path_factory):
    """One published Stratum-0 tree + an x509-DN-gated TLS nginx over it."""
    with LiveRun("cvmfs_s0_sec", NGINX_BIN) as run:
        run.mkdir("logs")
        binary, err = _build_repotool(run.mkdir("bin"))
        assert binary is not None, f"repotool build failed: {err}"
        web = run.mkdir("web")
        repo = run.mkdir("web", "cvmfs") / FQRN
        assert repotool(binary, "mkfs", FQRN, str(repo)).returncode == 0
        assert repotool(binary, "transaction", str(repo)).returncode == 0
        for rel, content in FILES.items():
            (_upper(repo) / rel).write_bytes(content)
        assert repotool(binary, "publish", str(repo)).returncode == 0

        d = tmp_path_factory.mktemp("s0_pki")
        ca_crt, ca_key = _self_signed(d, "BriX Test CA", "ca")
        srv_crt, srv_key = _self_signed(d, "localhost", "server")  # net-literal-allow: throwaway TLS cert subject
        pki = {
            "ca": ca_crt, "server": (srv_crt, srv_key),
            "alice": _leaf(d, "alice", ca_crt, ca_key, "alice"),
            "bob": _leaf(d, "bob", ca_crt, ca_key, "bob"),
        }
        rogue_ca = _self_signed(d, "Rogue CA", "rogue_ca")
        pki["rogue"] = _leaf(d, "alice", rogue_ca[0], rogue_ca[1], "rogue")

        port = _BLOCK.nginx()
        conf = _nginx_conf(
            run, port,
            f"ssl_certificate {srv_crt}; ssl_certificate_key {srv_key};"
            f" ssl_client_certificate {ca_crt}; ssl_verify_client optional;",
            f"""brix_cvmfs on;
        brix_cvmfs_stratum0_root {web};
        brix_scvmfs on;
        brix_scvmfs_authz x509;
        brix_scvmfs_x509_dn "*CN=alice*";""")
        run.start_nginx(run.root, conf, port)
        yield run, repo, port, pki, web


@pytest.fixture(scope="module")
def s0_voms(s0, tmp_path_factory):
    """A second nginx over the SAME tree, VOMS-VO-gated (needs the test PKI)."""
    if not (os.path.isfile(_VOMS_PROXY_FAKE) and os.path.exists(USER_CERT)
            and os.path.exists(USER_KEY) and os.path.exists(f"{CA_DIR}/ca.pem")):
        pytest.skip("test PKI / voms_proxy_fake incomplete")
    run, repo, _, _, web = s0
    d = tmp_path_factory.mktemp("s0_voms")
    voms_crt, voms_key = _voms_signing_cert(d)
    vd = _vomsdir(d, voms_crt)
    proxies = {
        vo: _split(_voms_proxy(d, vo, voms_crt, voms_key), d, vo)
        for vo in ("atlas", "cms")
    }
    srv_crt, srv_key = _self_signed(d, "localhost", "server")  # net-literal-allow: throwaway TLS cert subject

    port = _BLOCK.nginx()
    conf = _nginx_conf(
        run, port,
        f"ssl_certificate {srv_crt}; ssl_certificate_key {srv_key};"
        f" ssl_client_certificate {CA_DIR}/ca.pem; ssl_verify_client optional;",
        f"""brix_cvmfs on;
        brix_cvmfs_stratum0_root {web};
        brix_scvmfs on;
        brix_scvmfs_authz voms;
        brix_scvmfs_vomsdir {vd};
        brix_scvmfs_voms_cert_dir {CA_DIR};
        brix_scvmfs_voms "atlas";""")
    run.start_nginx(run.root, conf, port)
    return repo, port, proxies


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


_SURFACE = [".cvmfspublished", ".cvmfswhitelist", ".cvmfs_master_replica"]


# ---- success ---------------------------------------------------------------

def test_x509_matching_dn_serves_stratum0(s0):
    """alice (DN in the allow-glob) reads the full Stratum-0 surface —
    manifest/whitelist byte-identical to the published tree, the root
    catalog straight from CAS, and the replication marker."""
    _, repo, port, pki, _ = s0
    base = f"/cvmfs/{FQRN}"
    for name in (".cvmfspublished", ".cvmfswhitelist"):
        st, body = _fetch(port, f"{base}/{name}", client=pki["alice"])
        assert st == 200 and body == (repo / name).read_bytes(), name
    root_hex = parse_manifest(repo)["C"]
    st, body = _fetch(port, f"{base}/data/{root_hex[:2]}/{root_hex[2:]}C",
                      client=pki["alice"])
    assert st == 200 and body == cas_path(repo, root_hex, "C").read_bytes()
    st, body = _fetch(port, f"{base}/.cvmfs_master_replica", client=pki["alice"])
    assert st == 200 and b"Stratum-0" in body


def test_voms_matching_vo_serves_stratum0(s0_voms):
    """An /atlas VOMS proxy is admitted by the VO glob — the same composition,
    different authz mode, still pure configuration."""
    repo, port, proxies = s0_voms
    base = f"/cvmfs/{FQRN}"
    st, body = _fetch(port, f"{base}/.cvmfspublished", client=proxies["atlas"])
    assert st == 200 and body == (repo / ".cvmfspublished").read_bytes()
    st, body = _fetch(port, f"{base}/.cvmfs_master_replica",
                      client=proxies["atlas"])
    assert st == 200 and b"Stratum-0" in body


# ---- error -----------------------------------------------------------------

def test_no_credential_401_no_manifest_leak(s0):
    """Anonymous requests fail closed on EVERY class — `.cvmfspublished` is
    NOT fetchable around the preamble (the S14 manifest-leak pin), and the
    replication marker does not advertise a gated master copy."""
    _, repo, port, _, _ = s0
    base = f"/cvmfs/{FQRN}"
    root_hex = parse_manifest(repo)["C"]
    for path in [f"{base}/{n}" for n in _SURFACE] + [
            f"{base}/data/{root_hex[:2]}/{root_hex[2:]}C"]:
        st, _ = _fetch(port, path, client=None)
        assert st == 401, f"anonymous {path}: {st}"


# ---- security-negative -----------------------------------------------------

def test_verified_but_unlisted_dn_403(s0):
    """bob's chain verifies but his DN is outside the allow-glob — refused on
    the whole surface, marker included (authenticated ≠ authorized)."""
    _, _, port, pki, _ = s0
    for name in _SURFACE:
        st, _ = _fetch(port, f"/cvmfs/{FQRN}/{name}", client=pki["bob"])
        assert st == 403, f"bob {name}: {st}"


def test_untrusted_ca_rejected(s0):
    """The RIGHT DN minted by a rogue CA fails chain verification — DN
    spoofing never opens the Stratum-0 (nginx core 400s it, our X509_V_OK
    guard is the second line)."""
    _, _, port, pki, _ = s0
    st, _ = _fetch(port, f"/cvmfs/{FQRN}/.cvmfspublished", client=pki["rogue"])
    assert st in (400, 401) and st != 200


def test_voms_wrong_vo_and_anonymous_refused(s0_voms):
    """A /cms proxy carries a VO, just not the allowed one → 403; anonymous
    → 401. The gated manifest never leaks in voms mode either."""
    _, port, proxies = s0_voms
    st, _ = _fetch(port, f"/cvmfs/{FQRN}/.cvmfspublished", client=proxies["cms"])
    assert st == 403
    st, _ = _fetch(port, f"/cvmfs/{FQRN}/.cvmfspublished", client=None)
    assert st == 401
