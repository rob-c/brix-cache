"""Phase-85 F9 — per-VO / per-job QoS fill throttling: brix_cvmfs_qos.

Theme
-----
``brix_cvmfs_qos <class> sub=<subject>|default fills=<N>`` rate-limits ORIGIN
FILLS (token bucket, N fills/second, per worker) per requester class. Contract:

* classification key is the VALIDATED bearer subject (stashed by the F3
  repo-authz / scvmfs token paths) — an unvalidated Authorization header can
  never select a class;
* only remote miss-fills are charged: cache hits always flow, throttled or not;
* over budget → 429 + NOTICE ``qos class "<c>" fill budget exhausted``;
* ``fills=0`` = unlimited (parity with no directive for that class);
* no matching class and no ``default`` entry → unthrottled;
* empty subject (anonymous / ungated repo) falls to the ``default`` class.

Port block srv_authz (shares the F3 block; suites run sequentially).
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

try:                                     # cryptography is an optional test dep
    from tokenforge import TokenForge, write_scitokens_cfg
    _HAVE_TOKENFORGE = True
except Exception:                        # noqa: BLE001
    _HAVE_TOKENFORGE = False

REPO = "test.cern.ch"

requires_openssl = pytest.mark.skipif(shutil.which("openssl") is None,
                                      reason="openssl not installed")
requires_tokens = pytest.mark.skipif(not _HAVE_TOKENFORGE,
                                     reason="tokenforge (cryptography) unavailable")

pytestmark = [
    pytest.mark.skipif(not os.path.exists(NGINX_BIN),
                       reason=f"nginx binary not found: {NGINX_BIN}"),
    requires_openssl, requires_tokens,
]

# ONE module-wide allocator: a fresh PortBlock would restart at base+10 and
# collide with a still-listening earlier instance (F8 dead-sibling lesson).
_BLOCK = PortBlock("srv_authz")


@pytest.fixture(scope="module")
def tls_identity(tmp_path_factory):
    d = tmp_path_factory.mktemp("qos_tls")
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
         "-subj", "/CN=localhost", "-keyout", str(d / "key.pem"),
         "-out", str(d / "crt.pem")],
        check=True, capture_output=True)
    return d / "crt.pem", d / "key.pem"


@pytest.fixture(scope="module")
def mint(tmp_path_factory):
    """Local RS256 mint + the scitokens.cfg registry the server loads."""
    d = tmp_path_factory.mktemp("qos_tokens")
    forge = TokenForge(str(d))
    forge.init_keys()
    cfg = d / "scitokens.cfg"
    write_scitokens_cfg(str(cfg), [{
        "name": "qos-authz", "issuer": forge.issuer, "audience": forge.audience,
        "base_paths": ["/"], "jwks_path": forge.jwks_path,
        "strategy": "capability",
    }])
    return forge, cfg


@contextmanager
def _srv(qos, *, gate_cfg=None, tls=None, **kw):
    """cvmfs instance with the given brix_cvmfs_qos lines; F3 gate optional."""
    directives = qos
    if gate_cfg is not None:
        directives = f"brix_cvmfs_repo_authz {REPO} {gate_cfg}; " + directives
    kw["extra_directives"] = directives
    if tls is not None:
        kw["ssl_cert"], kw["ssl_key"] = tls
    with srv_instance(_BLOCK, objects=6, **kw) as srv:
        yield srv


def _fetch(port, path, *, https, token=None):
    scheme = "https" if https else "http"
    req = urllib.request.Request(f"{scheme}://127.0.0.1:{port}{path}")
    if token is not None:
        req.add_header("Authorization", f"Bearer {token}")
    kw = {"context": ssl._create_unverified_context()} if https else {}
    try:
        with urllib.request.urlopen(req, timeout=15, **kw) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def _exhausted_lines(srv, cls):
    text = Path(srv.error_log).read_text(errors="replace")
    return [l for l in text.splitlines()
            if f'qos class "{cls}" fill budget exhausted' in l]


# ---- success: the named class is bounded, everyone else flows ---------------

def test_class_throttled_others_flow(tls_identity, mint):
    forge, cfg = mint
    alice = forge.generate(sub="alice")
    bob = forge.generate(sub="bob")
    with _srv("brix_cvmfs_qos heavy sub=alice fills=1;",
              gate_cfg=cfg, tls=tls_identity) as srv:
        objs = srv.objects()

        # alice's first distinct-object miss spends the whole 1-fill/s budget
        st, body = _fetch(srv.nginx_port, objs[0], https=True, token=alice)
        assert st == 200 and body

        # immediate second miss (new object) → over budget → 429 + audit line
        st, _ = _fetch(srv.nginx_port, objs[1], https=True, token=alice)
        assert st == 429
        assert _exhausted_lines(srv, "heavy")

        # bob has no class and there is no default → unthrottled
        for o in objs[1:4]:
            st, body = _fetch(srv.nginx_port, o, https=True, token=bob)
            assert st == 200 and body


def test_cache_hits_never_throttled(tls_identity, mint):
    """A throttled class still reads everything already cached — only origin
    fills are charged."""
    forge, cfg = mint
    alice = forge.generate(sub="alice")
    with _srv("brix_cvmfs_qos heavy sub=alice fills=1;",
              gate_cfg=cfg, tls=tls_identity) as srv:
        obj = srv.objects()[0]
        st, body = _fetch(srv.nginx_port, obj, https=True, token=alice)
        assert st == 200

        # budget is now spent; the SAME object re-read is a local hit → 200
        st, body2 = _fetch(srv.nginx_port, obj, https=True, token=alice)
        assert st == 200 and body2 == body


def test_default_class_catches_anonymous(mint):
    """On an ungated (open) repo no token is validated, so requests carry an
    empty subject and land in the ``default`` class."""
    _forge, _cfg = mint
    with _srv("brix_cvmfs_qos anon default fills=1;") as srv:
        objs = srv.objects()
        st, body = _fetch(srv.nginx_port, objs[0], https=False)
        assert st == 200 and body
        st, _ = _fetch(srv.nginx_port, objs[1], https=False)
        assert st == 429
        assert _exhausted_lines(srv, "anon")


# ---- error / parity ---------------------------------------------------------

def test_fills_zero_is_unlimited(tls_identity, mint):
    forge, cfg = mint
    alice = forge.generate(sub="alice")
    with _srv("brix_cvmfs_qos heavy sub=alice fills=0;",
              gate_cfg=cfg, tls=tls_identity) as srv:
        for o in srv.objects()[:5]:
            st, body = _fetch(srv.nginx_port, o, https=True, token=alice)
            assert st == 200 and body
        assert _exhausted_lines(srv, "heavy") == []


def test_bad_directive_rejected(tmp_path):
    """fills= must be a number; the parser refuses garbage at config time."""
    (tmp_path / "cache").mkdir()
    conf = tmp_path / "bad.conf"
    conf.write_text(f"""daemon off; events {{}}
http {{ server {{ listen 127.0.0.1:1; location /cvmfs/ {{
    brix_cvmfs on;
    brix_cache_store posix:{tmp_path}/cache;
    brix_cvmfs_qos heavy sub=alice fills=lots;
}} }} }}
""")
    r = subprocess.run([NGINX_BIN, "-t", "-c", str(conf), "-p", str(tmp_path)],
                       capture_output=True, text=True)
    assert r.returncode != 0
    assert "fills=" in r.stderr


# ---- security-negative ------------------------------------------------------

def test_unvalidated_sub_cannot_buy_a_class(mint):
    """On an ungated repo the bearer is never validated — a client CLAIMING
    sub=alice must not select alice's unlimited class; it stays in the
    throttled default class."""
    forge, _cfg = mint
    claimed = forge.generate(sub="alice")
    with _srv("brix_cvmfs_qos vip sub=alice fills=0; "
              "brix_cvmfs_qos anon default fills=1;") as srv:
        objs = srv.objects()
        st, _ = _fetch(srv.nginx_port, objs[0], https=False, token=claimed)
        assert st == 200
        st, _ = _fetch(srv.nginx_port, objs[1], https=False, token=claimed)
        assert st == 429, "an unvalidated sub claim escaped the default class"
        lines = _exhausted_lines(srv, "anon")
        assert lines and 'sub "anonymous"' in lines[-1]
