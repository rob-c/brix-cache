"""Phase-84 srv_config corpus — config-load contract + scvmfs authz / read-only live behavior.

Half A (no server): `nginx -t -c <generated>` subprocess drives the config-load
contract of src/protocols/cvmfs/:
  * incompatible-grammar EMERG rejections (cvmfs_module_build.c
    brix_cvmfs_reject_unsupported): brix_stage / brix_stage_store /
    brix_cache_slice_size / brix_allow_write x `brix_cvmfs on`, with
    without-cvmfs control rows;
  * structural layering (cvmfs_module_merge.c): scvmfs-requires-cvmfs,
    bearer-requires-issuers, unified_origin-requires-http-backend;
  * full directive inventory from directives_core.h + directives_resilience.h:
    duplicate rejection ("is duplicate") for every single-shot directive (which
    also proves the directive exists and its sample value parses), bad-value
    diagnostics, geo-mode structural requirements, and valid corner values.

Half B (live, unprivileged): scvmfs bearer authz matrix per secure.c + the
shared token issuer registry (T22) — official CVMFS has NO bearer layer, so
these assert BRIX's documented contract (docs/04-protocols/cvmfs.md §8:
missing/garbage/invalid bearer -> 401; valid READ-scope token -> served; the
scvmfs preamble is transport-gated: non-TLS connection -> 400).  Plus the
public-by-design contract (auth adds nothing when scvmfs is off) and the
forced-read-only contract (PUT/POST/DELETE never mutate, even authenticated).
"""

import itertools
import os
import shutil
import ssl
import subprocess
import sys
import urllib.error
import urllib.request

import pytest

# conftest chdir()s into a scratch dir — anchor imports on this file's dir.
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "cvmfs"))

from conformance_common import NGINX_BIN, PortBlock, request, srv_instance
from cmdscripts.live_common import inject_nginx_load_modules
from settings import BIND_HOST, HOST

try:                                     # cryptography is an optional test dep
    from tokenforge import TokenForge, write_scitokens_cfg
    _HAVE_TOKENFORGE = True
except Exception:                        # noqa: BLE001
    _HAVE_TOKENFORGE = False

REPO = "test.cern.ch"

requires_nginx = pytest.mark.skipif(not os.path.exists(NGINX_BIN),
                                    reason=f"nginx binary not found: {NGINX_BIN}")
requires_openssl = pytest.mark.skipif(shutil.which("openssl") is None,
                                      reason="openssl not installed")
requires_tokens = pytest.mark.skipif(not _HAVE_TOKENFORGE,
                                     reason="tokenforge (cryptography) unavailable")

pytestmark = requires_nginx

_BLOCK = PortBlock("srv_config")         # file-owned ports 13240-13259
_seq = itertools.count()


# ---------------------------------------------------------------------------
# Half A — config-load contract via `nginx -t` (no server start)
# ---------------------------------------------------------------------------

class ConfCheck:
    """Generate a minimal brix_cvmfs config and run `nginx -t` on it."""

    def __init__(self, root):
        self.root = root
        (root / "logs").mkdir(exist_ok=True)
        self.cache = root / "cache"
        self.cache.mkdir(exist_ok=True)
        self.stage = root / "stage"
        self.stage.mkdir(exist_ok=True)
        # Enabled-location preamble mirroring the live suites: an http origin
        # backend (never dialled by -t) + a posix cache store.
        self.base = ("brix_cvmfs on; brix_storage_backend http://127.0.0.1:9; "  # net-literal-allow: config-load-only origin backend, never dialled by nginx -t
                     f"brix_cache_store posix:{self.cache};")

    def run(self, location_directives):
        conf = self.root / f"t{next(_seq)}.conf"
        conf.write_text(f"""daemon off; error_log {self.root}/logs/t.log info;
pid {self.root}/t.pid; thread_pool default threads=2;
events {{ worker_connections 64; }}
http {{ access_log off; server {{ listen {BIND_HOST}:{_BLOCK.base + 19};
    location /cvmfs/ {{ {location_directives} }}
}} }}
""")
        inject_nginx_load_modules(conf)
        p = subprocess.run([NGINX_BIN, "-t", "-p", str(self.root), "-c", str(conf)],
                           capture_output=True, text=True, timeout=30)
        return p.returncode, p.stderr + p.stdout

    def ok(self, directives):
        rc, out = self.run(directives)
        assert rc == 0, f"config unexpectedly rejected:\n{out}"
        return out

    def fails(self, directives, needle):
        rc, out = self.run(directives)
        assert rc != 0, f"config unexpectedly loaded: {directives}"
        assert needle in out, f"diagnostic {needle!r} missing from:\n{out}"
        return out


@pytest.fixture(scope="module")
def cc(tmp_path_factory):
    return ConfCheck(tmp_path_factory.mktemp("cvmfs_conf_t"))


# -- incompatible-grammar EMERG rejection matrix ----------------------------

_INCOMPATIBLE = [
    pytest.param("brix_stage on;",
                 "cvmfs is a read-only protocol; staging is not supported",
                 id="stage"),
    pytest.param("brix_stage_store {stage};",
                 "cvmfs is a read-only protocol; staging is not supported",
                 id="stage_store"),
    pytest.param("brix_cache_slice_size 4m;",
                 "cvmfs CAS objects are immutable whole objects; slicing is not supported",
                 id="cache_slice_size"),
    pytest.param("brix_allow_write on;",
                 "cvmfs is a read-only protocol; write permission cannot be granted",
                 id="allow_write"),
]

def _tls_fetch(port, path, token=None, headers=None, method="GET"):
    """HTTPS request with an unverified context; returns (status, body)."""
    ctx = ssl._create_unverified_context()
    req = urllib.request.Request(f"https://{HOST}:{port}{path}", method=method)
    if token is not None:
        req.add_header("Authorization", f"Bearer {token}")
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=15) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


@pytest.fixture(scope="module")
def tls_identity(tmp_path_factory):
    """Throwaway TLS listener identity."""
    if shutil.which("openssl") is None:
        pytest.skip("openssl not installed")
    d = tmp_path_factory.mktemp("scvmfs_tls")
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
         "-subj", "/CN=localhost", "-keyout", str(d / "key.pem"),  # net-literal-allow: throwaway TLS cert subject CN
         "-out", str(d / "crt.pem")],
        check=True, capture_output=True)
    return d / "crt.pem", d / "key.pem"


@pytest.fixture(scope="module")
def mint(tmp_path_factory):
    """A local RS256 token mint + the scitokens.cfg registry the server loads."""
    if not _HAVE_TOKENFORGE:
        pytest.skip("tokenforge (cryptography) unavailable")
    d = tmp_path_factory.mktemp("scvmfs_tokens")
    forge = TokenForge(str(d))
    forge.init_keys()
    cfg = d / "scitokens.cfg"
    write_scitokens_cfg(str(cfg), [{
        "name": "conformance", "issuer": forge.issuer, "audience": forge.audience,
        "base_paths": ["/"], "jwks_path": forge.jwks_path,
        "strategy": "capability",
    }])
    return forge, cfg


@pytest.fixture(scope="module")
def bearer_srv(tls_identity, mint):
    """TLS listener, brix_scvmfs on, authz bearer with the local registry."""
    crt, key = tls_identity
    _, cfg = mint
    with srv_instance(_BLOCK, objects=4, seed=84, scvmfs=True,
                      ssl_cert=crt, ssl_key=key,
                      scvmfs_authz="bearer", token_issuers=cfg) as srv:
        yield srv


@pytest.fixture(scope="module")
def none_srv(tls_identity):
    """TLS listener, brix_scvmfs on, authz none."""
    crt, key = tls_identity
    with srv_instance(_BLOCK, objects=4, seed=85, scvmfs=True,
                      ssl_cert=crt, ssl_key=key, scvmfs_authz="none") as srv:
        yield srv


@pytest.fixture(scope="module")
def plain_srv():
    """Plain-HTTP cvmfs site cache, no scvmfs (public-by-design + read-only)."""
    with srv_instance(_BLOCK, objects=4, seed=86) as srv:
        yield srv


@pytest.fixture(scope="module")
def scvmfs_plain_srv():
    """brix_scvmfs on but the listener has NO ssl — transport gate target."""
    with srv_instance(_BLOCK, objects=4, seed=87, scvmfs=True) as srv:
        yield srv


def _origin_bytes(srv, obj):
    return urllib.request.urlopen(srv.mock_url + obj, timeout=15).read()


# -- scvmfs bearer authz matrix (T22; brix-specific — official CVMFS has no
#    bearer layer; asserting docs/04-protocols/cvmfs.md §8 as implemented by
#    secure.c: every authz failure -> 401, success -> served) ----------------
