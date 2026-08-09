# tests/test_cvmfs_conformance_srv_proxy.py — Phase-84 srv_proxy corpus (~60).
#
# Forward-proxy (CVMFS_HTTP_PROXY) mode conformance: absolute-form request-line
# grammar (ports / schemes / userinfo / IPv6 / missing path / CONNECT),
# brix_cvmfs_upstream_allow enforcement + bypass attempts,
# brix_cvmfs_upstream_max cap, brix_cvmfs_shared_cache dedup across upstreams,
# and brix_cvmfs_unified_origin (dead named origin hidden + config contract).
#
# Port block: srv_proxy 13180 (mocks 13180-13189, nginx 13190-13199; the top of
# the nginx sub-block, 13197-13199, is reserved here as guaranteed-dead ports —
# only 7 nginx instances are ever allocated).
#
# Behavior contract sources:
#   src/protocols/cvmfs/request.c   — scheme check, port 1..65535, host allowlist
#   src/protocols/cvmfs/gate.c      — classify-then-bind order, reject lines
#   src/protocols/cvmfs/upstreams.c — per-upstream registry, shared_cache subtree
#   src/protocols/cvmfs/cvmfs_module_merge.c — unified_origin config contract
import os
import subprocess
import sys
import urllib.request

import pytest

# conftest chdir()s into a scratch dir — anchor imports on this file's dir.
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "cvmfs"))

from conformance_common import (NGINX_BIN, PortBlock, _ctl_get, _spawn_mock,
                                absolute_form_request, raw_http, request,
                                srv_instance)
from cmdscripts.live_common import (
    inject_nginx_load_modules,
    inject_nginx_runtime_paths,
)
from settings import BIND_HOST, HOST

pytestmark = pytest.mark.skipif(not os.path.exists(NGINX_BIN),
                                reason=f"nginx binary not found: {NGINX_BIN}")

REPO = "test.cern.ch"
MPATH = f"/cvmfs/{REPO}/.cvmfspublished"

BLOCK = PortBlock("srv_proxy")
# Guaranteed-dead in-block ports (never listened on; nginx allocation stops at 7).
DEAD1, DEAD2, DEAD3 = BLOCK.base + 17, BLOCK.base + 18, BLOCK.base + 19

# Keep dead-upstream connect failures fast across the whole module (client_hold
# bounds how long a failed fill parks the client before the error is emitted).
FAST = dict(connect_timeout=1, attempt_timeout=2, client_hold=2)


def af(srv, uri, method="GET", headers=None):
    """Absolute-form request through srv's nginx; returns (status, headers, body)."""
    return absolute_form_request(HOST, srv.nginx_port, uri,
                                 method=method, headers=headers)


def tgt(port, path, host="127.0.0.1"):  # net-literal-allow: upstream-authority payload matched by upstream_allow
    return f"http://{host}:{port}{path}"


def mock_count(port, needle):
    return sum(1 for e in _ctl_get(port, "log") if needle in e["path"])


# --------------------------------------------------------------------------- #
# Module fixtures — one instance per proxy configuration under test.
# --------------------------------------------------------------------------- #

@pytest.fixture(scope="module")
def psrv():
    """Proxy mode, allowlist '127.0.0.1' (the srv_instance proxy default)."""
    with srv_instance(BLOCK, proxy_mode=True, objects=8, seed=101, **FAST) as srv:
        yield srv


@pytest.fixture(scope="module")
def psrv_name():
    """Proxy mode, name-based allowlist (uppercase entry + IPv6 literal)."""
    with srv_instance(BLOCK, proxy_mode=True, objects=4, seed=102,
                      upstream_allow="LOCALHOST [::1]", **FAST) as srv:  # net-literal-allow: host-ACL match string under test
        yield srv


@pytest.fixture(scope="module")
def rev():
    """Reverse mode: no allowlist set at all — proxy mode is OFF."""
    with srv_instance(BLOCK, objects=4, seed=103) as srv:
        yield srv


@pytest.fixture(scope="module")
def upmax():
    """Proxy mode with a 2-slot upstream registry cap."""
    with srv_instance(BLOCK, proxy_mode=True, objects=4, seed=104,
                      upstream_max=2, **FAST) as srv:
        yield srv


@pytest.fixture(scope="module")
def shared_on():
    """shared_cache on + a twin mock (same seed => byte-identical object set)."""
    with srv_instance(BLOCK, proxy_mode=True, objects=6, seed=71,
                      shared_cache="on", **FAST) as srv:
        twin = BLOCK.mock()
        _spawn_mock(srv.run, twin, objects=6, seed=71)
        yield srv, twin


@pytest.fixture(scope="module")
def shared_off():
    """Default per-upstream cache isolation + a twin mock."""
    with srv_instance(BLOCK, proxy_mode=True, objects=6, seed=72, **FAST) as srv:
        twin = BLOCK.mock()
        _spawn_mock(srv.run, twin, objects=6, seed=72)
        yield srv, twin


@pytest.fixture(scope="module")
def unified():
    """unified_origin on: one ranked multi-endpoint backend behind the proxy."""
    m = BLOCK.mock()
    backend = f'brix_storage_backend "http://{HOST}:{m}|http://127.0.0.1:{DEAD3}";'  # net-literal-allow: dead ranked backend endpoint under test
    with srv_instance(BLOCK, proxy_mode=True, n_mocks=0, unified_origin="on",
                      extra_directives=backend, **FAST) as srv:
        _spawn_mock(srv.run, m, objects=6, seed=105)
        yield srv, m


# --------------------------------------------------------------------------- #
# A. Absolute-form request-line corpus
# --------------------------------------------------------------------------- #

def _nginx_t(tmp_path, backend_line):
    prefix = tmp_path / "p"
    (prefix / "logs").mkdir(parents=True, exist_ok=True)
    cache = tmp_path / "cache"
    cache.mkdir(exist_ok=True)
    conf = tmp_path / "t.conf"
    conf.write_text(f"""daemon off; error_log {prefix}/logs/e.log; pid {prefix}/nginx.pid;
thread_pool default threads=2;
events {{ worker_connections 32; }}
http {{ server {{ listen {BIND_HOST}:{DEAD3}; location / {{
    brix_cache_store posix:{cache};
    brix_cvmfs on;
    brix_cvmfs_upstream_allow {HOST};
    brix_cvmfs_unified_origin on;
    {backend_line}
}} }} }}
""")
    inject_nginx_load_modules(conf)
    inject_nginx_runtime_paths(conf, prefix)
    r = subprocess.run([NGINX_BIN, "-t", "-c", str(conf), "-p", str(prefix)],
                       capture_output=True, text=True, timeout=30)
    return r.returncode, (r.stderr or "") + (r.stdout or "")
