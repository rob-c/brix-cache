"""Phase-87 G16 — virtual / composed repos: brix_cvmfs_virtual_repo.

Theme
-----
``brix_cvmfs_virtual_repo <virtual-fqrn> <member-fqrn>...`` presents a
read-only UNION of member repos under a repo name that need not exist
anywhere upstream. Contract:

* a request naming the virtual fqrn is rewritten to member[0]; a definitive
  404 advances to the next member (declaration order = precedence); the first
  non-404 answer is final — origin traffic and cache keys are ALWAYS member
  paths (an object cached via the virtual name and via direct member access
  is one cache entry);
* signed metadata (.cvmfspublished) comes from the first member that has it —
  deterministic precedence, no catalog synthesis (HTTP-plane composition);
* a path absent in every member is a clean 404;
* each member's F3 repo authz is enforced independently after the rewrite —
  composition never elevates: a gated member answers 401 through the virtual
  name exactly as it does directly, and an ungated sibling cannot be used to
  reach it;
* config-time validation refuses ambiguous compositions (duplicate virtual
  names, self-membership, nesting).

Port block srv_authz (13280-13299), shared sequentially — each process gets a
private tile, so cross-file reuse never collides.
"""

import hashlib
import os
import re
import shutil
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from cmdscripts.live_common import (
    inject_nginx_load_modules,
    inject_nginx_runtime_paths,
)

# conftest chdir()s into a scratch dir — anchor imports on this file's dir.
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "cvmfs"))

from conformance_common import NGINX_BIN, PortBlock, srv_instance
from settings import BIND_HOST, HOST

try:                                     # cryptography is an optional test dep
    from tokenforge import TokenForge, write_scitokens_cfg
    _HAVE_TOKENFORGE = True
except Exception:                        # noqa: BLE001
    _HAVE_TOKENFORGE = False

pytestmark = pytest.mark.skipif(not os.path.exists(NGINX_BIN),
                                reason=f"nginx binary not found: {NGINX_BIN}")

# One shared allocator: each srv_instance below takes the next mock/nginx
# pair, so no port is rebound within this module's lifetime.
_BLOCK = PortBlock("srv_authz")

VIRT = "virt.cern.ch"
MEMBER_A = "repo-a.cern.ch"
MEMBER_B = "repo-b.cern.ch"
COMPOSE = f"brix_cvmfs_virtual_repo {VIRT} {MEMBER_A} {MEMBER_B};"


# ---- webroot forging -------------------------------------------------------

def _put(webroot: Path, repo: str, rel: str, body: bytes) -> None:
    p = webroot / "cvmfs" / repo / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(body)


def _put_cas(webroot: Path, repo: str, body: bytes) -> str:
    """Store `body` as an honest CAS object (name = sha1 of stored bytes,
    uncompressed) under `repo`; returns the repo-relative data path."""
    h = hashlib.sha1(body).hexdigest()
    rel = f"data/{h[:2]}/{h[2:]}"
    _put(webroot, repo, rel, body)
    return rel


def _forge_webroot(tmp: Path) -> tuple[Path, str, bytes, str, bytes]:
    """Two member trees: one object only in A, one only in B, manifests in
    both (with distinct bytes, so precedence is observable)."""
    webroot = tmp / "webroot"
    body_a = b"payload-only-in-repo-a\n"
    body_b = b"payload-only-in-repo-b\n"
    rel_a = _put_cas(webroot, MEMBER_A, body_a)
    rel_b = _put_cas(webroot, MEMBER_B, body_b)
    _put(webroot, MEMBER_A, ".cvmfspublished", b"manifest-of-repo-a\n")
    _put(webroot, MEMBER_B, ".cvmfspublished", b"manifest-of-repo-b\n")
    return webroot, rel_a, body_a, rel_b, body_b


# ---- fetch helper ----------------------------------------------------------

def _fetch(port, path, *, https=False, token=None):
    scheme = "https" if https else "http"
    req = urllib.request.Request(f"{scheme}://{HOST}:{port}{path}")
    if token is not None:
        req.add_header("Authorization", f"Bearer {token}")
    kw = {"context": ssl._create_unverified_context()} if https else {}
    try:
        with urllib.request.urlopen(req, timeout=15, **kw) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


# ---- success: union + precedence + shared cache keys -----------------------

def test_union_serves_both_members_with_precedence(tmp_path):
    webroot, rel_a, body_a, rel_b, body_b = _forge_webroot(tmp_path)
    with srv_instance(_BLOCK, webroot=webroot,
                      extra_directives=COMPOSE) as srv:
        # member[0] direct hit through the virtual name
        st, body = _fetch(srv.nginx_port, f"/cvmfs/{VIRT}/{rel_a}")
        assert (st, body) == (200, body_a)

        # only in member[1]: the repo-a 404 must advance, not surface
        st, body = _fetch(srv.nginx_port, f"/cvmfs/{VIRT}/{rel_b}")
        assert (st, body) == (200, body_b)

        # deterministic precedence: metadata is member[0]'s, never member[1]'s
        st, body = _fetch(srv.nginx_port, f"/cvmfs/{VIRT}/.cvmfspublished")
        assert (st, body) == (200, b"manifest-of-repo-a\n")

        # the virtual name NEVER reaches the origin — fills use member paths
        assert srv.count_log(VIRT) == 0
        assert srv.count_log(f"/cvmfs/{MEMBER_A}/{rel_a}") == 1
        assert srv.count_log(f"/cvmfs/{MEMBER_B}/{rel_b}") == 1

        # shared cache entry: a direct member request after the virtual fetch
        # is a pure cache hit (no second origin fill of the same object)
        srv.reset_log()
        st, body = _fetch(srv.nginx_port, f"/cvmfs/{MEMBER_B}/{rel_b}")
        assert (st, body) == (200, body_b)
        assert srv.count_log(rel_b) == 0, \
            "direct member access re-filled an object the virtual name cached"


# ---- error: absent in every member is a clean 404 --------------------------

def test_absent_everywhere_is_clean_404(tmp_path):
    webroot, rel_a, _body_a, _rel_b, _body_b = _forge_webroot(tmp_path)
    absent = hashlib.sha1(b"nowhere").hexdigest()
    path = f"/cvmfs/{VIRT}/data/{absent[:2]}/{absent[2:]}"
    with srv_instance(_BLOCK, webroot=webroot,
                      extra_directives=COMPOSE) as srv:
        st, _ = _fetch(srv.nginx_port, path)
        assert st == 404
        # both members were consulted, as member paths. Absence is discovered
        # at the fill's HEAD size-probe (never reaches a logged GET), so the
        # probe ledger — not the fetch log — is the witness here.
        probed = [h["path"] for h in srv.get_heads()]
        assert probed.count(f"/cvmfs/{MEMBER_A}/data/{absent[:2]}/{absent[2:]}") == 1
        assert probed.count(f"/cvmfs/{MEMBER_B}/data/{absent[:2]}/{absent[2:]}") == 1
        assert srv.count_log(VIRT) == 0
        # a retry is still 404 (T13 negative memo + member walk interplay)
        st, _ = _fetch(srv.nginx_port, path)
        assert st == 404
        # composition intact after the misses: real objects still serve
        st, _ = _fetch(srv.nginx_port, f"/cvmfs/{VIRT}/{rel_a}")
        assert st == 200


# ---- error: only a definitive 404 advances the walk ------------------------

def test_member_5xx_surfaces_and_never_advances(tmp_path):
    """An origin failure on member[0] must SURFACE, not silently fall through
    to member[1] — advancing on 5xx would mask outages behind stale siblings
    and turn one origin brownout into a full member-fan of retries."""
    webroot = tmp_path / "webroot"
    body = b"present-in-both-members\n"
    rel = _put_cas(webroot, MEMBER_A, body)
    assert _put_cas(webroot, MEMBER_B, body) == rel   # same bytes, same name
    # short T20 hold: the fill classifies an origin 500 as transient and holds
    # the client while it retries (default 25s) — 2s keeps the test brisk and
    # still exercises the hold→504 path
    with srv_instance(_BLOCK, webroot=webroot,
                      extra_directives=COMPOSE
                      + " brix_cvmfs_client_hold 2;") as srv:
        # every GET of the object on member[0] fails at the origin
        srv.set_fault("http500", 50,
                      path_re=re.escape(f"/cvmfs/{MEMBER_A}/{rel}"))
        st, _ = _fetch(srv.nginx_port, f"/cvmfs/{VIRT}/{rel}")
        assert 500 <= st < 600, f"member 5xx did not surface (got {st})"
        # member[0] was attempted; member[1] was NEVER consulted
        probed = [h["path"] for h in srv.get_heads()]
        assert f"/cvmfs/{MEMBER_A}/{rel}" in probed
        assert f"/cvmfs/{MEMBER_B}/{rel}" not in probed
        assert srv.count_log(f"/cvmfs/{MEMBER_B}/{rel}") == 0, \
            "a non-404 member error advanced the walk"

        # once the origin heals, the same path serves again (no poisoned
        # negative state from the failed fill; the background fill's own
        # retry backoff may take a few seconds to notice)
        srv.set_fault("none", 0)
        deadline = time.time() + 20
        while True:
            st, got = _fetch(srv.nginx_port, f"/cvmfs/{VIRT}/{rel}")
            if st == 200:
                assert got == body
                break
            assert time.time() < deadline, \
                f"virtual path did not recover after origin healed (last={st})"
            time.sleep(0.3)


# ---- security-neg: composition does not open new write surface -------------

def _mutate(port, path, method):
    req = urllib.request.Request(
        f"http://{HOST}:{port}{path}", method=method,
        data=b"x" if method == "PUT" else None)
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code


def test_virtual_name_is_read_only_like_members(tmp_path):
    """Method police applies through the virtual name exactly as directly:
    the rewrite runs before the method gate, so a PUT/DELETE on the virtual
    fqrn is the same 405 a direct member request gets — composition adds no
    write surface."""
    webroot, rel_a, _body_a, _rel_b, _body_b = _forge_webroot(tmp_path)
    with srv_instance(_BLOCK, webroot=webroot,
                      extra_directives=COMPOSE) as srv:
        for method in ("PUT", "DELETE"):
            via_virtual = _mutate(srv.nginx_port,
                                  f"/cvmfs/{VIRT}/{rel_a}", method)
            direct = _mutate(srv.nginx_port,
                             f"/cvmfs/{MEMBER_A}/{rel_a}", method)
            assert via_virtual == direct == 405, \
                f"{method}: virtual={via_virtual} direct={direct}"
        # nothing reached the origin, and reads still work afterwards
        assert srv.count_log("data/") == 0
        st, _ = _fetch(srv.nginx_port, f"/cvmfs/{VIRT}/{rel_a}")
        assert st == 200


# ---- security-neg: per-member F3 authz is never elevated -------------------

requires_openssl = pytest.mark.skipif(shutil.which("openssl") is None,
                                      reason="openssl not installed")
requires_tokens = pytest.mark.skipif(not _HAVE_TOKENFORGE,
                                     reason="tokenforge (cryptography) unavailable")


@requires_openssl
@requires_tokens
def test_gated_member_not_reachable_anonymously_via_virtual(tmp_path):
    webroot, rel_a, body_a, rel_b, body_b = _forge_webroot(tmp_path)

    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days",
         "1", "-subj", "/CN=localhost",  # net-literal-allow: throwaway TLS cert subject CN
         "-keyout", str(tmp_path / "key.pem"), "-out", str(tmp_path / "crt.pem")],
        check=True, capture_output=True)

    forge = TokenForge(str(tmp_path / "mint"))
    forge.init_keys()
    cfg = tmp_path / "mint" / "scitokens.cfg"
    write_scitokens_cfg(str(cfg), [{
        "name": "virt-authz", "issuer": forge.issuer,
        "audience": forge.audience, "base_paths": ["/"],
        "jwks_path": forge.jwks_path, "strategy": "capability",
    }])

    extra = COMPOSE + f" brix_cvmfs_repo_authz {MEMBER_B} {cfg};"
    with srv_instance(_BLOCK, webroot=webroot,
                      extra_directives=extra,
                      ssl_cert=tmp_path / "crt.pem",
                      ssl_key=tmp_path / "key.pem") as srv:
        # the gated member's object is NOT anonymously reachable through the
        # virtual name: repo-a 404s, the advance lands on repo-b's gate → 401
        st, _ = _fetch(srv.nginx_port, f"/cvmfs/{VIRT}/{rel_b}", https=True)
        assert st == 401, "composition elevated access to a gated member"

        # the ungated member keeps serving anonymously through the same name
        st, body = _fetch(srv.nginx_port, f"/cvmfs/{VIRT}/{rel_a}", https=True)
        assert (st, body) == (200, body_a)

        # a valid READ-scope bearer opens the gated member via the virtual
        # name exactly as it would directly
        st, body = _fetch(srv.nginx_port, f"/cvmfs/{VIRT}/{rel_b}",
                          https=True, token=forge.generate())
        assert (st, body) == (200, body_b)


# ---- config-time validation ------------------------------------------------

def _nginx_t(tmp_path, directive, port):
    # `nginx -t` binds its listen sockets, so the accept-case needs a real
    # allocated port (reject-cases abort at parse time, before bind).
    (tmp_path / "cache").mkdir(exist_ok=True)
    logs = tmp_path / "logs"
    logs.mkdir(exist_ok=True)
    conf = tmp_path / "nginx.conf"
    conf.write_text(f"""daemon off; error_log {logs}/e.log info; pid {tmp_path}/nginx.pid;
events {{ worker_connections 64; }}
http {{ server {{ listen {BIND_HOST}:{port};
    location /cvmfs/ {{ brix_cvmfs on;
        brix_storage_backend "http://{HOST}:1";
        brix_cache_store posix:{tmp_path}/cache;
        {directive}
    }}
}} }}
""")
    inject_nginx_load_modules(conf)
    inject_nginx_runtime_paths(conf, tmp_path)
    return subprocess.run([NGINX_BIN, "-t", "-p", str(tmp_path), "-c", str(conf)],
                          capture_output=True, text=True, timeout=30)


def test_config_rejects_ambiguous_compositions(tmp_path):
    port = _BLOCK.nginx()

    r = _nginx_t(tmp_path, f"brix_cvmfs_virtual_repo {VIRT} {VIRT};", port)
    assert r.returncode != 0 and "cannot be its own member" in r.stderr + r.stdout

    r = _nginx_t(tmp_path, f"brix_cvmfs_virtual_repo {VIRT} {MEMBER_A};\n"
                           f"        brix_cvmfs_virtual_repo {VIRT} {MEMBER_B};", port)
    assert r.returncode != 0 and "duplicate" in r.stderr + r.stdout

    r = _nginx_t(tmp_path, f"brix_cvmfs_virtual_repo {VIRT} {MEMBER_A};\n"
                           f"        brix_cvmfs_virtual_repo umbrella.cern.ch {VIRT};", port)
    assert r.returncode != 0 and "cannot nest" in r.stderr + r.stdout

    r = _nginx_t(tmp_path, COMPOSE, port)
    assert r.returncode == 0, f"valid composition refused: {r.stderr}"
