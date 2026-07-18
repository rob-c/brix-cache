"""Phase-84 srv_config corpus — config-load contract + scvmfs authz / read-only live behavior.

Half A (no server): `nginx -t -c <generated>` subprocess drives the config-load
contract of src/protocols/cvmfs/:
  * incompatible-grammar EMERG rejections (cvmfs_module_build.c
    brix_cvmfs_reject_unsupported): brix_stage / brix_stage_store /
    brix_cache_slice_size / brix_allow_write x `brix_cvmfs on`, with
    without-cvmfs control rows;
  * structural layering (cvmfs_module_merge.c): scvmfs-requires-cvmfs,
    bearer-requires-issuers, unified_origin-requires-http-backend;
  * full directive inventory from directives_core.inc + directives_resilience.inc:
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
        self.base = ("brix_cvmfs on; brix_storage_backend http://127.0.0.1:9; "
                     f"brix_cache_store posix:{self.cache};")

    def run(self, location_directives):
        conf = self.root / f"t{next(_seq)}.conf"
        conf.write_text(f"""daemon off; error_log {self.root}/logs/t.log info;
pid {self.root}/t.pid; thread_pool default threads=2;
events {{ worker_connections 64; }}
http {{ access_log off; server {{ listen 127.0.0.1:13259;
    location /cvmfs/ {{ {location_directives} }}
}} }}
""")
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


@pytest.mark.parametrize("directive, needle", _INCOMPATIBLE)
def test_incompatible_directive_rejected_with_cvmfs(cc, directive, needle):
    """brix_cvmfs_reject_unsupported: EMERG at config load, never a silent no-op."""
    cc.fails(cc.base + directive.format(stage=cc.stage), needle)


@pytest.mark.parametrize("directive, needle", _INCOMPATIBLE)
def test_incompatible_directive_without_cvmfs_loads(cc, directive, needle):
    """Control rows: the same directives are legal grammar outside cvmfs."""
    cc.ok(directive.format(stage=cc.stage))


# -- structural layering contracts ------------------------------------------

def test_scvmfs_requires_cvmfs(cc):
    cc.fails("brix_scvmfs on;", "brix_scvmfs requires brix_cvmfs on")


def test_scvmfs_bearer_requires_token_issuers(cc):
    cc.fails(cc.base + "brix_scvmfs on; brix_scvmfs_authz bearer;",
             "brix_scvmfs_authz bearer requires brix_scvmfs_token_issuers")


def test_scvmfs_authz_none_needs_no_issuers(cc):
    cc.ok(cc.base + "brix_scvmfs on; brix_scvmfs_authz none;")


def test_unified_origin_requires_http_backend(cc):
    cc.fails(f"brix_cvmfs on; brix_cache_store posix:{cc.cache}; "
             "brix_cvmfs_unified_origin on;",
             "brix_cvmfs_unified_origin on requires brix_storage_backend "
             "to name an http(s) origin set")


def test_unified_origin_with_http_backend_loads(cc):
    cc.ok(cc.base + "brix_cvmfs_unified_origin on;")


def test_unified_origin_multi_endpoint_loads(cc):
    cc.ok(f"brix_cvmfs on; brix_cache_store posix:{cc.cache}; "
          'brix_storage_backend "http://127.0.0.1:9|http://127.0.0.1:8"; '
          "brix_cvmfs_unified_origin on;")


# -- duplicate rejection: full single-shot directive inventory ---------------
# Every directive from directives_core.inc + directives_resilience.inc except
# the two accumulators (upstream_allow, origin_coords).  A passing row proves
# both that the directive exists with this sample value AND that the second
# occurrence is refused ("is duplicate").

_SINGLE_SHOT = [
    ("brix_cvmfs", "on"),
    ("brix_scvmfs", "on"),
    ("brix_scvmfs_authz", "none"),
    ("brix_scvmfs_token_issuers", "/tmp/scitokens.cfg"),
    ("brix_cvmfs_manifest_ttl", "61"),
    ("brix_cvmfs_negative_ttl", "10"),
    ("brix_cvmfs_quarantine_dir", "/tmp/quarantine"),
    ("brix_cvmfs_upstream_max", "8"),
    ("brix_cvmfs_trace", "off"),
    ("brix_cvmfs_origin_select", "rtt"),
    ("brix_cvmfs_here", "55.9:-3.2"),
    ("brix_cvmfs_client_hold", "25"),
    ("brix_cvmfs_fill_max_life", "300"),
    ("brix_cvmfs_rtt_interval", "60"),
    ("brix_cvmfs_origin_connect_timeout", "2"),
    ("brix_cvmfs_origin_stall_timeout", "4"),
    ("brix_cvmfs_origin_stall_bytes", "1"),
    ("brix_cvmfs_origin_attempt_timeout", "0"),
    ("brix_cvmfs_shared_cache", "off"),
    ("brix_cvmfs_unified_origin", "off"),
    ("brix_cvmfs_origin_reuse_conn", "on"),
    ("brix_cvmfs_fill_retry_policy", "failover"),
    ("brix_cvmfs_geo_answer", "off"),
    ("brix_cvmfs_geo_cache_ttl", "60"),
    ("brix_cvmfs_geo_max_servers", "16"),
]


@pytest.mark.parametrize("directive, value", _SINGLE_SHOT,
                         ids=[d for d, _ in _SINGLE_SHOT])
def test_duplicate_directive_rejected(cc, directive, value):
    cc.fails(f"{directive} {value}; {directive} {value};",
             f'"{directive}" directive is duplicate')


@pytest.mark.parametrize("directives", [
    pytest.param("brix_cvmfs_upstream_allow a.example b.example; "
                 "brix_cvmfs_upstream_allow c.example;", id="upstream_allow"),
    pytest.param("brix_cvmfs_origin_coords 127.0.0.1 46.2:6.1; "
                 "brix_cvmfs_origin_coords 127.0.0.2 55.9:-3.2;", id="origin_coords"),
])
def test_accumulating_directive_repeats_load(cc, directives):
    """The two list directives deliberately accumulate across repeats."""
    cc.ok(cc.base + directives)


# -- bad values --------------------------------------------------------------

@pytest.mark.parametrize("directives, needle", [
    pytest.param("brix_cvmfs banana;", 'it must be "on" or "off"', id="flag-junk"),
    pytest.param("brix_cvmfs_manifest_ttl -1;", "invalid value", id="manifest_ttl-neg"),
    pytest.param("brix_cvmfs_negative_ttl banana;", "invalid value", id="negative_ttl-junk"),
    pytest.param("brix_cvmfs_client_hold 5wq;", "invalid value", id="client_hold-junk"),
    pytest.param("brix_cvmfs_geo_cache_ttl -3;", "invalid value", id="geo_cache_ttl-neg"),
    pytest.param("brix_cvmfs_origin_select bogus;", "invalid value", id="origin_select-enum"),
    pytest.param("brix_cvmfs_geo_answer bogus;", "invalid value", id="geo_answer-enum"),
    pytest.param("brix_cvmfs_fill_retry_policy bogus;", "invalid value",
                 id="fill_retry_policy-enum"),
    pytest.param("brix_scvmfs_authz bogus;", "invalid value", id="scvmfs_authz-enum"),
    pytest.param("brix_cvmfs_upstream_max banana;", "invalid number", id="upstream_max-junk"),
    pytest.param("brix_cvmfs_upstream_max -1;", "invalid number", id="upstream_max-neg"),
    pytest.param("brix_cvmfs_geo_max_servers banana;", "invalid number",
                 id="geo_max_servers-junk"),
    pytest.param("brix_cvmfs_origin_stall_bytes banana;", "invalid number",
                 id="stall_bytes-junk"),
    pytest.param("brix_cvmfs_trace banana;", 'it must be "on" or "off"', id="trace-junk"),
])
def test_bad_value_rejected(cc, directives, needle):
    cc.fails(directives, needle)


@pytest.mark.parametrize("args, needle", [
    pytest.param("h1 91:0", "has invalid <lat>:<lon> coordinates", id="lat-over-90"),
    pytest.param("h1 0:181", "has invalid <lat>:<lon> coordinates", id="lon-over-180"),
    pytest.param("h1 46.2", "has invalid <lat>:<lon> coordinates", id="no-colon"),
    pytest.param("h1:0 1:1", "has an invalid port", id="port-0"),
    pytest.param("h1:70000 1:1", "has an invalid port", id="port-over-65535"),
    pytest.param("h1:banana 1:1", "has an invalid port", id="port-junk"),
    pytest.param("h1", "invalid number of arguments", id="one-arg"),
])
def test_origin_coords_bad_args_rejected(cc, args, needle):
    cc.fails(f"brix_cvmfs_origin_coords {args};", needle)


# -- geo-mode structural requirements ----------------------------------------

def test_geo_select_requires_here(cc):
    cc.fails(cc.base + "brix_cvmfs_origin_select geo;",
             "brix_cvmfs_origin_select geo requires brix_cvmfs_here")


def test_geo_select_rejects_malformed_here(cc):
    """brix_cvmfs_here is a plain str slot; geo mode validates it at merge."""
    cc.fails(cc.base + "brix_cvmfs_origin_select geo; brix_cvmfs_here banana;",
             "brix_cvmfs_origin_select geo requires brix_cvmfs_here")


def test_geo_select_requires_origin_coords(cc):
    cc.fails(cc.base + "brix_cvmfs_origin_select geo; brix_cvmfs_here 55.9:-3.2;",
             "requires one brix_cvmfs_origin_coords per configured origin")


def test_geo_full_config_loads(cc):
    cc.ok(cc.base + "brix_cvmfs_origin_select geo; brix_cvmfs_here 55.9:-3.2; "
          "brix_cvmfs_origin_coords 127.0.0.1 46.2:6.1;")


def test_coords_without_geo_mode_warns_but_loads(cc):
    """Coords in non-geo mode: loads OK with the ignored-coordinates WARN."""
    out = cc.ok(cc.base + "brix_cvmfs_origin_coords 127.0.0.1 1:1;")
    assert "coordinates are ignored" in out


# -- valid corner values ------------------------------------------------------

@pytest.mark.parametrize("directives", [
    pytest.param("brix_cvmfs_manifest_ttl 0;", id="manifest_ttl-0"),
    pytest.param("brix_cvmfs_negative_ttl 0;", id="negative_ttl-0"),
    pytest.param("brix_cvmfs_upstream_max 1;", id="upstream_max-1"),
    pytest.param("brix_cvmfs_geo_max_servers 1;", id="geo_max_servers-1"),
    pytest.param("brix_cvmfs_origin_attempt_timeout 0;", id="attempt_timeout-0"),
    pytest.param("brix_cvmfs_origin_stall_bytes 0;", id="stall_bytes-0"),
    pytest.param("brix_cvmfs_origin_coords 127.0.0.1:8000 -90:180;",
                 id="coords-boundary-latlon-with-port"),
])
def test_corner_value_loads(cc, directives):
    cc.ok(cc.base + directives)


def test_full_inventory_single_config_loads(cc):
    """Every brix_cvmfs*/brix_scvmfs* directive once, valid values, one load."""
    every = " ".join(f"{d} {v};" for d, v in _SINGLE_SHOT
                     if d not in ("brix_cvmfs", "brix_cvmfs_origin_select",
                                  "brix_scvmfs", "brix_scvmfs_authz",
                                  "brix_scvmfs_token_issuers"))
    cc.ok(cc.base + every
          + " brix_cvmfs_origin_select geo;"
          + " brix_cvmfs_origin_coords 127.0.0.1 46.2:6.1;"
          + " brix_cvmfs_upstream_allow a.example;")


# ---------------------------------------------------------------------------
# Half B — live behavior: scvmfs authz matrix, public-by-design, read-only
# ---------------------------------------------------------------------------

def _tls_fetch(port, path, token=None, headers=None, method="GET"):
    """HTTPS request with an unverified context; returns (status, body)."""
    ctx = ssl._create_unverified_context()
    req = urllib.request.Request(f"https://127.0.0.1:{port}{path}", method=method)
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
         "-subj", "/CN=localhost", "-keyout", str(d / "key.pem"),
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

@requires_tokens
@requires_openssl
def test_bearer_missing_token_401(bearer_srv):
    status, _ = _tls_fetch(bearer_srv.nginx_port, bearer_srv.objects()[0])
    assert status == 401


@requires_tokens
@requires_openssl
def test_bearer_garbage_token_401(bearer_srv):
    status, _ = _tls_fetch(bearer_srv.nginx_port, bearer_srv.objects()[0],
                           token="not.a.token")
    assert status == 401


@requires_tokens
@requires_openssl
def test_bearer_non_bearer_scheme_401(bearer_srv):
    """A non-Bearer Authorization scheme is no credential at all (NGX_DECLINED)."""
    status, _ = _tls_fetch(bearer_srv.nginx_port, bearer_srv.objects()[0],
                           headers={"Authorization": "Basic dXNlcjpwdw=="})
    assert status == 401


@requires_tokens
@requires_openssl
def test_bearer_corrupt_signature_401(bearer_srv, mint):
    forge, _ = mint
    status, _ = _tls_fetch(bearer_srv.nginx_port, bearer_srv.objects()[0],
                           token=forge.generate_bad_signature())
    assert status == 401


@requires_tokens
@requires_openssl
def test_bearer_expired_token_401(bearer_srv, mint):
    forge, _ = mint
    status, _ = _tls_fetch(bearer_srv.nginx_port, bearer_srv.objects()[0],
                           token=forge.generate_expired())
    assert status == 401


@requires_tokens
@requires_openssl
def test_bearer_unknown_issuer_401(bearer_srv, mint):
    forge, _ = mint
    status, _ = _tls_fetch(bearer_srv.nginx_port, bearer_srv.objects()[0],
                           token=forge.for_issuer("https://evil.example.com"))
    assert status == 401


@requires_tokens
@requires_openssl
def test_bearer_write_only_scope_401(bearer_srv, mint):
    """secure.c validates BRIX_TOKEN_OP_READ; a create-only scope must not read."""
    forge, _ = mint
    status, _ = _tls_fetch(bearer_srv.nginx_port, bearer_srv.objects()[0],
                           token=forge.generate(scope="storage.create:/"))
    assert status == 401


@requires_tokens
@requires_openssl
def test_bearer_valid_token_serves_exact_bytes(bearer_srv, mint):
    forge, _ = mint
    obj = bearer_srv.objects()[0]
    status, body = _tls_fetch(bearer_srv.nginx_port, obj, token=forge.generate())
    assert status == 200
    assert body == _origin_bytes(bearer_srv, obj)


@requires_tokens
@requires_openssl
def test_bearer_valid_token_head(bearer_srv, mint):
    forge, _ = mint
    status, body = _tls_fetch(bearer_srv.nginx_port, bearer_srv.objects()[1],
                              token=forge.generate(), method="HEAD")
    assert status == 200 and body == b""


@requires_tokens
@requires_openssl
def test_bearer_auth_does_not_grant_write(bearer_srv, mint):
    """Read-only is structural: a valid token cannot turn PUT into a write."""
    forge, _ = mint
    target = f"/cvmfs/{REPO}/data/ab/" + "cd" * 19
    status, _ = _tls_fetch(bearer_srv.nginx_port, target,
                           token=forge.generate(scope="storage.modify:/ storage.read:/"),
                           method="PUT")
    assert status >= 400
    status, _ = _tls_fetch(bearer_srv.nginx_port, target, token=forge.generate())
    assert status == 404, "PUT must never materialize an object"


# -- scvmfs authz none: TLS parity, auth adds nothing ------------------------

@requires_openssl
def test_scvmfs_none_serves_anonymously(none_srv):
    obj = none_srv.objects()[0]
    status, body = _tls_fetch(none_srv.nginx_port, obj)
    assert status == 200 and body == _origin_bytes(none_srv, obj)


@requires_openssl
def test_scvmfs_none_random_auth_header_changes_nothing(none_srv):
    obj = none_srv.objects()[0]
    anon = _tls_fetch(none_srv.nginx_port, obj)
    authed = _tls_fetch(none_srv.nginx_port, obj,
                        headers={"Authorization": "Bearer garbage.garbage.garbage"})
    assert anon == authed == (200, _origin_bytes(none_srv, obj))


# -- scvmfs transport gate ----------------------------------------------------

@requires_openssl
def test_plain_http_to_scvmfs_tls_port_refused(none_srv):
    """Cleartext HTTP on the ssl listener: nginx core 400s the plain request."""
    status, _, _ = request("127.0.0.1", none_srv.nginx_port, "GET",
                           none_srv.objects()[0])
    assert status == 400


def test_scvmfs_on_plain_listener_400(scvmfs_plain_srv):
    """secure.c: no r->connection->ssl -> 400 even when the listener itself is
    plain (config loads; the transport requirement is enforced per request)."""
    status, _, _ = request("127.0.0.1", scvmfs_plain_srv.nginx_port, "GET",
                           scvmfs_plain_srv.objects()[0])
    assert status == 400


# -- public-by-design (scvmfs off): auth adds nothing -------------------------

def test_public_anonymous_equals_authorized_object(plain_srv):
    obj = plain_srv.objects()[0]
    anon = request("127.0.0.1", plain_srv.nginx_port, "GET", obj)
    authed = request("127.0.0.1", plain_srv.nginx_port, "GET", obj,
                     headers={"Authorization": "Bearer whatever.some.token"})
    assert anon[0] == authed[0] == 200
    assert anon[2] == authed[2] == _origin_bytes(plain_srv, obj)


def test_public_anonymous_equals_authorized_manifest(plain_srv):
    path = f"/cvmfs/{REPO}/.cvmfspublished"
    anon = request("127.0.0.1", plain_srv.nginx_port, "GET", path)
    authed = request("127.0.0.1", plain_srv.nginx_port, "GET", path,
                     headers={"Authorization": "Basic dXNlcjpwdw=="})
    assert anon[0] == authed[0] == 200 and anon[2] == authed[2]


# -- forced read-only: mutating methods never mutate --------------------------

def test_put_never_creates_object(plain_srv):
    target = f"/cvmfs/{REPO}/data/ab/" + "ef" * 19
    status, _, _ = request("127.0.0.1", plain_srv.nginx_port, "PUT", target,
                           body=b"evil payload")
    assert status >= 400, f"PUT must be refused, got {status}"
    status, _, _ = request("127.0.0.1", plain_srv.nginx_port, "GET", target)
    assert status == 404, "PUT body must never materialize"


def test_delete_never_removes_cached_object(plain_srv):
    obj = plain_srv.objects()[2]
    ref = urllib.request.urlopen(plain_srv.base_url + obj, timeout=15).read()
    status, _, _ = request("127.0.0.1", plain_srv.nginx_port, "DELETE", obj)
    assert status >= 400, f"DELETE must be refused, got {status}"
    again = urllib.request.urlopen(plain_srv.base_url + obj, timeout=15).read()
    assert again == ref, "DELETE must not disturb the cached object"


def test_post_with_body_rejected(plain_srv):
    obj = plain_srv.objects()[3]
    status, _, _ = request("127.0.0.1", plain_srv.nginx_port, "POST", obj,
                           body=b"x" * 128)
    assert status >= 400, f"POST must be refused, got {status}"
