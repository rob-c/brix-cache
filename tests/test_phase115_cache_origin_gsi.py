"""Phase-115 W2.4 — the read cache authenticates OUTBOUND to a GSI-only origin
with the `brix_credential { x509_proxy ...; }` named by `brix_storage_credential`,
verifying the origin's certificate against that credential's own `ca_dir`.

The origin leg existed before W2.4 (`src/fs/cache/origin_auth_gsi.c`) but had no
end-to-end test of its own: only the chaos mixed-auth mesh drove it, inside a
fleet.  W2.4 moved its credential loading, certificate verification and
certreq construction onto the shared GSI kernels (`src/auth/gsi/cred_load.c`,
`brix_gsi_verify_peer_leaf`, `brix_gsi_build_certreq_from_parms`) that the
transparent upstream and native TPC now share, so this suite pins the three
behaviours the refactor had to preserve: fill succeeds with a trusted origin,
a credential-less cache fails closed with the operator hint, and a rogue trust
anchor refuses the origin BEFORE any credential is presented.

TWO DISCOVERIES this suite was WRONG about until 2026-09-07, both now pinned:

1. THIS leg never consults `brix_trusted_ca`.  The directive is not
   inbound-only — it is stream-level (`src/core/config/stream_common.c` →
   `common.trusted_ca`) and outbound legs DO read it (TPC outbound TLS at
   `src/tpc/outbound/tls.c:56`, the Pelican origin at
   `src/fs/cache/origin/pelican_register.c:286`).  What is true is narrower:
   the xroot cache→origin leg runs on a SYNTHETIC srv_conf, and that synth
   inherits nothing from the server-level directive.  Its trust store is built
   from the credential block's own `ca_dir` and from nothing else —
   `brix_vfs_backend_credential` copies `cred->ca_dir` into `e->origin_ca_dir`
   (`src/fs/vfs/vfs_backend_config.c:298-301`), `brix_vbr_build_xroot` passes
   it as `cfg.ca_dir` (`src/fs/vfs/vfs_backend_registry_source.c:163`), and
   `sd_xroot_origin_build_ca_store` (`src/fs/backend/xroot/sd_xroot.c:411-443`)
   returns early on an empty one.  An operator who writes the anchor at server
   level next to `brix_storage_credential` therefore gets NO verification on
   this leg and no warning —
   `test_brix_trusted_ca_does_not_anchor_the_outbound_origin_leg` holds that
   foot-gun still.

   COROLLARY, not exercised here (no TLS origin in this suite; reported by the
   phase-116 session 2026-09-07): the same early return also skips
   `sd_xroot.c:426-431`, where the origin CA is copied onto
   `synth->common.trusted_ca` so the root:// TLS upgrade verifies against it.
   With no `ca_dir` that assignment never runs and the TLS upgrade falls back
   to the system CA bundle.  One misconfiguration, two verification surfaces.

2. No store means verification is SKIPPED, not failed:
   `originauth_gsi_verify_srv_cert` returns 0 when `t->conf->gsi_store == NULL`
   (`src/fs/cache/origin_auth_gsi.c:127`), a documented operator opt-out shared
   with the transparent upstream (`src/net/upstream/auth_gsi.c:70`) and native
   TPC (`src/tpc/gsi/gsi_outbound_exchange.c:89`).  Consequence for THIS file:
   both the success row and the security-negative were passing vacuously —
   the rogue anchor was never consulted, so the negative was asserting only
   that the cache accepts connections.  Both fixtures now carry the anchor
   where the code actually reads it.

   The three sites do NOT announce the opt-out alike: the upstream logs
   NGX_LOG_WARN "no brix_trusted_ca configured; upstream server certificate
   not verified", while the cache-origin and TPC sites skip silently, and
   `sd_xroot.c:438` logs only when a store BUILD fails, never when none was
   attempted.  From the logs an operator cannot tell a silently unverified leg
   from a verified one.  That asymmetry is a live question owned by the
   phase-116 session, not decided here; this suite only pins today's behaviour
   so any future change to it is visible.
"""
from pathlib import Path

import pytest
from XRootD import client
from settings import HOST

# NEVER import `_test_gsi_handshake_helpers_b` (or any other `_<letter>` shard)
# directly: it is an exec-composed continuation, not a module.  The parent does
# `split_continuation.reexport(globals(), "..._b")`, which compiles the shard's
# source INTO the parent's namespace — so the shard's own module object never
# holds the parent-level helpers it calls (`pki` calls `_have`, defined in the
# parent), and importing it that way fails at fixture time, not at import time.
from _test_gsi_handshake_helpers import (_gsi_log, _gsi_nginx,  # noqa: F401
                                         _make_ca, pki)

pytestmark = [pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-p115-cache-origin-gsi")]

CACHE_TEMPLATE = "nginx_p115_cache_origin_gsi.conf"
ORIGIN_TEMPLATE = "nginx_gsi_handshake_root.conf"
HELLO = b"hello from gsi data root\n"


def _read_text(path):
    return Path(path).read_text(errors="replace") if Path(path).exists() else ""


@pytest.fixture(scope="module")
def gsi_origin(pki):
    """The handshake suite's GSI-only root:// server, serving pki["data"]."""
    hello = Path(pki["data"]) / "p115-origin.txt"
    hello.write_bytes(HELLO)
    harness, ep = _gsi_nginx("lc-p115-co-origin", ORIGIN_TEMPLATE, pki["data"],
                             CERT=pki["hostcert"], KEY=pki["hostkey"], CA=pki["ca"],
                             CIPHERS_DIRECTIVE="", SIGNED_DH_DIRECTIVE="")
    try:
        yield {"port": ep.port, "log": _gsi_log(ep)}
    finally:
        harness.close()


@pytest.fixture(scope="module")
def rogue_ca(tmp_path_factory):
    """A self-signed anchor the origin's host certificate does not chain to.

    Shared by the two rogue-anchor caches so they differ ONLY in WHERE the same
    bad anchor is written — inside the credential (honoured, refuses) versus at
    server level (ignored, fills).  Two anchors would leave that difference
    confounded with two different CAs.
    """
    d = tmp_path_factory.mktemp("lc-p115-co-rogue-ca")
    _key, pem = _make_ca(str(d), "/O=Rogue/CN=Rogue Cache Trust Anchor")
    return pem


def _cache(name, origin_port, tmp, cred_block, *server_lines):
    cache_dir = tmp / "store"
    cache_dir.mkdir()
    harness, ep = _gsi_nginx(
        name, CACHE_TEMPLATE, str(tmp / "empty-export"),
        ORIGIN_PORT=str(origin_port), CACHE_DIR=str(cache_dir),
        CRED_BLOCK=cred_block,
        SERVER_LINES="\n".join(f"        {line}" for line in server_lines))
    return harness, {"port": ep.port, "log": _gsi_log(ep), "store": cache_dir}


def _cache_fixture(name, cred_block_tmpl, *server_line_tmpls):
    @pytest.fixture(scope="module")
    def fixture(pki, gsi_origin, tmp_path_factory):
        tmp = tmp_path_factory.mktemp(name)
        (tmp / "empty-export").mkdir()
        harness, node = _cache(name, gsi_origin["port"], tmp,
                               cred_block_tmpl.format(**pki),
                               *[line.format(**pki) for line in server_line_tmpls])
        try:
            yield node
        finally:
            harness.close()
    return fixture


# The anchor lives INSIDE the credential block: that is the only place the
# outbound leg reads it from (see discovery 1 in the module docstring).
cache_ok = _cache_fixture(
    "lc-p115-co-ok",
    "    brix_credential p115 {{ x509_proxy {valid_proxy}; ca_dir {ca}; }}",
    "brix_storage_credential p115;")
cache_nocred = _cache_fixture("lc-p115-co-nocred", "")


def _rogue_conf(proxy, rogue_pem, in_cred):
    """(credential block, server lines) for a cache carrying the rogue anchor
    either inside the credential or at server level — the one axis the two
    rogue rows differ on, so they cannot drift apart in anything else."""
    if in_cred:
        return (f"    brix_credential p115 {{ x509_proxy {proxy}; "
                f"ca_dir {rogue_pem}; }}", ["brix_storage_credential p115;"])
    return (f"    brix_credential p115 {{ x509_proxy {proxy}; }}",
            ["brix_storage_credential p115;", f"brix_trusted_ca {rogue_pem};"])


def _rogue_fixture(name, in_cred):
    @pytest.fixture(scope="module")
    def fixture(pki, gsi_origin, tmp_path_factory, rogue_ca):
        tmp = tmp_path_factory.mktemp(name)
        (tmp / "empty-export").mkdir()
        cred, lines = _rogue_conf(pki["valid_proxy"], rogue_ca, in_cred)
        harness, node = _cache(name, gsi_origin["port"], tmp, cred, *lines)
        try:
            yield node
        finally:
            harness.close()
    return fixture


cache_rogue = _rogue_fixture("lc-p115-co-rogue", True)
cache_outerca = _rogue_fixture("lc-p115-co-outerca", False)


def _open(node, path="/p115-origin.txt"):
    f = client.File()
    status, _ = f.open(f"root://{HOST}:{node['port']}/{path}")
    return f, status


def _open_then_read(node, path="/p115-origin.txt"):
    """(status, bytes) for the whole operation, not just the open.

    THE TRAP this suite walked into: a cache miss is filled LAZILY, so
    `kXR_open` against a cold cache answers ok before the origin has been
    contacted at all.  A negative that only opened therefore passes on a cache
    with a rogue trust anchor, on a cache with a broken origin, and on a cache
    with no verification whatsoever — it was asserting that the cache accepts
    connections.  The bytes are the observable; ask for them.
    """
    f, status = _open(node, path)
    if not status.ok:
        f.close()
        return status, b""
    try:
        return f.read(size=len(HELLO) + 1)
    finally:
        f.close()


def _read_all(node, path="/p115-origin.txt"):
    f, status = _open(node, path)
    assert status.ok, (status.message, _read_text(node["log"])[-2500:])
    try:
        st_status, st = f.stat()
        assert st_status.ok, st_status.message
        rd_status, data = f.read(size=st.size)
        assert rd_status.ok, rd_status.message
        return data
    finally:
        f.close()


def test_fill_through_a_gsi_origin_is_byte_exact(cache_ok, gsi_origin):
    """success: the cache logs in to the origin with the named x509_proxy after
    the origin's kXR_ok+advert login reply, verifies the origin's certificate
    against the credential's ca_dir, and the client reads the origin's bytes."""
    assert _read_all(cache_ok) == HELLO
    assert "server certificate verification failed" not in _read_text(cache_ok["log"])
    assert "GSI auth OK" in _read_text(gsi_origin["log"])


def test_filled_object_lands_in_the_cache_store(cache_ok):
    """success: the fill is persisted — a second read is served locally and the
    store holds the object bytes (the whole point of the credentialed leg)."""
    assert _read_all(cache_ok) == HELLO
    stored = [p for p in Path(cache_ok["store"]).rglob("*") if p.is_file()
              and p.read_bytes() == HELLO]
    assert stored, sorted(str(p) for p in Path(cache_ok["store"]).rglob("*"))


def test_no_credential_fails_closed_with_the_operator_hint(cache_nocred):
    """error: the origin advertises gsi, the cache has no brix_storage_credential
    — the open fails (never an anonymous retry) and the message names the
    directive that fixes it."""
    status, data = _open_then_read(cache_nocred)
    text = status.message + _read_text(cache_nocred["log"])
    assert not status.ok, text[-3000:]
    assert data != HELLO, "a credential-less cache served the origin's bytes"
    assert "brix_storage_credential" in text, text[-2500:]


def test_rogue_trust_anchor_refuses_the_origin_before_presenting_the_proxy(
        cache_rogue, gsi_origin):
    """security-negative: with a credential ca_dir the origin's host certificate
    does not chain to, verification fails in round 1 and the cache stops there —
    the proxy is never sent to the unverified peer, so the origin sees no GSI
    login from this cache."""
    origin_log_before = _read_text(gsi_origin["log"]).count("GSI auth OK")
    status, data = _open_then_read(cache_rogue)
    # The cache log is attached to the refusal assertion too: a security
    # negative that merely says "it succeeded" cannot tell a missing check from
    # a check that silently opted out because its trust store failed to load.
    text = status.message + _read_text(cache_rogue["log"])
    assert data != HELLO, ("the rogue-anchor cache served the origin's bytes",
                           text[-2000:])
    assert not status.ok, (f"status={status!r} data={data!r}", text[-2500:])
    assert "server certificate verification failed" in text, text[-2500:]
    assert _read_text(gsi_origin["log"]).count("GSI auth OK") == origin_log_before


def test_brix_trusted_ca_does_not_anchor_the_outbound_origin_leg(
        cache_outerca, gsi_origin):
    """discovery (2026-09-07): the SAME rogue anchor, written at server level as
    `brix_trusted_ca` instead of inside the credential, is ignored on the
    cache→origin leg — the fill succeeds and the origin logs a GSI login.

    This is not a hole to be plugged, it is the documented shape held still:
    the xroot origin leg runs on a synthetic srv_conf that inherits nothing
    from the server-level directive, its store comes only from the credential's
    `ca_dir`, and an absent store is an operator opt-out
    (`src/fs/cache/origin_auth_gsi.c:127`).  Pinned because the difference is
    invisible in the config — this suite itself read the two as equivalent and
    ran a vacuous security-negative for it.  If a future change ever makes the
    server-level anchor apply here, this row fails and the docstring above,
    plus the phase-115 W2.4 register row, must be rewritten with it.
    """
    origin_log_before = _read_text(gsi_origin["log"]).count("GSI auth OK")
    status, data = _open_then_read(cache_outerca)
    text = status.message + _read_text(cache_outerca["log"])
    assert status.ok, text[-2500:]
    assert data == HELLO, (f"data={data!r}", text[-2500:])
    assert "server certificate verification failed" not in text, text[-2500:]
    assert _read_text(gsi_origin["log"]).count("GSI auth OK") > origin_log_before
