"""
test_audit15f_cache_admission_and_staging.py — read-cache admission and the
write-through staging tree (audit 2026-08-15, zero-coverage appendix residuals:
brix_cache_allow_prefix, brix_cache_index_cache, brix_cache_wt_stage_backend,
brix_cache_wt_stage_block_size are configured NOWHERE in the suite).

Two halves, because the four directives fail in two different ways.

The admission pair is behavioural.  sd_cache_admit() is consulted before any
fill, and a DECLINE is not an error: the open falls through to the source
(sd_cache.c), so the client's bytes are identical either way and the ONLY
observable is what does or does not appear under brix_cache_store.  Every
admission assertion here is therefore a pair — the bytes AND the store — which
is also what makes the byte-prefix finding below visible at all.

The staging pair is a config contract.  brix_server_validate_cache_stage_
backend() is the one place that ties brix_cache_wt_stage_backend to its root
and to a POSIX state root, and it is also where the backend is registered
(brix_vfs_backend_config with brix_cache_wt_stage_block_size).  It is reached
only from brix_server_validate_cache(), which begins `if (!xcf->cache) return
NGX_OK` — so the whole contract is conditional on `brix_cache on`, which the
last case pins.

Cases:
  * success      — a path under brix_cache_allow_prefix is filled into the store
  * error        — a path outside the whitelist still serves byte-exact from the
                   source and leaves the store empty (a decline is not a failure)
  * security-neg — DEFECT CANDIDATE #12: the whitelist is a BYTE prefix, so
                   `/admitted` also admits the sibling tree `/admittedsecrets`;
                   an operator scoping a cache to one directory silently caches
                   every directory whose name starts with the same bytes
  * success      — a one-entry brix_cache_index_cache alternated across two
                   differently-sized objects never serves the neighbour's header
  * success      — with the origin stopped, the bounded index still answers from
                   the store, while an object that was never admitted fails:
                   proof the earlier reads were store hits, not origin re-reads
  * error        — brix_cache_wt_stage_backend without its stage root is refused
  * error        — ... and without a POSIX brix_cache_state_root for its sidecars
  * success      — the full quartet parses, and the block size is a size
  * security-neg — DEFECT CANDIDATE #13: both refusals above disappear when
                   `brix_cache` is off — the staging tree is accepted unvalidated
                   and unregistered, so a misconfigured stage root is silent
  * error/pin    — DEFECT CANDIDATE #14: brix_cache_wt_stage() has no
                   callers, so the instance those directives build is never
                   consumed
"""

import os
import subprocess

import pytest

from cmdscripts.live_common import inject_nginx_load_modules
from server_registry import NginxInstanceSpec
from settings import NGINX_BIN, BIND_HOST
from _cache_partial_helpers import read_range

pytestmark = [pytest.mark.timeout(120),
              pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-audit15f-cacheadm")]

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Two sizes that cannot be confused for one another if a bounded cinfo index
# ever hands back the neighbour's header.
SMALL = 4096
LARGE = 12288


def _pattern(size, salt):
    return bytes((i * 131 + salt) & 0xFF for i in range(size))


# `nginx -t` never binds, so this listener is a parse-time literal only (same
# shape as test_cache_directive_parse.py); the origin it names is never dialled.
PARSE_PORT = 13296
PARSE_ORIGIN_PORT = 13295


def _nginx_t(root, body):
    """Render a stream server carrying `body` and return (rc, diagnostics)."""
    for name in ("logs", "data"):
        (root / name).mkdir(exist_ok=True)
    conf = root / "stage.conf"
    conf.write_text(f"""daemon off; error_log {root}/logs/e.log info;
pid {root}/n.pid; thread_pool default threads=2;
events {{ worker_connections 64; }}
stream {{ server {{ listen {BIND_HOST}:{PARSE_PORT};
    brix_root on;
    brix_auth none;
{body}
}} }}
""")
    inject_nginx_load_modules(conf)
    p = subprocess.run([str(NGINX_BIN), "-t", "-p", str(root), "-c", str(conf)],
                       capture_output=True, text=True, timeout=30)
    return p.returncode, p.stderr + p.stdout


def _stage_body(root, *, cache_on, stage_root=True, state_root=True):
    """A write-through staging tree, optionally missing one of its two
    prerequisites and optionally without the `brix_cache on` that gates the
    validation.  The read cache needs a REMOTE backend; a parse-only config
    never dials it."""
    for name in ("export", "state", "stage", "back"):
        (root / name).mkdir(exist_ok=True)
    lines = [f"    brix_storage_backend root://{BIND_HOST}:{PARSE_ORIGIN_PORT};"]
    if cache_on:
        lines += ["    brix_cache on;",
                  f"    brix_cache_export {root}/export;"]
    else:
        lines += [f"    brix_export {root}/export;"]
    if state_root:
        lines.append(f"    brix_cache_state_root {root}/state;")
    if stage_root:
        lines.append(f"    brix_cache_wt_stage_root {root}/stage;")
    lines += [f"    brix_cache_wt_stage_backend posix:{root}/back;",
              "    brix_cache_wt_stage_block_size 64k;"]
    return "\n".join(lines)


@pytest.fixture
def cacheadm(lifecycle, tmp_path):
    """An origin plus the two tiered cache planes over it.  The origin is its
    own registry instance so a test can stop it and see what the store alone
    can still answer."""
    if not os.path.exists(NGINX_BIN):
        pytest.skip(f"nginx binary not found at {NGINX_BIN}")

    origin_root = tmp_path / "origin"
    stores = {"admit": tmp_path / "admit-store", "l1": tmp_path / "l1-store"}
    # One export root per plane: the composed tier is registered under the
    # export's canonical root, so a shared root would make the second plane's
    # registration answer both listeners.
    exports = {"admit": tmp_path / "admit-export", "l1": tmp_path / "l1-export"}
    seeds = {
        # Under the whitelist.
        "/admitted/hot.bin": _pattern(SMALL, 7),
        # Outside it.
        "/elsewhere/cold.bin": _pattern(SMALL, 11),
        # Starts with the whitelist's BYTES but is a different tree.
        "/admittedsecrets/leak.bin": _pattern(SMALL, 13),
        # The bounded-index pair, deliberately different lengths.
        "/pair/a.bin": _pattern(SMALL, 17),
        "/pair/b.bin": _pattern(LARGE, 19),
        # Read for the first time only after the origin is gone.
        "/pair/never.bin": _pattern(SMALL, 23),
    }
    for path, blob in seeds.items():
        target = origin_root / path.lstrip("/")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(blob)
    for path in (*stores.values(), *exports.values()):
        path.mkdir()
    # The master may run as root while the worker drops privilege.
    for path in (tmp_path, origin_root, *stores.values(), *exports.values()):
        os.chmod(path, 0o777)
    for sub in origin_root.iterdir():
        os.chmod(sub, 0o777)

    origin = lifecycle.start(NginxInstanceSpec(
        name="lc-audit15f-cacheorigin",
        template="nginx_lc_cache_partial_origin.conf",
        protocol="root",
        readiness="tcp",
        data_root=str(origin_root),
        template_values={
            "BIND_HOST": BIND_HOST,
            "ORIGIN_STORAGE": f"brix_export {origin_root};",
            "ORIGIN_ALLOW_WRITE": ""},
        reason="audit-15f cache-admission origin"))

    ep = lifecycle.start(NginxInstanceSpec(
        name="lc-audit15f-cacheadm",
        template="nginx_audit15f_cacheadm.conf",
        protocol="root",
        readiness="tcp",
        data_root=str(stores["admit"]),
        template_values={
            "BIND_HOST": BIND_HOST,
            "ORIGIN_PORT": str(origin.port),
            "ADMIT_EXPORT": str(exports["admit"]),
            "ADMIT_STORE": str(stores["admit"]),
            "L1_EXPORT": str(exports["l1"]),
            "L1_STORE": str(stores["l1"])},
        reason="audit-15f brix_cache_allow_prefix + brix_cache_index_cache"))
    return ep, stores, seeds


def _stored(store, path):
    """True iff the tier actually laid the object down under its store — the
    store key is the request path without its leading slash (cstore.c)."""
    return os.path.exists(os.path.join(str(store), path.lstrip("/")))


def _errlog(ep):
    """Instance logs are wiped at teardown, so failures quote them inline."""
    try:
        with open(os.path.join(ep.prefix, "logs", "error.log")) as fh:
            return fh.read()
    except FileNotFoundError:
        return ""


# ---- brix_cache_allow_prefix ----------------------------------------------

def test_a_path_under_the_allow_prefix_is_filled_into_the_store(cacheadm):
    ep, stores, seeds = cacheadm
    path = "/admitted/hot.bin"

    got = read_range(ep.port, path, 0, SMALL)

    assert got == seeds[path], "the admitted read did not serve the origin bytes"
    assert _stored(stores["admit"], path), (
        f"{path} matches brix_cache_allow_prefix but never landed in the "
        f"store:\n{_errlog(ep)}")


def test_a_path_outside_the_allow_list_serves_but_is_never_stored(cacheadm):
    ep, stores, seeds = cacheadm
    path = "/elsewhere/cold.bin"

    got = read_range(ep.port, path, 0, SMALL)

    # A declined open is NOT an error: sd_cache_open_common falls through to the
    # source, so the client cannot tell — only the store can.
    assert got == seeds[path], "a declined path must still serve the source bytes"
    assert not _stored(stores["admit"], path), (
        f"{path} is outside brix_cache_allow_prefix but was cached anyway:\n"
        f"{_errlog(ep)}")


def test_the_allow_prefix_matches_bytes_not_path_components(cacheadm):
    """DEFECT CANDIDATE #12.  sd_cache_has_prefix() is an ngx_strncmp over the
    configured prefix, so `/admitted` also matches `/admittedsecrets/...`: a
    sibling directory whose name merely STARTS with the whitelisted one is
    admitted.  For brix_cache_deny_prefix the same shape over-denies (fail
    safe); for the allow list it over-admits, which is the direction that
    matters — an operator scoping a cache to one tree silently caches another.
    Flip this assertion when the match gains a component boundary."""
    ep, stores, seeds = cacheadm
    path = "/admittedsecrets/leak.bin"

    got = read_range(ep.port, path, 0, SMALL)

    assert got == seeds[path]
    assert _stored(stores["admit"], path), (
        "the byte-prefix behaviour changed — brix_cache_allow_prefix now "
        "respects a path-component boundary, so this pin (and the audit's "
        "defect list) must be retired")


# ---- brix_cache_index_cache ------------------------------------------------

def test_a_one_entry_index_never_serves_the_neighbours_header(cacheadm):
    """A one-entry L1 evicts on every alternation, so each of these reads is a
    fresh header lookup for an object whose neighbour was just resident.  The
    two objects differ in length, so a header handed back for the wrong key
    shows up as a short or over-long read rather than as a silent metric."""
    ep, _stores, seeds = cacheadm
    l1_port = ep.extra_ports["L1_PORT"]

    for _round in range(3):
        a = read_range(l1_port, "/pair/a.bin", 0, SMALL)
        b = read_range(l1_port, "/pair/b.bin", 0, LARGE)
        assert a == seeds["/pair/a.bin"], f"round {_round}: a.bin drifted"
        assert b == seeds["/pair/b.bin"], f"round {_round}: b.bin drifted"


def test_the_bounded_index_still_answers_once_the_origin_is_gone(cacheadm,
                                                                 lifecycle):
    """Both objects are cached, then the origin is stopped.  A re-read that
    still succeeds can only have come from the store (the L1 entry for the
    first object was evicted by the second), and a path that was never read
    must now fail — which is what makes the successes above store hits rather
    than quiet origin re-reads."""
    ep, stores, seeds = cacheadm
    l1_port = ep.extra_ports["L1_PORT"]

    read_range(l1_port, "/pair/a.bin", 0, SMALL)
    read_range(l1_port, "/pair/b.bin", 0, LARGE)
    assert _stored(stores["l1"], "/pair/a.bin"), _errlog(ep)
    assert _stored(stores["l1"], "/pair/b.bin"), _errlog(ep)

    lifecycle.stop("lc-audit15f-cacheorigin")

    assert read_range(l1_port, "/pair/a.bin", 0, SMALL) == seeds["/pair/a.bin"]
    with pytest.raises((AssertionError, OSError, RuntimeError)):
        read_range(l1_port, "/pair/never.bin", 0, SMALL)


# ---- brix_cache_wt_stage_backend / _block_size -----------------------------

def test_a_staging_backend_without_its_root_is_refused(tmp_path):
    rc, out = _nginx_t(tmp_path,
                       _stage_body(tmp_path, cache_on=True, stage_root=False))

    assert rc != 0, f"a staging backend with no stage root parsed clean:\n{out}"
    assert "brix_cache_wt_stage_backend requires brix_cache_wt_stage_root" in out, out


def test_a_staging_backend_without_a_state_root_is_refused(tmp_path):
    rc, out = _nginx_t(tmp_path,
                       _stage_body(tmp_path, cache_on=True, state_root=False))

    assert rc != 0, f"a staging backend with no state root parsed clean:\n{out}"
    assert "requires a POSIX brix_cache_state_root" in out, out


def test_the_staging_quartet_parses_and_its_block_size_is_a_size(tmp_path):
    rc, out = _nginx_t(tmp_path, _stage_body(tmp_path, cache_on=True))
    assert rc == 0, f"the complete staging config was refused:\n{out}"

    bad = _stage_body(tmp_path, cache_on=True).replace(
        "brix_cache_wt_stage_block_size 64k;",
        "brix_cache_wt_stage_block_size banana;")
    rc, out = _nginx_t(tmp_path, bad)
    assert rc != 0 and "invalid value" in out, out


def test_the_staging_validation_never_runs_when_the_cache_is_off(tmp_path):
    """DEFECT CANDIDATE #13.  brix_server_validate_cache() returns early on
    `if (!xcf->cache)`, and the stage-backend validation — together with the
    brix_vfs_backend_config() registration that gives brix_cache_wt_stage_
    block_size its only effect — lives behind that gate.  So on an export that
    configures staging without `brix_cache on`, BOTH refusals above vanish and
    the operator is told nothing.  Retire this when the validation moves ahead
    of the cache gate."""
    for missing in ("stage_root", "state_root"):
        body = _stage_body(tmp_path, cache_on=False,
                           **{missing: False})
        rc, out = _nginx_t(tmp_path, body)
        assert rc == 0, (
            f"a cache-off server missing {missing} is now validated — the gate "
            f"moved, so retire this pin:\n{out}")


def test_the_staged_backend_instance_still_has_no_consumer():
    """DEFECT CANDIDATE #14.  brix_cache_storage_init() builds the staging
    instance whenever brix_cache_wt_stage_root is set, and brix_cache_wt_stage() is the
    accessor for it — but nothing calls that accessor, so both directives
    configure an object no write path ever reads.  The two hits below are its
    own definition and declaration; a third means the wiring landed and this
    pin (and the audit's defect list) should be retired."""
    hits = []
    for sub in ("src", "client", "shared"):
        base = os.path.join(REPO, sub)
        for dirpath, _dirnames, filenames in os.walk(base):
            for name in filenames:
                if not name.endswith((".c", ".h")):
                    continue
                full = os.path.join(dirpath, name)
                with open(full, errors="ignore") as fh:
                    for lineno, line in enumerate(fh, 1):
                        if "brix_cache_wt_stage(" in line:
                            hits.append(f"{os.path.relpath(full, REPO)}:{lineno}")

    assert sorted(hits) == ["src/fs/cache/cache_storage.c:265",
                            "src/fs/cache/cache_storage.h:61"], (
        f"brix_cache_wt_stage() references changed: {sorted(hits)}")
