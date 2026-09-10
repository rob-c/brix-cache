"""2.0 F5(A) — brix_cache_urlcgi: per-open cache hints (XrdPfc pfc.urlcgi parity).

An XRootD client may append `pfc.blocksize=<bytes>` and `pfc.prefetch=<blocks>`
to the open path of a file served through the slice cache. Upstream XrdPfc
honours them only when the operator arms `pfc.urlcgi blocksize <min> <max>` /
`prefetch <min> <max>`; a hint is clamped into the operator's bounds, and an
unarmed clause ignores the hint. brix mirrors that with one directive,
`brix_cache_urlcgi [blocksize {ignore|<min> <max>}] [prefetch {ignore|<min> <max>}]`
(src/core/config/cache_urlcgi_conf.c), a typed `pfc.` namespace in the opaque
schema (src/protocols/root/path/opaque_validate.c), an open-hint carrier on
the VFS context, and the clamp in the slice-cache partial open
(src/fs/backend/cache/sd_cache_partial.c).

Layers, each with success / error / security-negative legs:
  * TestGrammar        — nginx -t accept/reject of every clause shape.
  * TestOpaqueSchema   — brix_opaque_strict types both keys; lenient parity.
  * TestBlockSizeHint  — live xroot slice-cache lab: a new object's block size
                         follows the hint inside the bounds, is clamped at the
                         max, raised to the min, rounded to the 1m granule,
                         ignored when unarmed, never re-slices an existing
                         object, and never turns whole-file mode into slices.
  * TestPrefetchHint   — the per-handle runway: narrowed, switched off, clamped
                         at the max, ignored when the clause is unarmed.

Wire driver: the raw root:// client of _cache_partial_helpers (open carries the
opaque after '?', exactly as xrdcp appends it); residency comes from xrdcinfo.
"""
import subprocess
import time
from pathlib import Path

import pytest

from _cache_partial_helpers import (
    make_cache_node, read_range, residency, seed_origin,
)
from fleet_lifecycle_ports import SHARED_PARSE_PLACEHOLDER_PORT
from server_registry import NginxInstanceSpec
from settings import HOST, BIND_HOST, NGINX_BIN
from test_opaque_strict import _login, _errcode, KXR_ERROR, kXR_ArgInvalid
from test_phase25_ratelimit import _xrd_open, KXR_OK

pytestmark = [pytest.mark.serial, pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-r20-urlcgi")]

REPO = Path(__file__).resolve().parents[1]
BLK = 1024 * 1024               # the 1m slice granule
GRACE = 1.0                     # seconds a speculative fill may still land in


def _poll(predicate, timeout=10.0, interval=0.2):
    deadline = time.monotonic() + timeout
    value = predicate()
    while not value and time.monotonic() < deadline:
        time.sleep(interval)
        value = predicate()
    return value


def _present(store_dir, key):
    r = residency(store_dir, key)
    return [] if r.get("absent") else r.get("present_blocks", [])


def _block_size(store_dir, key):
    r = residency(store_dir, key)
    return None if r.get("absent") else r.get("block_size")


# ===========================================================================
# Grammar
# ===========================================================================

class TestGrammar:
    def _nginx_t(self, lifecycle, tmp_path, line):
        cache = tmp_path / "cache"
        cache.mkdir(exist_ok=True)
        reg = lifecycle.register(NginxInstanceSpec(
            name="lc-r20-urlcgi-validate",
            template="nginx_vfs_prefetch_validate.conf",
            protocol="none",
            readiness="none",
            port=SHARED_PARSE_PLACEHOLDER_PORT,       # nginx -t only, never bound
            template_values={"HOST": HOST, "CACHE_DIR": str(cache),
                             "PREFETCH_LINES": f"        {line}\n"},
            reason="brix_cache_urlcgi directive parse/validate (nginx -t).",
        ))
        endpoint = lifecycle.launcher.render_nginx(reg)
        proc = subprocess.run(
            [NGINX_BIN, "-t", "-p", endpoint.prefix, "-c", "conf/nginx.conf"],
            capture_output=True, text=True, timeout=30)
        return proc.returncode, proc.stdout + proc.stderr

    @pytest.mark.parametrize("line", [
        "brix_cache_urlcgi blocksize 1m 8m prefetch 0 16;",
        "brix_cache_urlcgi blocksize ignore prefetch 1 4;",
        "brix_cache_urlcgi prefetch ignore;",
        "brix_cache_urlcgi blocksize 2m 2m;",
    ], ids=["both", "blocksize-ignore", "prefetch-ignore", "min-eq-max"])
    def test_valid_forms_accepted(self, lifecycle, tmp_path, line):
        """Success: every documented clause shape parses."""
        rc, out = self._nginx_t(lifecycle, tmp_path, line)
        assert rc == 0, f"{line!r} rejected:\n{out}"

    @pytest.mark.parametrize("line,needle", [
        ("brix_cache_urlcgi blocksize 1m 3000k;",
         "bounds must be positive multiples of 1m"),
        ("brix_cache_urlcgi blocksize 4m 1m;", "blocksize: min exceeds max"),
        ("brix_cache_urlcgi blocksize 1m;", 'needs "ignore" or <min> <max>'),
        ("brix_cache_urlcgi prefetch 0 0;", "max must be at least 1 block"),
        ("brix_cache_urlcgi prefetch 8 2;", "prefetch: min exceeds max"),
        ("brix_cache_urlcgi prefetch 1 many;", "prefetch: bad block count"),
        ("brix_cache_urlcgi blocksize 1m 2m blocksize 1m 2m;", "clause repeated"),
        ("brix_cache_urlcgi window 1 2;", "unknown clause"),
    ], ids=["non-granule", "bs-inverted", "bs-one-bound", "pf-max-zero",
            "pf-inverted", "pf-non-numeric", "repeated", "unknown"])
    def test_malformed_forms_rejected(self, lifecycle, tmp_path, line, needle):
        """Error: each malformed shape is refused at nginx -t with the
        diagnostic that names the clause and the rule."""
        rc, out = self._nginx_t(lifecycle, tmp_path, line)
        assert rc != 0, f"{line!r} must be rejected:\n{out}"
        assert needle in out, out

    def test_directive_twice_in_one_block_rejected(self, lifecycle, tmp_path):
        """Security negative: a second brix_cache_urlcgi line cannot silently
        widen the bounds the first one set — it is a duplicate."""
        rc, out = self._nginx_t(
            lifecycle, tmp_path,
            "brix_cache_urlcgi blocksize 1m 2m;\n"
            "        brix_cache_urlcgi blocksize 1m 64m;")
        assert rc != 0, out
        assert "is duplicate" in out, out


# ===========================================================================
# Opaque schema
# ===========================================================================

class TestOpaqueSchema:
    def _start(self, lifecycle, tmp_path, *, strict):
        data = tmp_path / "data"
        data.mkdir(exist_ok=True)
        (data / "real.dat").write_text("present\n")
        # One stable ledger name for all four legs: the lifecycle fixture is
        # per-test, the class is serialised on one xdist_group, and only the
        # STRICT template value differs -- so this is one slot, not four.
        ep = lifecycle.start(NginxInstanceSpec(
            name="lc-r20-urlcgi-opaque", template="nginx_opaque_strict.conf",
            data_root=str(data),
            template_values={"BIND_HOST": BIND_HOST, "STRICT": strict},
            reason=f"2.0 F5 pfc.* opaque schema coverage (strict={strict})"))
        return ep.port

    @staticmethod
    def _open(port, path):
        s = _login(port)
        try:
            return _xrd_open(s, path)
        finally:
            s.close()

    def test_strict_accepts_typed_pfc_hints(self, lifecycle, tmp_path):
        """Success: both keys are known, typed, and open under strict."""
        port = self._start(lifecycle, tmp_path, strict="on")
        st, _ = self._open(port, "/real.dat?pfc.blocksize=1048576&pfc.prefetch=4")
        assert st == KXR_OK, ("typed pfc hints must open under strict", st)

    def test_strict_rejects_non_integer_blocksize(self, lifecycle, tmp_path):
        """Error: pfc.blocksize is typed uint — a word is refused pre-handler."""
        port = self._start(lifecycle, tmp_path, strict="on")
        st, body = self._open(port, "/real.dat?pfc.blocksize=abc")
        assert st == KXR_ERROR, st
        assert _errcode(body) == kXR_ArgInvalid, _errcode(body)

    def test_strict_rejects_negative_prefetch(self, lifecycle, tmp_path):
        """Security negative: a negative block count cannot reach the clamp
        (an unsigned wrap there would be a huge window) — refused as BAD_TYPE."""
        port = self._start(lifecycle, tmp_path, strict="on")
        st, body = self._open(port, "/real.dat?pfc.prefetch=-1")
        assert st == KXR_ERROR, st
        assert _errcode(body) == kXR_ArgInvalid, _errcode(body)

    def test_lenient_ignores_garbage_hint(self, lifecycle, tmp_path):
        """Parity: with strict off (default) a garbage hint is dropped, not an
        error — stock clients that append junk keep working."""
        port = self._start(lifecycle, tmp_path, strict="off")
        st, _ = self._open(port, "/real.dat?pfc.blocksize=abc&pfc.prefetch=-1")
        assert st == KXR_OK, st


# ===========================================================================
# Live slice-cache lab
# ===========================================================================

def _node(tmp_path, lifecycle, **kw):
    kw.setdefault("slice_size", BLK)
    return make_cache_node("xroot", tmp=tmp_path, lifecycle=lifecycle, **kw)


def _hinted(path, **hints):
    return path + "?" + "&".join(f"pfc.{k}={v}" for k, v in hints.items())


class TestBlockSizeHint:
    def test_hint_sets_new_object_block_size(self, lifecycle, tmp_path):
        """Success: inside the bounds the hint IS the new object's geometry —
        a 1m read fills one 2m block of a 4-block object."""
        with _node(tmp_path, lifecycle, urlcgi="blocksize 1m 4m") as node:
            data = seed_origin(node, "/f.bin", 8 * BLK)
            got = read_range(node.cache_port, _hinted("/f.bin", blocksize=2 * BLK),
                             0, BLK)
            assert got == data[:BLK]
            r = residency(node.store_dir, "f.bin")
            assert r["block_size"] == 2 * BLK, r
            assert r["nblocks"] == 4 and r["present_blocks"] == [0], r

    def test_hint_clamped_to_operator_max(self, lifecycle, tmp_path):
        """Security negative: a client cannot dictate a block above the
        operator's max (a 1 GiB block would turn every 1-byte read into a
        1 GiB origin fill) — it is clamped to the max."""
        with _node(tmp_path, lifecycle, urlcgi="blocksize 1m 4m") as node:
            seed_origin(node, "/f.bin", 8 * BLK)
            read_range(node.cache_port, _hinted("/f.bin", blocksize=1 << 30), 0, BLK)
            assert _block_size(node.store_dir, "f.bin") == 4 * BLK

    def test_hint_raised_to_min_and_rounded_to_granule(self, lifecycle, tmp_path):
        """Error: a hint below the min is raised to it; one that is not a
        multiple of 1m is rounded down to the granule."""
        with _node(tmp_path, lifecycle, urlcgi="blocksize 2m 4m") as node:
            seed_origin(node, "/lo.bin", 8 * BLK)
            seed_origin(node, "/odd.bin", 8 * BLK)
            read_range(node.cache_port, _hinted("/lo.bin", blocksize=BLK), 0, BLK)
            read_range(node.cache_port, _hinted("/odd.bin", blocksize=3 * BLK + 4096),
                       0, BLK)
            assert _block_size(node.store_dir, "lo.bin") == 2 * BLK
            assert _block_size(node.store_dir, "odd.bin") == 3 * BLK

    def test_hint_ignored_without_directive(self, lifecycle, tmp_path):
        """Security negative: the default posture ignores the hint — the
        policy slice size wins unless the operator arms the clamp."""
        with _node(tmp_path, lifecycle) as node:
            seed_origin(node, "/f.bin", 4 * BLK)
            read_range(node.cache_port, _hinted("/f.bin", blocksize=2 * BLK), 0, BLK)
            assert _block_size(node.store_dir, "f.bin") == BLK

    def test_hint_ignored_when_clause_says_ignore(self, lifecycle, tmp_path):
        """Error: `blocksize ignore` beside an armed prefetch clause keeps the
        policy geometry — the clauses are independent."""
        with _node(tmp_path, lifecycle, prefetch=2, prefetch_window=2 * BLK,
                   urlcgi="blocksize ignore prefetch 0 4") as node:
            seed_origin(node, "/f.bin", 4 * BLK)
            read_range(node.cache_port, _hinted("/f.bin", blocksize=2 * BLK), 0, BLK)
            assert _block_size(node.store_dir, "f.bin") == BLK

    def test_existing_object_geometry_wins(self, lifecycle, tmp_path):
        """Security negative: a hinted open of an object the cache already
        holds adopts that object's geometry — two handles never race two
        bitmaps over one file — and its blocks stay valid."""
        with _node(tmp_path, lifecycle, urlcgi="blocksize 1m 4m") as node:
            data = seed_origin(node, "/f.bin", 4 * BLK)
            read_range(node.cache_port, "/f.bin", 0, BLK)
            assert _block_size(node.store_dir, "f.bin") == BLK
            got = read_range(node.cache_port, _hinted("/f.bin", blocksize=2 * BLK),
                             BLK, BLK)
            assert got == data[BLK:2 * BLK]
            r = residency(node.store_dir, "f.bin")
            assert r["block_size"] == BLK and r["present_blocks"] == [0, 1], r

    def test_whole_file_mode_ignores_hint(self, lifecycle, tmp_path):
        """Error: without brix_cache_slice_size the cache serves whole files;
        a hint cannot switch an export into slice mode."""
        with _node(tmp_path, lifecycle, slice_size=None,
                   urlcgi="blocksize 1m 4m") as node:
            data = seed_origin(node, "/f.bin", 2 * BLK)
            got = read_range(node.cache_port, _hinted("/f.bin", blocksize=2 * BLK),
                             0, 2 * BLK)
            assert got == data
            assert _block_size(node.store_dir, "f.bin") != 2 * BLK


class TestPrefetchHint:
    """The prefetch engine (brix_cache_prefetch 4, 4m window): a 1m read of an
    8-block file speculates blocks 1..4 from the read cursor. The hint bounds
    that runway per handle."""

    def _lab(self, tmp_path, lifecycle, urlcgi="prefetch 0 4"):
        return _node(tmp_path, lifecycle, prefetch=4, prefetch_window=4 * BLK,
                     urlcgi=urlcgi)

    @staticmethod
    def _settled(node, key, expect):
        assert _poll(lambda: set(_present(node.store_dir, key)) >= set(expect)), \
            f"fill missing: {_present(node.store_dir, key)}"
        time.sleep(GRACE)                       # nothing beyond it may land
        assert _present(node.store_dir, key) == expect

    def test_hint_narrows_the_runway(self, lifecycle, tmp_path):
        """Success: pfc.prefetch=1 speculates exactly one block past the read."""
        with self._lab(tmp_path, lifecycle) as node:
            seed_origin(node, "/f.bin", 8 * BLK)
            read_range(node.cache_port, _hinted("/f.bin", prefetch=1), 0, BLK)
            self._settled(node, "f.bin", [0, 1])

    def test_hint_zero_switches_speculation_off(self, lifecycle, tmp_path):
        """Error: pfc.prefetch=0 (min 0) — this handle fills only what it
        reads; no background origin traffic."""
        with self._lab(tmp_path, lifecycle) as node:
            seed_origin(node, "/f.bin", 8 * BLK)
            read_range(node.cache_port, _hinted("/f.bin", prefetch=0), 0, BLK)
            time.sleep(1.5)
            assert _present(node.store_dir, "f.bin") == [0]

    def test_hint_clamped_to_operator_max(self, lifecycle, tmp_path):
        """Security negative: pfc.prefetch=100 cannot widen the runway past the
        operator's max (4 blocks) — the last three blocks stay absent."""
        with self._lab(tmp_path, lifecycle) as node:
            seed_origin(node, "/f.bin", 8 * BLK)
            read_range(node.cache_port, _hinted("/f.bin", prefetch=100), 0, BLK)
            self._settled(node, "f.bin", [0, 1, 2, 3, 4])

    def test_hint_ignored_when_clause_unarmed(self, lifecycle, tmp_path):
        """Security negative: with only the blocksize clause armed, a
        pfc.prefetch=0 cannot switch the operator's speculation off."""
        with self._lab(tmp_path, lifecycle, urlcgi="blocksize 1m 4m") as node:
            seed_origin(node, "/f.bin", 8 * BLK)
            read_range(node.cache_port, _hinted("/f.bin", prefetch=0), 0, BLK)
            self._settled(node, "f.bin", [0, 1, 2, 3, 4])


# ===========================================================================
# Regression pin for the 2026-09-09 discovery: root:// dropped the hints
# ===========================================================================

class TestHintsReachTheDriverOnTheRootPlane:
    """Every hint above was silently ignored until 2026-09-09.

    The VFS carries the parsed pfc.* hints on the per-open ctx, and the
    davs/S3 call sites deliver them through ``brix_vfs_open`` — but the
    root:// data plane opens the driver directly from
    ``brix_open_resolved_via_driver``, which called the PLAIN cred open. The
    hints were parsed, clamped-ready and never handed to a driver, so the
    slice geometry silently stayed at the policy value on the one protocol
    this feature is for. The live tests above are the behavioural proof;
    these pin the seam so the plain slot cannot creep back into that call.
    """
    DRIVER_OPEN = "src/protocols/root/read/open_resolved_file_open.c"

    def test_root_driver_open_uses_the_hinted_slot(self):
        """Success: the root:// driver open goes through the hinted helper."""
        text = (REPO / self.DRIVER_OPEN).read_text()
        assert "brix_sd_open_hinted_maybe_cred(sd, logical," in text

    def test_root_driver_open_no_longer_uses_the_plain_slot(self):
        """Error: the plain cred open in that call is the regression itself —
        it compiles, serves bytes, and drops every hint."""
        text = (REPO / self.DRIVER_OPEN).read_text()
        assert "brix_sd_open_maybe_cred(sd, logical," not in text

    def test_the_hinted_helper_still_falls_back_without_a_hint(self):
        """Security negative: routing to the hinted slot must stay conditional
        on there BEING a hint and on the cred contract — an unconditional
        open_hinted would take a cred-forwarding open to a driver with no
        open_cred slot, dropping the caller's identity."""
        helper = (REPO / "src/fs/backend/sd_cred_forward.h").read_text()
        body = helper[helper.index("brix_sd_open_hinted_maybe_cred(brix_sd_instance_t"):]
        body = body[:body.index("brix_sd_staged_open_maybe_cred")]
        assert "brix_sd_open_hints_empty(hints)" in body
        assert "cred == NULL || inst->driver->open_cred != NULL" in body
        assert "return brix_sd_open_maybe_cred(" in body
