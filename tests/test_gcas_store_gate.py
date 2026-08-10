"""Config-parse gates for phase-88 W1: the commit-time-dedup SD slot un-posixes
G13 (brix_cache_global_cas) and the cvmfs-cas verify store constraint.

`nginx -t` only (no server start, no bind): every case renders a minimal
config and asserts accept (rc==0) or reject (rc!=0 + the exact [emerg] needle
brix_tier_register_cache_store emits). Two planes because the enums differ:
the STREAM plane carries the global_cas legs (its brix_cache_verify has no
cvmfs-cas value), the HTTP cvmfs plane carries the cvmfs-cas verify legs.

  * SUCCESS      — a pblock cache store with `?dedup=1` accepts global_cas
                   (+ cvmfs-cas verify on the http plane), and the `?tail`
                   lands as the store's pblock.opts sidecar; the classic posix
                   store still accepts.
  * ERROR        — a store whose driver has no dedup_publish (remote root://)
                   or no staged_path is rejected loudly; a `?tail` on a
                   non-pblock store is an operator error, never ignored.
  * SECURITY-NEG — a pblock store WITHOUT the refs gate is rejected: dedup
                   must never silently no-op (ENOTSUP on every verified fill).

Harness mirrors tests/test_cache_directive_parse.py (nginx -t pattern).
"""

import subprocess

from cmdscripts.live_common import inject_nginx_load_modules
from settings import BIND_HOST, NGINX_BIN

# -t never binds, so the port is inert; same convention as
# tests/test_cache_directive_parse.py.
PARSE_PORT = 13299


def _run_t(root, conf_text):
    (root / "logs").mkdir(exist_ok=True)
    (root / "data").mkdir(exist_ok=True)
    (root / "cache").mkdir(exist_ok=True)
    conf = root / "gcas_gate.conf"
    conf.write_text(conf_text)
    inject_nginx_load_modules(conf)
    p = subprocess.run([str(NGINX_BIN), "-t", "-p", str(root), "-c", str(conf)],
                       capture_output=True, text=True, timeout=30)
    return p.returncode, p.stderr + p.stdout


def _stream_t(root, srv_directives):
    return _run_t(root, f"""daemon off; error_log {root}/logs/e.log info;
pid {root}/n.pid; thread_pool default threads=2;
events {{ worker_connections 64; }}
stream {{ server {{ listen {BIND_HOST}:{PARSE_PORT};
    brix_root on;
    brix_storage_backend root://127.0.0.1:1;
    brix_auth none;
    {srv_directives}
    brix_cache_export /;
}} }}
""")


def _cvmfs_t(root, loc_directives):
    return _run_t(root, f"""daemon off; error_log {root}/logs/e.log info;
pid {root}/n.pid; thread_pool default threads=2;
events {{ worker_connections 64; }}
http {{ server {{ listen {BIND_HOST}:{PARSE_PORT};
    location /cvmfs/ {{
        brix_cvmfs on;
        brix_storage_backend "http://127.0.0.1:1";
        {loc_directives}
    }}
}} }}
""")


class TestGlobalCasStoreGate:
    """STREAM plane: the dedup_publish-slot capability gate for global_cas."""

    def test_pblock_store_with_dedup_accepts(self, tmp_path):
        """SUCCESS: pblock + ?dedup=1 accepts global_cas and the tail is
        persisted as the pblock.opts sidecar."""
        rc, out = _stream_t(tmp_path, f"""
    brix_cache_store pblock:{tmp_path}/cache?dedup=1;
    brix_cache_global_cas on;
""")
        assert rc == 0, f"expected accept for pblock?dedup=1 global_cas:\n{out}"
        sidecar = tmp_path / "cache" / "pblock.opts"
        assert sidecar.exists(), "config did not persist the pblock.opts sidecar"
        assert "dedup=1" in sidecar.read_text(), \
            f"sidecar lacks dedup=1: {sidecar.read_text()!r}"

    def test_pack_tail_persists(self, tmp_path):
        """SUCCESS (phase-88 W2): a combined ?dedup=1&pack=1 tail reaches the
        sidecar intact, so the packed small-blob arena is config-armable on a
        cache store."""
        rc, out = _stream_t(tmp_path, f"""
    brix_cache_store pblock:{tmp_path}/cache?dedup=1&pack=1;
    brix_cache_global_cas on;
""")
        assert rc == 0, f"expected accept for dedup+pack tail:\n{out}"
        sidecar = tmp_path / "cache" / "pblock.opts"
        assert sidecar.exists() and "pack=1" in sidecar.read_text(), \
            "pack=1 did not persist to the pblock.opts sidecar"

    def test_posix_store_still_accepts(self, tmp_path):
        """SUCCESS (regression): the classic posix store keeps working."""
        rc, out = _stream_t(tmp_path, f"""
    brix_cache_store posix:{tmp_path}/cache;
    brix_cache_global_cas on;
""")
        assert rc == 0, f"expected accept for posix global_cas:\n{out}"

    def test_pblock_store_without_dedup_rejected(self, tmp_path):
        """SECURITY-NEG: a refs-off pblock store must be rejected — global_cas
        silently no-opping (ENOTSUP per fill) is not an acceptable state."""
        rc, out = _stream_t(tmp_path, f"""
    brix_cache_store pblock:{tmp_path}/cache;
    brix_cache_global_cas on;
""")
        assert rc != 0, "expected reject for pblock store without ?dedup=1"
        assert "requires its refs gate" in out, \
            f"expected the refs-gate diagnostic, got:\n{out}"

    def test_remote_store_rejected(self, tmp_path):
        """ERROR: a driver with no dedup_publish slot (remote root://) is
        rejected with the slot-capability diagnostic."""
        rc, out = _stream_t(tmp_path, """
    brix_cache_store root://127.0.0.1:1094;
    brix_cache_global_cas on;
""")
        assert rc != 0, "expected reject for root:// store + global_cas"
        assert "supports commit-time dedup" in out, \
            f"expected the dedup-slot diagnostic, got:\n{out}"

    def test_opts_tail_on_posix_store_rejected(self, tmp_path):
        """ERROR: a `?tail` on a non-pblock store is an operator error — it
        must never be silently folded into the path or dropped."""
        rc, out = _stream_t(tmp_path, f"""
    brix_cache_store posix:{tmp_path}/cache?dedup=1;
""")
        assert rc != 0, "expected reject for posix store with ?tail"
        assert "only supported on pblock stores" in out, \
            f"expected the pblock-only diagnostic, got:\n{out}"


class TestCvmfsCasVerifyStoreGate:
    """HTTP cvmfs plane: the staged_path capability gate for cvmfs-cas."""

    def test_pblock_store_accepts_cvmfs_cas(self, tmp_path):
        """SUCCESS: a dedup-armed pblock store with a CVMFS-ceiling stripe
        accepts cvmfs-cas verify + global_cas — the full G13-over-pblock
        stack parses."""
        rc, out = _cvmfs_t(tmp_path, f"""
        brix_cache_store pblock:{tmp_path}/cache?dedup=1 block_size=256m;
        brix_cache_verify cvmfs-cas;
        brix_cache_global_cas on;
""")
        assert rc == 0, f"expected accept for the pblock cvmfs-cas stack:\n{out}"

    def test_remote_store_rejected_for_cvmfs_cas(self, tmp_path):
        """ERROR: cvmfs-cas verify needs staged fill paths; a remote store
        has none and is rejected loudly."""
        rc, out = _cvmfs_t(tmp_path, """
        brix_cache_store root://127.0.0.1:1094;
        brix_cache_verify cvmfs-cas;
""")
        assert rc != 0, "expected reject for root:// store + cvmfs-cas"
        assert "staged fill paths" in out, \
            f"expected the staged-path diagnostic, got:\n{out}"

    def test_small_block_size_warns(self, tmp_path):
        """SUCCESS + advisory: a pblock store below the CVMFS object ceiling
        still parses, but the operator is warned about fail-closed oversize
        fills."""
        rc, out = _cvmfs_t(tmp_path, f"""
        brix_cache_store pblock:{tmp_path}/cache?dedup=1 block_size=64m;
        brix_cache_verify cvmfs-cas;
        brix_cache_global_cas on;
""")
        assert rc == 0, f"expected accept with a warning:\n{out}"
        assert "below the CVMFS object ceiling" in out, \
            f"expected the block-size advisory, got:\n{out}"
