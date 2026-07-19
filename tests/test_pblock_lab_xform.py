"""Phase-83 F12/F13 — per-block transforms (pblock crypt / zstd).

With `xform=crypt:<keyfile>` or `xform=zstd` in the backend `?tail` (persisted as
the `<root>/pblock.opts` sidecar), every block of every object is stored through
a whole-block transform seam (`pblock_xform.c`) as a self-describing block file:

    [u32 logical_len LE][u32 phys_len LE][phys bytes]

  * `crypt` — a keyed XOR keystream per block (phys_len == logical_len). NOT a
    reviewed cryptographic boundary; a lab keyed obfuscation, per the phase
    non-goals. The on-disk bytes are unreadable without the export's keyfile.
  * `zstd` — level-3 compression (phys_len == compressed size, usually far below
    logical). The catalog keeps the LOGICAL size; the block file holds the
    physical bytes.

The transform is fail-closed config: an unknown spec, an unreadable crypt
keyfile, or `zstd` without libzstd fails instance init so `nginx -t` refuses the
export (unlike the lab toys, which are best-effort). A transformed export drops
`CAP_SENDFILE|CAP_IOURING` (block 0 holds transformed, not raw, bytes) and
records the transform kind per file in `objects.xform`; reopening an object
whose recorded kind does not match the export's configured kind is refused with
EIO (the config-mismatch guard) so bytes written under one transform can never
be served as another.

Proves: a crypt export round-trips byte-identical over WebDAV while the plaintext
marker never appears on disk and the block file is headered (success); a zstd
export round-trips a highly-compressible object byte-identical with the physical
block far smaller than the logical size the catalog still reports (F13 success);
and a malformed / unreadable transform spec refuses at `nginx -t`, while an
object written under `zstd` is refused (EIO ⇒ 500) when the same root is later
served raw — the recorded-kind guard (error + security-neg).
"""

from __future__ import annotations

import os
from pathlib import Path
import sqlite3
import time

import pytest

from cmdscripts.live_common import LiveFailure, LiveRun, sha256
from cmdscripts.pblock_live import (
    pblock_lab_spec,
    pblock_worker_own,
    pblock_worker_readable,
)

pytestmark = pytest.mark.uses_lifecycle_harness


def _need_bins() -> None:
    nginx = Path(os.environ.get("NGINX_BIN", "/tmp/nginx-1.28.3/objs/nginx"))
    if not nginx.exists():
        pytest.skip(f"nginx binary not found: {nginx}")


def _block_files(root: Path) -> list[Path]:
    """Every numeric-named block leaf under <root>/data/<..>/<..>/<blob>/."""
    data = root / "data"
    return [p for p in data.rglob("*") if p.is_file() and p.name.isdigit()]


def _catalog_size(root: Path, path: str) -> int:
    conn = sqlite3.connect(str(root / "catalog.db"), timeout=10)
    try:
        row = conn.execute("SELECT size FROM objects WHERE path=?",
                           (path,)).fetchone()
        return int(row[0]) if row else -1
    finally:
        conn.close()
        pblock_worker_own(root / "catalog.db")


@pytest.mark.optin
@pytest.mark.timeout(120)
def test_xform_crypt_roundtrip(lifecycle) -> None:
    """(success) A crypt export round-trips byte-identical over WebDAV, yet the
    plaintext marker never lands on disk and the block file carries the transform
    header (logical_len in the first four bytes) — the stored bytes are keyed."""
    _need_bins()
    with LiveRun("pblock_xform_crypt", None) as run:
        keyfile = run.write(run.root / "xform.key", "phase-83 lab crypt key\n")
        pblock_worker_readable(keyfile)
        ep = lifecycle.start(pblock_lab_spec(
            "lc-pblock-xform-crypt", f"?xform=crypt:{keyfile}",
            workers=1, webdav=True))
        data_root = Path(ep.data_root)
        url = f"http://{ep.host}:{ep.port}"

        marker = b"BRIX-PLAINTEXT-MARKER-F12F13-"
        payload = (marker * 20000)[:600_000]      # single 1m block, scannable
        src = run.root / "secret.bin"
        src.write_bytes(payload)

        time.sleep(1)
        assert run.curl_status(f"{url}/s", "-T", str(src)) in (201, 204)
        assert run.curl_bytes(f"{url}/s") == payload, "crypt roundtrip not exact"
        lifecycle.stop("lc-pblock-xform-crypt")

        blocks = _block_files(data_root)
        assert blocks, "no block file written"
        for blk in blocks:
            data = blk.read_bytes()
            assert marker not in data, f"plaintext leaked to disk: {blk}"
            llen = int.from_bytes(data[0:4], "little")
            assert llen == len(payload), f"bad header logical_len in {blk}: {llen}"
        # crypt is length-preserving: the recorded logical size is the true size.
        assert _catalog_size(data_root, "/s") == len(payload)


@pytest.mark.optin
@pytest.mark.timeout(120)
def test_xform_zstd_compresses(lifecycle) -> None:
    """(F13 success) A zstd export round-trips a highly-compressible object
    byte-identical, while the physical block on disk is far smaller than the
    logical size the catalog still reports."""
    _need_bins()
    with LiveRun("pblock_xform_zstd", None) as run:
        ep = lifecycle.start(pblock_lab_spec("lc-pblock-xform-zstd", "?xform=zstd",
                                             workers=1, webdav=True))
        data_root = Path(ep.data_root)
        url = f"http://{ep.host}:{ep.port}"

        payload = b"\x00" * 800_000               # trivially compressible
        src = run.root / "zeros.bin"
        src.write_bytes(payload)

        time.sleep(1)
        rc = run.curl_status(f"{url}/z", "-T", str(src))
        if rc == 0:
            lifecycle.stop("lc-pblock-xform-zstd")
            pytest.skip("zstd export refused — libzstd not built in")
        assert rc in (201, 204)
        assert run.curl_bytes(f"{url}/z") == payload, "zstd roundtrip not exact"
        lifecycle.stop("lc-pblock-xform-zstd")

        blocks = _block_files(data_root)
        assert blocks, "no block file written"
        physical = sum(p.stat().st_size for p in blocks)
        assert physical < len(payload) // 10, \
            f"zstd block not compressed: {physical} vs {len(payload)}"
        # The catalog keeps the LOGICAL size, not the compressed physical size.
        assert _catalog_size(data_root, "/z") == len(payload)


@pytest.mark.optin
@pytest.mark.timeout(120)
def test_xform_config_errors_and_mismatch(lifecycle) -> None:
    """(error + security-neg) A malformed spec and an unreadable crypt keyfile
    each fail the pblock instance init — the block store is never built (the
    init-failure line is logged), the same fail-closed contract every malformed
    lab opt shares — and an object written under zstd is refused (EIO ⇒ 500) when
    the same root is later served raw: the recorded-kind guard keeps transformed
    bytes from ever being served as another transform."""
    _need_bins()

    # (error) A bad transform spec / unreadable keyfile fails the lazy per-export
    # instance init: pblock_xform_config returns -1, sd_pblock_init aborts, and no
    # block store is ever created for the export (logged as "backend init failed").
    for name, tail in (("lc-pblock-xform-bad", "?xform=bogus"),
                       ("lc-pblock-xform-nokey", "?xform=crypt:/no/such/keyfile")):
        with LiveRun(name, None) as run:
            src = run.root / "p.bin"
            src.write_bytes(b"x" * 4096)
            ep = lifecycle.start(pblock_lab_spec(name, tail, workers=1, webdav=True))
            time.sleep(1)
            url = f"http://{ep.host}:{ep.port}"
            run.curl_status(f"{url}/p", "-T", str(src))   # triggers lazy build
            lifecycle.stop(name)
            log = (Path(ep.prefix) / "logs" / "error.log").read_text(errors="replace")
            assert "pblock backend init failed" in log, \
                f"{tail}: bad xform spec did not fail the pblock init"
            # The pblock store was never built: no transformed block ever landed.
            assert not _block_files(Path(ep.data_root)), \
                f"{tail}: a pblock object was stored despite the bad spec"

    # (security-neg) write an object under zstd, then reconfigure the SAME root
    # for a DIFFERENT transform (crypt — which overwrites the opts sidecar): the
    # per-file recorded kind ("zstd") no longer matches the export's configured
    # kind (crypt) ⇒ the mismatch guard fails at the stat metadata boundary (EIO
    # ⇒ 500), so no read fast-path ever hands the object's bytes back decoded as
    # the wrong transform.
    with LiveRun("pblock_xform_shift", None) as run:
        keyfile = run.write(run.root / "k", "another key\n")
        pblock_worker_readable(keyfile)
        ep = lifecycle.start(pblock_lab_spec("lc-pblock-xform-shift", "?xform=zstd",
                                             workers=1, webdav=True))
        url = f"http://{ep.host}:{ep.port}"
        payload = b"\x00" * 400_000
        src = run.root / "z.bin"
        src.write_bytes(payload)

        time.sleep(1)
        rc = run.curl_status(f"{url}/z", "-T", str(src))
        if rc == 0:
            lifecycle.stop("lc-pblock-xform-shift")
            pytest.skip("zstd export refused — libzstd not built in")
        assert rc in (201, 204)
        assert run.curl_bytes(f"{url}/z") == payload
        lifecycle.stop("lc-pblock-xform-shift")

        # Reconfigure the same root under crypt (overwrites the opts sidecar).
        lifecycle.reconfigure("lc-pblock-xform-shift", TAIL=f"?xform=crypt:{keyfile}")
        lifecycle.start_registered("lc-pblock-xform-shift")
        time.sleep(1)
        assert run.curl_status(f"{url}/z", "-I") == 500, \
            "zstd object served under a crypt export — recorded-kind guard failed"
        assert run.curl_status(f"{url}/z") == 500, "mismatched object readable"
        lifecycle.stop("lc-pblock-xform-shift")
