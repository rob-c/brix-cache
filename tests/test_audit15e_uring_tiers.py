"""
test_audit15e_uring_tiers.py — the io_uring disk-I/O backend under storage
tiers (audit §B2.13, testsuite-combinatorial-coverage-audit 2026-08-15:
`brix_io_uring on` only ever ran over a bare posix export; never under a
cache spool serve, a passthrough spool, or the phase-70 whole-object staged
writer, though all three route their disk I/O through the ring).

One instance (nginx_audit15e_uring_tiers.conf): a WebDAV posix origin and
two ring-forced stream fronts over it — a read-only root:// cache front
(fills land in a posix spool; repeat reads are served from that spool
through the ring; objects over `brix_cache_max_object` take the
store-then-serve passthrough path instead) and a root:// staged writer
(http:// backend advertises no RANDOM_WRITE, so writes stage whole-object
into brix_stage_dir and the close commits one PUT).  `brix_io_uring on`
fail-fasts at boot, and the "backend active" NOTICE is waited for, so the
ring is provably live under every tier.  Skips cleanly where the
build/kernel has no io_uring.

Cases:
  * success — a read through the cache front is byte-exact with valid
    per-page CRC32c, the fill lands in the spool, and a repeat read after
    the ORIGIN object is destroyed still serves the bytes: the second read
    came from the ring-backed spool, not the origin
  * success — an object over the caching cap is served through the ring by
    the passthrough path and leaves NO durable spool copy behind
  * success — a writev(+doSync) through the staged writer commits the
    whole object to the origin byte-exact and drains the spool
  * security-negative — the read-only cache front refuses a WRITE open
  * security-negative — a writev whose descriptor block is not a whole
    number of 16-byte descriptors is rejected (kXR_ArgInvalid) on the
    staged-writer front: the ring under a tier never widens the framing
    contract
"""

import os
import struct
import time

import pytest

from server_launcher import RegistryCommandFailure
from server_registry import NginxInstanceSpec
from settings import BIND_HOST, HOST

from _test_conf_pgio_helpers import (
    _session, _open, _close, pgread, pgread_bytes, crc32c,
    kXR_open_updt, kXR_new, kXR_delete, kXR_open_read, kXR_ok, kXR_error,
)
from test_io_uring_runtime import _writev, kXR_writev, kXR_ArgInvalid

pytestmark = [pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-audit15e-uring")]


def _boot(lifecycle, tmp_path):
    """Boot the ring-forced tier instance; returns (endpoint, origin, cache,
    spool).  Skips when the build/kernel has no io_uring (same needles as
    test_io_uring_runtime._start)."""
    origin = tmp_path / "origin"
    export = tmp_path / "export"
    cache = tmp_path / "cache"
    spool = tmp_path / "spool"
    for d in (origin, export / "cf", export / "st", cache, spool):
        d.mkdir(parents=True)
    try:
        ep = lifecycle.start(NginxInstanceSpec(
            name="lc-audit15e-uring",
            template="nginx_audit15e_uring_tiers.conf",
            protocol="root",
            readiness="tcp",
            data_root=str(origin),
            template_values={"BIND_HOST": BIND_HOST,
                             "ORIGIN_ROOT": str(origin),
                             "EXPORT_ROOT": str(export),
                             "CACHE_ROOT": str(cache),
                             "SPOOL_DIR": str(spool)},
            reason="audit-15e io_uring x cache/staged-writer tier crosses"))
    except RegistryCommandFailure as failure:
        diagnostic = f"{failure.stdout_tail}\n{failure.stderr_tail}"
        if ("compiled WITHOUT it" in diagnostic
                or "io_uring is unavailable" in diagnostic):
            pytest.skip("io_uring live backend is unavailable in this build")
        raise
    # The TCP readiness gate can precede the worker's boot NOTICE; wait it
    # out so a silent auto-fallback (which "on" forbids) can never pass.
    errlog = os.path.join(ep.prefix, "logs", "error.log")
    deadline = time.monotonic() + 10.0
    while time.monotonic() < deadline:
        try:
            with open(errlog) as f:
                if "io_uring disk-I/O backend active" in f.read():
                    break
        except FileNotFoundError:
            pass
        time.sleep(0.1)
    else:
        raise AssertionError("io_uring ring did not report active at boot")
    return ep, origin, cache, spool


def _pgread_all(port, path, length):
    s = _session(HOST, port)
    try:
        _sid, st, ob = _open(s, path, options=kXR_open_read,
                             streamid=b"\x00\x02")
        assert st == kXR_ok, f"open-for-read failed: {st} {ob!r}"
        fh = ob[:4]
        status, pages = pgread(s, fh, 0, length)
        assert status == kXR_ok, f"pgread failed: {pages}"
        _close(s, fh)
        return pgread_bytes(pages), pages
    finally:
        s.close()


def test_uring_cache_spool_serves_after_origin_gone(lifecycle, tmp_path):
    ep, origin, cache, _ = _boot(lifecycle, tmp_path)
    payload = os.urandom(9000)          # spans three 4096-byte pages
    (origin / "obj.bin").write_bytes(payload)

    got, pages = _pgread_all(ep.port, "/obj.bin", len(payload))
    assert got == payload, "read-through bytes differ from the origin object"
    assert all(crc32c(page) == crc for (_off, page, crc) in pages), \
        "a per-page CRC32c from the ring's hybrid pgread did not verify"
    assert [p for p in cache.rglob("*") if p.is_file()], \
        "read-through returned bytes but nothing landed in the cache spool"

    # Destroy the origin object: a repeat read can now ONLY be served from
    # the ring-backed spool.
    (origin / "obj.bin").unlink()
    got2, pages2 = _pgread_all(ep.port, "/obj.bin", len(payload))
    assert got2 == payload, \
        "spool serve after origin loss returned different bytes"
    assert all(crc32c(page) == crc for (_off, page, crc) in pages2)


def test_uring_passthrough_oversize_not_spooled(lifecycle, tmp_path):
    """io_uring x passthrough: an object above `brix_cache_max_object` but
    under `brix_cache_passthrough_max` takes the store-then-serve path, whose
    disk I/O is the ring's — the bytes and their per-page CRC32c must be
    exact, and no durable spool copy may survive the read."""
    ep, origin, cache, _ = _boot(lifecycle, tmp_path)
    payload = os.urandom(300 * 1024)     # > 16384 cap, < 1 MiB passthrough cap
    (origin / "big.bin").write_bytes(payload)

    got, pages = _pgread_all(ep.port, "/big.bin", len(payload))
    assert got == payload, "passthrough read through the ring returned " \
                           "different bytes than the origin object"
    assert all(crc32c(page) == crc for (_off, page, crc) in pages), \
        "a per-page CRC32c from a ring-backed passthrough read did not verify"
    assert not [p for p in cache.rglob("*")
                if p.is_file() and p.stat().st_size >= len(payload)], \
        "the passthrough-served object left a durable copy in the cache spool"


def test_uring_staged_write_commits_to_origin(lifecycle, tmp_path):
    ep, origin, _, spool = _boot(lifecycle, tmp_path)
    stage_port = ep.extra_ports["STAGE_PORT"]
    payload = os.urandom(10000)

    s = _session(HOST, stage_port)
    try:
        _sid, st, ob = _open(s, "/staged.bin",
                             options=kXR_open_updt | kXR_new | kXR_delete,
                             streamid=b"\x00\x02")
        assert st == kXR_ok, f"open-for-write failed: {st} {ob!r}"
        fh = ob[:4]
        half = len(payload) // 2
        st, body = _writev(s, fh, [(0, payload[:half]), (half, payload[half:])],
                           do_sync=True)
        assert st == kXR_ok, f"writev+doSync rejected on the staged path: {body}"
        _close(s, fh)
    finally:
        s.close()

    assert (origin / "staged.bin").read_bytes() == payload, \
        "the staged close did not commit the whole object to the origin"
    assert not [p for p in spool.rglob("*") if p.is_file()], \
        "the staged writer left its spool copy behind after the commit"


def test_cache_front_refuses_write_open(lifecycle, tmp_path):
    ep, origin, _, _ = _boot(lifecycle, tmp_path)
    s = _session(HOST, ep.port)
    try:
        _sid, st, _ob = _open(s, "/never.bin",
                              options=kXR_open_updt | kXR_new | kXR_delete,
                              streamid=b"\x00\x02")
        assert st != kXR_ok, \
            "read-only ring-backed cache front accepted a WRITE open"
    finally:
        s.close()
    assert not (origin / "never.bin").exists()


def test_staged_writev_bad_framing_rejected(lifecycle, tmp_path):
    ep, origin, _, _ = _boot(lifecycle, tmp_path)
    stage_port = ep.extra_ports["STAGE_PORT"]
    s = _session(HOST, stage_port)
    try:
        _sid, st, ob = _open(s, "/badframe.bin",
                             options=kXR_open_updt | kXR_new | kXR_delete,
                             streamid=b"\x00\x02")
        assert st == kXR_ok
        fh = ob[:4]
        # One descriptor plus a stray 5 bytes (the legacy data-in-dlen
        # layout) — not a whole descriptor count.
        desc = fh + struct.pack(">I", 5) + struct.pack(">q", 0)
        bad = desc + b"HELLO"
        hdr = b"\x00\x05" + struct.pack(">H", kXR_writev) + b"\x00" * 16 \
            + struct.pack(">I", len(bad))
        s.sendall(hdr + bad)
        resp = b""
        while len(resp) < 8:
            resp += s.recv(8 - len(resp))
        status = struct.unpack(">H", resp[2:4])[0]
        dlen = struct.unpack(">I", resp[4:8])[0]
        body = b""
        while len(body) < dlen:
            body += s.recv(dlen - len(body))
        def _assert_test_staged_writev_bad_framing_rejected_1():
            assert status == kXR_error
            assert struct.unpack(">I", body[:4])[0] == kXR_ArgInvalid, \
                f"expected kXR_ArgInvalid, got {body!r}"

        _assert_test_staged_writev_bad_framing_rejected_1()
    finally:
        s.close()
    assert not (origin / "badframe.bin").exists(), \
        "the rejected staged write still committed an object"
