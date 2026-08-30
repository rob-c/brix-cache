"""Regression guards for a brix gateway in front of a root:// origin.

Covers four bugs found bringing up the pure-python xrd client (uproot) against a
`brix_storage_backend root://…` gateway with a staged write tier:

  1. Concurrent-open file-handle collision. brix_alloc_fhandle treated a slot as
     free on `fd < 0`, but a driver-backed (remote) open is memory-served with
     fd=-1 and sd_obj.driver set, so every concurrent remote open collapsed onto
     handle 0. Closing one tore down the shared slot and a read/close on another
     open got kXR_FileNotOpen. Guard: two concurrent opens on one connection must
     return DISTINCT handles, and closing the first must not disturb the second.

  2. Staged write to a nested subdir. sd_posix_staged_open did not create the
     target's parent chain in the store root, so a POSC write to a new subdir
     failed ENOENT at commit. Guard: a staged write to /a/b/c lands byte-exact on
     the origin.

  3. >1 MiB origin read. sd_xroot_pread issued one origin read for the whole
     request, but the origin read-response path rejects frames >1 MiB. Guard: a
     >2 MiB driver-backed read is byte-exact (also exercises the read-gate that
     keeps driver handles off the pread thread pool — hence thread_pool below).

  4. Explicit kXR_mkdir over a remote backend used to return EAGAIN (xroot had no
     mkdir vtable slot). Guard: mkdir -p /a/b/c creates the tree on the origin.

The checks speak XRootD directly over sockets (no native client needed), so the
only prerequisite is an nginx binary with the brix module.
"""

from __future__ import annotations

from pathlib import Path
import os
import signal
import socket
import struct
import time

from cmdscripts import run
from cmdscripts.command_results import print_results
from fleet_ports import cmdscript_ports
from settings import BIND_HOST, HOST, NGINX_BIN

import _test_a_robustness_helpers as H

# kXR_open option bits (XProtocol).
kXR_delete = 0x0002
kXR_new = 0x0008
kXR_open_read = 0x0010
kXR_open_updt = 0x0020
kXR_mkpath = 0x0100
kXR_posc = 0x1000
WRITE_OPTS = kXR_new | kXR_delete | kXR_open_updt | kXR_mkpath | kXR_posc

# Metadata request opcodes + the ASCII-stat isDir flag (XProtocol). These guard
# the phase-1x remote-metadata gap fixes: a root:// export used to stat the
# empty LOCAL export (statx/locate) and describe every path by opening it
# (directories → kXR_isDirectory), which broke isdir, mv, statx and locate.
kXR_chmod = 3002
kXR_mv = 3009
kXR_stat = 3017
kXR_statx = 3022
kXR_locate = 3027
kXR_truncate = 3028
kXR_isDir = 2       # ASCII-stat flag bit: path is a directory
kXR_ok = 0


def _stat_over_gateway(s: socket.socket, path: bytes, sid: bytes):
    """kXR_stat `path` through the gateway. Returns (status, flags) where flags
    is the integer from the "id size flags mtime" ASCII reply, or None if the
    reply was an error / unparsable."""
    s.sendall(H.make_stat_req(path, streamid=sid))
    status, body = H._recv_response(s)
    if status != kXR_ok or not body:
        return status, None
    try:
        fields = body.split(b"\x00", 1)[0].split()
        return status, int(fields[2])   # id size FLAGS mtime
    except (IndexError, ValueError):
        return status, None


def deterministic_bytes(size: int, seed: int) -> bytes:
    return bytes((seed + i) % 251 for i in range(size))


def stop_nginx(prefix: Path) -> None:
    try:
        pid = int((prefix / "nginx.pid").read_text(encoding="utf-8").strip())
    except (OSError, ValueError):
        return
    try:
        os.kill(pid, signal.SIGTERM)
    except OSError:
        pass


def write_origin_config(prefix: Path, port: int) -> Path:
    root = prefix / "root"
    logs = prefix / "logs"
    root.mkdir(parents=True, exist_ok=True)
    logs.mkdir(parents=True, exist_ok=True)
    conf = prefix / "nginx.conf"
    conf.write_text(
        f"""daemon on; error_log {logs / 'e.log'} info; pid {prefix / 'nginx.pid'};
events {{ worker_connections 64; }}
stream {{ server {{ listen {BIND_HOST}:{port}; brix_root on; brix_export {root};
    brix_auth none; brix_allow_write on;
    brix_access_log {logs / 'access.log'}; }} }}
""",
        encoding="utf-8",
    )
    return conf


def write_gateway_config(prefix: Path, port: int, origin_port: int) -> Path:
    export = prefix / "gw"
    stage = prefix / "stage"
    logs = prefix / "logs"
    for path in (export, stage, logs):
        path.mkdir(parents=True, exist_ok=True)
    conf = prefix / "nginx.conf"
    # thread_pool is deliberate: bug #3's read-gate only engages when a pread
    # thread pool is configured (driver handles must be served inline, not
    # offloaded — off-thread the backend driver returns EIO).
    conf.write_text(
        f"""daemon on; error_log {logs / 'e.log'} info; pid {prefix / 'nginx.pid'};
thread_pool gwpool threads=4 max_queue=4096;
events {{ worker_connections 64; }}
stream {{ server {{
    listen {BIND_HOST}:{port}; brix_root on; brix_auth none;
    brix_export {export}; brix_allow_write on; brix_thread_pool gwpool;
    brix_storage_backend root://{HOST}:{origin_port};
    brix_stage on; brix_stage_store posix:{stage}; brix_stage_flush sync;
}} }}
""",
        encoding="utf-8",
    )
    return conf


# --- raw XRootD client helpers (session + typed requests) ------------------


def _session(port: int) -> socket.socket:
    s = socket.create_connection((HOST, port), timeout=5)
    s.settimeout(5)
    hs, pr, lg = H._full_anon_login(s)
    if (hs, pr, lg) != (0, 0, 0):
        s.close()
        raise RuntimeError(f"login handshake failed: hs={hs} proto={pr} login={lg}")
    return s


def _open(s: socket.socket, path: bytes, options: int, sid: bytes) -> tuple[int, bytes]:
    s.sendall(H.make_open_req(path, options=options, streamid=sid))
    status, body = H._recv_response(s)
    return status, body[:4]  # (status, fhandle)


def _read(s: socket.socket, fh: bytes, off: int, n: int, sid: bytes) -> tuple[int, bytes]:
    s.sendall(H.make_read_req(fh, off, n, streamid=sid))
    return H._recv_response(s)


def _close(s: socket.socket, fh: bytes, sid: bytes) -> int:
    s.sendall(H.make_close_req(fh, streamid=sid))
    return H._recv_response(s)[0]


def _mkdir(s: socket.socket, path: bytes, mode: int, sid: bytes) -> int:
    body = bytes([0x01]) + b"\x00" * 13 + struct.pack(">H", mode)  # kXR_mkdirpath + mode BE
    s.sendall(H.make_request(sid, H.kXR_mkdir, body, path + b"\x00"))
    return H._recv_response(s)[0]


def _write(s: socket.socket, fh: bytes, off: int, data: bytes, sid: bytes) -> int:
    body = fh[:4] + struct.pack(">q", off) + b"\x00" * 4  # fhandle offset pathid+reserved
    s.sendall(H.make_request(sid, H.kXR_write, body, data))
    return H._recv_response(s)[0]


def _read_whole(s: socket.socket, fh: bytes, total: int, sid: bytes, chunk: int = 1_000_000) -> bytes:
    got = b""
    off = 0
    while off < total:
        want = min(chunk, total - off)
        st, blk = _read(s, fh, off, want, sid)
        if st != 0:
            raise RuntimeError(f"read status={st} at off={off}")
        if not blk:
            break
        got += blk
        off += len(blk)
    return got


# --- checks -----------------------------------------------------------------


def _check_concurrent_handles(port: int, results: list[tuple[bool, str]]) -> None:
    s = _session(port)
    try:
        st_a, fh_a = _open(s, b"/reg_small.bin", kXR_open_read, b"\x00\x11")
        st_b, fh_b = _open(s, b"/reg_small.bin", kXR_open_read, b"\x00\x12")
        results.append((st_a == 0 and st_b == 0, "concurrent opens both succeed"))
        results.append((fh_a != fh_b, "concurrent opens return distinct handles"))

        r_st, r_body = _read(s, fh_a, 0, 100, b"\x00\x11")
        results.append((r_st == 0 and len(r_body) == 100, "read on first handle ok"))

        c_st = _close(s, fh_a, b"\x00\x11")
        results.append((c_st == 0, "close first handle ok"))

        # Before the fix this read returned kXR_FileNotOpen: closing handle A
        # (slot 0) tore down handle B, which had also been aliased to slot 0.
        r2_st, r2_body = _read(s, fh_b, 0, 100, b"\x00\x12")
        results.append(
            (r2_st == 0 and len(r2_body) == 100, "peer handle survives close of the other"),
        )
    finally:
        s.close()


def _check_big_read(origin_root: Path, port: int, results: list[tuple[bool, str]]) -> None:
    expected = (origin_root / "reg_big.bin").read_bytes()
    s = _session(port)
    try:
        st, fh = _open(s, b"/reg_big.bin", kXR_open_read, b"\x00\x21")
        if st != 0:
            results.append((False, "open big.bin for read"))
            return
        got = _read_whole(s, fh, len(expected), b"\x00\x21")
        _close(s, fh, b"\x00\x21")
        results.append((got == expected, "multi-MiB driver read byte-exact"))
    finally:
        s.close()


def _check_remote_mkdir(origin_root: Path, port: int, results: list[tuple[bool, str]]) -> None:
    s = _session(port)
    try:
        st = _mkdir(s, b"/regdir/a/b/c", 0o755, b"\x00\x31")
    finally:
        s.close()
    landed = (origin_root / "regdir" / "a" / "b" / "c").is_dir()
    results.append((st == 0 and landed, "explicit mkdir -p lands on remote origin"))


def _check_staged_subdir_write(origin_root: Path, port: int, results: list[tuple[bool, str]]) -> None:
    data = deterministic_bytes(120_000, 7)
    s = _session(port)
    try:
        st, fh = _open(s, b"/regw/deep/nest/file.bin", WRITE_OPTS, b"\x00\x41")
        if st != 0:
            results.append((False, "open staged write to nested subdir"))
            return
        w_st = _write(s, fh, 0, data, b"\x00\x41")
        c_st = _close(s, fh, b"\x00\x41")
        results.append((w_st == 0 and c_st == 0, "staged write + POSC close ok"))
    finally:
        s.close()
    dst = origin_root / "regw" / "deep" / "nest" / "file.bin"
    landed = False
    for _ in range(20):  # sync flush, but tolerate a brief commit delay
        if dst.exists() and dst.read_bytes() == data:
            landed = True
            break
        time.sleep(0.1)
    results.append((landed, "staged write to nested subdir lands byte-exact on origin"))


def _check_stat_directory(port: int, results: list[tuple[bool, str]]) -> None:
    """Keystone guard: a real kXR_stat (by name) over root:// must describe a
    DIRECTORY with the isDir flag — the old stat-by-open returned
    kXR_isDirectory→EISDIR and could never represent a dir, breaking isdir/mv.
    A regular file must stat with isDir CLEAR (discrimination)."""
    s = _session(port)
    try:
        # /regdir/a/b/c was created on the origin by _check_remote_mkdir.
        st_d, flags_d = _stat_over_gateway(s, b"/regdir/a/b", b"\x00\x51")
        results.append(
            (st_d == kXR_ok and flags_d is not None and (flags_d & kXR_isDir),
             "stat of a directory over root:// reports isDir"),
        )
        st_f, flags_f = _stat_over_gateway(s, b"/reg_small.bin", b"\x00\x52")
        results.append(
            (st_f == kXR_ok and flags_f is not None and not (flags_f & kXR_isDir),
             "stat of a file over root:// reports NOT isDir"),
        )
    finally:
        s.close()


def _check_statx(port: int, results: list[tuple[bool, str]]) -> None:
    """statx must route through the backend (not the empty local export). A
    statx of an existing origin file returns kXR_ok with one flag byte; a
    missing path still errors (no silent leak)."""
    s = _session(port)
    try:
        s.sendall(H.make_request(b"\x00\x53", kXR_statx,
                                 payload=b"/reg_small.bin\x00"))
        st_ok, body_ok = H._recv_response(s)
        results.append((st_ok == kXR_ok and len(body_ok) >= 1,
                        "statx of an existing file over root:// returns ok"))
        s.sendall(H.make_request(b"\x00\x54", kXR_statx,
                                 payload=b"/does_not_exist.bin\x00"))
        st_miss, _ = H._recv_response(s)
        results.append((st_miss != kXR_ok,
                        "statx of a missing path over root:// still errors"))
    finally:
        s.close()


def _check_locate(port: int, results: list[tuple[bool, str]]) -> None:
    """locate must probe existence via the backend. A locate of an existing
    origin file returns kXR_ok (before the fix it answered kXR_NotFound because
    it stat'd the empty local export)."""
    s = _session(port)
    try:
        s.sendall(H.make_request(b"\x00\x55", kXR_locate,
                                 payload=b"/reg_small.bin\x00"))
        st, _ = H._recv_response(s)
        results.append((st == kXR_ok,
                        "locate of an existing file over root:// returns ok"))
    finally:
        s.close()


def _check_mv(origin_root: Path, port: int,
              results: list[tuple[bool, str]]) -> None:
    """mv must reach the driver rename. Before the fix the destination-parent
    WRITE probe opened the parent dir (→EISDIR) and mv failed "invalid
    destination path"; with a real dir-aware stat the probe passes and
    sd_xroot_rename runs. Verify the file moved on the origin."""
    (origin_root / "reg_mv_src.bin").write_bytes(deterministic_bytes(64, 11))
    s = _session(port)
    try:
        src, dst = b"/reg_mv_src.bin", b"/reg_mv_dst.bin"
        body = b"\x00" * 14 + struct.pack(">h", len(src))   # reserved[14] arg1len
        s.sendall(H.make_request(b"\x00\x56", kXR_mv, body, src + b" " + dst))
        st, _ = H._recv_response(s)
        results.append((st == kXR_ok,
                        "mv (rename) over root:// returns ok"))
    finally:
        s.close()
    moved = ((origin_root / "reg_mv_dst.bin").exists()
             and not (origin_root / "reg_mv_src.bin").exists())
    results.append((moved, "mv landed on the origin (dst present, src gone)"))


def _check_truncate(origin_root: Path, port: int,
                    results: list[tuple[bool, str]]) -> None:
    """truncate must resize the origin object BY PATH (no staged write-open).
    Before the fix, kXR_truncate over the auto write-stage tier opened a staged
    write handle whose commit re-opened the origin and self-collided → the client
    saw kXR_Unsupported. A path-native kXR_truncate (dlen>0, path payload) resizes
    the origin in one round-trip. Verify both shrink and grow land on the origin."""
    tf = origin_root / "reg_trunc.bin"
    tf.write_bytes(deterministic_bytes(64, 41))

    # shrink 64 -> 4
    s = _session(port)
    try:
        body = b"\x00" * 4 + struct.pack(">q", 4) + b"\x00" * 4   # fhandle,off,resv
        s.sendall(H.make_request(b"\x00\x57", kXR_truncate, body,
                                 b"/reg_trunc.bin\x00"))
        st, _ = H._recv_response(s)
        results.append((st == kXR_ok,
                        "truncate (shrink) over root:// returns ok"))
    finally:
        s.close()
    results.append((tf.stat().st_size == 4,
                    "truncate shrank the origin file to 4 bytes"))

    # grow 4 -> 100
    s = _session(port)
    try:
        body = b"\x00" * 4 + struct.pack(">q", 100) + b"\x00" * 4
        s.sendall(H.make_request(b"\x00\x58", kXR_truncate, body,
                                 b"/reg_trunc.bin\x00"))
        st, _ = H._recv_response(s)
        results.append((st == kXR_ok,
                        "truncate (grow) over root:// returns ok"))
    finally:
        s.close()
    results.append((tf.stat().st_size == 100,
                    "truncate grew the origin file to 100 bytes"))


def _check_chmod(origin_root: Path, port: int,
                 results: list[tuple[bool, str]]) -> None:
    """§4.6: chmod over the gateway must forward kXR_chmod to the origin and
    change its on-disk mode. Before the sd_xroot .setattr slot existed,
    brix_vfs_chmod saw a NULL setattr slot and returned a SILENT no-op success —
    the client got kXR_ok but the origin file's mode never changed. Verify both
    the wire ok AND the mode actually landed on the origin."""
    tf = origin_root / "reg_chmod.bin"
    tf.write_bytes(deterministic_bytes(64, 61))
    os.chmod(tf, 0o644)

    s = _session(port)
    try:
        # ClientChmodRequest: reserved[14] mode(BE16) dlen path.
        body = b"\x00" * 14 + struct.pack(">H", 0o600)
        s.sendall(H.make_request(b"\x00\x59", kXR_chmod, body,
                                 b"/reg_chmod.bin\x00"))
        st, _ = H._recv_response(s)
        results.append((st == kXR_ok, "chmod over root:// returns ok"))
    finally:
        s.close()
    landed = (tf.stat().st_mode & 0o777) == 0o600
    results.append((landed,
                    "chmod landed on the origin (mode is now 0600)"))

    # error path: chmod of a MISSING origin path must surface the origin's
    # error, not the old silent-no-op false success.
    s = _session(port)
    try:
        body = b"\x00" * 14 + struct.pack(">H", 0o600)
        s.sendall(H.make_request(b"\x00\x5a", kXR_chmod, body,
                                 b"/reg_chmod_absent.bin\x00"))
        st, _ = H._recv_response(s)
        results.append((st != kXR_ok,
                        "chmod of a missing origin path is refused"))
    finally:
        s.close()


def _query_info(port: int, infotype: int, arg: bytes,
                sid: bytes) -> tuple[int, bytes]:
    """kXR_query/<infotype> for `arg` on a fresh gateway session. The gateway
    runs a thread pool, so the answer may arrive async: absorb kXR_waitresp and
    unwrap the kXR_attn(asynresp) frame (actnum[4] reserved[4] inner-hdr[8]
    inner-body) exactly as a stock client does. Returns (status, body)."""
    kXR_query, kXR_attn, kXR_waitresp = 3001, 4001, 4006
    s = _session(port)
    try:
        body = struct.pack(">H", infotype) + b"\x00" * 14
        s.sendall(H.make_request(sid, kXR_query, body, arg + b"\x00"))
        for _ in range(8):
            status, resp = H._recv_response(s)
            if status == kXR_waitresp:
                continue
            if status == kXR_attn:
                if len(resp) >= 16:
                    return struct.unpack(">H", resp[10:12])[0], resp[16:]
                continue
            return status, resp
        return -1, b""
    finally:
        s.close()


def _query_cksum(port: int, arg: bytes, sid: bytes) -> tuple[int, bytes]:
    return _query_info(port, 3, arg, sid)   # kXR_Qcksum


def _query_space(port: int, arg: bytes, sid: bytes) -> tuple[int, bytes]:
    return _query_info(port, 5, arg, sid)   # kXR_Qspace


def _log_matches(log: Path, needle: str) -> list[str]:
    if not log.exists():
        return []
    text = log.read_text(encoding="utf-8", errors="replace")
    return [line for line in text.splitlines() if needle in line]


def _origin_log_lines(origin_prefix: Path, needle: str,
                      wait_for: str = "") -> list[str]:
    """Lines of the origin access log naming `needle`. The log is written
    through a per-worker buffer, so when `wait_for` is given, poll briefly
    until a matching line containing it has flushed (bounded, never fails —
    the caller's assertion decides)."""
    log = origin_prefix / "logs" / "access.log"
    lines: list[str] = []
    for _ in range(50):
        lines = _log_matches(log, needle)
        if not wait_for or any(wait_for in line for line in lines):
            break
        time.sleep(0.1)
    return lines


def _cksum_offload_success(origin_prefix: Path, port: int, data: bytes,
                           results: list[tuple[bool, str]]) -> None:
    """Default alg (adler32) served from the origin digest, with zero reads."""
    import zlib

    st, resp = _query_cksum(port, b"/reg_cksum.bin", b"\x00\x61")
    text = resp.rstrip(b"\x00").decode("ascii", "replace")
    want = f"adler32 {zlib.adler32(data) & 0xffffffff:08x}"
    results.append((st == kXR_ok and text == want,
                    "gateway Qcksum (default alg) returns the origin digest"))
    queried = _origin_log_lines(origin_prefix, "reg_cksum.bin",
                                wait_for="cksum")
    results.append(
        (any("cksum" in line for line in queried)
         and not any("READ" in line for line in queried),
         "offloaded Qcksum queried the origin without reading bytes"),
    )


def _cksum_offload_fallback(origin_prefix: Path, port: int, data: bytes,
                            results: list[tuple[bool, str]]) -> None:
    """Origin advertises adler32 only → md5 must be computed from the bytes."""
    import hashlib

    st, resp = _query_cksum(port, b"/reg_cksum.bin?cks.type=md5", b"\x00\x62")
    text = resp.rstrip(b"\x00").decode("ascii", "replace")
    want = f"md5 {hashlib.md5(data).hexdigest()}"
    results.append((st == kXR_ok and text == want,
                    "non-origin algorithm falls back to compute correctly"))
    after = _origin_log_lines(origin_prefix, "reg_cksum.bin",
                              wait_for="READ")
    results.append((any("READ" in line for line in after),
                    "compute fallback read the object bytes from the origin"))


def _check_cksum_offload(origin_prefix: Path, port: int,
                         results: list[tuple[bool, str]]) -> None:
    """Checksum offload (driver query_checksum slot). A default-algorithm
    Qcksum through the gateway must be answered from the origin's OWN digest —
    witnessed in the origin access log as a cksum QUERY with ZERO reads of the
    file (success). A non-default algorithm the origin does not advertise must
    fall back to the byte-reading compute and still answer correctly, now WITH
    origin reads (error/fallback). A missing path and a traversal path must
    error, never fabricate a digest (security-neg)."""
    data = deterministic_bytes(300_000, 37)
    (origin_prefix / "root" / "reg_cksum.bin").write_bytes(data)

    _cksum_offload_success(origin_prefix, port, data, results)
    _cksum_offload_fallback(origin_prefix, port, data, results)

    # security-neg: no digest for a missing path or a traversal attempt
    st_miss, _ = _query_cksum(port, b"/reg_cksum_missing.bin", b"\x00\x63")
    st_esc, _ = _query_cksum(port, b"/../../etc/passwd", b"\x00\x64")
    results.append((st_miss != kXR_ok and st_esc != kXR_ok,
                    "Qcksum errors on missing and traversal paths"))


def _parse_oss(resp: bytes) -> dict[str, int]:
    """The oss.* key=value report ("&"- or space-joined) as an int dict."""
    out: dict[str, int] = {}
    text = resp.rstrip(b"\x00").decode("ascii", "replace")
    for part in text.replace("&", " ").split():
        key, _, val = part.partition("=")
        if val.lstrip("-").isdigit():
            out[key] = int(val)
    return out


def _check_space_delegation(origin_prefix: Path, port: int,
                            results: list[tuple[bool, str]]) -> None:
    """Space delegation (driver `space` slot). A Qspace through the gateway
    must be answered with the ORIGIN's capacity — witnessed in the origin
    access log as a space QUERY (success). An empty/relative path must be
    rejected on the gateway before any backend call (security-neg). The
    origin-down fallback leg runs last in run_checks (_check_space_fallback)."""
    st, resp = _query_space(port, b"/", b"\x00\x71")
    oss = _parse_oss(resp)
    ok = (st == kXR_ok and oss.get("oss.space", 0) > 0
          and 0 < oss.get("oss.free", 0) <= oss["oss.space"])
    results.append((ok, "gateway Qspace reports origin-derived totals"))
    queried = _origin_log_lines(origin_prefix, "space", wait_for="QUERY")
    results.append((any("QUERY" in line for line in queried),
                    "gateway Qspace delegated to the origin (origin QUERY space logged)"))

    st_neg, _ = _query_space(port, b"", b"\x00\x72")
    results.append((st_neg != kXR_ok,
                    "gateway Qspace rejects an empty (relative) path"))


def _check_space_fallback(origin_prefix: Path, origin_port: int, port: int,
                          results: list[tuple[bool, str]]) -> None:
    """Origin down → the driver `space` slot fails and the gateway must fall
    back to local statvfs, still answering kXR_ok. DESTRUCTIVE (stops the
    origin): must be the LAST check; the run_checks finally-block re-stop is a
    no-op."""
    stop_nginx(origin_prefix)
    for _ in range(50):
        try:
            with socket.create_connection((HOST, origin_port), timeout=0.5):
                pass
        except OSError:
            break
        time.sleep(0.1)

    st, resp = _query_space(port, b"/", b"\x00\x73")
    oss = _parse_oss(resp)
    results.append((st == kXR_ok and oss.get("oss.space", 0) > 0,
                    "gateway Qspace falls back to local statvfs when the origin is down"))


def run_checks(base: Path, nginx_bin: str = NGINX_BIN) -> list[tuple[bool, str]]:
    origin_port, gw_port = cmdscript_ports("xroot_gateway_regress", 2)
    origin = base / "o"
    gateway = base / "g"
    origin_conf = write_origin_config(origin, origin_port)
    gw_conf = write_gateway_config(gateway, gw_port, origin_port)

    origin_root = origin / "root"
    (origin_root / "reg_small.bin").write_bytes(deterministic_bytes(600_000, 23))
    (origin_root / "reg_big.bin").write_bytes(deterministic_bytes(2_800_000, 29))

    started: list[Path] = []
    for name, prefix, conf in (
        ("origin", origin, origin_conf),
        ("gateway", gateway, gw_conf),
    ):
        result = run([nginx_bin, "-p", str(prefix), "-c", str(conf)])
        if result.returncode != 0:
            for item in reversed(started):
                stop_nginx(item)
            return [(False, f"{name} start failed: {(result.stderr or result.stdout)[-4000:]}")]
        started.append(prefix)

    try:
        time.sleep(1)
        results: list[tuple[bool, str]] = []
        _check_concurrent_handles(gw_port, results)
        _check_big_read(origin_root, gw_port, results)
        _check_remote_mkdir(origin_root, gw_port, results)
        _check_staged_subdir_write(origin_root, gw_port, results)
        # Remote-metadata gap regressions (keystone kXR_stat + routed handlers).
        # _check_stat_directory relies on /regdir created by _check_remote_mkdir.
        _check_stat_directory(gw_port, results)
        _check_statx(gw_port, results)
        _check_locate(gw_port, results)
        _check_mv(origin_root, gw_port, results)
        _check_truncate(origin_root, gw_port, results)
        _check_chmod(origin_root, gw_port, results)
        # Checksum offload (driver query_checksum slot) — needs the origin
        # access log written by write_origin_config for its read/query witness.
        _check_cksum_offload(origin, gw_port, results)
        # Space delegation (driver space slot) — same access-log witness. The
        # fallback leg STOPS the origin, so it must stay last.
        _check_space_delegation(origin, gw_port, results)
        _check_space_fallback(origin, origin_port, gw_port, results)
        return results
    finally:
        for prefix in reversed(started):
            stop_nginx(prefix)


def entry(argv: list[str]) -> int:
    nginx_bin = argv[0] if argv else NGINX_BIN
    import tempfile

    with tempfile.TemporaryDirectory(prefix="xroot_gw_regress.") as tmp:
        results = run_checks(Path(tmp), nginx_bin=nginx_bin)
    return print_results(results, "run_xroot_gateway_regress")


if __name__ == "__main__":
    from cmdscripts import main

    raise SystemExit(main(entry))
