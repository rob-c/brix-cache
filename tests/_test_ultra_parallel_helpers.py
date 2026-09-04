"""
tests/_test_ultra_parallel_helpers.py

Shared machinery for the ultra-parallel breaking-point storm suites:

  * test_ultra_parallel_breaking_point.py — the single-shape FTS-job ladder;
  * test_ultra_parallel_mixed_storm.py   — 16k-wide MIXED metadata+transfer
                                           storms.

Contents: raw-wire FTS-shaped jobs (framing mirrors test_fsoverload_stall.py),
the outcome classification that IS the graceful-degradation contract, rung
accounting, and the BriX / official-xrootd subjects on identical payloads.

Outcome classes: served (byte-verified) / throttled (kXR_wait — the protocol
backoff FTS honors) / refused (broken before login completed — clean
admission-time shedding) / errored (an ESTABLISHED session was broken: the
fall-over signal).  A rung "breaks" a server only when errored exceeds
max(3, 1% of dispatched).
"""

import functools
import os
import random
import resource
import shutil
import socket
import struct
import subprocess
import time

import pytest

from settings import HOST, BIND_HOST
from server_registry import NginxInstanceSpec
from _test_metadata_stress_helpers import _pct

kXR_close, kXR_protocol, kXR_login = 3003, 3006, 3007
kXR_open, kXR_read, kXR_stat = 3010, 3013, 3017
kXR_ok, kXR_oksofar, kXR_wait = 0, 4000, 4005

OP_TIMEOUT = float(os.environ.get("ULTRA_OP_TIMEOUT", "20"))

STORM_SIZE = 1 << 20        # the single-shape ladder's transfer payload
VICTIM_SIZE = 4 << 20       # the fairness victim's file
MIX_SIZE = 64 << 10         # the mixed storm's transfer payload (16k-wide)

XROOTD = shutil.which("xrootd")


@functools.lru_cache(maxsize=None)
def _blob(size, seed):
    """Deterministic payload; lazy so PR-tier collection never pays for it."""
    return random.Random(seed).randbytes(size)


def _storm_blob():
    return _blob(STORM_SIZE, 0xF75)


def _victim_blob():
    return _blob(VICTIM_SIZE, 0xB0B)


def _mix_blob():
    return _blob(MIX_SIZE, 0x171)


# --------------------------------------------------------------------------- #
# Outcome classes.  The classification IS the contract: kXR_wait and a
# pre-login refusal are CLEAN degradation; anything that breaks an
# established session is the fall-over signal.
# --------------------------------------------------------------------------- #

class _Shed(Exception):
    """Server answered kXR_wait — clean protocol backoff; the job retries."""


class _Refused(Exception):
    """Refused/reset before login completed — clean admission-time shedding."""


class _Dirty(Exception):
    """An established session was broken — the graceful-degradation failure."""


# --------------------------------------------------------------------------- #
# Raw-wire FTS job                                                             #
# --------------------------------------------------------------------------- #

def _recv_exact(s, n):
    buf = b""
    while len(buf) < n:
        chunk = s.recv(n - len(buf))
        if not chunk:
            raise _Dirty("connection closed mid-frame")
        buf += chunk
    return buf


def _send(s, streamid, reqid, body=b"", payload=b""):
    hdr = streamid + struct.pack("!H", reqid)
    hdr += body.ljust(16, b"\x00") + struct.pack("!I", len(payload))
    s.sendall(hdr + payload)


def _resp(s):
    hdr = _recv_exact(s, 8)
    status = struct.unpack("!H", hdr[2:4])[0]
    dlen = struct.unpack("!I", hdr[4:8])[0]
    body = _recv_exact(s, dlen) if dlen else b""
    if status == kXR_wait:
        raise _Shed("kXR_wait")
    return status, body


def _expect_ok(s, what):
    status, body = _resp(s)
    if status not in (kXR_ok, kXR_oksofar):
        raise _Dirty(f"{what}: status {status}")
    return status, body


def _login(port, src=None):
    """Fresh session: connect + handshake + kXR_login.  Anything broken before
    login-OK is admission-time shedding (_Refused), not a dirty failure.
    `src` optionally pins the SOURCE address — the 16k-wide storms spread
    clients over 127.0.0.2-9 so the 4-tuple space (and the client-side
    TIME_WAIT budget) never becomes the bottleneck under test."""
    try:
        s = socket.create_connection(
            (HOST, port), timeout=OP_TIMEOUT,
            source_address=(src, 0) if src else None)
    except OSError as exc:
        raise _Refused(f"connect: {exc}") from exc
    s.settimeout(OP_TIMEOUT)
    try:
        s.sendall(struct.pack("!IIIII", 0, 0, 0, 4, 2012))
        status, _ = _resp(s)
        if status != kXR_ok:
            raise _Dirty(f"handshake: status {status}")
        body = b"\x00" * 13 + b"\x04\x00\x00"
        _send(s, b"\x00\x01", kXR_login, body=body, payload=b"anonymous\x00")
        status, _ = _resp(s)
        if status != kXR_ok:
            raise _Dirty(f"login: status {status}")
        return s
    except _Shed:
        s.close()
        raise
    except (_Dirty, OSError) as exc:
        s.close()
        raise _Refused(f"pre-login: {exc}") from exc


def _op_stat(s, path):
    _send(s, b"\x00\x04", kXR_stat, body=b"\x00" * 16,
          payload=path.encode() + b"\x00")
    _expect_ok(s, "stat")


def _op_open_read(s, path):
    # ClientOpenRequest: mode(2) options(2) reserved(12); options 0 = read.
    _send(s, b"\x00\x01", kXR_open,
          body=struct.pack("!HH", 0, 0) + b"\x00" * 12,
          payload=path.encode() + b"\x00")
    _st, body = _expect_ok(s, "open")
    if len(body) < 4:
        raise _Dirty("open: short fhandle")
    return body[:4]


def _op_read_all(s, fh, offset, size):
    _send(s, b"\x00\x02", kXR_read, body=fh + struct.pack("!qi", offset, size))
    buf = b""
    while True:
        status, body = _expect_ok(s, "read")
        buf += body
        if status == kXR_ok:
            return buf


def _op_close(s, fh):
    _send(s, b"\x00\x03", kXR_close, body=fh)
    _expect_ok(s, "close")


def _verify_payload(buf, ref, what):
    if len(buf) != len(ref) or buf[:16] != ref[:16] or buf[-16:] != ref[-16:]:
        raise _Dirty(f"{what}: payload mismatch ({len(buf)}/{len(ref)} bytes)")


def _fts_job(port, path, ref, src=None):
    """One FTS-shaped transfer: connect+login+stat+open+read+close."""
    s = _login(port, src)
    try:
        _op_stat(s, path)
        fh = _op_open_read(s, path)
        _verify_payload(_op_read_all(s, fh, 0, len(ref)), ref, "read")
        _op_close(s, fh)
    finally:
        s.close()


def _outcome(fn):
    """Run one job callable and classify it under the contract."""
    started = time.perf_counter()
    try:
        fn()
        return "served", time.perf_counter() - started, ""
    except _Shed as exc:
        return "throttled", 0.0, str(exc)
    except _Refused as exc:
        return "refused", 0.0, str(exc)
    except (_Dirty, OSError) as exc:
        return "errored", 0.0, f"{type(exc).__name__}: {exc}"


def _job_outcome(port, path, ref):
    return _outcome(lambda: _fts_job(port, path, ref))


# --------------------------------------------------------------------------- #
# Rung accounting                                                              #
# --------------------------------------------------------------------------- #

def _empty_rung(n):
    return {"n": n, "served": 0, "throttled": 0, "refused": 0, "errored": 0,
            "lat": [], "err": [], "wall": 0.0}


def _merge_rung(row, res):
    for key in ("served", "throttled", "refused", "errored"):
        row[key] += res[key]
    row["lat"].extend(res["lat"])
    row["err"].extend(res["err"][:3])


def _dispatched(row):
    return row["served"] + row["throttled"] + row["refused"] + row["errored"]


def _dirty_tol(row):
    return max(3, _dispatched(row) // 100)


def _breaking_rung(rows):
    for row in rows:
        if row["errored"] > _dirty_tol(row) or row.get("died"):
            return row["n"]
    return None


def _print_table(label, rows, jobs):
    print(f"\n[{label}] jobs/rung = n x {jobs}")
    print("   n  served throttl refused errored  jobs/s   p50ms   p99ms")
    for r in rows:
        rate = _dispatched(r) / r["wall"] if r["wall"] else 0.0
        died = "  DIED" if r.get("died") else ""
        print(f"{r['n']:5d}  {r['served']:6d} {r['throttled']:7d} "
              f"{r['refused']:7d} {r['errored']:7d} {rate:7.1f} "
              f"{_pct(r['lat'], 0.5) * 1000:7.1f} "
              f"{_pct(r['lat'], 0.99) * 1000:7.1f}{died}", flush=True)
        for e in r["err"][:3]:
            print(f"      dirty: {e}")


def _server_alive(port):
    try:
        s = _login(port)
        try:
            _op_stat(s, "/storm.bin")
        finally:
            s.close()
        return True
    except Exception:
        return False


def _victim_reads_stay_clean(victim, fh):
    """Sequential chunked reads on the pre-storm session: each byte-exact and
    inside the op deadline, or the storm has starved an established session."""
    ref, chunk = _victim_blob(), 256 * 1024
    for i in range(0, VICTIM_SIZE, chunk):
        started = time.perf_counter()
        buf = _op_read_all(victim, fh, i, chunk)
        elapsed = time.perf_counter() - started
        assert buf == ref[i:i + chunk], \
            f"victim read at {i} corrupted under storm"
        assert elapsed < OP_TIMEOUT, \
            f"victim read at {i} starved: {elapsed:.1f}s"


def _raise_nofile(want):
    """Raise the soft fd limit toward `want`; returns the usable CLIENT
    budget (soft minus harness slack).  A hard limit below the top rung
    clamps the ladder rather than failing it."""
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    if soft < want:
        resource.setrlimit(resource.RLIMIT_NOFILE, (min(want, hard), hard))
        soft = resource.getrlimit(resource.RLIMIT_NOFILE)[0]
    return max(0, soft - 512)


# --------------------------------------------------------------------------- #
# Subjects                                                                     #
# --------------------------------------------------------------------------- #

def _seed(tmp_path):
    data = tmp_path / "data"
    data.mkdir(exist_ok=True)
    (data / "storm.bin").write_bytes(_storm_blob())
    (data / "victim.bin").write_bytes(_victim_blob())
    (data / "mix.bin").write_bytes(_mix_blob())
    return data


def _start(lifecycle, tmp_path, rl_zone="", rl_rule=""):
    data = _seed(tmp_path)
    ep = lifecycle.start(NginxInstanceSpec(
        name="lc-ultra-parallel",
        template="nginx_lc_ultra_parallel.conf",
        protocol="root",
        template_values={"BIND_HOST": BIND_HOST, "DATA_DIR": str(data),
                         "RL_ZONE": rl_zone, "RL_RULE": rl_rule},
        reason="ultra-parallel FTS-storm breaking point"))
    return ep.port


def _launch_stock(root, port):
    data = _seed(root)
    admin = root / "admin"
    admin.mkdir()
    cfg = root / "xrootd.cfg"
    cfg.write_text(f"xrd.port {port}\nall.adminpath {admin}\n"
                   f"all.pidpath {admin}\noss.localroot {data}\n"
                   f"all.export /\nxrd.network nodnr\n")
    return subprocess.Popen([XROOTD, "-c", str(cfg), "-l",
                             str(root / "xrootd.log")],
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL)


def _await_stock_up(proc, port):
    for _ in range(50):
        if _server_alive(port):
            return
        if proc.poll() is not None:
            pytest.skip("official xrootd failed to start")
        time.sleep(0.2)
    pytest.skip("official xrootd did not start listening in time")


@pytest.fixture()
def stock_xrootd(tmp_path_factory):
    """An official xrootd on the same payloads, drawing a mock-range port.
    The fd limit is raised BEFORE the spawn so the daemon inherits headroom
    for the widest rung (xrootd sizes its connection table from the rlimit)."""
    if XROOTD is None:
        pytest.skip("official `xrootd` not installed")
    from ephemeral_port import free_port
    _raise_nofile(65536)
    root = tmp_path_factory.mktemp("ultrastock")
    port = free_port(BIND_HOST)
    proc = _launch_stock(root, port)
    try:
        _await_stock_up(proc, port)
        yield port
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
