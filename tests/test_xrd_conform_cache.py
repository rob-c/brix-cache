"""Controlled paired cache/origin fixtures for Phase-118 CAC probes."""
import hashlib
import json
import struct
import subprocess

import pytest

from _test_phase115_pgread_verify_helpers import (
    PgOrigin, error_frame, kXR_close, kXR_open, kXR_query, kXR_read,
    kXR_rm, kXR_stat, kXR_write, ok_frame,
)
from settings import HOST
from test_xrd_conform_http_semantics import XRD, _clean_environment


PAYLOAD = bytes((index * 17 + 3) & 0xFF for index in range(8192))
kXR_prepare = 3021
kXR_Unsupported = 3013
kXR_delete = 0x0002
kXR_open_updt = 0x0020
kXR_evict = 0x0001
kXR_fresh = 0x40


class CacheOrigin(PgOrigin):
    """Serve bytes plus the SHA-256 query required by the cache assessor."""

    def __init__(self, payload, corrupt_read=None, read_error=None):
        self.corrupt_read = corrupt_read
        self.read_error = read_error
        super().__init__(payload, behaviour="ok")

    def _read(self, conn, sid, hdr, request_args=b""):
        with self._lock:
            self.reads += 1
            sequence = self.reads
        if self.read_error is not None:
            conn.sendall(error_frame(sid, self.read_error, b"fixture refusal"))
            return
        offset, rlen = struct.unpack("!qi", hdr[8:20])
        payload = self.payload
        if self.corrupt_read == sequence and payload:
            payload = bytes([payload[0] ^ 0xFF]) + payload[1:]
        conn.sendall(ok_frame(
            sid, payload[offset:offset + max(rlen, 0)],
        ))

    def _dispatch(self, conn, sid, reqid, hdr, body=b"",
                  authenticated=False):
        if reqid == kXR_query:
            digest = hashlib.sha256(self.payload).hexdigest().encode("ascii")
            conn.sendall(ok_frame(sid, b"sha256 " + digest))
            return authenticated
        return super()._dispatch(
            conn, sid, reqid, hdr, body, authenticated,
        )


class EvictOrigin(PgOrigin):
    """Mutable path store used as the authoritative eviction origin."""

    def __init__(self):
        self.objects = {}
        self.handles = {}
        self.current_path = None
        super().__init__(b"", behaviour="ok")

    def get(self, path):
        with self._lock:
            return self.objects.get(path)

    def _dispatch(self, conn, sid, reqid, hdr, body=b"",
                  authenticated=False):
        handlers = {
            kXR_open: self._open,
            kXR_write: self._write,
            kXR_read: self._read_object,
            kXR_stat: self._stat,
            kXR_rm: self._remove,
            kXR_close: self._ack,
        }
        handler = handlers.get(reqid)
        if handler is None:
            return super()._dispatch(
                conn, sid, reqid, hdr, body, authenticated,
            )
        handler(conn, sid, hdr, body)
        return authenticated or reqid == 3007

    def _open(self, conn, sid, hdr, body):
        key = conn.fileno()
        path = body.decode("utf-8")
        options = struct.unpack("!H", hdr[6:8])[0]
        with self._lock:
            if options & kXR_open_updt and options & kXR_delete:
                self.objects[path] = b""
            self.handles[key] = path
            self.current_path = path
        conn.sendall(ok_frame(sid, struct.pack("!I", 7) + b"\x00" * 8))

    def _write(self, conn, sid, hdr, body):
        key = conn.fileno()
        offset = struct.unpack("!q", hdr[8:16])[0]
        with self._lock:
            path = self.handles.get(key, self.current_path)
            current = bytearray(self.objects.get(path, b""))
            end = offset + len(body)
            if len(current) < end:
                current.extend(b"\x00" * (end - len(current)))
            current[offset:end] = body
            self.objects[path] = bytes(current)
        conn.sendall(ok_frame(sid))

    def _read_object(self, conn, sid, hdr, _body):
        key = conn.fileno()
        offset, length = struct.unpack("!qi", hdr[8:20])
        with self._lock:
            path = self.handles.get(key, self.current_path)
            data = self.objects.get(path, b"")
        conn.sendall(ok_frame(sid, data[offset:offset + max(length, 0)]))

    def _stat(self, conn, sid, _hdr, body):
        data = self.get(body.decode("utf-8"))
        if data is None:
            conn.sendall(error_frame(sid, 3011, b"not found"))
            return
        conn.sendall(ok_frame(sid, b"0 %d 0 0\x00" % len(data)))

    def _remove(self, conn, sid, _hdr, body):
        with self._lock:
            self.objects.pop(body.decode("utf-8"), None)
        conn.sendall(ok_frame(sid))

    @staticmethod
    def _ack(conn, sid, _hdr, _body):
        conn.sendall(ok_frame(sid))


class EvictCache(PgOrigin):
    """Read-through cache that can evict, refuse, or retain stale bytes."""

    def __init__(self, origin, behaviour="evict"):
        self.origin = origin
        self.cache = {}
        self.handles = {}
        self.current_path = None
        self.evict_behaviour = behaviour
        self.prepare_seen = False
        super().__init__(b"", behaviour="ok")

    def _dispatch(self, conn, sid, reqid, hdr, body=b"",
                  authenticated=False):
        handlers = {
            kXR_open: self._open,
            kXR_read: self._read_cached,
            kXR_prepare: self._prepare,
            kXR_close: self._ack,
        }
        handler = handlers.get(reqid)
        if handler is None:
            return super()._dispatch(
                conn, sid, reqid, hdr, body, authenticated,
            )
        handler(conn, sid, hdr, body)
        return authenticated or reqid == 3007

    def _open(self, conn, sid, _hdr, body):
        with self._lock:
            self.current_path = body.decode("utf-8")
            self.handles[conn.fileno()] = self.current_path
        conn.sendall(ok_frame(sid, struct.pack("!I", 7) + b"\x00" * 8))

    def _read_cached(self, conn, sid, hdr, _body):
        offset, length = struct.unpack("!qi", hdr[8:20])
        with self._lock:
            path = self.handles.get(conn.fileno(), self.current_path)
            if path not in self.cache:
                self.cache[path] = self.origin.get(path) or b""
            data = self.cache[path]
        conn.sendall(ok_frame(sid, data[offset:offset + max(length, 0)]))

    def _prepare(self, conn, sid, hdr, body):
        self.prepare_seen = True
        options = hdr[4]
        option_x = struct.unpack("!H", hdr[8:10])[0]
        if options & kXR_fresh:
            self._prepare_fresh(conn, sid, body)
            return
        if self.evict_behaviour == "refuse" or option_x != kXR_evict:
            conn.sendall(error_frame(
                sid, kXR_Unsupported, b"eviction unsupported",
            ))
            return
        self._evict_path(body, retain=self.evict_behaviour == "stale")
        conn.sendall(ok_frame(sid))

    def _prepare_fresh(self, conn, sid, body):
        if self.evict_behaviour == "fresh_refuse":
            conn.sendall(error_frame(
                sid, kXR_Unsupported, b"fresh unsupported",
            ))
            return
        self._evict_path(body, retain=self.evict_behaviour == "fresh_stale")
        conn.sendall(ok_frame(sid))

    def _evict_path(self, body, retain):
        if retain:
            return
        with self._lock:
            self.cache.pop(body.decode("utf-8"), None)

    @staticmethod
    def _ack(conn, sid, _hdr, _body):
        conn.sendall(ok_frame(sid))


def _require_xrd():
    if not XRD.exists():
        pytest.skip(f"native xrd client is not built: {XRD}")


def _extend_cache_origin(command, origin):
    if origin is not None:
        command.extend(["--also", f"root://{HOST}:{origin.port}//fixture"])


def _extend_verification(command, verify):
    for clause in verify:
        command.extend(["--verify-negative", clause])


def _run_pair(tmp_path, cache, origin=None, verify=()):
    _require_xrd()
    output = tmp_path / "report"
    target = f"root://{HOST}:{cache.port}//fixture"
    command = [
        str(XRD), "conform", "accept", target,
        "--profile", "cache", "--families", "CAC",
        "--budget", "boundary", "--fail-on", "divergent",
        "--wall-seconds", "30", "--request-limit", "4096",
        "--byte-limit", "67108864", "--out", str(output),
    ]
    _extend_cache_origin(command, origin)
    _extend_verification(command, verify)
    result = subprocess.run(
        command, text=True, capture_output=True, timeout=45,
        env=_clean_environment(), check=False,
    )
    report = json.loads((output / "report.json").read_text(encoding="utf-8"))
    return result, {row["id"]: row for row in report["results"]}


def _run_prepare(tmp_path, cache, origin, row, verify=False):
    output = tmp_path / "evict-report"
    command = [
        str(XRD), "conform", "accept",
        f"root://{HOST}:{cache.port}//fixture",
        "--also", f"root://{HOST}:{origin.port}//fixture",
        "--profile", "cache", "--only", row,
        "--allow-mutate", "--scratch", "/phase118-cache-scratch",
        "--budget", "boundary", "--fail-on", "divergent",
        "--wall-seconds", "30", "--request-limit", "256",
        "--byte-limit", "1048576", "--out", str(output),
    ]
    if verify:
        command.extend(["--verify-negative", row])
    result = subprocess.run(
        command, text=True, capture_output=True, timeout=45,
        env=_clean_environment(), check=False,
    )
    report = json.loads((output / "report.json").read_text(encoding="utf-8"))
    return result, {row["id"]: row for row in report["results"]}


def _run_evict(tmp_path, cache, origin, verify=False):
    return _run_prepare(tmp_path, cache, origin, "CAC-006", verify)


def _run_cache_fixture(tmp_path, cache, origin, row, kind, verify=False):
    output = tmp_path / f"{kind}-report"
    target = f"root://{HOST}:{cache.port}//fixture"
    command = [
        str(XRD), "conform", "accept", target,
        "--also", f"root://{HOST}:{origin.port}//fixture",
        "--profile", "cache", "--only", row,
        "--cache-fixture", kind,
        "--budget", "boundary", "--fail-on", "divergent",
        "--wall-seconds", "30", "--request-limit", "256",
        "--byte-limit", "1048576", "--out", str(output),
    ]
    if row in ("CAC-005", "CAC-009"):
        command.extend(["--allow-disrupt", "--confirm-target", target])
    if verify:
        command.extend(["--verify-negative", row])
    result = subprocess.run(
        command, text=True, capture_output=True, timeout=45,
        env=_clean_environment(), check=False,
    )
    report = json.loads((output / "report.json").read_text(encoding="utf-8"))
    return result, {item["id"]: item for item in report["results"]}


def test_cache_pair_agrees_across_population_grid_stat_and_checksum(tmp_path):
    """Success: the explicit cache/origin pair satisfies four independent rows."""
    with CacheOrigin(PAYLOAD) as cache, CacheOrigin(PAYLOAD) as origin:
        result, rows = _run_pair(tmp_path, cache, origin)
    assert result.returncode == 0, result.stderr + result.stdout
    for row_id in ("CAC-001", "CAC-002", "CAC-007", "CAC-008"):
        assert rows[row_id]["verdict"] == "conformant"


def test_cache_pair_detects_changed_second_population_read(tmp_path):
    """Security-negative: a cache that changes its second read is divergent."""
    with CacheOrigin(PAYLOAD, corrupt_read=2) as cache, \
            CacheOrigin(PAYLOAD) as origin:
        result, rows = _run_pair(tmp_path, cache, origin, ("CAC-001",))
    assert result.returncode == 1
    assert rows["CAC-001"]["verdict"] == "divergent"


def test_cache_pair_detects_origin_byte_and_checksum_mismatch(tmp_path):
    """Error: equal-size split-brain content fails both bytes and checksum."""
    changed = PAYLOAD[:-1] + bytes([PAYLOAD[-1] ^ 0xFF])
    with CacheOrigin(PAYLOAD) as cache, CacheOrigin(changed) as origin:
        result, rows = _run_pair(
            tmp_path, cache, origin, ("CAC-002", "CAC-007"),
        )
    assert result.returncode == 1
    assert rows["CAC-002"]["verdict"] == "divergent"
    assert rows["CAC-007"]["verdict"] == "divergent"


def test_cache_pair_detects_origin_size_mismatch(tmp_path):
    """Security-negative: cache and origin stat sizes cannot disagree."""
    with CacheOrigin(PAYLOAD) as cache, \
            CacheOrigin(PAYLOAD + b"extra") as origin:
        result, rows = _run_pair(
            tmp_path, cache, origin, verify=("CAC-008",),
        )
    assert result.returncode == 1
    assert rows["CAC-008"]["verdict"] == "divergent"


def test_cache_pair_absence_is_explicitly_inconclusive(tmp_path):
    """Fixture error: a cache-only run cannot claim paired observations."""
    with CacheOrigin(PAYLOAD) as cache:
        result, rows = _run_pair(tmp_path, cache)
    assert result.returncode == 0, result.stderr + result.stdout
    assert rows["CAC-001"]["verdict"] == "inconclusive"
    assert rows["CAC-001"]["reason"] == \
        "fixture-required:paired-cache-origin"


def test_cache_evict_refetches_replacement_bytes(tmp_path):
    """Success: accepted eviction makes the next read fetch new origin bytes."""
    with EvictOrigin() as origin, EvictCache(origin) as cache:
        result, rows = _run_evict(tmp_path, cache, origin)
        assert cache.prepare_seen
    assert result.returncode == 0, result.stderr + result.stdout
    assert rows["CAC-006"]["verdict"] == "conformant"


def test_cache_evict_refusal_is_divergent(tmp_path):
    """Error: an endpoint that refuses the eviction contract is divergent."""
    with EvictOrigin() as origin, EvictCache(origin, "refuse") as cache:
        result, rows = _run_evict(tmp_path, cache, origin, verify=True)
    assert result.returncode == 1
    assert rows["CAC-006"]["verdict"] == "divergent"
    assert rows["CAC-006"]["reason"] == "cache-evict-refused"


def test_cache_evict_never_serves_retained_stale_bytes(tmp_path):
    """Security-negative: acknowledged eviction cannot retain the old block."""
    with EvictOrigin() as origin, EvictCache(origin, "stale") as cache:
        result, rows = _run_evict(tmp_path, cache, origin, verify=True)
    assert result.returncode == 1
    assert rows["CAC-006"]["verdict"] == "divergent"
    assert rows["CAC-006"]["reason"] == \
        "cache-evict-served-stale-or-wrong-bytes"


def test_prepare_evict_reuses_the_exact_cache_contract(tmp_path):
    """Success: PRP-003 independently selects the eviction/refetch probe."""
    with EvictOrigin() as origin, EvictCache(origin) as cache:
        result, rows = _run_prepare(tmp_path, cache, origin, "PRP-003")
    assert result.returncode == 0, result.stderr + result.stdout
    assert rows["PRP-003"]["verdict"] == "conformant"


def test_prepare_evict_rejects_retained_stale_bytes(tmp_path):
    """Security-negative: PRP-003 owns stale data after acknowledged eviction."""
    with EvictOrigin() as origin, EvictCache(origin, "stale") as cache:
        result, rows = _run_prepare(
            tmp_path, cache, origin, "PRP-003", verify=True,
        )
    assert result.returncode == 1, result.stderr + result.stdout
    assert rows["PRP-003"]["verdict"] == "divergent"
    assert rows["PRP-003"]["reason"] == \
        "cache-evict-served-stale-or-wrong-bytes"


def test_prepare_fresh_refetches_replacement_bytes(tmp_path):
    """Success: kXR_fresh replaces an already resident cache copy."""
    with EvictOrigin() as origin, EvictCache(origin) as cache:
        result, rows = _run_prepare(tmp_path, cache, origin, "PRP-004")
    assert result.returncode == 0, result.stderr + result.stdout
    assert rows["PRP-004"]["verdict"] == "conformant"


def test_prepare_fresh_refusal_is_divergent(tmp_path):
    """Error: accepting no fresh-stage operation cannot satisfy PRP-004."""
    with EvictOrigin() as origin, EvictCache(origin, "fresh_refuse") as cache:
        result, rows = _run_prepare(
            tmp_path, cache, origin, "PRP-004", verify=True,
        )
    assert result.returncode == 1
    assert rows["PRP-004"]["reason"] == "cache-fresh-refused"


def test_prepare_fresh_never_serves_retained_stale_bytes(tmp_path):
    """Security-negative: acknowledged fresh cannot return resident old bytes."""
    with EvictOrigin() as origin, EvictCache(origin, "fresh_stale") as cache:
        result, rows = _run_prepare(
            tmp_path, cache, origin, "PRP-004", verify=True,
        )
    assert result.returncode == 1
    assert rows["PRP-004"]["verdict"] == "divergent"
    assert rows["PRP-004"]["reason"] == \
        "cache-fresh-served-stale-or-wrong-bytes"


@pytest.mark.parametrize(("row", "kind"), (
    ("CAC-003", "partial"),
    ("CAC-004", "filling"),
))
def test_prepared_cache_state_serves_origin_exact_bytes(tmp_path, row, kind):
    """Success: prepared partial/in-flight states return every origin byte."""
    with CacheOrigin(PAYLOAD) as cache, CacheOrigin(PAYLOAD) as origin:
        result, rows = _run_cache_fixture(tmp_path, cache, origin, row, kind)
    assert result.returncode == 0, result.stderr + result.stdout
    assert rows[row]["verdict"] == "conformant"


@pytest.mark.parametrize(("row", "kind"), (
    ("CAC-003", "partial"),
    ("CAC-004", "filling"),
))
def test_prepared_cache_state_rejects_zero_or_wrong_tail(tmp_path, row, kind):
    """Security-negative: equal-size wrong cache bytes are always divergent."""
    changed = PAYLOAD[:4096] + b"\x00" * (len(PAYLOAD) - 4096)
    with CacheOrigin(changed) as cache, CacheOrigin(PAYLOAD) as origin:
        result, rows = _run_cache_fixture(
            tmp_path, cache, origin, row, kind, verify=True,
        )
    assert result.returncode == 1
    assert rows[row]["verdict"] == "divergent"
    assert rows[row]["reason"] == "cache-fixture-byte-mismatch"


def test_over_capacity_cache_may_evict_and_serve(tmp_path):
    """Success: eviction followed by correct service satisfies CAC-005."""
    with CacheOrigin(PAYLOAD) as cache, CacheOrigin(PAYLOAD) as origin:
        result, rows = _run_cache_fixture(
            tmp_path, cache, origin, "CAC-005", "capacity",
        )
    assert result.returncode == 0, result.stderr + result.stdout
    assert rows["CAC-005"]["verdict"] == "conformant"


def test_over_capacity_cache_may_refuse_with_capacity_error(tmp_path):
    """Error: a defined capacity refusal is conformant, not a transient."""
    with CacheOrigin(PAYLOAD, read_error=3009) as cache, \
            CacheOrigin(PAYLOAD) as origin:
        result, rows = _run_cache_fixture(
            tmp_path, cache, origin, "CAC-005", "capacity",
        )
    assert result.returncode == 0, result.stderr + result.stdout
    assert rows["CAC-005"]["verdict"] == "conformant"


def test_over_capacity_cache_rejects_generic_io_failure(tmp_path):
    """Security-negative: a generic transient-looking I/O error turns red."""
    with CacheOrigin(PAYLOAD, read_error=3007) as cache, \
            CacheOrigin(PAYLOAD) as origin:
        result, rows = _run_cache_fixture(
            tmp_path, cache, origin, "CAC-005", "capacity", verify=True,
        )
    assert result.returncode == 1
    assert rows["CAC-005"]["verdict"] == "divergent"


def test_corrupt_cache_refetches_origin_bytes(tmp_path):
    """Success: a prepared corrupt block may be replaced with origin bytes."""
    with CacheOrigin(PAYLOAD) as cache, CacheOrigin(PAYLOAD) as origin:
        result, rows = _run_cache_fixture(
            tmp_path, cache, origin, "CAC-009", "corrupt",
        )
    assert result.returncode == 0, result.stderr + result.stdout
    assert rows["CAC-009"]["verdict"] == "conformant"


def test_corrupt_cache_may_fail_closed(tmp_path):
    """Error: an explicit cache read failure serves no corrupt bytes."""
    with CacheOrigin(PAYLOAD, read_error=3007) as cache, \
            CacheOrigin(PAYLOAD) as origin:
        result, rows = _run_cache_fixture(
            tmp_path, cache, origin, "CAC-009", "corrupt",
        )
    assert result.returncode == 0, result.stderr + result.stdout
    assert rows["CAC-009"]["reason"] == "corrupt-cache-failed-closed"


def test_corrupt_cache_never_serves_corruption(tmp_path):
    """Security-negative: returned bytes differing from origin turn red."""
    changed = bytes([PAYLOAD[0] ^ 0xFF]) + PAYLOAD[1:]
    with CacheOrigin(changed) as cache, CacheOrigin(PAYLOAD) as origin:
        result, rows = _run_cache_fixture(
            tmp_path, cache, origin, "CAC-009", "corrupt", verify=True,
        )
    assert result.returncode == 1
    assert rows["CAC-009"]["verdict"] == "divergent"
    assert rows["CAC-009"]["reason"] == "corrupt-cache-served-corruption"
