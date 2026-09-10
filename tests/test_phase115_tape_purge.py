"""Phase-115 W3.2 — the tape-buffer purge engine behind a ``tape://`` tier.

Until this phase the online buffer of a ``tape://`` tier (``<base>/.online``)
only ever grew: recalls and staged writes landed copies there and nothing
released them, and ``brix_frm_purge_watermark`` / ``brix_frm_purge_interval``
parsed but were read by nothing (release-2.0 register §(c.1)). The engine
(``src/fs/backend/frm/sd_frm_purge.c``, paced from worker 0 by
``src/core/config/process_frm_purge.c``) now runs one LRU pass per interval
with two arms: the filesystem watermark pair and the new owned-bytes cap
``brix_frm_purge_max_bytes``. A copy is released only when it is older than
30 s, no live stage request pins it, and the adapter's ``on_tape`` probe
confirms a durable copy — an un-migrated online copy is the only copy there is.

Coverage (each subject is its own nginx; no shared fleet):
  * success      — the cap arm releases the cold, migrated, unpinned copies in
                   LRU order, keeps the pinned / young / un-migrated ones, and a
                   ``root://`` read of a released copy recalls it byte-exact;
  * error        — a purge lock held by someone else defers the pass until it is
                   dropped; purge directives on an export without a ``tape://``
                   tier WARN and never arm;
  * security-neg — a symlink planted in the buffer is never followed (its target
                   survives) and no tape copy is ever touched;
  * grammar      — ``brix_frm_purge_max_bytes`` takes a size, is stream-scoped,
                   and the watermark pair still refuses low > high.
"""

import fcntl
import os
import re
import struct
import subprocess
import time

import pytest

from settings import BIND_HOST, NGINX_BIN
from server_registry import NginxInstanceSpec

import _test_session_bind_helpers as H

pytestmark = [pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-p115-tape-purge")]

kXR_prepare = 3021
kXR_stage = 0x08          # ClientPrepareRequest option bit
kXR_noerrs = 0x04         # ... do not fail the prepare on a missing path

FILE_BYTES = 1000
# migrated copies: name -> seconds before "now" the online copy was last touched
COLD = {"a": 500, "b": 400, "c": 300, "d": 200, "e": 100}
ALL_ONLINE = ["a", "b", "c", "d", "e", "evil", "u", "y"]

PURGE_CAP = "brix_frm_purge_max_bytes 2500; brix_frm_purge_interval 1s;"
PURGE_CAP_LRU = "brix_frm_purge_max_bytes 5500; brix_frm_purge_interval 1s;"
PURGE_IDLE = ("brix_frm_purge_max_bytes 100000; "
              "brix_frm_purge_watermark 0.999 0.99; brix_frm_purge_interval 1s;")

SUMMARY_RX = (r'tape purge "[^"]+/\.online": released (\d+) file\(s\), (\d+) bytes '
              r'\(occupancy \d+ -> \d+ ppm, owned (\d+) -> (\d+) bytes; skipped '
              r'young=(\d+) pinned=(\d+) unmigrated=(\d+) symlink=(\d+) failed=(\d+)\)')


def _payload(name):
    return (name * FILE_BYTES).encode()[:FILE_BYTES]


def _plant(base):
    """Tape copies under ``base``, online copies under ``base/.online``:
    a..e migrated and cold, ``u`` online-only (never migrated) and the coldest
    of all, ``y`` migrated but touched now, plus a symlink pointing out of the
    buffer. Returns the symlink's target."""
    online = base / ".online"
    online.mkdir(parents=True)
    now = time.time()
    for name, back in COLD.items():
        (base / name).write_bytes(_payload(name))
        (online / name).write_bytes(_payload(name))
        os.utime(online / name, (now - back, now - back))
    (online / "u").write_bytes(_payload("u"))
    os.utime(online / "u", (now - 600, now - 600))
    (base / "y").write_bytes(_payload("y"))
    (online / "y").write_bytes(_payload("y"))
    victim = base.parent / "victim.dat"
    victim.write_bytes(b"V" * FILE_BYTES)
    (online / "evil").symlink_to(victim)
    return victim


def _launch(lifecycle, tmp_path, name, backend, purge_lines, first_ms):
    export = tmp_path / "export"
    export.mkdir(exist_ok=True)
    for sub in ("cache", "control"):
        (tmp_path / sub).mkdir(exist_ok=True)
    return lifecycle.start(NginxInstanceSpec(
        name=name,
        template="nginx_p115_tape_purge.conf",
        data_root=str(export),
        env={"BRIX_CACHE_REAP_FIRST_MS": str(first_ms)},
        template_values={
            "BIND_HOST": BIND_HOST,
            "BACKEND": backend,
            "CACHE_DIR": str(tmp_path / "cache"),
            "QUEUE_PATH": str(tmp_path / "frm.queue"),
            "CONTROL_DIR": str(tmp_path / "control"),
            "PURGE_LINES": purge_lines,
            "ALLOW_WRITE": "on",
        },
        reason="phase-115 W3.2 tape-buffer purge engine"))


def _elog(endpoint):
    return os.path.join(endpoint.prefix, "logs", "error.log")


def _wait_log(elog, pattern, timeout=20.0):
    """Block until ``pattern`` appears in the error log; the match or None."""
    rx = re.compile(pattern)
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with open(elog) as fh:
                for line in fh:
                    m = rx.search(line)
                    if m:
                        return m
        except FileNotFoundError:
            pass
        time.sleep(0.1)
    return None


def _summary(elog):
    m = _wait_log(elog, SUMMARY_RX)
    assert m is not None, "no purge summary line within the deadline"
    return [int(x) for x in m.groups()]


def _online_names(base):
    return sorted(p.name for p in (base / ".online").iterdir()
                  if p.name != ".brix-purge.lock")


def _session(port):
    H.ANON_HOST = BIND_HOST
    return H._establish_primary(port)


def _prepare_stage(sock, streamid, path):
    # kXR_noerrs: a path that is not yet on disk (staged later) must not fail
    # the whole prepare with kXR_NotFound.
    body = struct.pack(">BBHH10s", kXR_stage | kXR_noerrs, 0, 0, 0, b"\x00" * 10)
    return H._send_req(sock, streamid, kXR_prepare, body=body,
                       payload=path.encode() + b"\n")


def _read_all(port, path, length):
    sock, _sessid, stream = _session(port)
    try:
        status, body = H._open_waiting(sock, stream, path, H.kXR_open_read)
        assert status == H.kXR_ok, f"open {path}: status {status} {body!r}"
        status, data = H._read_handle(sock, stream, body[:4], length)
        assert status == H.kXR_ok, f"read {path}: status {status}"
        return data
    finally:
        sock.close()


# --------------------------------------------------------------------------
# success
# --------------------------------------------------------------------------

def test_cap_arm_releases_cold_migrated_unpinned_copies(lifecycle, tmp_path):
    """(success) owned 7000 B > cap 2500 B: a, b, d, e go; ``c`` is pinned by a
    live kXR_prepare(stage), ``u`` was never migrated, ``y`` is younger than
    30 s — all three stay. A read of the released ``a`` recalls it from tape
    byte-exact."""
    base = tmp_path / "tape"
    _plant(base)
    ep = _launch(lifecycle, tmp_path, "lc-p115-purge-cap", f"tape://{base}",
                 PURGE_CAP, first_ms=3000)
    elog = _elog(ep)
    assert _wait_log(elog, r'tape purge engine armed for export "[^"]+" '
                     r'\(hi=0 lo=0 ppm, max_bytes=2500, interval=1000 ms\)'), \
        "engine did not report itself armed"

    sock, _sessid, stream = _session(ep.port)
    try:
        status, body = _prepare_stage(sock, stream, "/c")
        assert status == H.kXR_ok, f"kXR_prepare(stage) failed: {status} {body!r}"
    finally:
        sock.close()

    released, nbytes, owned_before, owned_after, young, pinned, unmig, syml, failed = \
        _summary(elog)
    assert (released, nbytes) == (4, 4 * FILE_BYTES)
    assert (owned_before, owned_after) == (7 * FILE_BYTES, 3 * FILE_BYTES)
    assert (young, pinned, unmig, syml, failed) == (1, 1, 1, 1, 0)
    assert _online_names(base) == ["c", "evil", "u", "y"]

    assert _read_all(ep.port, "/a", FILE_BYTES) == _payload("a")
    assert (base / ".online" / "a").read_bytes() == _payload("a"), \
        "the read did not recall the released copy back into the buffer"


def test_watermark_arm_below_high_releases_nothing(lifecycle, tmp_path):
    """(success, idle) a watermark pair the buffer's mount does not exceed and a
    cap far above the owned bytes: the engine arms, ticks, and keeps every copy."""
    base = tmp_path / "tape"
    _plant(base)
    ep = _launch(lifecycle, tmp_path, "lc-p115-purge-idle", f"tape://{base}",
                 PURGE_IDLE, first_ms=500)
    elog = _elog(ep)
    assert _wait_log(elog, r"tape purge engine armed .*hi=999000 lo=990000 ppm, "
                     r"max_bytes=100000")
    released = _summary(elog)[0]
    assert released == 0
    assert _online_names(base) == ALL_ONLINE


# --------------------------------------------------------------------------
# error
# --------------------------------------------------------------------------

def test_held_purge_lock_defers_the_pass_until_released(lifecycle, tmp_path):
    """(error) another holder of ``.online/.brix-purge.lock`` (a second worker,
    an operator's manual run) makes the tick step aside; once the lock drops the
    next tick releases exactly the two oldest migrated copies — the LRU order,
    since the cap of 5500 B needs only 1500 B back."""
    base = tmp_path / "tape"
    _plant(base)
    lock = base / ".online" / ".brix-purge.lock"
    fd = os.open(lock, os.O_RDWR | os.O_CREAT, 0o600)
    fcntl.flock(fd, fcntl.LOCK_EX)
    try:
        ep = _launch(lifecycle, tmp_path, "lc-p115-purge-lock", f"tape://{base}",
                     PURGE_CAP_LRU, first_ms=500)
        elog = _elog(ep)
        assert _wait_log(elog, r'tape purge "[^"]+" skipped: another pass holds '
                         r"the lock"), "held lock was not reported"
        time.sleep(1.5)                       # at least one more deferred tick
        assert _online_names(base) == ALL_ONLINE
        with open(elog) as fh:
            assert "released" not in fh.read(), "a pass ran while the lock was held"
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)

    released, nbytes = _summary(elog)[:2]
    assert (released, nbytes) == (2, 2 * FILE_BYTES)
    assert _online_names(base) == ["c", "d", "e", "evil", "u", "y"], \
        "not the two least-recently-touched migrated copies"


def test_directives_without_tape_tier_warn_and_never_arm(lifecycle, tmp_path):
    """(error) purge directives on a plain POSIX export: one WARN, no engine,
    and the export still serves."""
    export = tmp_path / "export"
    export.mkdir()
    (export / "plain.bin").write_bytes(b"P" * 64)
    ep = _launch(lifecycle, tmp_path, "lc-p115-purge-notier", f"posix:{export}",
                 PURGE_CAP, first_ms=500)
    elog = _elog(ep)
    assert _wait_log(elog, r'brix_frm_purge_\* configured but export "[^"]+" has '
                     r"no tape:// tier; purge engine not armed")
    assert _read_all(ep.port, "/plain.bin", 64) == b"P" * 64
    with open(elog) as fh:
        assert "tape purge engine armed" not in fh.read()


# --------------------------------------------------------------------------
# security-negative
# --------------------------------------------------------------------------

def _tape_copies(base):
    return {n: (base / n).read_bytes() for n in [*COLD, "y"]}


def test_symlink_never_followed_and_tape_copies_never_touched(lifecycle, tmp_path):
    """(security-neg) a symlink planted in the buffer must be counted, not
    followed: its target outside the buffer survives, and the pass — which
    releases every cold migrated copy here (no pin) — leaves every tape copy
    byte-identical."""
    base = tmp_path / "tape"
    victim = _plant(base)
    tape_before = _tape_copies(base)
    ep = _launch(lifecycle, tmp_path, "lc-p115-purge-cap", f"tape://{base}",
                 PURGE_CAP, first_ms=500)
    summary = _summary(_elog(ep))
    assert (summary[0], summary[7]) == (5, 1), f"released/symlink: {summary}"
    evil = base / ".online" / "evil"
    assert evil.is_symlink()
    assert os.readlink(evil) == str(victim)
    assert victim.read_bytes() == b"V" * FILE_BYTES, "the symlink target was touched"
    assert _tape_copies(base) == tape_before
    assert _online_names(base) == ["evil", "u", "y"]


# --------------------------------------------------------------------------
# grammar (nginx -t only, no server)
# --------------------------------------------------------------------------

def _nginx_t(root, srv_directives, http_directives=""):
    (root / "logs").mkdir(exist_ok=True)
    (root / "data").mkdir(exist_ok=True)
    http = ""
    if http_directives:
        http = (f"http {{ server {{ listen unix:{root}/h.sock; "
                f"location / {{ brix_webdav on; brix_export {root}/data; "
                f"{http_directives} }} }} }}")
    conf = root / "purge.conf"
    conf.write_text(f"""daemon off; error_log {root}/logs/e.log info;
pid {root}/n.pid; thread_pool default threads=2;
events {{ worker_connections 64; }}
stream {{ server {{ listen unix:{root}/s.sock;
    brix_root on; brix_storage_backend posix:{root}/data; brix_auth none;
    {srv_directives}
}} }}
{http}
""")
    p = subprocess.run([str(NGINX_BIN), "-t", "-p", str(root), "-c", str(conf)],
                       capture_output=True, text=True, timeout=30)
    return p.returncode, p.stderr + p.stdout


def test_purge_max_bytes_parses_a_size(tmp_path):
    rc, out = _nginx_t(tmp_path, "brix_frm_purge_max_bytes 10g; "
                                 "brix_frm_purge_watermark 0.90 0.80; "
                                 "brix_frm_purge_interval 5m;")
    assert rc == 0, f"purge trio no longer parses:\n{out}"


def test_purge_max_bytes_rejects_a_non_size(tmp_path):
    rc, out = _nginx_t(tmp_path, "brix_frm_purge_max_bytes plenty;")
    assert rc != 0 and "invalid value" in out, out


def test_purge_watermark_low_above_high_still_refused(tmp_path):
    rc, out = _nginx_t(tmp_path, "brix_frm_purge_watermark 0.50 0.80;")
    assert rc != 0 and "must not exceed high" in out, out


def test_purge_max_bytes_is_not_an_http_directive(tmp_path):
    """(security-neg, grammar) the cap is a stream-server knob of the tape tier;
    an http location must not silently accept it."""
    rc, out = _nginx_t(tmp_path, "", http_directives="brix_frm_purge_max_bytes 1m;")
    # nginx knows the name (it is a stream directive) and refuses the context.
    assert rc != 0 and "is not allowed here" in out, out
