"""
test_evil_actor.py — adversarial worker-crash hunt for the root:// stream plane.

WHAT
    A malicious-client harness that fires byte-accurate hostile XRootD wire frames
    and concurrency races at a REAL master+worker nginx, then proves no worker
    process broke. Unlike the existing fuzz suites (which run against the shared
    fleet and only check "the session still answers"), this owns its own
    master_process-on server with >=2 workers, enumerates worker PIDs, and after
    each attack phase asserts: the master is alive, no worker exited on a fatal
    signal, the error log carries no SIGSEGV/SIGABRT/sanitizer report, and a
    legitimate request still returns correct bytes. A worker that SIGSEGVs and is
    silently respawned by the master is therefore caught (it would pass a
    login+ping health check).

THE ATTACK SURFACE (from a recon of the parsers/bounds):
    * frame/allocation gate   — lying/oversized/zero dlen, dlen at each per-opcode
                                cap and cap+1, truncated-body half-open frames.
    * fhandle out-of-range    — fhandle[0] in 16..255 (valid uchar cast, OOB for
                                the 16-slot table) on read/pgread/readv/write/
                                pgwrite/stat/close/truncate.
    * readv/writev segments   — bad seg counts, dlen not a multiple of 16, mixed
                                valid/invalid handles, huge per-seg rlen, long
                                contiguous coalesce runs, N-discovery confusion.
    * pgread/pgwrite math     — unaligned offsets + rlen near the cap, negative
                                offsets, rlen 0, bad CRC, edge dlens.
    * kXR_clone offsets       — negative/near-2^63 src/dst offsets (the one wire
                                offset path with no pre-validation).
    * fattr / query           — numattr 17/255, subcode 4..255, truncated nvec,
                                hostile query subcodes/paths.
    * login / open            — invalid usernames, path traversal/NUL/overlong.
    * THE HEADLINE — disconnect-mid-AIO: a large pgread/readv/write offloads to a
                     worker thread that pread/pwrites into ctx scratch buffers;
                     a hard RST then drives brix_on_disconnect to free those
                     buffers while the worker is still in the syscall (a classic
                     use-after-free with no thread-pool drain). Hammered from many
                     connections to widen the window.
    * endsess-then-pipelined-read + RST (post-teardown reuse / double-disconnect).
    * resource exhaustion (handle/session floods).

Strongest under an AddressSanitizer build (TEST_NGINX_BIN=<asan nginx>): a UAF
that only sometimes faults on a release build is a deterministic ASAN abort.

RUN
    TEST_SKIP_SERVER_SETUP=1 PYTHONPATH=tests pytest tests/test_evil_actor.py -v -s
"""

import os
import random
import shutil
import socket
import struct
import subprocess
import tempfile
import threading
import time

import pytest

from settings import NGINX_BIN, REMOTE_SERVER, HOST, BIND_HOST
from server_launcher import LifecycleHarness
from server_registry import NginxInstanceSpec

pytestmark = [pytest.mark.serial, pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-evil-actor")]

# tunables (env-overridable so CI can dial intensity)
AIO_ROUNDS   = int(os.environ.get("TEST_EVIL_AIO_ROUNDS", "600"))
AIO_THREADS  = int(os.environ.get("TEST_EVIL_AIO_THREADS", "8"))
FUZZ_REPEAT  = int(os.environ.get("TEST_EVIL_FUZZ_REPEAT", "3"))
BIGFILE_MB   = 48

# opcodes
kXR_query=3001; kXR_close=3003; kXR_dirlist=3004; kXR_login=3007; kXR_open=3010
kXR_ping=3011; kXR_read=3013; kXR_stat=3017; kXR_write=3019; kXR_fattr=3020
kXR_endsess=3023; kXR_bind=3024; kXR_readv=3025; kXR_pgwrite=3026
kXR_truncate=3028; kXR_pgread=3030; kXR_writev=3031; kXR_clone=3033

kXR_ok=0; kXR_error=4003; kXR_wait=4005; kXR_status=4007

CRASH_PATTERNS = ("signal 11", "signal 6", "signal 4", "signal 7", "signal 8",
                  "SIGSEGV", "SIGABRT", "core dumped", "segfault",
                  "AddressSanitizer", "runtime error:", "LeakSanitizer",
                  "heap-use-after-free", "heap-buffer-overflow",
                  "stack-buffer-overflow", "attempting double-free")


# ---------------------------------------------------------------------------
# process / liveness helpers (lifted from test_shm_fork_safety.py)
# ---------------------------------------------------------------------------

def _aio_rst_worker(port, rounds, stop_at, counter):
    rng = random.Random(threading.get_ident())
    while time.time() < stop_at and counter[0] < rounds:
        counter[0] += 1
        s = None
        try:
            s = _connect(port, timeout=4)
            _login(s)
            fh = _open_big(s)
        except Exception:
            if s is not None:
                _rst_close(s)
            continue
        # pick a large-offload op and a big range so the worker thread is mid
        # pread/CRC-encode when the RST lands.
        op = rng.choice(("pgread", "readv", "read", "write"))
        off = rng.randrange(0, max(1, BIGFILE_MB * 1024 * 1024 - (32 << 20)))
        rlen = rng.choice((8 << 20, 24 << 20, 48 << 20))
        try:
            if op == "pgread":
                s.sendall(_frame(kXR_pgread, struct.pack("!4sqi", fh, off, rlen)))
            elif op == "read":
                s.sendall(_frame(kXR_read, struct.pack("!4sqi", fh, off, rlen)))
            elif op == "readv":
                segs = b"".join(struct.pack("!4siq", fh, 1 << 20, off + i * (1 << 20))
                                for i in range(16))
                s.sendall(_frame(kXR_readv, b"", segs))
            else:  # write: detached-payload pwrite from a buffer freed on RST
                try:
                    fw = _open_w(s)
                except Exception:
                    fw = fh
                s.sendall(_frame(kXR_write, struct.pack("!4sqB3s", fw, 0, 0, b"\x00" * 3),
                                 b"Z" * (1 << 20)))
        except OSError:
            pass
        # RST after a jittered delay spanning the post→pread window
        d = rng.choice((0, 0, 0.0005, 0.002, 0.008))
        if d:
            time.sleep(d)
        _rst_close(s)
