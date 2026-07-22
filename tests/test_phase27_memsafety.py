"""
Phase 27 — memory-safety & anti-abuse hardening.

Coverage:
  1. Source-marker checks: the W1 safe_size header, W3 scoped header, F1 readv
     segment-count guard, F4 session-registry reaper + F5 cap-drift fix, the
     metrics, the W8 lint, and the W7 fuzz target are all present/wired.
  2. W8 lint runs clean (advisory; exit 0).
  3. W7 fuzz target builds and a short run is crash-free (the W1 overflow
     contract holds under fuzzing).  Skipped if clang+libFuzzer is unavailable.
  4. Functional F1: a valid readv succeeds (success), and an oversized readv is
     rejected cleanly without crashing the server (error / security-neg).
"""

import os
import shutil
import socket
import struct
import subprocess
from pathlib import Path

import pytest

from settings import NGINX_BIN, HOST, BIND_HOST
from server_registry import NginxInstanceSpec

pytestmark = [pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-memsafety")]

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(autouse=True)
def _require_binary():
    if not os.path.exists(NGINX_BIN):
        pytest.skip(f"nginx binary not found at {NGINX_BIN}")


def _read(rel):
    p = ROOT / rel
    assert p.exists(), f"missing {rel}"
    return p.read_text(encoding="utf-8")


# --------------------------------------------------------------------------- #
# 1. Source-marker checks                                                      #
# --------------------------------------------------------------------------- #

def test_w1_safe_size_header():
    h = _read("src/core/compat/safe_size.h")
    assert "brix_size_mul" in h
    assert "__builtin_mul_overflow" in h
    assert "brix_alloc_array" in h


def test_w3_scoped_header():
    h = _read("src/auth/crypto/scoped.h")
    assert "brix_evp_pkey_free" in h
    assert "brix_x509_stack_free" in h
    assert "JANSSON OWNERSHIP CHEATSHEET" in h


def test_f1_readv_segment_guard():
    # readv.c was split; the segment-guard logic now spans readv.c + readv_engine.c.
    rv = _read("src/protocols/root/read/readv.c") + _read("src/protocols/root/read/readv_engine.c")
    assert "safe_size.h" in rv
    assert "BRIX_READV_MAXSEGS" in rv
    assert "brix_size_mul" in rv
    assert "brix_alloc_array" in rv


def test_f4_session_reaper_and_f5_cap_drift():
    h = _read("src/protocols/root/session/registry.h")
    assert "last_seen" in h
    assert "BRIX_SESSION_REAP_MIN_AGE_MS" in h
    # F5: cap-drift fixed — no stale "default 256" docstring remains.
    assert "default 256" not in h
    c = _read("src/protocols/root/session/registry.c")
    assert "session_evict_total" in c
    assert "session_registry_full_total" in c


def test_f9_evict_realloc_guard():
    e = _read("src/fs/cache/evict_candidates.c")
    assert "brix_size_mul" in e
    assert "BRIX_EVICT_MAX_CANDIDATES" in e


def test_metrics_present():
    m = _read("src/observability/metrics/metrics.h")
    assert "session_registry_full_total" in m
    assert "session_evict_total" in m
    s = _read("src/observability/metrics/stream.c")
    assert "brix_session_evict_total" in s


def test_w7_fuzz_target_present():
    assert (ROOT / "tests/fuzz/fuzz_safe_size.c").exists()
    assert (ROOT / "tests/fuzz/README.md").exists()


# --------------------------------------------------------------------------- #
# 2. W8 lint                                                                   #
# --------------------------------------------------------------------------- #

def test_w8_lint_runs_clean():
    from cmdscripts.lint_alloc import run_checks

    rc, output = run_checks()
    assert rc == 0, output
    assert "lint_alloc:" in output


# --------------------------------------------------------------------------- #
# 3. W7 fuzz build + short run                                                 #
# --------------------------------------------------------------------------- #

def test_w7_fuzz_safe_size_builds_and_runs(tmp_path):
    clang = shutil.which("clang")
    if clang is None:
        pytest.skip("clang not available")
    # Confirm libFuzzer is usable.
    probe = tmp_path / "probe.c"
    probe.write_text("int LLVMFuzzerTestOneInput(const unsigned char*d,"
                     "unsigned long s){(void)d;(void)s;return 0;}\n")
    if subprocess.run([clang, "-fsanitize=fuzzer,address", str(probe),
                       "-o", str(tmp_path / "probe")],
                      capture_output=True).returncode != 0:
        pytest.skip("clang libFuzzer/ASAN not available")

    out = tmp_path / "fuzz_safe_size"
    rc = subprocess.run(
        [clang, "-O1", "-g", "-fsanitize=fuzzer,address,undefined",
         "-I", str(ROOT / "src/core/compat"),
         str(ROOT / "tests/fuzz/fuzz_safe_size.c"), "-o", str(out)],
        capture_output=True, text=True)
    assert rc.returncode == 0, rc.stderr

    run = subprocess.run([str(out), "-runs=100000", "-max_total_time=20"],
                         capture_output=True, text=True, cwd=str(tmp_path),
                         timeout=60)
    # A crash leaves a crash-* artifact and non-zero exit.
    assert run.returncode == 0, run.stdout + run.stderr
    assert not list(tmp_path.glob("crash-*")), "fuzzer found a crash"


# --------------------------------------------------------------------------- #
# 4. W6b/W6c — Valgrind Memcheck findings closed + harness committed           #
# --------------------------------------------------------------------------- #

def test_w6c_valgrind_findings_closed_and_harness_present():
    """The two Memcheck-found defects are fixed and the harness is committed.

    Detailed regression guards live in test_valgrind_regression.py; this is the
    Phase 27 cross-reference. Both fixes are pure module-code changes that LSan
    could not catch under WSL2 (Memcheck did) — see valgrind-findings.md.
    """
    # Finding 1: bounded copy in the dashboard client-IP path.
    assert "ngx_min(r->connection->addr_text.len" in _read(
        "src/observability/dashboard/http_tracking.c")
    # Finding 2: JWKS pool cleanup registered at both conf load sites.
    # (phase-79 split: the webdav registration site moved into config_proxy.c.)
    assert "brix_jwks_register_cleanup" in _read("src/protocols/webdav/config_proxy.c")
    assert "brix_jwks_register_cleanup" in _read("src/auth/token/config.c")
    # Committed harness (Python port: operator_runtime.run_valgrind) + findings writeup.
    assert (ROOT / "tests/cmdscripts/operator_runtime.py").exists()
    assert (ROOT / "docs/07-security/valgrind-findings.md").exists()


# --------------------------------------------------------------------------- #
# Functional F1 helpers (raw XRootD wire)                                      #
# --------------------------------------------------------------------------- #

def _spawn_stream(lifecycle, tmp_path, name):
    data = tmp_path / "data"; data.mkdir()
    (data / "f.txt").write_bytes(b"A" * 4096)
    ep = lifecycle.start(NginxInstanceSpec(
        name=name,
        template="nginx_lc_memsafety_stream.conf",
        protocol="root",
        template_values={"BIND_HOST": BIND_HOST, "DATA_DIR": str(data)},
        reason="phase-27 readv segment-count guard"))
    return ep.port


def _login(port):
    s = socket.socket(); s.settimeout(5); s.connect((HOST, port))
    s.sendall(struct.pack(">IIIII", 0, 0, 0, 4, 2012))
    s.sendall(struct.pack(">BB H I BB 10x I", 0, 1, 3006, 0x520, 2, 3, 0))
    s.recv(16)
    h = s.recv(8); dl = struct.unpack(">I", h[4:8])[0]
    if dl: s.recv(dl)
    s.sendall(struct.pack(">BB H I 8s BB B B I", 0, 1, 3007, 0,
                          b"test\0\0\0\0", 0, 0, 5, 0, 0))
    h = s.recv(8); dl = struct.unpack(">I", h[4:8])[0]
    if dl: s.recv(dl)
    return s


def _recv_resp(s):
    h = s.recv(8)
    if len(h) < 8:
        return None, b""
    status = struct.unpack(">H", h[2:4])[0]
    dl = struct.unpack(">I", h[4:8])[0]
    body = b""
    while len(body) < dl:
        c = s.recv(dl - len(body))
        if not c:
            break
        body += c
    return status, body


def _open_read(s, path):
    # kXR_open = 3010; body: mode[2], options[2]=kXR_open_read(0x10), 12 reserved
    payload = path.encode()
    body = struct.pack(">HH12s", 0, 0x10, b"\0" * 12)
    s.sendall(struct.pack(">BBH", 0, 1, 3010) + body
              + struct.pack(">I", len(payload)) + payload)
    st, b = _recv_resp(s)
    fh = b[:4] if (st == 0 and len(b) >= 4) else None  # kXR_ok → fhandle first
    return st, fh


def _readv(s, segments):
    # segments: list of (fhandle4, rlen, offset). readahead_list = fhandle[4] +
    # rlen[4] + offset[8] = 16 bytes.
    payload = b"".join(struct.pack(">4siq", fh, rlen, off)
                       for fh, rlen, off in segments)
    s.sendall(struct.pack(">BBH16sI", 0, 1, 3025, b"\0" * 16, len(payload))
              + payload)
    return _recv_resp(s)


# --------------------------------------------------------------------------- #
# 4. Functional F1                                                             #
# --------------------------------------------------------------------------- #

def test_readv_valid(lifecycle, tmp_path):
    port = _spawn_stream(lifecycle, tmp_path, "lc-memsafety-readv-valid")
    s = _login(port)
    st, fh = _open_read(s, "/f.txt")
    assert st == 0 and fh is not None, ("open failed", st)
    st, body = _readv(s, [(fh, 256, 0)])
    assert st == 0, ("readv status", st)
    assert len(body) >= 256, len(body)
    s.close()


def test_readv_oversized_rejected_cleanly(lifecycle, tmp_path):
    # An over-MAXSEGS readv must be rejected without crashing the server: the
    # process must survive and keep serving other clients.
    port = _spawn_stream(lifecycle, tmp_path, "lc-memsafety-readv-oversized")
    s = _login(port)
    st, fh = _open_read(s, "/f.txt")
    assert st == 0 and fh is not None
    # 4000 segments (> BRIX_READV_MAXSEGS=1024): the recv-layer cap and the
    # readv callsite cap both reject; the connection is dropped or errored.
    bogus = [(fh, 16, 0)] * 4000
    try:
        st2, _ = _readv(s, bogus)
        # Either an error status or a closed connection — never kXR_ok.
        assert st2 != 0, st2
    except (OSError, struct.error):
        pass  # connection dropped — acceptable rejection
    s.close()

    # The server is still alive: a fresh client can log in and readv.
    s2 = _login(port)
    st3, fh3 = _open_read(s2, "/f.txt")
    assert st3 == 0 and fh3 is not None, "server died after oversized readv"
    st4, body4 = _readv(s2, [(fh3, 128, 0)])
    assert st4 == 0 and len(body4) >= 128
    s2.close()
