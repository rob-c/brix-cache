# _test_evil_actor_v3_helpers.py - shared header/helpers/fixtures/constants for the Phase-38
# split of test_evil_actor_v3.py.  `from _test_evil_actor_v3_helpers import *` re-exports EVERYTHING via
# the __all__ below so the test functions keep their exact module namespace.


"""
test_evil_actor_v3.py — "hyper-evil" worker-crash / data-race / UAF hunt.

Escalates beyond test_evil_actor.py (v1: hostile frames, disconnect-mid-AIO,
endsess+pipeline, exhaustion) and test_evil_actor_v2.py (v2: cross-connection
bind inode-swap, bind contract, shim-widened AIO, pipelined scratch, cross-
protocol) by attacking the surfaces v1/v2 NEVER touch, all under the worker-gated
race_shim.c (LD_PRELOAD syscall-slower):

  A1  roots:// in-protocol TLS bring-up correctness — raw kXR_protocol(kXR_ableTLS)
      -> kXR_haveTLS -> client wraps socket (CERT_NONE, no GSI PKI) -> windowed
      multi-window read byte-exact. The entire server-side TLS upgrade state
      machine + the TLS-forces-memory-windowed-read path, unexercised by v1/v2.
  A2  roots:// TLS disconnect-mid-AIO — RST the raw fd while a worker is held
      mid-pread by the shim AND an SSL connection object is being torn down: a
      SECOND teardown actor (SSL_free + ngx pool ssl cleanup) the cleartext
      tests structurally cannot produce.
  B6  cross-WORKER kXR_bind — reuseport spreads primary + secondary across worker
      PROCESSES; the secondary reads a primary handle published in cross-process
      SHM (v2's paired conns were effectively same-worker).
  B7  cross-worker bind-vs-teardown TOCTOU + handle-slot ABA — race a primary
      RST/endsess (memzeros the SHM session+handle slot) against a secondary's
      first cross-worker read, plus a free/reuse (ABA) cycle republishing a slot
      to a different inode; per-read dev/inode + sessid revalidation must revoke.
  C1  FRM async asynresp deliver-into-recycled-connection (cross-process UAF) —
      park a kXR_waitresp recall waiter, RST mid-stall, storm new clients onto
      recycled fds; the deliver-time liveness re-check must prevent any foreign-
      streamid kXR_attn(asynresp) injection. Brand-new FRM/kXR_prepare plane.
  C2  FRM reqid forgery — a foreign session must not cancel another's stage
      request by its guessable monotonic reqid; the cancel/evict path enforces
      requester ownership (brix_prepare_handle_cancel -> frm_request_owner_check).
  C3  FRM admission flood — durable queue + SHM index + waiter table + stage-agent
      fork bound must shed cleanly (no crash, no unbounded RSS, no fork storm).
  D   chaos capstone — sustained randomized interleave of every vector across all
      listeners concurrently under the shim, with surviving control connections
      proving no silent cross-plane corruption.

Same master+worker pgrep-churn + error-log crash detector as v2. Strongest under
ASAN (heap-use-after-free) — see "Running" at the bottom.

RUN: TEST_SKIP_SERVER_SETUP=1 PYTHONPATH=tests pytest tests/test_evil_actor_v3.py -v -s
"""

import hashlib
import os
import random
import shutil
import socket
import ssl
import struct
import subprocess
import tempfile
import threading
import time

import pytest

from settings import NGINX_BIN, REMOTE_SERVER, HOST, BIND_HOST
from server_launcher import LifecycleHarness
from server_registry import NginxInstanceSpec

# Fixed-port target (evil-actor-v3 ledger, 30357 + TLS/HTTPS/metrics extras): one
# driver at a time.  serial because the client-side flood exhausts ephemeral fds.
pytestmark = [pytest.mark.serial, pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("evil-actor-v3")]

BIGFILE_MB = 32
SHIM_DELAY_US = int(os.environ.get("XRD_RACE_DELAY_US", "15000"))
SHIM_SAN = os.environ.get("TEST_EVIL_SHIM_SAN", "")          # ""|address|thread
class _Srv:
    def __init__(self, prefix, conf, pidfile, ports, datadir, tsandir):
        self.prefix = prefix; self.conf = conf; self.pidfile = pidfile
        (self.root_port, self.root_tls_port,
         self.https_port, self.metrics_port) = ports
        self.datadir = datadir; self.tsandir = tsandir
        self.master: "int | None" = None
        self._mark = 0
        self.have_xattr = False
        self.frm_ok = False
        self.near_names: "list[str]" = []
        self.audit = ""
        self.queue = ""

    @property
    def logfile(self):
        return os.path.join(self.prefix, "logs", "error.log")

    def mark(self):
        try:
            self._mark = os.path.getsize(self.logfile)
        except OSError:
            self._mark = 0

    def _delta(self):
        try:
            with open(self.logfile, errors="replace") as f:
                f.seek(self._mark); return f.read()
        except OSError:
            return ""

    def _tsan_module_races(self):
        if not self.tsandir or not os.path.isdir(self.tsandir):
            return ""
        reports = (self._read_tsan_report(name) for name in os.listdir(self.tsandir))
        return ",".join(name for name, text in reports if self._module_race(text))

    def _read_tsan_report(self, name):
        try:
            with open(os.path.join(self.tsandir, name), errors="replace") as stream:
                return name, stream.read()
        except OSError:
            return name, ""

    @staticmethod
    def _module_race(text):
        markers = (
            "/src/core/aio/", "/src/protocols/root/read/",
            "/src/protocols/root/write/", "/src/fs/cache/",
            "/src/protocols/root/session/", "/src/protocols/root/connection/",
            "/src/frm/", "_aio_thread", "_aio_done", "read_scratch",
            "payload_to_free", "ctx->destroyed", "brix_",
        )
        return "data race" in text and any(marker in text for marker in markers)

    def assert_no_crash(self, phase):
        """Crash/race/liveness check WITHOUT a fresh ping — safe to call mid-flight
        while attack threads saturate the listeners (a fresh ping would race the
        load and false-positive)."""
        delta = self._delta()
        for pat in CRASH_PATTERNS:
            assert pat not in delta, (
                "WORKER BROKE during %s — %r in error log:\n%s"
                % (phase, pat, delta[-2000:]))
        races = self._tsan_module_races()
        assert not races, "TSan module-frame DATA RACE during %s: %s" % (phase, races)
        assert _alive(self.master), "master died during %s" % phase
        assert _workers(self.master), "no workers after %s" % phase

    def assert_healthy(self, phase):
        self.assert_no_crash(phase)
        assert _ping_ok_retry(self.root_port), "server not serving after %s" % phase


def _build_shim(workdir):
    src = os.path.join(os.path.dirname(__file__), "race_shim.c")
    so = os.path.join(workdir, "librace.so")
    cmd = ["cc", "-shared", "-fPIC", "-O0", "-g", "-o", so, src, "-ldl", "-lpthread"]
    if SHIM_SAN in ("address", "thread"):
        cmd[1:1] = ["-fsanitize=" + SHIM_SAN]
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        return None, r.stderr
    return so, ""


def _xattr_ok(tmp):
    try:
        p = os.path.join(tmp, ".xattrprobe")
        open(p, "w").close()
        os.setxattr(p, "user.frm.test", b"1")
        os.remove(p)
        return True
    except Exception:
        return False


def _gen_cert(workdir):
    cert = os.path.join(workdir, "cert.pem")
    key = os.path.join(workdir, "key.pem")
    r = subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-keyout", key,
         "-out", cert, "-days", "1", "-nodes", "-subj", "/CN=127.0.0.1",  # net-literal-allow: throwaway TLS cert subject CN
         "-addext", "subjectAltName=IP:127.0.0.1"],  # net-literal-allow: throwaway TLS cert SAN
        capture_output=True, text=True)
    if r.returncode != 0 or not os.path.exists(cert):
        return None, None
    return cert, key


def _require_evil_actor_prerequisites():
    if REMOTE_SERVER:
        pytest.skip("self-contained; not REMOTE")
    if not os.path.exists(NGINX_BIN):
        pytest.skip("nginx not built at %s" % NGINX_BIN)
    for tool in ("pgrep", "cc", "openssl"):
        if shutil.which(tool) is None:
            pytest.skip("%s required" % tool)


def _prepare_scratch():
    workdir = tempfile.mkdtemp(prefix="evil3-")
    paths = {
        "workdir": workdir,
        "datadir": os.path.join(workdir, "data"),
        "tapedir": os.path.join(workdir, "tape"),
        "tsandir": os.path.join(workdir, "tsan"),
        "audit": os.path.join(workdir, "audit.log"),
        "queue": os.path.join(workdir, "frm.queue"),
    }
    for name in ("datadir", "tapedir", "tsandir"):
        os.makedirs(paths[name], exist_ok=True)
    paths["have_xattr"] = _xattr_ok(paths["datadir"])
    paths["shim"] = _require_shim(workdir)
    paths["cert"], paths["key"] = _require_certificate(workdir)
    _seed_regular_data(paths["datadir"])
    paths["copycmd"] = _prepare_copy_command(workdir)
    paths["near_names"] = _seed_nearline_data(paths)
    return paths


def _require_shim(workdir):
    shim, error = _build_shim(workdir)
    if shim is not None:
        return shim
    shutil.rmtree(workdir, ignore_errors=True)
    pytest.skip("could not build race shim: %s" % error[-300:])


def _require_certificate(workdir):
    cert, key = _gen_cert(workdir)
    if cert is not None:
        return cert, key
    shutil.rmtree(workdir, ignore_errors=True)
    pytest.skip("could not generate self-signed cert")


def _seed_regular_data(datadir):
    chunk = bytes((index * 31 + 7) & 0xFF for index in range(65536))
    with open(os.path.join(datadir, "big.bin"), "wb") as stream:
        for _ in range(BIGFILE_MB * 16):
            stream.write(chunk)
    for name in ("shared.bin", "w.bin", "xp.bin"):
        with open(os.path.join(datadir, name), "wb") as stream:
            stream.write(chunk * 8)


def _prepare_copy_command(workdir):
    destination = os.path.join(workdir, "copycmd.py")
    source = os.path.join(os.path.dirname(__file__), "cmdscripts", "frm_fake_mss.py")
    shutil.copy(source, destination)
    os.chmod(destination, 0o755)
    return destination


def _seed_nearline_data(paths):
    if not paths["have_xattr"]:
        return []
    _write_nearline(paths, "near.dat", b"TAPE-" + b"z" * 4096 + b"\n")
    names = []
    for index in range(60):
        name = "near%03d.dat" % index
        _write_nearline(paths, name, b"T%03d" % index + b"q" * 512)
        names.append("/" + name)
    return names


def _write_nearline(paths, name, body):
    with open(os.path.join(paths["tapedir"], name), "wb") as stream:
        stream.write(body)
    stub = os.path.join(paths["datadir"], name)
    open(stub, "wb").close()
    os.setxattr(stub, "user.frm.residency", b"nearline")


def _frm_block(paths):
    if not paths["have_xattr"]:
        return ""
    return (
        "        brix_frm on; brix_frm_queue_path %s;\n"
        "        brix_frm_copycmd %s; brix_frm_copymax 4;\n"
        "        brix_frm_async_recall on; brix_frm_stage_ttl 30s;\n"
        "        brix_frm_xfrhold 50ms;\n"
        "        brix_frm_max_inflight 64; brix_frm_max_per_source 16;\n"
        % (paths["queue"], paths["copycmd"])
    )


def _sanitizer_runtime():
    if SHIM_SAN not in ("address", "thread"):
        return ""
    wanted = "libasan.so" if SHIM_SAN == "address" else "libtsan.so"
    try:
        output = subprocess.run(
            ["ldd", NGINX_BIN], capture_output=True, text=True
        ).stdout
    except Exception:
        return ""
    return _find_sanitizer_runtime(output, wanted)


def _find_sanitizer_runtime(output, wanted):
    for line in output.splitlines():
        if wanted not in line or "=>" not in line:
            continue
        candidate = line.split("=>", 1)[1].strip().split(" ", 1)[0]
        if candidate and os.path.exists(candidate):
            return candidate
    return ""


def _launch_environment(paths):
    env = {}
    preload = os.environ.get("LD_PRELOAD", "")
    pieces = (_sanitizer_runtime(), preload, paths["shim"])
    env["LD_PRELOAD"] = " ".join(value for value in pieces if value)
    env["XRD_RACE_DELAY_US"] = str(SHIM_DELAY_US)
    env.update(
        FRM_DATA_DIR=os.path.realpath(paths["datadir"]),
        FRM_TAPE_DIR=paths["tapedir"],
        FRM_LATENCY_MS=str(FRM_LATENCY_MS),
        FRM_AUDIT_LOG=paths["audit"],
    )
    _configure_sanitizer(env, paths)
    return env


def _configure_sanitizer(env, paths):
    if SHIM_SAN == "thread":
        suppression = _write_tsan_suppression(paths)
        env["TSAN_OPTIONS"] = (
            "suppressions=%s:halt_on_error=0:exitcode=0:"
            "history_size=4:log_path=%s/tsan"
            % (suppression, paths["tsandir"])
        )
    elif SHIM_SAN == "address":
        env["ASAN_OPTIONS"] = (
            "detect_leaks=0:abort_on_error=1:halt_on_error=1:"
            "verify_asan_link_order=0"
        )


def _write_tsan_suppression(paths):
    suppression = os.path.join(paths["workdir"], "tsan.supp")
    with open(suppression, "w") as stream:
        stream.write(
            "race:ngx_atomic_\nrace:^brix_metrics_\nrace:ngx_thread_pool_cycle\n"
            "race:ngx_time_update\nrace:ngx_event_\ncalled_from_lib:libssl\n"
            "called_from_lib:libcrypto\ncalled_from_lib:libjansson\n"
        )
    return suppression


def _server_spec(paths, env):
    return NginxInstanceSpec(
        name="evil-actor-v3",
        template="nginx_evil_actor_v3.conf",
        protocol="root",
        data_root=paths["datadir"],
        readiness="tcp",
        template_values={
            "WORKERS": WORKERS,
            "BIND_HOST": BIND_HOST,
            "CERT": paths["cert"],
            "KEY": paths["key"],
            "FRM_BLOCK": _frm_block(paths),
        },
        env=env,
    )


def _start_evil_server(paths):
    harness = LifecycleHarness()
    try:
        return harness, harness.start(
            _server_spec(paths, _launch_environment(paths))
        )
    except Exception as error:
        harness.close()
        shutil.rmtree(paths["workdir"], ignore_errors=True)
        pytest.skip("nginx did not start: %s" % str(error)[-400:])


def _make_service(paths, endpoint):
    ports = (
        endpoint.port,
        endpoint.extra_ports["ROOT_TLS_PORT"],
        endpoint.extra_ports["HTTPS_PORT"],
        endpoint.extra_ports["METRICS_PORT"],
    )
    service = _Srv(
        endpoint.prefix, endpoint.config, endpoint.pidfile, ports,
        paths["datadir"], paths["tsandir"],
    )
    service.master = _master_pid(endpoint.pidfile)
    service.have_xattr = paths["have_xattr"]
    service.near_names = paths["near_names"]
    service.audit = paths["audit"]
    service.queue = paths["queue"]
    service.frm_ok = _frm_available(service, ports[3])
    return service


def _frm_available(service, metrics_port):
    if not service.have_xattr:
        return False
    try:
        request = __import__("urllib.request", fromlist=["request"])
        with request.urlopen(
            "http://%s:%d/metrics" % (HOST, metrics_port), timeout=5
        ) as response:
            return b"brix_frm_" in response.read()
    except Exception:
        return False


def _require_live_master(service, harness, paths):
    if service.master and _alive(service.master):
        return
    harness.close()
    shutil.rmtree(paths["workdir"], ignore_errors=True)
    pytest.skip("master pid never appeared")


def _print_server_details(service, paths):
    print(
        "\n[evil3] master=%d root=%d roots_tls=%d https=%d metrics=%d shim=%s "
        "delay=%dus workers=%s xattr=%s"
        % (
            service.master, service.root_port, service.root_tls_port,
            service.https_port, service.metrics_port, SHIM_SAN or "plain",
            SHIM_DELAY_US, _workers(service.master), paths["have_xattr"],
        )
    )


@pytest.fixture(scope="module")
def srv():
    _require_evil_actor_prerequisites()
    paths = _prepare_scratch()
    harness, endpoint = _start_evil_server(paths)
    service = _make_service(paths, endpoint)
    _require_live_master(service, harness, paths)
    _print_server_details(service, paths)
    try:
        yield service
    finally:
        harness.close()
        shutil.rmtree(paths["workdir"], ignore_errors=True)


# ----------------------- A1: roots:// TLS bring-up ---------------------------

def _tls_available(srv):
    try:
        t = _roots_tls_connect(srv.root_tls_port)
        t.close()
        return True
    except Exception:
        return False


# ----------------------- A2: TLS disconnect-mid-AIO --------------------------

# ----------------------- B6: cross-worker bind -------------------------------

# ----------------- B7: bind-vs-teardown TOCTOU + handle ABA ------------------

# ------------- C1: FRM async asynresp deliver-into-recycled-conn -------------

def _frm_skip(srv):
    if not srv.have_xattr:
        pytest.skip("filesystem lacks user xattrs (FRM residency)")
    if not srv.frm_ok:
        pytest.skip("FRM not compiled/enabled (nearline open not intercepted)")


# ------------- C2: FRM reqid forgery — owner check ---------------------------

# ------------------------- C3: FRM admission flood ---------------------------

# --------------------------- D: chaos capstone -------------------------------

__all__ = [n for n in dir() if not n.startswith('__')]
