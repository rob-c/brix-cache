"""
test_lifecycle_speed.py — guards the startup/shutdown speed work.

Self-contained: each test provisions its OWN minimal nginx-xrootd instance (own
prefix, own self-signed cert, high ports) and drives the freshly-built objs/nginx
directly, so it does not depend on the shared test fleet (and never collides with
it). It validates by parsing the module's permanent per-phase summary lines:

    xrootd postconfig: prepare=... total=...
    xrootd init_process[wN]: uring=... servers=... keypool=... total=...

What it asserts:
  * the permanent phase instrumentation is emitted and well-formed;
  * the lazy GSI keypool path: with a thread pool only a small seed is generated
    synchronously (fast boot) and the pool then fills to its target off-thread;
  * the safety fallback: with NO thread pool the full target is warmed
    synchronously (unchanged behaviour);
  * xrootd_gsi_keypool_size is honoured (pool warms to the configured target).

These are timing/observability assertions; real GSI handshake correctness is
covered by test_gsi_handshake.py / test_gsi_concurrency.py against the fleet.
"""

import os
import re
import shutil
import socket
import subprocess
import time

import pytest

NGINX_BIN = os.environ.get("LIFECYCLE_NGINX_BIN", "/tmp/nginx-1.28.3/objs/nginx")

pytestmark = pytest.mark.skipif(
    not os.path.isfile(NGINX_BIN),
    reason=f"nginx binary not built at {NGINX_BIN}",
)


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def _wait_accept(port, timeout=15.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.02)
    return False


def _wait_for(elog, pattern, timeout=15.0):
    """Block until a regex appears in the error log; return the match or None."""
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
        time.sleep(0.05)
    return None


class Instance:
    """A throwaway nginx-xrootd instance built from a template."""

    def __init__(self, prefix, with_thread_pool=True, keypool_size=None,
                 keypool_seed=None, workers=1):
        self.prefix = prefix
        self.conf = os.path.join(prefix, "conf", "nginx.conf")
        self.elog = os.path.join(prefix, "logs", "error.log")
        self.port_anon = _free_port()
        self.port_gsi = _free_port()
        self._build(with_thread_pool, keypool_size, keypool_seed, workers)

    def _build(self, with_pool, size, seed, workers):
        for sub in ("conf", "logs", "data"):
            os.makedirs(os.path.join(self.prefix, sub), exist_ok=True)
        crt = os.path.join(self.prefix, "conf", "host.crt")
        key = os.path.join(self.prefix, "conf", "host.key")
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
             "-days", "1", "-keyout", key, "-out", crt,
             "-subj", "/CN=lifecycle-test"],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        pool_line = ("thread_pool default threads=4 max_queue=512;"
                     if with_pool else "")
        knobs = ""
        if size is not None:
            knobs += f"        xrootd_gsi_keypool_size {size};\n"
        if seed is not None:
            knobs += f"        xrootd_gsi_keypool_seed {seed};\n"
        with open(self.conf, "w") as fh:
            fh.write(f"""\
worker_processes {workers};
daemon on;
pid {self.prefix}/logs/nginx.pid;
error_log {self.elog} notice;
{pool_line}
events {{ worker_connections 1024; }}
stream {{
    server {{
        listen {self.port_anon};
        xrootd on;
        xrootd_root {self.prefix}/data;
        xrootd_auth none;
    }}
    server {{
        listen {self.port_gsi};
        xrootd on;
        xrootd_root {self.prefix}/data;
        xrootd_auth gsi;
        xrootd_certificate     {self.prefix}/conf/host.crt;
        xrootd_certificate_key {self.prefix}/conf/host.key;
        xrootd_trusted_ca      {self.prefix}/conf/host.crt;
{knobs}    }}
}}
""")

    def start(self):
        subprocess.run([NGINX_BIN, "-p", self.prefix, "-c", self.conf],
                       check=True)
        assert _wait_accept(self.port_anon), "server never accepted connections"

    def stop(self):
        subprocess.run([NGINX_BIN, "-p", self.prefix, "-c", self.conf,
                        "-s", "stop"], stderr=subprocess.DEVNULL)


@pytest.fixture
def instance(tmp_path):
    insts = []

    def _make(**kw):
        inst = Instance(str(tmp_path / f"inst{len(insts)}"), **kw)
        inst.start()
        insts.append(inst)
        return inst

    yield _make
    for inst in insts:
        inst.stop()
    shutil.rmtree(str(tmp_path), ignore_errors=True)


def test_phase_instrumentation_emitted(instance):
    """The permanent postconfig + init_process summary lines are well-formed."""
    inst = instance()
    post = _wait_for(inst.elog, r"xrootd postconfig: .*total=(\d+)us")
    init = _wait_for(inst.elog,
                     r"xrootd init_process\[w\d+\]: .*keypool=(\d+)us .*total=(\d+)us")
    assert post is not None, "no postconfig phase line"
    assert init is not None, "no init_process phase line"
    assert int(post.group(1)) >= 0
    assert int(init.group(2)) >= 0


def test_lazy_keypool_fast_boot_with_thread_pool(instance):
    """With a thread pool: only a small seed is synchronous; pool fills off-thread."""
    inst = instance(keypool_size=64, keypool_seed=4)
    seed = _wait_for(inst.elog,
                     r"GSI DH key pool seeded (\d+)/(\d+) keys \(rest filling off-thread\)")
    assert seed is not None, "expected lazy seed log line"
    assert int(seed.group(1)) == 4
    assert int(seed.group(2)) == 64

    warmed = _wait_for(inst.elog, r"GSI DH key pool warmed to (\d+)/(\d+) keys")
    assert warmed is not None, "pool did not finish filling off-thread"
    assert int(warmed.group(1)) == 64

    # The synchronous portion of init must be small (only the seed was generated).
    init = _wait_for(inst.elog, r"init_process\[w\d+\]: .*keypool=(\d+)us")
    assert init is not None
    keypool_us = int(init.group(1))
    assert keypool_us < 8000, f"keypool seed took {keypool_us}us; lazy path not engaged"


def test_keypool_synchronous_fallback_without_thread_pool(instance):
    """With no thread pool there is nowhere to offload: warm the full target sync."""
    inst = instance(with_thread_pool=False, keypool_size=64)
    line = _wait_for(inst.elog,
                     r"GSI DH key pool seeded (\d+)/(\d+) keys \(synchronous, no thread pool\)")
    assert line is not None, "expected synchronous fallback log line"
    assert int(line.group(1)) == int(line.group(2)) == 64


def test_keypool_size_is_configurable(instance):
    """xrootd_gsi_keypool_size changes the warm target the pool fills to."""
    inst = instance(keypool_size=16, keypool_seed=2)
    warmed = _wait_for(inst.elog, r"GSI DH key pool warmed to (\d+)/(\d+) keys")
    assert warmed is not None
    assert int(warmed.group(2)) == 16, "configured keypool size not honoured"
