"""
test_lifecycle_speed.py — guards the startup/shutdown speed work.

Registry-backed: each test provisions its OWN minimal nginx-xrootd instance
through the `lifecycle` harness (template `nginx_lifecycle_speed.conf`, own
self-signed cert, OS-assigned ports), so it does not depend on the shared test
fleet (and never collides with it). It validates by parsing the module's
permanent per-phase summary lines:

    xrootd postconfig: prepare=... total=...
    xrootd init_process[wN]: uring=... servers=... keypool=... total=...

What it asserts:
  * the permanent phase instrumentation is emitted and well-formed;
  * the lazy GSI keypool path: with a thread pool only a small seed is generated
    synchronously (fast boot) and the pool then fills to its target off-thread;
  * the safety fallback: with NO thread pool the full target is warmed
    synchronously (unchanged behaviour);
  * brix_gsi_keypool_size is honoured (pool warms to the configured target).

These are timing/observability assertions; real GSI handshake correctness is
covered by test_gsi_handshake.py / test_gsi_concurrency.py against the fleet.
"""

import os
import re
import subprocess
import time

import pytest

import settings
from server_registry import NginxInstanceSpec
from settings import NGINX_BIN

pytestmark = pytest.mark.skipif(
    not os.path.isfile(NGINX_BIN),
    reason=f"nginx binary not built at {NGINX_BIN}",
)


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
    """A throwaway registry-backed nginx-xrootd instance."""

    def __init__(self, harness, base, name, with_thread_pool=True,
                 keypool_size=None, keypool_seed=None, workers=1):
        data = base / "data"
        data.mkdir(parents=True, exist_ok=True)
        # nginx master may run as root here, so the worker drops to the
        # built-in 'nobody' user. The worker's checkpoint-recovery writes a
        # lock INSIDE the export, so the export must be writable by that
        # worker (the fleet exports are 0777 for the same reason). Without
        # this the worker fails the recovery lock with EACCES and exits before
        # it can log the init_process/keypool phase lines these tests assert
        # on (the master still holds the listen socket, so TCP readiness
        # succeeds regardless).
        os.chmod(data, 0o777)
        crt = base / "host.crt"
        key = base / "host.key"
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
             "-days", "1", "-keyout", str(key), "-out", str(crt),
             "-subj", "/CN=lifecycle-test"],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        knobs = ""
        if keypool_size is not None:
            knobs += f"        brix_gsi_keypool_size {keypool_size};\n"
        if keypool_seed is not None:
            knobs += f"        brix_gsi_keypool_seed {keypool_seed};\n"
        (gsi_port,) = settings.free_ports(1)
        endpoint = harness.start(
            NginxInstanceSpec(
                name=name,
                template="nginx_lifecycle_speed.conf",
                data_root=str(data),
                extra_ports={"GSI_PORT": gsi_port},
                template_values={
                    "WORKERS": workers,
                    "THREAD_POOL_LINE": (
                        "thread_pool default threads=4 max_queue=512;"
                        if with_thread_pool else ""
                    ),
                    "CERT": str(crt),
                    "KEY": str(key),
                    "GSI_KNOBS": knobs,
                },
                reason="startup/shutdown speed instrumentation coverage",
            )
        )
        self.elog = os.path.join(endpoint.prefix, "logs", "error.log")


# Module-wide counter: registry prefixes live under a per-name directory whose
# error.log appends across starts, so every instance in this module needs a
# distinct name or a later test would match phase lines from an earlier one.
_SEQ = iter(range(10_000))


@pytest.fixture
def instance(lifecycle, tmp_path):
    def _make(**kw):
        name = f"lc-speed-{next(_SEQ)}"
        return Instance(lifecycle, tmp_path / name, name, **kw)

    yield _make
    # Teardown (stop + unregister) is owned by the lifecycle fixture.


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

    # The synchronous portion of init must reflect a small seed (4 keys), not a
    # full synchronous warm of all 64.  The "seeded 4/64 (rest filling
    # off-thread)" line above is the deterministic proof the lazy path engaged;
    # this timing check is only a coarse guard that the synchronous cost is that
    # of a 4-key seed and not a full 64-key warm.  The threshold is deliberately
    # generous: 4-key seed time can spike to well over the sub-ms typical under
    # concurrent CI load, whereas a regression that warmed all 64 synchronously
    # would cost ~16x more and blow well past this bound.
    init = _wait_for(inst.elog, r"init_process\[w\d+\]: .*keypool=(\d+)us")
    assert init is not None
    keypool_us = int(init.group(1))
    assert keypool_us < 50000, f"keypool seed took {keypool_us}us; lazy path not engaged"


def test_keypool_synchronous_fallback_without_thread_pool(instance):
    """With no thread pool there is nowhere to offload: warm the full target sync."""
    inst = instance(with_thread_pool=False, keypool_size=64)
    line = _wait_for(inst.elog,
                     r"GSI DH key pool seeded (\d+)/(\d+) keys \(synchronous, no thread pool\)")
    assert line is not None, "expected synchronous fallback log line"
    assert int(line.group(1)) == int(line.group(2)) == 64


def test_keypool_size_is_configurable(instance):
    """brix_gsi_keypool_size changes the warm target the pool fills to."""
    inst = instance(keypool_size=16, keypool_seed=2)
    warmed = _wait_for(inst.elog, r"GSI DH key pool warmed to (\d+)/(\d+) keys")
    assert warmed is not None
    assert int(warmed.group(2)) == 16, "configured keypool size not honoured"
