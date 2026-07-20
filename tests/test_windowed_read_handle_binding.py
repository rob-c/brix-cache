"""
Windowed-read handle binding regression tests (fast-lane burndown 2026-07).

The kXR_read windowed pump (brix_read_window_pump) shares one reusable AIO
task struct per session with the single-shot buffered path (read_post_aio).
The worker routes the pread through the task's storage object (t->obj) when a
driver is bound — and the obj carries its own fd — so a pump post that does
not rebind t->obj/t->csi executes the window against the PREVIOUS read's
handle: the previous cycle's fd (wrong file once the number is recycled by a
concurrent connection, EBADF once it is closed or write-only) and a dangling
CSI record.  Single-connection runs mask the bug because the freed fd number
is usually handed straight back to the next open.

Trio per CLAUDE.md:
  * success      — concurrent write→read cycles, full-file (read-to-EOF)
                   windowed reads byte-exact under fd-number recycling
  * error        — a read that cannot be served fails with a clean kXR error
                   and the connection survives for the next operation
  * security-neg — a connection must never receive another connection's file
                   content through a recycled descriptor (cross-file bleed)
"""

import hashlib
import threading

import pytest
from XRootD import client
from XRootD.client.flags import OpenFlags
from settings import NGINX_ANON_PORT, SERVER_HOST

pytestmark = pytest.mark.timeout(240)

ANON_URL = f"root://{SERVER_HOST}:{NGINX_ANON_PORT}"

# Bigger than one streaming window (2 MiB) so the read-to-EOF request is served
# by the windowed pump; the +123 tail keeps EOF off any block boundary.
BIG = 4 * 1024 * 1024
TAIL = 123


def _payload(tag: str, cycle: int) -> bytes:
    """Per-worker, per-cycle unique bytes so a read served from the wrong
    file (a stale-fd hit on a recycled descriptor) can never verify."""
    out = bytearray()
    seed = 0
    salt = f"{tag}#{cycle}".encode()
    while len(out) < BIG + TAIL:
        out += hashlib.sha256(salt + seed.to_bytes(8, "little")).digest()
        seed += 1
    return bytes(out[: BIG + TAIL])


def _write_file(remote: str, payload: bytes) -> None:
    w = client.File()
    status, _ = w.open(f"{ANON_URL}/{remote}", OpenFlags.DELETE | OpenFlags.NEW)
    assert status.ok, f"open for write failed: {status.message}"
    status, _ = w.write(payload)
    assert status.ok, f"write failed: {status.message}"
    w.close()


def _cycle(tag: str, cycle: int, errors: list) -> None:
    """One write→read cycle: the buffered read arms the shared task's obj/csi,
    the following read-to-EOF windowed read must not inherit them."""
    payload = _payload(tag, cycle)
    remote = f"/test_winread_bind_{tag}.bin"
    _write_file(remote, payload)

    r = client.File()
    status, _ = r.open(f"{ANON_URL}/{remote}", OpenFlags.READ)
    if not status.ok:
        errors.append(f"[{tag}#{cycle}] open-r: {status.message}")
        return
    # (offset, size, expected-slice); size 0 = read to EOF (windowed serve).
    plan = (
        (0, 0, payload),
        (0, BIG, payload[:BIG]),
        (BIG - 4096, 8 * BIG, payload[BIG - 4096:]),
    )
    for off, size, want in plan:
        status, data = r.read(offset=off, size=size)
        if not status.ok:
            errors.append(f"[{tag}#{cycle}] read off={off} size={size}: "
                          f"errno={status.errno} {status.message}")
            return
        if data != want:
            errors.append(f"[{tag}#{cycle}] WRONG DATA off={off} size={size}: "
                          f"got {len(data)} bytes")
            return
    r.close()


def _run_workers(tags, cycles: int) -> list:
    """Concurrent per-tag write→read cycles against one worker process: the
    close/open churn recycles fd numbers across connections, which is the
    trigger a stale task obj needs to hit the wrong descriptor."""
    errors: list = []
    threads = []
    for tag in tags:
        def work(t=tag):
            for i in range(cycles):
                if errors:
                    return
                _cycle(t, i, errors)
        th = threading.Thread(target=work, name=f"winread-{tag}")
        th.start()
        threads.append(th)
    for th in threads:
        th.join()
    return errors


# ---------------------------------------------------------------------------
# success — concurrent windowed reads stay byte-exact across handle churn.
# Pre-fix this failed within 1-3 cycles (kXR_IOError EBADF, or silently wrong
# bytes when the recycled fd pointed at a readable file).
# ---------------------------------------------------------------------------

def test_windowed_read_correct_under_concurrent_handle_churn():
    errors = _run_workers(("a", "b", "c"), cycles=10)
    assert not errors, "\n".join(errors)


# ---------------------------------------------------------------------------
# error — an unservable read fails with a clean kXR error and the connection
# (and its windowed-read machinery) survives for the next request.
# ---------------------------------------------------------------------------

def test_read_on_write_only_handle_fails_clean_and_connection_survives():
    payload = _payload("errcase", 0)
    remote = "/test_winread_bind_err.bin"
    _write_file(remote, payload)

    f = client.File()
    status, _ = f.open(f"{ANON_URL}/{remote}", OpenFlags.UPDATE)
    assert status.ok, f"open for update failed: {status.message}"

    # A read on the update handle is served from the write-side descriptor; it
    # must either succeed byte-exact or fail with a kXR error — never hang the
    # connection or return foreign bytes.
    status, data = f.read(offset=0, size=0)
    if status.ok:
        assert data == payload, "update-handle read returned wrong bytes"
    f.close()

    # The same physical connection must still serve a fresh windowed read.
    r = client.File()
    status, _ = r.open(f"{ANON_URL}/{remote}", OpenFlags.READ)
    assert status.ok, f"reopen after error case failed: {status.message}"
    status, data = r.read(offset=0, size=0)
    assert status.ok, f"windowed read after error case failed: {status.message}"
    assert data == payload, "windowed read after error case returned wrong bytes"
    r.close()


# ---------------------------------------------------------------------------
# security-neg — cross-file bleed: with distinct secrets per connection, no
# read may ever return another file's content through a recycled descriptor.
# ---------------------------------------------------------------------------

def test_windowed_read_never_bleeds_other_connections_file():
    errors = _run_workers(("s0", "s1"), cycles=8)
    bleeds = [e for e in errors if "WRONG DATA" in e]
    assert not errors, (
        ("CROSS-FILE BLEED: " if bleeds else "") + "\n".join(errors)
    )
