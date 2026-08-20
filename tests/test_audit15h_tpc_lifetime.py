"""
test_audit15h_tpc_lifetime.py — the two native-TPC lifetime kill-switches
(audit §A2 "TPC lifetime enforcement": `brix_tpc_max_transfer_secs` and
`brix_tpc_transfer_max_age`, both with zero coverage of any kind).

These are the only two directives in the TPC surface whose job is to end a
transfer that has stopped being worth waiting for.  Everything else in the TPC
suite drives transfers that behave: a local source, a fast loopback link, a
prompt completion.  A kill-switch is by construction untestable against a
well-behaved transfer, which is exactly why both were still at zero after seven
tranches — each needs a pull that is deliberately made pathological.

`brix_tpc_max_transfer_secs` is the wall-clock cap on a whole pull, checked
once per 1 MiB kXR_read window rather than per frame (`tpc_stream_to_dst`,
tpc/outbound/source_stream.c:261-278).  Its documented purpose is the case a
per-recv idle timeout cannot catch: a source that keeps delivering bytes, just
far too slowly, resetting the 60s `TPC_IO_TIMEOUT_SEC` on every read.  That is
reproduced here exactly — `brix-fault-proxy --rate` in front of an ordinary
source paces the byte stream to a fixed ceiling, so the link never goes idle
and only the wall-clock cap can end it.

`brix_tpc_transfer_max_age` is the abandoned-slot reaper for the 1024-entry SHM
transfer registry.  It is where **DEFECT CANDIDATE #22** lives.

THE FINDING — DEFECT CANDIDATE #22.  `brix_tpc_transfer_max_age` cannot reclaim
an abandoned slot until the registry is COMPLETELY FULL.  The reap is driven
from exactly one place: `brix_tpc_registry_add` runs
`brix_tpc_registry_reap_locked` only after failing to find a free slot among
all 1024 (tpc/common/registry.c:290-303).  The function written to be called on
a timer — `brix_tpc_registry_reap_stale()`, whose own comment says "intended
for a coarse timer" (registry.c:218-224) — **has no callers anywhere in the
tree**.  So a site that sets `brix_tpc_transfer_max_age 300` to bound stale
transfers gets nothing at all until slot 1024 is refused; until then every
leaked entry is reported as an active transfer by the dashboard and by metrics,
forever.  The leak is not hypothetical: a registry entry is created on the
destination's pull sync (`launch.c:392`) and removed by the completion callback
(`done.c:59`), so a worker that dies between the two — OOM-killed, crashed,
`kill -9` — leaves its slots behind with no owner to remove them.  That is
precisely the "flood of stalled transfers self-heals" case the directive's own
comment claims to cover.

Fails OPEN (a stale row is reported as live, a full registry 503s new
transfers), and it is unobservable from the client, which is why it is pinned
here from the dashboard's registry snapshot rather than from a wire outcome.

Cases:
  * success      — a healthy pull under the cap completes on the capped plane:
                   the kill-switch does not fire on a transfer that behaves
  * error        — the same pull, paced below the cap, is killed mid-transfer
                   and the error names the directive
  * control      — the identical paced pull COMPLETES on the uncapped plane,
                   which is what makes the kill above attributable to the cap
  * success      — a completed pull leaves no row in the TPC registry (the
                   normal removal path works, so the pin below is about the
                   reaper and not about removal in general)
  * defect pin   — a slot orphaned by a dead worker is still reported active
                   long after `brix_tpc_transfer_max_age`, because nothing
                   calls the periodic reaper (#22)
  * sec-negative — the cap is a hard stop, not a pause: the killed transfer's
                   destination object is not published
"""

import json
import os
import signal
import socket
import struct
import subprocess
import time
import urllib.request

import pytest

from server_registry import NginxInstanceSpec
from settings import HOST, BIND_HOST, NGINX_BIN
from _test_a_robustness_helpers import make_close_req
from _test_audit15g_helpers import (
    XERR_NOT_FOUND, open_fails, pattern, seed_tree, wait_until)
from test_audit15c_tpc_token_exchange import _drive_pull
from test_phase25_ratelimit import KXR_OK, _xrd_login, _xrd_open, _xrd_recv_status

pytestmark = [pytest.mark.timeout(180),
              pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-audit15h-tpclife")]

NAME = "lc-audit15h-tpclife"

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLIENT_DIR = os.path.join(REPO, "client")
BFP = os.path.join(CLIENT_DIR, "bin", "brix-fault-proxy")

KXR_ERROR = 4003
XERR_IO_ERROR = 3007        # what kXR_IOError becomes on the wire
# The TPC destination open: kXR_new | kXR_open_wrto | kXR_mkpath.
TPC_FLAGS = 0x0008 | 0x4000 | 0x0100

# 4 MiB against a 512 KiB/s ceiling is an 8s transfer under a 2s cap, so the
# kill lands at a 1 MiB chunk boundary two thirds of the way in — genuinely
# mid-transfer, with bytes already written, rather than at the EOF probe.
SEED = pattern(4 * 1024 * 1024, 0x15)
RATE_KBPS = 512
SRC_LFN = "/src.bin"


# --------------------------------------------------------------------------- #
# the instance, the paced link, and the pull driver
# --------------------------------------------------------------------------- #

@pytest.fixture(scope="module")
def _proxy_built():
    proc = subprocess.run(["make", "-C", CLIENT_DIR, "brix-fault-proxy"],
                          capture_output=True, text=True, timeout=240)
    if proc.returncode != 0 or not os.path.exists(BFP):
        pytest.skip(f"brix-fault-proxy build failed:\n{proc.stdout}\n{proc.stderr}")
    return BFP


@pytest.fixture
def tpclife(lifecycle, tmp_path):
    """(endpoint, dirs) — source, capped destination, uncapped destination and
    an anonymous dashboard, all under one master so they share the SHM TPC
    registry the last two tests read."""
    if not os.path.exists(NGINX_BIN):
        pytest.skip(f"nginx binary not found at {NGINX_BIN}")

    dirs = {name: tmp_path / name for name in ("src", "cap", "free")}
    for path in dirs.values():
        path.mkdir()
        os.chmod(path, 0o777)
    os.chmod(tmp_path, 0o777)
    seed_tree(dirs["src"], {SRC_LFN: SEED})

    endpoint = lifecycle.start(NginxInstanceSpec(
        name=NAME,
        template="nginx_audit15h_tpclife.conf",
        protocol="root",
        readiness="tcp",
        data_root=str(dirs["src"]),
        template_values={"BIND_HOST": BIND_HOST,
                         "SRC_DIR": str(dirs["src"]),
                         "CAP_DIR": str(dirs["cap"]),
                         "FREE_DIR": str(dirs["free"])},
        reason="audit-15h TPC lifetime kill-switches"))
    return endpoint, dirs


def _free_port():
    from ephemeral_port import free_port
    return free_port(BIND_HOST)


@pytest.fixture
def paced(_proxy_built):
    """A factory for a rate-limited relay in front of the source.

    A bandwidth ceiling rather than `drip`/`latency` on purpose: the cap exists
    for a source that never stops sending, so the fault has to keep the link
    busy.  Both directions are paced, which costs the ~1 KiB kXR handshake a
    negligible fraction of a second at this ceiling."""
    procs = []

    def _start(upstream_port, *, kbps=RATE_KBPS):
        listen, control = _free_port(), _free_port()
        proc = subprocess.Popen(
            [BFP, "--listen", str(listen),
             "--target", f"{HOST}:{upstream_port}",
             "--control", str(control),      # required by the CLI even unused
             "--rate", str(kbps), "--quiet"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        procs.append(proc)
        wait_until(lambda: _port_open(listen), timeout=10,
                   what="the fault proxy listener")
        return listen

    yield _start
    for proc in procs:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


def _port_open(port):
    try:
        with socket.create_connection((HOST, port), timeout=0.25):
            return True
    except OSError:
        return False


def _key(tag):
    """Rendezvous keys live in a SHM registry shared by every worker and every
    test in this instance, so each pull mints its own."""
    return f"a15h{tag}{int(time.monotonic() * 1000) % 1000000}"


def _arm(port, key):
    """Client leg 1: a read-open carrying tpc.key + tpc.dst registers the key on
    the source.  Returned rather than closed — the arm has to outlive the pull
    that consumes it."""
    sock = _xrd_login(HOST, port)
    sock.settimeout(120)
    status, body = _xrd_open(
        sock, f"{SRC_LFN}?tpc.key={key}&tpc.dst={HOST}&tpc.stage=placement")
    assert status == KXR_OK, ("TPC source arm refused", status, body)
    return sock


def _open_frame(sock, path, flags, mode=0o644):
    payload = path.encode()
    sock.sendall(struct.pack(">BBH", 0, 1, 3010)
                 + struct.pack(">HH12s", mode, flags, b"\x00" * 12)
                 + struct.pack(">I", len(payload)) + payload)
    return _xrd_recv_status(sock)


def _pull(dst_port, src_port, dest, *, tag="x", arm_port=None):
    """Drive one native pull and return (status, body, elapsed_seconds).

    `arm_port` is the port the rendezvous is REGISTERED on and `src_port` the
    address the destination dials — the same server in every test here, but
    different values whenever the fault proxy is spliced in, because the key
    lives on the source while the bytes come through the relay."""
    key = _key(tag)
    armed = _arm(arm_port if arm_port is not None else src_port, key)
    sock = _xrd_login(HOST, dst_port)
    sock.settimeout(120)
    started = time.monotonic()
    try:
        opaque = (f"?tpc.src={HOST}:{src_port}&tpc.key={key}"
                  f"&tpc.lfn={SRC_LFN}&tpc.stage=copy&oss.asize={len(SEED)}")
        status, body = _open_frame(sock, dest + opaque, TPC_FLAGS)
        if status != KXR_OK:
            return status, body, time.monotonic() - started
        fhandle = body[:4]
        status, body = _drive_pull(sock, fhandle)
        if status != KXR_OK:
            return status, body, time.monotonic() - started
        sock.sendall(make_close_req(fhandle))
        status, body = _xrd_recv_status(sock)
        return status, body, time.monotonic() - started
    finally:
        sock.close()
        armed.close()


def _errcode(body):
    return struct.unpack("!I", body[:4])[0] if len(body) >= 4 else -1


def _snapshot(port):
    """The v1 snapshot, or None while no worker is up to serve it — the defect
    pin below deliberately kills every worker, and the master's respawn is not
    instantaneous."""
    try:
        with urllib.request.urlopen(
                f"http://{HOST}:{port}/brix/api/v1/snapshot", timeout=10) as resp:
            return json.loads(resp.read().decode())
    except (OSError, ValueError):
        return None


def _registry_ids(port):
    """The set of transfer ids the TPC registry is currently publishing.

    Ids rather than paths on purpose: this dashboard is anonymous, and
    `brix_dashboard_anonymous` redacts `source` to "[redacted]" and
    `destination` to "" (api_transfers.c:320-325).  The id is minted per
    registry slot and is not redacted, which makes it the only stable handle on
    a specific row — and identity is all these two tests need."""
    snap = _snapshot(port)
    rows = (snap or {}).get("tpc_transfers")
    if not isinstance(rows, list):
        return set()
    return {row.get("id") for row in rows if row.get("id")}


def _server_msec(port):
    """The server's own `ngx_current_msec`, published as `server_ms`.

    The pin below has to prove that real time passed ON THE SERVER, and it
    cannot do that with a client-side sleep: this host's wall clock is known to
    step backwards (see the `wsl2-clock-backwards-steps` note), and a sleep
    would in any case only prove the *test* waited."""
    snap = _snapshot(port)
    return None if snap is None else snap.get("server_ms")


def _log(endpoint):
    path = os.path.join(endpoint.prefix, "logs", "error.log")
    if not os.path.exists(path):
        return ""
    with open(path, errors="replace") as fh:
        return fh.read()


def _tree(root):
    """Every regular file under `root`, relative.  brix's own bookkeeping is
    excluded: every export root gets a `.nginx-xrootd-ckp-recovery.lock` at
    worker init, so an export that has stored nothing is not an empty dir."""
    out = {}
    for dirpath, _dirs, files in os.walk(str(root)):
        for name in files:
            if name.startswith(".nginx-xrootd-"):
                continue
            full = os.path.join(dirpath, name)
            out[os.path.relpath(full, str(root))] = os.path.getsize(full)
    return out


# --------------------------------------------------------------------------- #

def test_a_healthy_pull_under_the_cap_completes(tpclife):
    """success (control): the capped plane, dialled directly, with no pacing.
    4 MiB across loopback is well under 2s, so the cap must not fire — without
    this every failure below could just mean "this plane cannot pull"."""
    endpoint, dirs = tpclife
    ports = endpoint.extra_ports
    status, body, elapsed = _pull(endpoint.port, ports["SRC_PORT"],
                                  "/fast.bin", tag="fast")

    assert status == KXR_OK, (status, body, _log(endpoint)[-2000:])
    assert elapsed < 2.0, f"the control pull was not fast: {elapsed:.1f}s"
    assert (dirs["cap"] / "fast.bin").read_bytes() == SEED


def test_a_pull_slower_than_the_cap_is_killed_mid_transfer(tpclife, paced):
    """error: the directive's whole purpose.  The relay paces the source to
    512 KiB/s, so the 4 MiB object needs ~8s against a 2s cap while the link
    stays continuously busy — the per-recv 60s idle timeout can never fire, and
    only the wall-clock cap can end this.

    The elapsed-time assertion is the one that proves the cap acted rather than
    something else failing: a kill takes a bit over the cap (it is sampled at
    1 MiB boundaries), and far less than the ~8s the transfer needs.

    The diagnosis is asserted on the WIRE rather than in error.log: the cap
    writes its reason into `t->err_msg` and returns it in the kXR_error body
    (source_stream.c:271-277) — it is not logged at all, so the operator's only
    copy of "which directive ended my transfer" is the one the client got."""
    endpoint, _dirs = tpclife
    ports = endpoint.extra_ports
    relay = paced(ports["SRC_PORT"])

    status, body, elapsed = _pull(endpoint.port, relay, "/slow.bin",
                                  tag="slow", arm_port=ports["SRC_PORT"])

    assert status == KXR_ERROR, ("the cap did not fire", status, body, elapsed)
    assert 2.0 <= elapsed < 7.5, \
        f"killed at {elapsed:.1f}s — not at the 2s cap boundary"
    assert _errcode(body) == XERR_IO_ERROR, (_errcode(body), body)
    assert b"brix_tpc_max_transfer_secs" in body, body
    # ...and at a chunk boundary in the middle, not at the EOF probe: the pull
    # names the offset it died at, and it must not be the whole object.
    assert b"at offset 0" not in body, ("killed before a byte moved", body)


def test_the_same_slow_pull_completes_where_the_cap_is_absent(tpclife, paced):
    """control, and the load-bearing one: the identical paced pull into the
    plane that carries NEITHER kill-switch.  It has to complete — otherwise the
    kill above is a statement about a slow link, not about the directive."""
    endpoint, dirs = tpclife
    ports = endpoint.extra_ports
    relay = paced(ports["SRC_PORT"])

    status, body, elapsed = _pull(ports["FREE_PORT"], relay, "/slow-ok.bin",
                                  tag="free", arm_port=ports["SRC_PORT"])

    assert status == KXR_OK, (status, body, elapsed, _log(endpoint)[-2000:])
    assert elapsed > 2.0, \
        f"the control pull finished in {elapsed:.1f}s — it was not actually paced"
    assert (dirs["free"] / "slow-ok.bin").read_bytes() == SEED


def test_a_killed_transfer_publishes_nothing(tpclife, paced):
    """security-negative: the cap is a hard stop, not a pause.  A destination
    object is published by the handle close, and a capped pull never gets
    there — so a later reader must not find a truncated `slow.bin` sitting in
    the export looking like a complete object.

    This is the failure mode that has no client-side symptom: the pull reported
    an error to the caller who issued it, and anyone who arrives afterwards
    sees only a file.  `tpc_done_teardown_dst` (done.c) exists to close and
    unlink the partial destination on every failure path, and a kill by the
    wall-clock cap is one of them — so the export must be clean and the next
    reader must be told the object is not there, not handed 2 MiB of it."""
    endpoint, dirs = tpclife
    ports = endpoint.extra_ports
    relay = paced(ports["SRC_PORT"])

    status, _body, _elapsed = _pull(endpoint.port, relay, "/killed.bin",
                                    tag="kill", arm_port=ports["SRC_PORT"])
    assert status == KXR_ERROR, "the cap did not fire; nothing to assert about"

    published = _tree(dirs["cap"])
    assert "killed.bin" not in published, (
        "a capped pull left its partial destination in the export", published)
    assert open_fails(endpoint.port, "/killed.bin") == XERR_NOT_FOUND, \
        "a reader was served the remains of a killed transfer"


def test_a_completed_transfer_leaves_no_registry_row(tpclife):
    """success: the removal path works.  Establishes that the registry empties
    on a normal completion, so the pin below is a statement about the REAPER
    and not about rows never being removed at all."""
    endpoint, _dirs = tpclife
    ports = endpoint.extra_ports
    before = _registry_ids(ports["DASH_PORT"])

    status, body, _elapsed = _pull(endpoint.port, ports["SRC_PORT"],
                                   "/clean.bin", tag="clean")
    assert status == KXR_OK, (status, body)

    # Removal is done by the completion callback that also answers the close,
    # so it has happened by now in every ordering — the poll only absorbs the
    # dashboard's own read of a table another worker just wrote.
    wait_until(lambda: not (_registry_ids(ports["DASH_PORT"]) - before),
               timeout=15, tick=0.5,
               what="the completed transfer's registry slot to be released")


def test_an_orphaned_registry_slot_outlives_max_age(tpclife, paced):
    """An abandoned registry slot is reclaimed after its configured max age.

    `brix_tpc_transfer_max_age 1` is configured on this
    instance.  A pull is started through the paced relay so it is guaranteed to
    still be running, then the worker that owns it is SIGKILLed: the registry
    row is in SHM and its completion callback will never run.  The periodic
    reaper must reclaim it without requiring the registry to become full.

    Killing a worker is the honest reproduction rather than a shortcut: it is
    exactly the "abandoned slot" the directive's own comment describes, and it
    is the only way to abandon one without the process that owns it noticing.
    The master respawns the worker, so the plane is serving again immediately —
    the leak survives that too, which is the point.

    The wait afterwards is measured on the SERVER's clock (`server_ms`), not by
    sleeping: a client-side sleep would only prove the test waited, and this
    host's wall clock is known to step backwards.

    INVERT WHEN FIXED: `leaked - _registry_ids(...)` becomes the assertion —
    the orphaned ids must all be gone once max_age has elapsed."""
    endpoint, _dirs = tpclife
    ports = endpoint.extra_ports
    relay = paced(ports["SRC_PORT"], kbps=64)   # ~64s for 4 MiB: it cannot finish
    before = _registry_ids(ports["DASH_PORT"])

    key = _key("orphan")
    armed = _arm(ports["SRC_PORT"], key)
    sock = _xrd_login(HOST, ports["FREE_PORT"])   # uncapped: no cap may end it
    sock.settimeout(30)
    try:
        opaque = (f"?tpc.src={HOST}:{relay}&tpc.key={key}"
                  f"&tpc.lfn={SRC_LFN}&tpc.stage=copy&oss.asize={len(SEED)}")
        status, body = _open_frame(sock, "/orphan.bin" + opaque, TPC_FLAGS)
        assert status == KXR_OK, (status, body)
        fhandle = body[:4]
        # One sync arms the pull, the second starts it.  The second is NOT read
        # back: it only answers when the transfer ends, and this transfer is
        # about to be orphaned instead.
        sock.sendall(_sync_req(fhandle))
        assert _xrd_recv_status(sock)[0] == KXR_OK
        sock.sendall(_sync_req(fhandle))

        leaked = wait_until(
            lambda: _registry_ids(ports["DASH_PORT"]) - before,
            timeout=20, tick=0.25,
            what="the pull to appear in the TPC registry")

        killed = _kill_a_worker(endpoint)
        assert killed, "no worker to kill — the plane is not running as expected"
    finally:
        sock.close()
        armed.close()

    # max_age is 1s; give the server an order of magnitude more than that, and
    # read the elapsed time off the server so a respawn gap or a clock step
    # cannot shorten it.
    _wait_server_seconds(ports["DASH_PORT"], 12)

    # The periodic reaper must remove orphaned rows without a subsequent add.
    survivors = leaked & _registry_ids(ports["DASH_PORT"])
    assert not survivors, (
        "orphaned registry slots survived brix_tpc_transfer_max_age",
        leaked, survivors)


def _wait_server_seconds(dash_port, seconds):
    """Block until the server's own millisecond clock has advanced by
    `seconds`, tolerating the window in which no worker is up to answer."""
    start = wait_until(lambda: _server_msec(dash_port), timeout=30, tick=0.25,
                       what="the dashboard to come back after the worker kill")
    wait_until(lambda: (_server_msec(dash_port) or 0) - start >= seconds * 1000,
               timeout=seconds + 30, tick=1.0,
               what=f"{seconds}s of server-side time")


def _sync_req(fhandle):
    """kXR_sync (3016) carrying the destination handle."""
    return (struct.pack(">BBH", 0, 1, 3016) + fhandle + b"\x00" * 12
            + struct.pack(">I", 0))


def _kill_a_worker(endpoint):
    """SIGKILL every worker of this instance's master; returns how many died.

    By pid file rather than by name: the suite runs many nginx masters at once,
    so a pkill would take out somebody else's fleet.  Every worker rather than
    a guessed one: the transfer's owner is whichever worker accepted the
    destination open, and nothing on the wire says which that was."""
    with open(endpoint.pidfile) as fh:
        master = int(fh.read().strip())
    killed = 0
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        try:
            with open(f"/proc/{entry}/stat") as fh:
                # comm can contain spaces and parens; ppid is the field after
                # the state letter that follows the closing paren.
                stat = fh.read()
            ppid = int(stat[stat.rindex(")") + 2:].split()[1])
        except (OSError, ValueError):
            continue
        if ppid == master:
            try:
                os.kill(int(entry), signal.SIGKILL)
                killed += 1
            except OSError:
                pass
    return killed
