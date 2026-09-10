"""brix_cache_serve_while_filling — the XrdPfc serve-while-filling analog (§4.5).

Before this, whole-file cache mode was strictly foreground: every concurrent
reader of a cold object serialised behind ONE fill and paid the full object's
transfer time before its first byte.  With the knob set, a miss whose fill is
already in flight FOLLOWS that fill (``src/fs/backend/cache/sd_cache_follow.c``):
it reads the staged bytes below the fill frontier and is told to retry past it.

The coordination channel is deliberately a plain file — ``<local_root><key>``
plus ``.brixfill``, holding ``"<pid> <declared size> <staged path>"`` — so it
works across workers and processes with no SHM and no IPC.  That is what makes
the behaviour testable without racing anything: these tests PLANT a marker and a
staged file and then read through the cache, which drives the follower down
exactly the paths a real in-flight fill would.  A race would be untestable here
anyway (``worker_processes 1``, and the whole-file fill runs inline).

Coverage:
  success   — a follower serves the staged bytes, not the source bytes, and
              reports the DECLARED size rather than the staged frontier
              (the phase-107 C5 admission reserve uses
              fallocate(FALLOC_FL_KEEP_SIZE), so a staged file's st_size is the
              frontier, and reporting it would truncate the client)
  frontier  — a read past the frontier is kXR_wait, not an error or a short EOF
  error     — an ABORTED fill (staged unlinked under the follower) fails closed
              with kXR_IOError instead of passing a truncated object off as a
              clean EOF, and a filler that dies without withdrawing its marker
              is bounded by the no-progress deadline rather than hanging
  security  — a verifying export refuses to follow at all (staged bytes are
              PROVISIONAL under verify); a malformed marker is treated as
              absent; a marker naming a staged path OUTSIDE the cache store is
              refused rather than streamed to the client

Directive grammar accept/reject lives in tests/test_cache_directive_parse.py.

Run:
    PYTHONPATH=tests pytest tests/test_phase115_serve_while_filling.py -v
"""

import os
import struct
import subprocess
import time

import pytest

from _test_open_flags_lifecycle_helpers import (
    _close, _error_code, _open, _read, _session,
    kXR_IOError, kXR_ok, kXR_error, kXR_open_read, kXR_retstat,
)
from server_launcher import LifecycleHarness, NginxInstanceSpec
from settings import BIND_HOST, HOST

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_XRDCP = os.path.join(_REPO, "client", "bin", "xrdcp")

kXR_wait = 4005

# The no-progress deadline. Small so the stall test finishes quickly, but well
# clear of a loopback round trip so the frontier tests are not flaky.
_SWF = 2

pytestmark = [
    pytest.mark.timeout(240),
    pytest.mark.xdist_group("lc-cache-swf"),
]


# ---------------------------------------------------------------------------
# Fixtures — one plain instance and one verifying twin (the security negative)
# ---------------------------------------------------------------------------

def _spec(name, base, verify_line):
    data, cache, export = (base / "data", base / "cache", base / "export")
    for path in (data, cache, export, cache / "swf", export / "swf"):
        path.mkdir(parents=True, exist_ok=True)
    return NginxInstanceSpec(
        name=name,
        template="nginx_lc_cache_serve_while_filling.conf",
        protocol="root",
        template_values={
            "BIND_HOST": BIND_HOST,
            "DATA_ROOT": str(data),
            "CACHE_ROOT": str(cache),
            "EXPORT_ROOT": str(export),
            "SWF": str(_SWF),
            "VERIFY": verify_line,
        },
        reason="audit §4.5 serve-while-filling")


class _Node:
    """An instance plus the two directories the tests plant into and read from."""

    def __init__(self, port, base):
        self.port = port
        self.data = base / "data"          # the posix SOURCE
        self.store = base / "cache" / "swf"  # the cache store's local root


@pytest.fixture(scope="module")
def nodes(tmp_path_factory):
    harness = LifecycleHarness()
    made = {}
    try:
        for key, name, verify in (
            ("plain", "lc-cache-swf", ""),
            ("verify", "lc-cache-swf-verify",
             "        brix_cache_verify   best-effort;\n"),
        ):
            base = tmp_path_factory.mktemp(key)
            try:
                endpoint = harness.start(_spec(name, base, verify))
            except Exception as exc:                            # noqa: BLE001
                pytest.skip(f"{name} did not start: {exc}")
            made[key] = _Node(endpoint.port, base)
        yield made
    finally:
        harness.close()


@pytest.fixture
def node(nodes):
    return nodes["plain"]


# ---------------------------------------------------------------------------
# Helpers — planting the coordination channel, and reading through the cache
# ---------------------------------------------------------------------------

def _source(node, name, data):
    """Write `data` into the posix source and return it."""
    (node.data / name).write_bytes(data)
    return data


def _plant(node, name, staged, declared, *, staged_path=None, text=None):
    """Publish an in-flight-fill marker for `name`.

    `staged` is written to the staged file (under the store, i.e. where
    brix_staged_open would have put it, unless `staged_path` overrides it) and
    `declared` goes into the marker as the source's final size.  `text`
    overrides the marker body verbatim, for the malformed-marker negative."""
    if staged_path is None:
        staged_path = node.store / (name + ".stage")
    staged_path.write_bytes(staged)
    body = text if text is not None else \
        f"{os.getpid()} {declared} {staged_path}\n"
    (node.store / (name + ".brixfill")).write_text(body)
    return staged_path


def _xrdcp(node, name, dest):
    """Pull `name` through the cache with the stock-compatible client."""
    result = subprocess.run(
        [_XRDCP, "-f", "-s", f"root://{HOST}:{node.port}//{name}", str(dest)],
        capture_output=True, text=True, timeout=60)
    return result


def _open_handle(sock, name, options=kXR_open_read):
    _, status, body = _open(sock, f"/{name}", options=options)
    assert status == kXR_ok, f"open of /{name} rejected: {body!r}"
    return body[:4], body


def _wait_secs(body):
    return struct.unpack("!I", body[:4])[0]


@pytest.fixture
def sock(node):
    connection = _session(host=HOST, port=node.port)
    try:
        yield connection
    finally:
        connection.close()


# ---------------------------------------------------------------------------
# The marker plane — the layout the whole suite plants against
# ---------------------------------------------------------------------------

@pytest.mark.skipif(not os.path.exists(_XRDCP), reason="xrdcp not built")
def test_a_plain_fill_lands_where_the_marker_plane_expects(node, tmp_path):
    """A normal (unfollowed) fill puts the object at `<local_root><key>`.

    Everything else in this file plants `<local_root><key>.brixfill`, so this
    pins the one convention those plants depend on: if the store layout ever
    changed, the negatives below would silently stop testing anything (they
    would all "pass" by serving source bytes)."""
    payload = b"probe" * 200
    _source(node, "probe.bin", payload)
    result = _xrdcp(node, "probe.bin", tmp_path / "probe.out")
    assert result.returncode == 0, result.stderr
    assert (tmp_path / "probe.out").read_bytes() == payload
    assert (node.store / "probe.bin").exists(), (
        f"a fill did not land at <local_root>/probe.bin; store holds "
        f"{sorted(p.name for p in node.store.iterdir())}")


# ---------------------------------------------------------------------------
# SUCCESS — the follower is on the read path and serves the staged bytes
# ---------------------------------------------------------------------------

@pytest.mark.skipif(not os.path.exists(_XRDCP), reason="xrdcp not built")
def test_follower_serves_staged_bytes_not_source_bytes(node, tmp_path):
    """A fully-pumped in-flight fill is served from the STAGED file.

    Source and staged content differ byte for byte at the same length, so the
    bytes that come back name which path served them — there is no way to pass
    this by accident."""
    size = 64 * 1024
    _source(node, "hit.bin", b"S" * size)
    _plant(node, "hit.bin", b"F" * size, size)

    result = _xrdcp(node, "hit.bin", tmp_path / "hit.out")
    assert result.returncode == 0, result.stderr
    assert (tmp_path / "hit.out").read_bytes() == b"F" * size, (
        "the read did not follow the in-flight fill (it served source bytes)")


def test_follower_reports_declared_size_not_the_staged_frontier(node):
    """kXR_open(retstat) reports the marker's declared size.

    The staged file is deliberately much shorter than the declared size: its
    st_size is the FRONTIER, because the phase-107 C5 admission reserve claims
    blocks with fallocate(FALLOC_FL_KEEP_SIZE) and never moves st_size.  A
    follower that reported st_size would tell the client the object is short
    and the client would stop reading at the frontier."""
    declared, frontier = 1 << 20, 4096
    _source(node, "size.bin", b"S" * declared)
    _plant(node, "size.bin", b"F" * frontier, declared)

    connection = _session(host=HOST, port=node.port)
    try:
        handle, body = _open_handle(connection, "size.bin",
                                    kXR_open_read | kXR_retstat)
        assert len(body) > 12, f"retstat body too short: {len(body)}"
        reported = int(body[12:].rstrip(b"\x00").decode().split()[1])
        assert reported == declared, (
            f"follower reported {reported}, the staged frontier, not the "
            f"declared size {declared}")
        _close(connection, handle)
    finally:
        connection.close()


def test_read_below_the_frontier_serves_and_past_it_waits(node, sock):
    """The frontier is the whole contract: below it bytes, at it kXR_wait.

    kXR_wait (not an error, and not a zero-length EOF) is what keeps the client
    streaming at the origin's pace instead of either failing or silently
    truncating the object."""
    declared, frontier = 1 << 20, 8192
    _source(node, "front.bin", b"S" * declared)
    _plant(node, "front.bin", b"F" * frontier, declared)

    handle, _ = _open_handle(sock, "front.bin")
    _, status, body = _read(sock, handle, 0, 4096)
    assert status == kXR_ok and body == b"F" * 4096, (
        "a read below the frontier did not serve the staged bytes")

    _, status, body = _read(sock, handle, frontier, 4096)
    assert status == kXR_wait, (
        f"a read AT the frontier answered {status}, not kXR_wait")
    assert 0 < _wait_secs(body) <= 60, f"implausible wait: {body!r}"
    _close(sock, handle)


# ---------------------------------------------------------------------------
# ERROR — the two ways a fill can stop, both of which must fail CLOSED
# ---------------------------------------------------------------------------

def test_aborted_fill_fails_closed_instead_of_short_eof(node, sock):
    """A fill that aborts under a follower is kXR_IOError, never a clean EOF.

    The follower decides this from st_nlink on its OWN fd — the only race-free
    signal — which is why the fill spine unlinks the staged file BEFORE
    withdrawing the marker.  Reporting EOF here would hand the client a
    truncated object it had no way to tell from a complete one."""
    declared, frontier = 1 << 20, 8192
    _source(node, "abort.bin", b"S" * declared)
    staged = _plant(node, "abort.bin", b"F" * frontier, declared)

    handle, _ = _open_handle(sock, "abort.bin")
    _, status, _ = _read(sock, handle, 0, 4096)
    assert status == kXR_ok, "the follower did not take the read"

    staged.unlink()                       # the fill aborts under the follower
    _, status, body = _read(sock, handle, frontier, 4096)
    assert status == kXR_error, (
        f"an aborted fill answered {status}, not an error")
    assert _error_code(body) == kXR_IOError, (
        f"aborted fill reported {_error_code(body)}, not kXR_IOError")


def test_stalled_fill_gives_up_at_the_no_progress_deadline(node, sock):
    """A filler that dies without withdrawing its marker must not hang readers.

    The marker outlives the process that wrote it, so "the marker is present"
    can never mean "the fill is alive".  The follower bounds it with its own
    no-progress deadline: kXR_wait while the frontier could still move, then
    kXR_IOError once it demonstrably has not."""
    declared, frontier = 1 << 20, 8192
    _source(node, "stall.bin", b"S" * declared)
    _plant(node, "stall.bin", b"F" * frontier, declared)

    handle, _ = _open_handle(sock, "stall.bin")
    waits, status, body = 0, None, b""
    deadline = time.monotonic() + _SWF + 30
    while time.monotonic() < deadline:
        _, status, body = _read(sock, handle, frontier, 4096)
        if status != kXR_wait:
            break
        waits += 1
        time.sleep(0.25)

    assert waits >= 1, "the stalled fill never returned a single kXR_wait"
    assert status == kXR_error, (
        f"the stalled fill never gave up (last status {status})")
    assert _error_code(body) == kXR_IOError, (
        f"the deadline reported {_error_code(body)}, not kXR_IOError")


# ---------------------------------------------------------------------------
# SECURITY — three ways a marker must NOT be honoured
# ---------------------------------------------------------------------------

@pytest.mark.skipif(not os.path.exists(_XRDCP), reason="xrdcp not built")
def test_verifying_export_refuses_to_follow(nodes, tmp_path):
    """Under any verify mode the staged bytes are PROVISIONAL.

    cache_fill_verify may still reject a fill as a digest mismatch or a broken
    signature chain — by which time a follower would already have served the
    bytes.  Both sides refuse: the fill never publishes a marker, and the read
    side refuses to follow one it finds (a marker under a verifying export is
    stale or planted, exactly as it is here)."""
    verify = nodes["verify"]
    size = 32 * 1024
    _source(verify, "vfy.bin", b"S" * size)
    _plant(verify, "vfy.bin", b"F" * size, size)

    result = _xrdcp(verify, "vfy.bin", tmp_path / "vfy.out")
    assert result.returncode == 0, result.stderr
    assert (tmp_path / "vfy.out").read_bytes() == b"S" * size, (
        "a verifying export followed an unverified in-flight fill")


@pytest.mark.skipif(not os.path.exists(_XRDCP), reason="xrdcp not built")
@pytest.mark.parametrize("name,text", [
    ("garbage.bin", "not a marker at all\n"),
    ("nopath.bin", "4321\n"),                       # pid only, no size/path
    ("nosize.bin", "4321 /tmp/whatever\n"),         # size field missing
    ("relative.bin", "4321 100 relative/path\n"),   # path not absolute
    ("negative.bin", "4321 -5 /tmp/whatever\n"),    # negative declared size
])
def test_malformed_marker_is_treated_as_absent(node, tmp_path, name, text):
    """A marker is only ever written by sd_cache_follow.c, so anything that does
    not parse is refused rather than guessed at: the read falls through to a
    normal fill and serves SOURCE bytes."""
    size = 8192
    _source(node, name, b"S" * size)
    _plant(node, name, b"F" * size, size, text=text)

    result = _xrdcp(node, name, tmp_path / "out.bin")
    assert result.returncode == 0, result.stderr
    assert (tmp_path / "out.bin").read_bytes() == b"S" * size, (
        f"a malformed marker ({text!r}) was followed")


@pytest.mark.skipif(not os.path.exists(_XRDCP), reason="xrdcp not built")
def test_staged_path_outside_the_cache_store_is_not_followed(node, tmp_path):
    """The marker names a path this process opens and streams to a client.

    The staged temp is always created beside its final object, so a marker
    naming anything outside the store's local root is malformed — and honouring
    one would turn a writable marker into an arbitrary-file read.  The follower
    confines the path to the store and refuses everything else."""
    size = 8192
    outside = tmp_path / "outside.bin"
    _source(node, "escape.bin", b"S" * size)
    _plant(node, "escape.bin", b"F" * size, size, staged_path=outside)

    result = _xrdcp(node, "escape.bin", tmp_path / "escape.out")
    assert result.returncode == 0, result.stderr
    assert (tmp_path / "escape.out").read_bytes() == b"S" * size, (
        "a marker naming a staged path outside the cache store was followed")


@pytest.mark.skipif(not os.path.exists(_XRDCP), reason="xrdcp not built")
def test_prefix_sibling_of_the_cache_store_is_not_followed(node, tmp_path):
    """Confinement is at a path-component boundary, not a string prefix.

    `<store>swf-evil/x` shares the store's textual prefix but is a SIBLING
    directory, so a plain strncmp would have accepted it."""
    size = 8192
    sibling = node.store.parent / (node.store.name + "-evil")
    sibling.mkdir(exist_ok=True)
    _source(node, "sibling.bin", b"S" * size)
    _plant(node, "sibling.bin", b"F" * size, size,
           staged_path=sibling / "x.stage")

    result = _xrdcp(node, "sibling.bin", tmp_path / "sibling.out")
    assert result.returncode == 0, result.stderr
    assert (tmp_path / "sibling.out").read_bytes() == b"S" * size, (
        "a staged path in a prefix-sibling of the cache store was followed")
