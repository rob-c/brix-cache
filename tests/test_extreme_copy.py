"""
Phase-100 extreme copy (xrdcp --sources N) — dedicated suite.

The extreme-copy engine downloads one known-size file from up to N replicas
concurrently: per-block claim from a shared table, plus BLOCK STEALING — when
no unclaimed block remains, idle sources re-fetch blocks still in flight on
slower/dead sources so the transfer finishes at the fastest replicas' pace.
Replica lists come from a metalink mirror set, else a kXR_locate, else the
source duplicated.  ``BRIX_XCP_DEBUG=1`` prints the per-source accounting this
suite asserts on; ``BRIX_XCP_BLOCK`` shrinks blocks so small files exercise
many claims.

Two genuinely independent replicas are staged by writing the SAME bytes into
the anon fleet server's export (DATA_ROOT) and the dedicated readonly server's
export (TEST_ROOT/data-readonly) — two servers, two roots, one logical file.

  * success   — 2-source reassembly (both sources carry blocks), slow-open
                mirror still carries blocks (join gate), locate/duplicate
                fallback on a plain URL, --sources 1 no-op
  * error     — dead mirror mid-set rescued by the live one; bad flag values
  * security  — corrupt replica vs the metalink digest fails CLOSED (no
                destination file survives); tarpit mirror cannot stall the
                start beyond the join gate's bounded grace

Run:
    PYTHONPATH=tests pytest tests/test_extreme_copy.py -v
"""

import hashlib
import os
import re
import socket
import subprocess
import threading
import time

import pytest

from ephemeral_port import free_port
from settings import DATA_ROOT

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_XRDCP = os.path.join(_REPO, "client", "bin", "xrdcp")
_TEST_ROOT = os.environ.get("TEST_ROOT", "/tmp/xrd-test")
_READONLY_DATA = os.path.join(_TEST_ROOT, "data-readonly")

pytestmark = [
    pytest.mark.requires_local_server,
    pytest.mark.registry_server("main"),
    pytest.mark.registry_server("readonly"),
    pytest.mark.skipif(not os.path.exists(_XRDCP),
                       reason="brix-xrdcp not built (client/bin/xrdcp)"),
]

_DEBUG_RE = re.compile(
    r"xcp sources=(\d+) blocks=(\d+) per-source=\[([\d,]+)\] steals=(\d+)")


def _det(n, seed=0):
    p = bytes((i + seed) % 251 for i in range(251))
    full, rem = divmod(n, 251)
    return p * full + p[:rem]


def _stage(dirpath, name, content):
    os.makedirs(dirpath, exist_ok=True)
    with open(os.path.join(dirpath, name), "wb") as f:
        f.write(content)


def _unstage(dirpath, name):
    try:
        os.remove(os.path.join(dirpath, name))
    except FileNotFoundError:
        pass


def _meta4(mirrors, md5=None, name="data.bin"):
    lines = ['<metalink xmlns="urn:ietf:params:xml:ns:metalink">',
             f'  <file name="{name}">']
    if md5 is not None:
        lines.append(f'    <hash type="md5">{md5}</hash>')
    for url, prio in mirrors:
        lines.append(f'    <url priority="{prio}">{url}</url>')
    lines.append("  </file>")
    lines.append("</metalink>")
    return "\n".join(lines) + "\n"


def _splice(src, dst):
    """Pump bytes src→dst until EOF/error, then half-close the write side."""
    try:
        while True:
            data = src.recv(65536)
            if not data:
                break
            dst.sendall(data)
    except OSError:
        pass
    finally:
        try:
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            pass


class _MirrorShim(threading.Thread):
    """TCP shim playing a misbehaving mirror (a free_port in-process mock).

    Two modes exercise the engine's join gate:
      * ``delay`` + ``backend`` — accept, sleep, then splice to a live server:
        a mirror whose XRootD open RESOLVES late (slow network/handshake).
      * ``hold_close`` — accept and stay silent for that many seconds, then
        close: a black-holed mirror whose open never completes.
    """

    def __init__(self, backend=None, delay=0.0, hold_close=None):
        super().__init__(daemon=True)
        self._backend = backend
        self._delay = delay
        self._hold_close = hold_close
        self._stop = threading.Event()
        self._lsock = socket.socket()
        self._lsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._lsock.bind(("127.0.0.1", 0))
        self._lsock.listen(8)
        self._lsock.settimeout(0.2)
        self.port = self._lsock.getsockname()[1]

    def run(self):
        while not self._stop.is_set():
            try:
                conn, _ = self._lsock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._serve, args=(conn,),
                             daemon=True).start()
        self._lsock.close()

    def _serve(self, conn):
        try:
            if self._hold_close is not None:
                self._stop.wait(self._hold_close)
                return
            time.sleep(self._delay)
            back = socket.create_connection(self._backend, timeout=10)
            threading.Thread(target=_splice, args=(back, conn),
                             daemon=True).start()
            _splice(conn, back)
            back.close()
        except OSError:
            pass
        finally:
            conn.close()

    def stop(self):
        self._stop.set()


def _run_xcp(args, timeout=180, block=65536):
    """Run xrdcp with the xcp debug + small-block env armed."""
    env = dict(os.environ)
    env["BRIX_XCP_DEBUG"] = "1"
    env["BRIX_XCP_BLOCK"] = str(block)
    return subprocess.run([_XRDCP] + args, capture_output=True, text=True,
                          timeout=timeout, env=env)


def _xcp_line(stderr):
    m = _DEBUG_RE.search(stderr)
    assert m is not None, f"no xcp debug line in stderr:\n{stderr}"
    sources, blocks, per_source, steals = m.groups()
    return (int(sources), int(blocks),
            [int(x) for x in per_source.split(",")], int(steals))


@pytest.fixture(scope="module")
def anon(test_env):
    return test_env["server_host"], test_env["anon_port"]


@pytest.fixture(scope="module")
def readonly(test_env):
    return test_env["server_host"], test_env["readonly_port"]


class TestExtremeCopy:

    def test_two_sources_reassemble_and_share_blocks(self, anon, readonly,
                                                     tmp_path):
        """Two independent servers each carry blocks of one download and the
        reassembly is byte-exact — the core multi-source property."""
        host, aport = anon
        _, rport = readonly
        content = _det(8 * 1024 * 1024)          # 128 blocks at 64 KiB
        _stage(DATA_ROOT, "xcp-two.bin", content)
        _stage(_READONLY_DATA, "xcp-two.bin", content)
        try:
            ml = tmp_path / "two.meta4"
            ml.write_text(_meta4([
                (f"root://{host}:{aport}//xcp-two.bin", 1),
                (f"root://{host}:{rport}//xcp-two.bin", 2),
            ], md5=hashlib.md5(content).hexdigest()))
            dst = tmp_path / "out.bin"
            res = _run_xcp(["--sources", "2", str(ml), str(dst)])
            assert res.returncode == 0, res.stderr
            assert dst.read_bytes() == content
            sources, blocks, per_source, _steals = _xcp_line(res.stderr)
            assert sources == 2
            assert blocks == 128
            assert sum(per_source) >= blocks   # steals may double-count
            assert all(c > 0 for c in per_source), (
                f"one source carried nothing: {per_source}; stderr={res.stderr}")
        finally:
            _unstage(DATA_ROOT, "xcp-two.bin")
            _unstage(_READONLY_DATA, "xcp-two.bin")

    def test_slow_open_mirror_still_carries_blocks(self, anon, tmp_path):
        """A mirror whose open resolves late (shim delays the handshake) still
        carries blocks: the join gate holds the fast source's claiming until
        every source's open RESOLVES, so a quick loopback drain cannot
        silently degrade --sources 2 to a single source."""
        host, aport = anon
        content = _det(4 * 1024 * 1024, seed=41)  # 64 blocks
        _stage(DATA_ROOT, "xcp-slow.bin", content)
        shim = _MirrorShim(backend=(host, aport), delay=0.4)
        shim.start()
        try:
            ml = tmp_path / "slow.meta4"
            ml.write_text(_meta4([
                (f"root://{host}:{shim.port}//xcp-slow.bin", 1),
                (f"root://{host}:{aport}//xcp-slow.bin", 2),
            ], md5=hashlib.md5(content).hexdigest()))
            dst = tmp_path / "out.bin"
            res = _run_xcp(["--sources", "2", str(ml), str(dst)])
            assert res.returncode == 0, res.stderr
            assert dst.read_bytes() == content
            sources, blocks, per_source, _ = _xcp_line(res.stderr)
            assert sources == 2
            assert blocks == 64
            assert all(c > 0 for c in per_source), (
                f"the slow-open mirror carried nothing: {per_source}")
        finally:
            shim.stop()
            _unstage(DATA_ROOT, "xcp-slow.bin")

    def test_dead_mirror_is_rescued_by_live_one(self, anon, tmp_path):
        """One dead replica in the set: its blocks return to the pool / get
        stolen and the live replica completes the whole file."""
        host, aport = anon
        content = _det(4 * 1024 * 1024, seed=17)  # 64 blocks
        _stage(DATA_ROOT, "xcp-rescue.bin", content)
        try:
            dead = free_port()
            ml = tmp_path / "rescue.meta4"
            ml.write_text(_meta4([
                (f"root://{host}:{aport}//xcp-rescue.bin", 1),
                (f"root://{host}:{dead}//xcp-rescue.bin", 2),
            ], md5=hashlib.md5(content).hexdigest()))
            dst = tmp_path / "out.bin"
            res = _run_xcp(["--sources", "2", str(ml), str(dst)])
            assert res.returncode == 0, res.stderr
            assert dst.read_bytes() == content
            sources, blocks, per_source, _ = _xcp_line(res.stderr)
            assert sources == 2
            assert max(per_source) == blocks == 64   # live source did it all
        finally:
            _unstage(DATA_ROOT, "xcp-rescue.bin")

    def test_plain_url_locate_or_duplicate_fallback(self, anon, tmp_path):
        """--sources on a PLAIN root:// URL (no metalink): replicas come from
        locate discovery, else the source is duplicated — either way the
        engine runs at the asked width and reassembles byte-exact."""
        host, aport = anon
        content = _det(2 * 1024 * 1024, seed=23)  # 32 blocks
        _stage(DATA_ROOT, "xcp-plain.bin", content)
        try:
            dst = tmp_path / "out.bin"
            res = _run_xcp(["--sources", "3",
                            f"root://{host}:{aport}//xcp-plain.bin", str(dst)])
            assert res.returncode == 0, res.stderr
            assert dst.read_bytes() == content
            sources, blocks, per_source, _ = _xcp_line(res.stderr)
            assert sources == 3
            assert blocks == 32
            assert sum(per_source) >= blocks
        finally:
            _unstage(DATA_ROOT, "xcp-plain.bin")

    def test_sources_one_is_plain_serial(self, anon, tmp_path):
        """--sources 1 never engages the engine (no debug line): the serial
        resilient pump remains the single-source path."""
        host, aport = anon
        content = _det(1024 * 1024, seed=29)
        _stage(DATA_ROOT, "xcp-serial.bin", content)
        try:
            dst = tmp_path / "out.bin"
            res = _run_xcp(["--sources", "1",
                            f"root://{host}:{aport}//xcp-serial.bin",
                            str(dst)])
            assert res.returncode == 0, res.stderr
            assert dst.read_bytes() == content
            assert _DEBUG_RE.search(res.stderr) is None
        finally:
            _unstage(DATA_ROOT, "xcp-serial.bin")


class TestExtremeCopyHostile:

    def test_corrupt_replicas_fail_closed(self, anon, readonly, tmp_path):
        """SECURITY: replicas serving bytes that do not match the metalink
        digest fail the whole transfer and leave NO destination file — a
        poisoned replica set cannot plant content."""
        host, aport = anon
        _, rport = readonly
        expected = _det(1024 * 1024, seed=31)
        served = _det(1024 * 1024, seed=97)      # corrupt: different bytes
        _stage(DATA_ROOT, "xcp-poison.bin", served)
        _stage(_READONLY_DATA, "xcp-poison.bin", served)
        try:
            ml = tmp_path / "poison.meta4"
            ml.write_text(_meta4([
                (f"root://{host}:{aport}//xcp-poison.bin", 1),
                (f"root://{host}:{rport}//xcp-poison.bin", 2),
            ], md5=hashlib.md5(expected).hexdigest()))
            dst = tmp_path / "out.bin"
            res = _run_xcp(["-s", "--sources", "2", str(ml), str(dst)])
            assert res.returncode != 0
            assert not dst.exists()
        finally:
            _unstage(DATA_ROOT, "xcp-poison.bin")
            _unstage(_READONLY_DATA, "xcp-poison.bin")

    def test_tarpit_mirror_start_is_bounded(self, anon, tmp_path):
        """SECURITY: a tarpit mirror (accepts TCP, never answers the
        handshake) cannot stall the transfer: the join gate's grace cap lets
        the live source proceed, the whole file lands from it, and the dead
        worker's failure is named on the debug channel."""
        host, aport = anon
        content = _det(4 * 1024 * 1024, seed=43)  # 64 blocks
        _stage(DATA_ROOT, "xcp-tarpit.bin", content)
        tarpit = _MirrorShim(hold_close=2.0)
        tarpit.start()
        try:
            ml = tmp_path / "tarpit.meta4"
            ml.write_text(_meta4([
                (f"root://{host}:{aport}//xcp-tarpit.bin", 1),
                (f"root://{host}:{tarpit.port}//xcp-tarpit.bin", 2),
            ], md5=hashlib.md5(content).hexdigest()))
            dst = tmp_path / "out.bin"
            t0 = time.monotonic()
            res = _run_xcp(["--sources", "2", str(ml), str(dst)])
            elapsed = time.monotonic() - t0
            assert res.returncode == 0, res.stderr
            assert dst.read_bytes() == content
            sources, blocks, per_source, _ = _xcp_line(res.stderr)
            assert sources == 2
            assert per_source[0] == blocks == 64   # live source did it all
            assert per_source[1] == 0
            assert f"xcp worker 1 (root://{host}:{tarpit.port}" in res.stderr, (
                f"tarpit worker's failure not reported:\n{res.stderr}")
            assert elapsed < 15, f"tarpit mirror stalled the copy: {elapsed:.1f}s"
        finally:
            tarpit.stop()
            _unstage(DATA_ROOT, "xcp-tarpit.bin")

    def test_sources_flag_bounds(self, tmp_path):
        """--sources outside 1..16 is a usage error (exit 50), before any
        network activity."""
        dst = tmp_path / "out.bin"
        for bad in ("0", "17", "-3"):
            res = subprocess.run(
                [_XRDCP, "--sources", bad, "root://h:1094//f", str(dst)],
                capture_output=True, text=True, timeout=30)
            assert res.returncode == 50, (bad, res.returncode, res.stderr)
            assert "--sources" in res.stderr
