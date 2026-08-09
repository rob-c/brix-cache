"""
Phase-100 metalink virtual redirector (client-side) — dedicated suite.

A ``.meta4`` (RFC 5854 v4) / ``.metalink`` (v3) source names ranked mirror URLs
for one logical file.  brix-xrdcp resolves the document (local file or served
by any transport it speaks), fails over across the mirrors in rank order, and
inherits the document's digest as an integrity gate when the user gave no
--cksum.  The parser itself is unit-tested in client/tests/c/metalink_unit.c;
this suite proves the END-TO-END behaviors against the shared fleet:

  * success   — local + remote metalink resolve, v4 + v3 dialects, digest OK
  * error     — dead-mirror failover, all-mirrors-dead clean failure
  * security  — file:// mirrors refused, corrupt-digest download dropped
                (never a partial/poisoned destination file)

Run:
    PYTHONPATH=tests pytest tests/test_metalink.py -v
"""

import hashlib
import os
import subprocess

import pytest

from ephemeral_port import free_port
from settings import DATA_ROOT, SERVER_HOST

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_XRDCP = os.path.join(_REPO, "client", "bin", "xrdcp")

pytestmark = [
    pytest.mark.requires_local_server,
    pytest.mark.skipif(not os.path.exists(_XRDCP),
                       reason="brix-xrdcp not built (client/bin/xrdcp)"),
]


def _det(n, seed=0):
    """Deterministic content: seed-shifted period-251 pattern tiled to n."""
    p = bytes((i + seed) % 251 for i in range(251))
    full, rem = divmod(n, 251)
    return p * full + p[:rem]


def _stage(dirpath, name, content):
    os.makedirs(dirpath, exist_ok=True)
    path = os.path.join(dirpath, name)
    with open(path, "wb") as f:
        f.write(content)
    return path


def _unstage(dirpath, name):
    try:
        os.remove(os.path.join(dirpath, name))
    except FileNotFoundError:
        pass


def _meta4(mirrors, size=None, md5=None, name="data.bin"):
    """Compose a metalink v4 document from (url, priority) pairs."""
    lines = ['<?xml version="1.0" encoding="UTF-8"?>',
             '<metalink xmlns="urn:ietf:params:xml:ns:metalink">',
             f'  <file name="{name}">']
    if size is not None:
        lines.append(f"    <size>{size}</size>")
    if md5 is not None:
        lines.append(f'    <hash type="md5">{md5}</hash>')
    for url, prio in mirrors:
        lines.append(f'    <url priority="{prio}">{url}</url>')
    lines.append("  </file>")
    lines.append("</metalink>")
    return "\n".join(lines) + "\n"


def _run_xrdcp(args, timeout=120, env_extra=None):
    env = dict(os.environ)
    if env_extra:
        env.update(env_extra)
    return subprocess.run([_XRDCP] + args, capture_output=True, text=True,
                          timeout=timeout, env=env)


@pytest.fixture(scope="module")
def anon(test_env):
    return test_env["server_host"], test_env["anon_port"]


class TestMetalinkResolve:

    def test_local_meta4_single_mirror(self, anon, tmp_path):
        """A local .meta4 naming one live mirror downloads that mirror's bytes
        byte-exact (the base virtual-redirector behavior)."""
        host, port = anon
        content = _det(512 * 1024)
        _stage(DATA_ROOT, "mtln-single.bin", content)
        try:
            ml = tmp_path / "single.meta4"
            ml.write_text(_meta4(
                [(f"root://{host}:{port}//mtln-single.bin", 1)]))
            dst = tmp_path / "out.bin"
            res = _run_xrdcp(["-s", str(ml), str(dst)])
            assert res.returncode == 0, res.stderr
            assert dst.read_bytes() == content
        finally:
            _unstage(DATA_ROOT, "mtln-single.bin")

    def test_failover_dead_then_live(self, anon, tmp_path):
        """Rank-1 mirror dead (connection refused) -> the copy notes the
        failure and completes from the rank-2 live mirror."""
        host, port = anon
        content = _det(256 * 1024, seed=3)
        _stage(DATA_ROOT, "mtln-failover.bin", content)
        try:
            dead = free_port()
            ml = tmp_path / "failover.meta4"
            ml.write_text(_meta4([
                (f"root://{host}:{dead}//mtln-failover.bin", 1),
                (f"root://{host}:{port}//mtln-failover.bin", 2),
            ]))
            dst = tmp_path / "out.bin"
            res = _run_xrdcp([str(ml), str(dst)])
            assert res.returncode == 0, res.stderr
            assert dst.read_bytes() == content
            assert "trying next mirror" in res.stderr
        finally:
            _unstage(DATA_ROOT, "mtln-failover.bin")

    def test_remote_metalink_root_source(self, anon, tmp_path):
        """A metalink SERVED over root:// (the document itself remote) is
        fetched, resolved and followed like a local one."""
        host, port = anon
        content = _det(128 * 1024, seed=7)
        _stage(DATA_ROOT, "mtln-remote-data.bin", content)
        _stage(DATA_ROOT, "mtln-remote.meta4", _meta4(
            [(f"root://{host}:{port}//mtln-remote-data.bin", 1)]
        ).encode())
        try:
            dst = tmp_path / "out.bin"
            res = _run_xrdcp(
                ["-s", f"root://{host}:{port}//mtln-remote.meta4", str(dst)])
            assert res.returncode == 0, res.stderr
            assert dst.read_bytes() == content
        finally:
            _unstage(DATA_ROOT, "mtln-remote-data.bin")
            _unstage(DATA_ROOT, "mtln-remote.meta4")

    def test_v3_document_resolves(self, anon, tmp_path):
        """The legacy v3 dialect (files/resources/url preference=) works
        end-to-end, preferring the higher preference value."""
        host, port = anon
        content = _det(64 * 1024, seed=11)
        _stage(DATA_ROOT, "mtln-v3.bin", content)
        try:
            dead = free_port()
            doc = (
                '<metalink version="3.0" xmlns="http://www.metalinker.org/">\n'
                " <files><file name=\"mtln-v3.bin\">\n"
                "  <resources>\n"
                f'   <url type="root" preference="10">root://{host}:{dead}//mtln-v3.bin</url>\n'
                f'   <url type="root" preference="100">root://{host}:{port}//mtln-v3.bin</url>\n'
                "  </resources>\n"
                " </file></files>\n"
                "</metalink>\n")
            ml = tmp_path / "v3.metalink"
            ml.write_text(doc)
            dst = tmp_path / "out.bin"
            res = _run_xrdcp(["-s", str(ml), str(dst)])
            assert res.returncode == 0, res.stderr
            assert dst.read_bytes() == content
            # preference 100 ranks FIRST — the dead pref-10 mirror was never
            # needed, so no failover note.
            assert "trying next mirror" not in res.stderr
        finally:
            _unstage(DATA_ROOT, "mtln-v3.bin")

    def test_no_metalink_copies_document_verbatim(self, anon, tmp_path):
        """--no-metalink treats the .meta4 as a plain file: the destination is
        the XML document itself, not the mirror's content."""
        host, port = anon
        doc = _meta4([(f"root://{host}:{port}//whatever.bin", 1)])
        _stage(DATA_ROOT, "mtln-verbatim.meta4", doc.encode())
        try:
            dst = tmp_path / "out.meta4"
            res = _run_xrdcp(
                ["-s", "--no-metalink",
                 f"root://{host}:{port}//mtln-verbatim.meta4", str(dst)])
            assert res.returncode == 0, res.stderr
            assert dst.read_bytes() == doc.encode()
        finally:
            _unstage(DATA_ROOT, "mtln-verbatim.meta4")


class TestMetalinkIntegrity:

    def test_document_digest_verifies_download(self, anon, tmp_path):
        """The metalink md5 rides into the transfer as an integrity gate and
        reports OK for a clean mirror."""
        host, port = anon
        content = _det(200 * 1024, seed=5)
        _stage(DATA_ROOT, "mtln-digest.bin", content)
        try:
            ml = tmp_path / "digest.meta4"
            ml.write_text(_meta4(
                [(f"root://{host}:{port}//mtln-digest.bin", 1)],
                size=len(content), md5=hashlib.md5(content).hexdigest()))
            dst = tmp_path / "out.bin"
            res = _run_xrdcp([str(ml), str(dst)])
            assert res.returncode == 0, res.stderr
            assert dst.read_bytes() == content
            assert "md5" in res.stdout and "OK" in res.stdout
        finally:
            _unstage(DATA_ROOT, "mtln-digest.bin")

    def test_corrupt_digest_drops_download(self, anon, tmp_path):
        """SECURITY: a mirror serving bytes that do not match the metalink
        digest fails the copy and leaves NO destination file (a poisoned
        replica cannot plant content)."""
        host, port = anon
        content = _det(96 * 1024, seed=9)
        _stage(DATA_ROOT, "mtln-poison.bin", content)
        try:
            wrong = hashlib.md5(b"not these bytes").hexdigest()
            ml = tmp_path / "poison.meta4"
            ml.write_text(_meta4(
                [(f"root://{host}:{port}//mtln-poison.bin", 1)], md5=wrong))
            dst = tmp_path / "out.bin"
            res = _run_xrdcp(["-s", str(ml), str(dst)])
            assert res.returncode != 0
            assert not dst.exists()
        finally:
            _unstage(DATA_ROOT, "mtln-poison.bin")

    def test_user_cksum_beats_document_digest(self, anon, tmp_path):
        """An explicit --cksum wins over the document digest: a WRONG document
        digest with a correct user spec still succeeds."""
        host, port = anon
        content = _det(64 * 1024, seed=13)
        _stage(DATA_ROOT, "mtln-user-ck.bin", content)
        try:
            ml = tmp_path / "userck.meta4"
            ml.write_text(_meta4(
                [(f"root://{host}:{port}//mtln-user-ck.bin", 1)],
                md5=hashlib.md5(b"garbage").hexdigest()))
            dst = tmp_path / "out.bin"
            good = hashlib.md5(content).hexdigest()
            res = _run_xrdcp(["-s", "--cksum", f"md5:{good}",
                              str(ml), str(dst)])
            assert res.returncode == 0, res.stderr
            assert dst.read_bytes() == content
        finally:
            _unstage(DATA_ROOT, "mtln-user-ck.bin")


class TestMetalinkHostile:

    def test_all_mirrors_dead_fails_cleanly(self, tmp_path):
        """Every mirror refusing connections -> nonzero exit, no destination,
        and the last mirror's failure is reported (not a hang/partial)."""
        host = SERVER_HOST
        dead1, dead2 = free_port(), free_port()
        ml = tmp_path / "dead.meta4"
        ml.write_text(_meta4([
            (f"root://{host}:{dead1}//nope.bin", 1),
            (f"root://{host}:{dead2}//nope.bin", 2),
        ]))
        dst = tmp_path / "out.bin"
        res = _run_xrdcp([str(ml), str(dst)], timeout=180)
        assert res.returncode != 0
        assert not dst.exists()

    def test_file_scheme_mirror_refused(self, tmp_path):
        """SECURITY: a metalink whose only mirror is file:///etc/passwd is
        rejected outright — a hostile document must not make the client read
        an arbitrary local file."""
        ml = tmp_path / "exfil.meta4"
        ml.write_text(_meta4([("file:///etc/passwd", 1)]))
        dst = tmp_path / "out.bin"
        res = _run_xrdcp([str(ml), str(dst)])
        assert res.returncode != 0
        assert not dst.exists()
        assert "no usable mirror" in res.stderr

    def test_not_a_metalink_document_fails(self, anon, tmp_path):
        """A .meta4 whose content is not metalink XML fails with a clean
        parse error instead of being half-interpreted."""
        ml = tmp_path / "junk.meta4"
        ml.write_text("<html><body>totally not metalink</body></html>")
        dst = tmp_path / "out.bin"
        res = _run_xrdcp([str(ml), str(dst)])
        assert res.returncode != 0
        assert not dst.exists()
        assert "metalink" in res.stderr.lower()
