"""test_stage_cross_device_commit.py — the EXDEV staged-commit fallback over HTTP.

`brix_commit_staged()` publishes a completed upload with rename(2) when the
staged partial and the export share a filesystem, and falls back to
copy → fsync → rename-a-temp-adjacent-to-the-final-path when rename(2) answers
EXDEV.  That fallback is what makes "stage uploads on a fast device, store them
on the bulk mount" work, and it was exercised only through root:// close
(test_shutdown_resume.py::test_upload_resume_stage_dir).  On the HTTP plane the
same code is reached by a Content-Range PUT under `brix_upload_resume on`
plus `brix_webdav_stage_dir` — a directive with no behavioural coverage at all.

The cross-device condition is real, not simulated: the stage dir is created on
tmpfs (/dev/shm) and the export on the ordinary filesystem, so rename(2) between
them genuinely returns EXDEV.  The whole module skips when /dev/shm is absent,
unwritable, or turns out to be the same device as the export — an assertion that
"the fallback ran" is worthless if the fast path could have served it.

Coverage (success + error + security-negative):
  * a single-chunk ranged PUT commits across the device boundary byte-exact, and
    leaves neither the partial, the pending-commit marker, nor the adjacent temp
    behind on either device;
  * a three-chunk resumable PUT keeps its partial on the STAGE device between
    chunks (proving the bytes really crossed at commit) and lands byte-exact;
  * a payload larger than one copy chunk crosses correctly (the copy loop, not
    just a single read);
  * an overwrite replaces the object in place — same path, new content, and the
    old inode is gone (an atomic replace, not a truncate-in-place);
  * an out-of-order chunk is refused 409 with the honest X-Upload-Offset and the
    partial survives on the stage device — the error branch;
  * a traversal PUT is refused and writes nothing outside the export, on either
    device — the security-negative for a path that never reaches the commit.
"""

import hashlib
import http.client
import os
import pathlib
import uuid

import pytest
import requests

from settings import BIND_HOST, HOST, NGINX_BIN
from server_registry import NginxInstanceSpec

# Bucket-2 lifecycle subject: the tests PUT into, overwrite in, and read the
# stage/export dirs of one fixed-port instance, so the whole file serialises.
pytestmark = [pytest.mark.serial, pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-stage-xdev")]

SHM = "/dev/shm"
NAME = "lc-stage-xdev"


def _stage_dir(export: pathlib.Path) -> str:
    """A writable tmpfs stage dir that is provably a DIFFERENT device from the
    export — otherwise commit takes the rename(2) fast path and the module would
    pass without ever entering the fallback it exists to test."""
    if not (os.path.isdir(SHM) and os.access(SHM, os.W_OK)):
        pytest.skip("no writable /dev/shm — cannot stage on a second device")
    stage = pathlib.Path(SHM) / f"xrd-xdev-{os.getpid()}"
    stage.mkdir(parents=True, exist_ok=True)
    # The worker may run as another user (see test_shutdown_resume.py): a
    # 0755 root-owned stage dir fails staged-open and the PUT 503s.
    os.chmod(stage, 0o777)
    if os.stat(stage).st_dev == os.stat(export).st_dev:
        pytest.skip("/dev/shm is the same device as the export — no EXDEV")
    return str(stage)


class _Server:
    """A WebDAV tier whose resumable-upload staging lives on another device."""

    def __init__(self, lifecycle, tmp_path):
        self._lifecycle = lifecycle
        self.data = pathlib.Path(tmp_path) / "data"
        self.data.mkdir(parents=True, exist_ok=True)
        self.stage = pathlib.Path(_stage_dir(self.data))
        self.base = None
        self.port = None

    def start(self):
        ep = self._lifecycle.start(NginxInstanceSpec(
            name=NAME,
            template="nginx_lc_stage_xdev_webdav.conf",
            protocol="webdav",
            template_values={
                "BIND_HOST": BIND_HOST,
                "DATA_DIR": str(self.data),
                "STAGE_DIR": str(self.stage),
            },
            reason="WebDAV tier staging resumable uploads on a second device "
                   "so the commit must take the EXDEV copy fallback",
        ))
        self.base = f"http://{HOST}:{ep.port}"
        self.port = ep.port
        return self

    def url(self, name=None):
        return f"{self.base}/{name or uuid.uuid4().hex}"

    def staged(self):
        """Everything the stage device is currently holding for us."""
        return sorted(p.name for p in self.stage.iterdir())

    def raw_put(self, raw_path, body):
        """PUT a verbatim request-target so the SERVER does the normalisation."""
        conn = http.client.HTTPConnection(HOST, self.port, timeout=30)
        try:
            conn.putrequest("PUT", raw_path, skip_accept_encoding=True)
            conn.putheader("Content-Length", str(len(body)))
            conn.putheader("Content-Range", f"bytes 0-{len(body) - 1}/{len(body)}")
            conn.endheaders()
            conn.send(body)
            resp = conn.getresponse()
            return resp.status, resp.read()
        finally:
            conn.close()


def _put_range(url, chunk, start, total):
    """One Content-Range PUT chunk of a resumable upload."""
    end = start + len(chunk) - 1
    return requests.put(url, data=chunk, timeout=30, headers={
        "Content-Range": f"bytes {start}-{end}/{total}",
    })


@pytest.fixture()
def srv(lifecycle, tmp_path):
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx not executable: {NGINX_BIN}")
    server = _Server(lifecycle, tmp_path).start()
    yield server
    for leftover in server.stage.iterdir():
        leftover.unlink(missing_ok=True)
    server.stage.rmdir()


# --------------------------------------------------------------------------- #
# Success — the fallback publishes byte-exactly and cleans up both devices     #
# --------------------------------------------------------------------------- #

def test_single_chunk_commits_across_devices(srv):
    """A whole-file ranged PUT stages on tmpfs and commits onto the export: 201,
    byte-exact, and nothing left on either device."""
    payload = os.urandom(64 * 1024)
    r = _put_range(srv.url("xdev-one.bin"), payload, 0, len(payload))

    assert r.status_code == 201, r.text
    assert (srv.data / "xdev-one.bin").read_bytes() == payload
    assert srv.staged() == [], "stage device still holding the partial/marker"
    # commit_cross_device writes its temp NEXT TO the final path; a leftover
    # would mean the rename onto the final never happened.
    assert [p.name for p in srv.data.iterdir()] == ["xdev-one.bin"]


def test_partial_lives_on_the_stage_device_between_chunks(srv):
    """Three chunks: the partial is on the STAGE device (never the export) until
    the last chunk, which is what makes the commit a cross-device move."""
    payload = os.urandom(96 * 1024)
    url = srv.url("xdev-chunked.bin")
    total = len(payload)
    chunk = 32 * 1024

    first = _put_range(url, payload[:chunk], 0, total)
    assert first.status_code == 200, first.text
    assert first.headers.get("X-Upload-Offset") == str(chunk)
    assert srv.staged(), "partial should be sitting on the stage device"
    assert not (srv.data / "xdev-chunked.bin").exists(), \
        "an incomplete upload must not be visible on storage"
    # Non-vacuity: the partial's device is not the export's, so the commit below
    # cannot be served by rename(2) — it is the EXDEV fallback or nothing.
    partial = srv.stage / srv.staged()[0]
    assert partial.stat().st_dev != srv.data.stat().st_dev

    second = _put_range(url, payload[chunk:2 * chunk], chunk, total)
    assert second.status_code == 200, second.text
    assert second.headers.get("X-Upload-Offset") == str(2 * chunk)

    last = _put_range(url, payload[2 * chunk:], 2 * chunk, total)
    assert last.status_code == 201, last.text
    assert (srv.data / "xdev-chunked.bin").read_bytes() == payload
    assert srv.staged() == [], "partial/marker left on the stage device"


def test_multi_chunk_copy_loop_is_byte_exact(srv):
    """A payload well past one copy iteration crosses intact — the fallback's
    read/write loop, not just a single-shot copy."""
    payload = os.urandom(5 * 1024 * 1024)
    r = _put_range(srv.url("xdev-big.bin"), payload, 0, len(payload))

    assert r.status_code == 201, r.text
    landed = (srv.data / "xdev-big.bin").read_bytes()
    assert hashlib.md5(landed).hexdigest() == hashlib.md5(payload).hexdigest()
    assert srv.staged() == []


def test_overwrite_replaces_atomically(srv):
    """Committing over an existing object replaces it wholesale: the final path
    carries the new bytes and the OLD inode is gone, so a reader saw one version
    or the other and never a half-written file."""
    dst = srv.data / "xdev-replace.bin"
    url = srv.url("xdev-replace.bin")
    old = os.urandom(8 * 1024)
    assert _put_range(url, old, 0, len(old)).status_code == 201
    old_ino = dst.stat().st_ino

    new = os.urandom(24 * 1024)
    r = _put_range(url, new, 0, len(new))

    assert r.status_code == 201, r.text
    assert dst.read_bytes() == new
    assert dst.stat().st_ino != old_ino, "replaced in place, not atomically"
    assert srv.staged() == []


# --------------------------------------------------------------------------- #
# Error — a rejected chunk keeps the partial where it is                       #
# --------------------------------------------------------------------------- #

def test_out_of_order_chunk_is_refused_and_partial_survives(srv):
    """A chunk that does not start at the current partial size is 409 with the
    real offset, and the partial stays on the stage device so the client can
    resume — the append-only branch, never a silent hole."""
    payload = os.urandom(48 * 1024)
    url = srv.url("xdev-gap.bin")
    total = len(payload)
    chunk = 16 * 1024

    assert _put_range(url, payload[:chunk], 0, total).status_code == 200
    before = srv.staged()

    skipped = _put_range(url, payload[2 * chunk:], 2 * chunk, total)
    assert skipped.status_code == 409, skipped.text
    assert skipped.headers.get("X-Upload-Offset") == str(chunk)
    assert srv.staged() == before, "the refused chunk disturbed the partial"
    assert not (srv.data / "xdev-gap.bin").exists()

    # …and the honest offset really is resumable.
    assert _put_range(url, payload[chunk:2 * chunk], chunk, total).status_code == 200
    assert _put_range(url, payload[2 * chunk:], 2 * chunk, total).status_code == 201
    assert (srv.data / "xdev-gap.bin").read_bytes() == payload
    assert srv.staged() == []


# --------------------------------------------------------------------------- #
# Security-negative — a path that escapes never reaches the commit             #
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("escape", ["/../xdev-escape.bin",
                                    "/%2e%2e/xdev-escape.bin",
                                    "/%2E%2E/xdev-escape.bin",
                                    "/sub/../../xdev-escape.bin"])
def test_traversal_put_writes_nothing_on_either_device(srv, escape):
    """A staged upload aimed outside the export is refused before anything is
    staged: nothing appears above the export, and the stage device — which is
    NOT under the export root and so is not covered by the export's own
    confinement — stays empty too.

    Sent with raw http.client, deliberately: requests/urllib3 collapse `..`
    client-side, which turns this whole assertion into a 201 against a perfectly
    legal in-export path."""
    parent = srv.data.parent
    before_parent = sorted(p.name for p in parent.iterdir())

    status, _ = srv.raw_put(escape, os.urandom(4096))

    assert status in (400, 403, 404, 409), status
    assert not (parent / "xdev-escape.bin").exists()
    assert sorted(p.name for p in parent.iterdir()) == before_parent
    assert srv.staged() == [], "a refused traversal staged bytes anyway"
