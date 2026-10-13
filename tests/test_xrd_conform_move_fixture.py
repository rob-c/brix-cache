"""Phase-118 MV-005 two-export refusal fixture coverage."""
import json
import struct
import subprocess
from pathlib import Path

import pytest

from _test_phase115_pgread_verify_helpers import (
    PgOrigin,
    error_frame,
    kXR_close,
    kXR_open,
    kXR_rm,
    kXR_stat,
    kXR_write,
    ok_frame,
)
from settings import HOST
from test_xrd_conform_http_semantics import _clean_environment


ROOT = Path(__file__).resolve().parents[1]
XRD = ROOT / "client" / "bin" / "xrd"
KXR_MV = 3009
KXR_NOT_FOUND = 3011
KXR_UNSUPPORTED = 3013


class MoveFixtureOrigin(PgOrigin):
    """Track scratch names and inject a refused move or a covert copy."""

    def __init__(self, behaviour="refuse"):
        self.paths = set()
        self.move_behaviour = behaviour
        super().__init__(b"fixture", behaviour="ok")

    def _dispatch(self, conn, sid, reqid, hdr, body=b"",
                  authenticated=False):
        path = body.decode("utf-8", "replace")
        handlers = {
            kXR_open: self._open,
            kXR_stat: self._stat,
            KXR_MV: self._move,
            kXR_rm: self._remove,
            kXR_write: self._ack,
            kXR_close: self._ack,
        }
        handler = handlers.get(reqid)
        if handler is not None:
            handler(conn, sid, hdr, body, path)
            return authenticated
        return super()._dispatch(conn, sid, reqid, hdr, body, authenticated)

    def _open(self, conn, sid, _hdr, _body, path):
        self.paths.add(path)
        conn.sendall(ok_frame(sid, struct.pack("!I", 7) + b"\x00" * 8))

    def _stat(self, conn, sid, _hdr, _body, path):
        if path not in self.paths:
            conn.sendall(error_frame(sid, KXR_NOT_FOUND, b"missing"))
            return
        stat = f"0 {len(self.payload)} 0 0".encode("ascii") + b"\x00"
        conn.sendall(ok_frame(sid, stat))

    def _move(self, conn, sid, hdr, body, _path):
        split = struct.unpack("!h", hdr[18:20])[0]
        source = body[:split].decode("utf-8", "replace")
        destination = body[split + 1:].decode("utf-8", "replace")
        if self.move_behaviour == "copy":
            self.paths.add(destination)
        if self.move_behaviour == "move":
            self.paths.discard(source)
            self.paths.add(destination)
            conn.sendall(ok_frame(sid))
            return
        conn.sendall(error_frame(sid, KXR_UNSUPPORTED, b"cross export"))

    def _remove(self, conn, sid, _hdr, _body, path):
        self.paths.discard(path)
        conn.sendall(ok_frame(sid))

    @staticmethod
    def _ack(conn, sid, _hdr, _body, _path):
        conn.sendall(ok_frame(sid))


def _run(tmp_path, origin, destination=None, verify=False):
    if not XRD.exists():
        pytest.skip(f"native xrd client is not built: {XRD}")
    output = tmp_path / f"move-{origin.move_behaviour}"
    target = f"root://{HOST}:{origin.port}//export-a/object"
    fixture = destination or f"root://{HOST}:{origin.port}//export-b/scratch"
    command = [str(XRD), "conform", "accept", target,
         "--profile", "data", "--only", "MV-005",
         "--allow-mutate", "--scratch", "/export-a/scratch",
         "--move-fixture", fixture,
         "--fail-on", "divergent", "--wall-seconds", "10",
         "--request-limit", "64", "--byte-limit", "1048576",
         "--out", str(output)]
    _extend_verification(command, verify)
    result = subprocess.run(
        command,
        text=True, capture_output=True, timeout=15, check=False,
        env=_clean_environment(),
    )
    report = json.loads((output / "report.json").read_text(encoding="utf-8"))
    row = next(item for item in report["results"] if item["id"] == "MV-005")
    return result, row


def _extend_verification(command, verify):
    if verify:
        command.extend(["--verify-negative", "MV-005"])


def test_cross_export_move_refusal_preserves_source_without_copy(tmp_path):
    """Success: a defined refusal leaves the two-export state unchanged."""
    with MoveFixtureOrigin() as origin:
        result, row = _run(tmp_path, origin)
    assert result.returncode == 0, result.stderr + result.stdout
    assert row["verdict"] == "conformant"
    assert row["reason"] == "cross-export-move-refused-without-copy"


def test_cross_export_move_refusal_detects_covert_copy(tmp_path):
    """Security-negative: an error response cannot hide a destination copy."""
    with MoveFixtureOrigin("copy") as origin:
        result, row = _run(tmp_path, origin, verify=True)
    assert result.returncode == 1
    assert row["verdict"] == "divergent"
    assert "destination=1" in row["received"]


def test_cross_export_move_fixture_rejects_different_authority(tmp_path):
    """Error: a second server is not evidence for a same-server export seam."""
    with MoveFixtureOrigin() as origin:
        different = f"root://{HOST}:{origin.port + 1}//export-b/scratch"
        result, row = _run(tmp_path, origin, different)
    assert result.returncode == 0, result.stderr + result.stdout
    assert row["verdict"] == "inconclusive"
    assert row["reason"] == "move-fixture-authority-mismatch"
