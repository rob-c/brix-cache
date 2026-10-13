"""Controlled success, error, and security-negative OPEN fixture runners."""
import json
import struct
import subprocess
import time

from _test_phase115_pgread_verify_helpers import (
    error_frame, kXR_open, kXR_wait,
)
from settings import HOST
from test_xrd_conform_cache import EvictOrigin
from test_xrd_conform_http_semantics import XRD, _clean_environment


class StagedNowaitOrigin(EvictOrigin):
    """Return a controlled first answer to an open carrying kXR_nowait."""

    def __init__(self, behaviour):
        self.fixture_behaviour = behaviour
        self.nowait_seen = False
        super().__init__()

    def _dispatch(self, conn, sid, reqid, hdr, body=b"",
                  authenticated=False):
        if reqid == kXR_open:
            options = struct.unpack("!H", hdr[6:8])[0]
            self.nowait_seen = (options & 0x2000) != 0
            if self.fixture_behaviour == "slow":
                time.sleep(2.2)
            if self.fixture_behaviour == "server-error":
                conn.sendall(error_frame(sid, 3012, b"unsafe fixture error"))
            else:
                wait = struct.pack("!I", 0)
                conn.sendall(sid + struct.pack("!HI", kXR_wait, len(wait))
                             + wait)
            return authenticated
        return super()._dispatch(conn, sid, reqid, hdr, body, authenticated)


def _run(tmp_path, behaviour):
    with EvictOrigin() as primary, StagedNowaitOrigin(behaviour) as staged:
        primary.objects["/primary"] = b"online control"
        primary_url = f"root://{HOST}:{primary.port}//primary"
        staged_url = f"root://{HOST}:{staged.port}//offline"
        output = tmp_path / behaviour
        command = [str(XRD), "conform", "full", primary_url,
             "--profile", "data", "--only", "OPN-020",
             "--open-fixture", f"staged-nowait={staged_url}",
             "--allow-disrupt", "--confirm-target", primary_url,
             "--fail-on", "divergent", "--wall-seconds", "15",
             "--request-limit", "128", "--byte-limit", "1048576",
             "--out", str(output)]
        if behaviour != "wait":
            command.extend(["--verify-negative", "OPN-020"])
        result = subprocess.run(
            command,
            env=_clean_environment(), text=True, capture_output=True,
            timeout=25, check=False,
        )
        report = json.loads((output / "report.json").read_text(
            encoding="utf-8"))
        row = next(row for row in report["results"]
                   if row["id"] == "OPN-020")
        return result, row, staged.nowait_seen


def test_staged_nowait_first_wait_is_prompt_and_defined(tmp_path):
    result, row, nowait_seen = _run(tmp_path, "wait")
    assert result.returncode == 0, result.stderr + result.stdout
    assert nowait_seen
    assert row["verdict"] == "conformant"
    assert row["reason"] == "offline-nowait-returned-prompt-defined-answer"


def test_staged_nowait_detects_a_blocking_first_answer(tmp_path):
    result, row, nowait_seen = _run(tmp_path, "slow")
    assert result.returncode == 1, result.stderr + result.stdout
    assert nowait_seen
    assert row["verdict"] == "divergent"
    assert row["reason"] == \
        "offline-nowait-blocked-or-returned-undefined-answer"


def test_staged_nowait_rejects_generic_server_errors(tmp_path):
    result, row, nowait_seen = _run(tmp_path, "server-error")
    assert result.returncode == 1, result.stderr + result.stdout
    assert nowait_seen
    assert row["verdict"] == "divergent"
    assert row["reason"] == \
        "offline-nowait-blocked-or-returned-undefined-answer"
