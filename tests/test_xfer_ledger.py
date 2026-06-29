"""Unified durable-transfer audit ledger (src/fs/xfer/xfer_ledger.c).

Every terminal STAGE publish (WebDAV/S3 PUT) appends exactly one line to the
transfer audit log with a stable schema:

    <ts> kind=stage dir=in result=<r> bytes=<n> errno=<e> principal=<p> path="..."

These tests assert the three behaviours required for any change:
  * success    — a completed PUT logs result=ok with the right byte count
  * error      — a publish that cannot commit logs result=commit_err, not ok
  * security   — control bytes in the object name are escaped in the line
                 (no raw newline → no audit-log injection)

The audit sink defaults to <prefix>/logs/xfer_audit.log; the shared fleet
instance uses prefix /tmp/xrd-test.
"""

import glob
import os
import shutil
import subprocess
import time
import uuid

import pytest
import requests

from settings import TEST_ROOT, NGINX_ANON_PORT, HOST

AUDIT_GLOB = os.path.join(TEST_ROOT, "**", "xfer_audit.log")
AUDIT_DEFAULT = os.path.join(TEST_ROOT, "logs", "xfer_audit.log")


@pytest.fixture(scope="module")
def base_url(test_env):
    return test_env["http_webdav_url"]


def _audit_lines():
    """All audit lines from every xfer_audit.log under the test root."""
    lines = []
    paths = set(glob.glob(AUDIT_GLOB, recursive=True)) | {AUDIT_DEFAULT}
    for p in paths:
        try:
            with open(p, "r", errors="replace") as fh:
                lines.extend(fh.readlines())
        except OSError:
            pass
    return lines


def _wait_for_line(token, timeout=5.0):
    """Return the first audit line containing token, polling until timeout."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        for line in _audit_lines():
            if token in line:
                return line
        time.sleep(0.1)
    return None


def test_successful_put_logs_ok_publish(base_url):
    name = f"xfer_ledger_ok_{uuid.uuid4().hex}.txt"
    payload = b"unified-transfer-ledger-success\n"

    r = requests.put(f"{base_url}/{name}", data=payload, timeout=10)
    assert r.status_code in (200, 201, 204), r.status_code

    line = _wait_for_line(name)
    assert line is not None, "no audit line for the committed object"
    assert "kind=stage" in line
    assert "dir=in" in line
    assert "result=ok" in line
    assert f"bytes={len(payload)}" in line
    assert line.count("\n") == 1  # exactly one record, well-formed


def test_uncommittable_put_logs_commit_err(base_url):
    # Make the target name a collection, then PUT a file onto it: the staged
    # commit (rename onto a directory) cannot succeed → result=commit_err.
    name = f"xfer_ledger_err_{uuid.uuid4().hex}"
    mk = requests.request("MKCOL", f"{base_url}/{name}", timeout=10)
    assert mk.status_code in (201, 405), mk.status_code

    r = requests.put(f"{base_url}/{name}", data=b"should-not-publish", timeout=10)
    assert r.status_code >= 400, f"PUT onto a collection should fail, got {r.status_code}"

    line = _wait_for_line(name)
    assert line is not None, "no audit line for the failed publish"
    assert "result=commit_err" in line
    assert "result=ok" not in line


def test_root_upload_logs_stage_publish(tmp_path):
    """A root:// upload (xrdcp) emits the SAME unified stage audit line as the
    HTTP PUTs above — closing the prior gap where root:// commits bypassed the
    ledger. This is also the path a resumed upload commits through."""
    xrdcp = shutil.which("xrdcp")
    if xrdcp is None:
        pytest.skip("xrdcp not available")

    name = f"xfer_root_stage_{uuid.uuid4().hex}.bin"
    src = tmp_path / "root_payload.bin"
    payload = b"root-stage-ledger-" + b"k" * 64
    src.write_bytes(payload)

    r = subprocess.run(
        [xrdcp, "-f", str(src), f"root://{HOST}:{NGINX_ANON_PORT}//{name}"],
        capture_output=True, timeout=30)
    assert r.returncode == 0, r.stderr.decode(errors="replace")

    line = _wait_for_line(name)
    assert line is not None, "no unified audit line for the root:// upload"
    assert "kind=stage" in line
    assert "dir=in" in line
    assert "result=ok" in line
    assert f"bytes={len(payload)}" in line


def test_control_byte_in_name_is_escaped(base_url):
    # A tab (0x09) in the object name must appear escaped in the audit line, and
    # the record must remain a single physical line (no log injection).
    tag = uuid.uuid4().hex
    name = f"xfer_ledger_ctl_{tag}%09tail.txt"  # %09 decodes server-side to TAB
    r = requests.put(f"{base_url}/{name}", data=b"ctl", timeout=10)
    assert r.status_code in (200, 201, 204), r.status_code

    line = _wait_for_line(tag)
    assert line is not None, "no audit line for the control-byte object"
    assert "\t" not in line, "raw control byte leaked into the audit line"
    assert "\\x09" in line, "tab byte was not hex-escaped in the path field"
    assert line.count("\n") == 1
