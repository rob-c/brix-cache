"""Observe stream-session and structured JSON logs without starting a server."""

import json
from pathlib import Path
import re
import time

from log_records import semantic_log_text


def _log_lines(inst):
    """Read the fixture's session rows without treating a missing file as data."""
    log = Path(inst.prefix) / "logs" / "brixsess.log"
    if not log.exists():
        return []
    return [line for line in log.read_text(errors="replace").splitlines() if line.strip()]


def _fields(line):
    """Parse one `k=v k=v` log line into a dict."""
    return dict(re.findall(r"(\w+)=(\S+)", line))


def _transfer_line(lines):
    """A readiness connection has zero bytes; select an actual data session."""
    for line in lines:
        amount = _fields(line).get("out", "-")
        if amount.isdigit() and int(amount) > 0:
            return line
    return ""


def wait_for_log_value(read_rows, select, *, before=0, timeout=15.0):
    """Observe fresh log rows through the bounded batch-flush window."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = select(read_rows()[before:])
        if value:
            return value
        time.sleep(0.05)
    return None


def _wait_for_transfer_line(inst, before, timeout=15.0):
    """Observe only this transfer's new log rows, allowing log-phase latency."""
    return wait_for_log_value(lambda: _log_lines(inst), _transfer_line,
                              before=before, timeout=timeout) or ""


def _brix_access_json(inst):
    """Decode canonical diagnostic messages before reading a complete JSON event."""
    log = Path(inst.prefix) / "logs" / "error.log"
    if not log.exists():
        return []
    out = []
    for line in semantic_log_text(log.read_text(errors="replace")).splitlines():
        index = line.find("brix_access_json: ")
        if index == -1:
            continue
        text = line[index + len("brix_access_json: "):]
        try:
            record, _ = json.JSONDecoder().raw_decode(text)
        except ValueError:
            continue
        if isinstance(record, dict):
            out.append(record)
    return out


def _uniform_lines(inst):
    """Read the fixture's per-session uniform-format rows."""
    log = Path(inst.prefix) / "logs" / "brixuniform.log"
    if not log.exists():
        return []
    return [line for line in log.read_text(errors="replace").splitlines() if line.strip()]


def _checksum_in(lines):
    """Return the last recorded checksum, never a missing-value sentinel."""
    for line in reversed(lines):
        checksum = _fields(line).get("ck", "-")
        if checksum != "-":
            return checksum
    return None


def _latest_uniform_checksum(inst, before=0, timeout=15.0):
    """Wait for this query's checksum row, not an older or unrelated close."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        checksum = _checksum_in(_uniform_lines(inst)[before:])
        if checksum is not None:
            return checksum
        time.sleep(0.05)
    return None


def _wait_uniform_op(inst, op, timeout=15.0, *, status=None, before=0):
    """Wait for a matching session close after this operation's log boundary."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        reads = [line for line in _uniform_lines(inst)[before:]
                 if _fields(line).get("op") == op
                 and (status is None or _fields(line).get("st") == status)]
        if reads:
            return reads[-1]
        time.sleep(0.05)
    return None
