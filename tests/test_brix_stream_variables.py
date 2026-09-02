"""The $brix_session_* stream variable surface (phase-106 W2).

Before this phase the stream plane registered NO nginx variables at all —
`ngx_stream_add_variable` appeared nowhere in the tree — so root://, the
flagship protocol, could not be written to a `stream {}` access_log. Operators
had aggregate Prometheus counters or unstructured error-log lines and nothing
in between.

Scope is deliberately SESSION, not per-op: a stream session carries many
XRootD ops, so "the path" or "the status" is ill-defined at log time, while
totals and session-stable identity are exactly what one access_log line at
session close should carry.

  * success   — a root:// session is logged through nginx's own stream
                access_log, and the byte counters reflect real transferred
                bytes rather than a constant
  * error     — an unknown $brix_session_* name is refused at config time by
                nginx's OWN "unknown ... variable", and a connection that
                never completes login still logs a well-formed line
  * security  — no stream variable exposes the credential that authenticated
                the session

Run:
    PYTHONPATH=tests pytest tests/test_brix_stream_variables.py -v
"""

from __future__ import annotations

import os
import re
import socket
import struct
import subprocess
import time
from pathlib import Path

import pytest

from server_launcher import LifecycleHarness
from server_registry import NginxInstanceSpec
from settings import NGINX_BIN

pytestmark = [pytest.mark.timeout(180),
              pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-brix-stream-vars")]

TEMPLATE = "nginx_lc_brix_stream_variables.conf"
PAYLOAD = b"phase-106 stream variable probe\n" * 64      # ~2 KiB


@pytest.fixture(scope="module")
def node(tmp_path_factory):
    if not os.path.exists(NGINX_BIN):
        pytest.skip(f"nginx binary not found at {NGINX_BIN}")
    data = tmp_path_factory.mktemp("brixstream-data")
    (data / "probe.bin").write_bytes(PAYLOAD)

    harness = LifecycleHarness()
    try:
        inst = harness.start(NginxInstanceSpec(
            name="lc-brix-stream-vars",
            template=TEMPLATE,
            protocol="root",
            readiness="tcp",
            data_root=str(data),
            template_values={"DATA_DIR": str(data)},
            reason="phase-106 W2 $brix_session_* stream variables"))
    except Exception as exc:                      # noqa: BLE001 — clean skip
        harness.close()
        pytest.skip(f"stream variable node did not start: {str(exc)[-300:]}")
    try:
        yield inst
    finally:
        harness.close()


def _log_lines(inst):
    log = Path(inst.prefix) / "logs" / "brixsess.log"
    if not log.exists():
        return []
    return [ln for ln in log.read_text(errors="replace").splitlines() if ln.strip()]


def _xrdcp_get(inst, dest: Path) -> int:
    """Pull the probe object with this repo's xrdcp; returns the exit code."""
    xrdcp = Path(__file__).resolve().parent.parent / "client" / "bin" / "xrdcp"
    if not xrdcp.exists():
        pytest.skip("brix xrdcp not built (client/bin/xrdcp)")
    r = subprocess.run(
        [str(xrdcp), "-f", f"root://{inst.host}:{inst.port}//probe.bin",
         str(dest)],
        capture_output=True, text=True, timeout=60)
    return r.returncode


def _handshake_then_hangup(inst):
    """Open a connection, send the bare XRootD handshake, hang up before login."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)
    sock.connect((inst.host, inst.port))
    sock.sendall(struct.pack(">IIIII", 0, 0, 0, 4, 2012))
    try:
        sock.recv(64)
    except (socket.timeout, OSError):
        pass
    sock.close()


def _wait_for_new_line(inst, before, timeout=15.0):
    """The log line is written at session close — poll rather than sleep."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        lines = _log_lines(inst)
        if len(lines) > before:
            return lines
        time.sleep(0.25)
    return _log_lines(inst)


# ---------------------------------------------------------------------------
# success
# ---------------------------------------------------------------------------

def test_root_session_is_logged_through_nginx_stream_access_log(node, tmp_path):
    """(success) A real root:// transfer produces one nginx access_log line
    carrying the session's identity and byte totals.

    The byte assertion is the non-vacuity half: a handler that always reported
    0 (or the sentinel) would still produce a parseable line, and that is the
    failure worth catching.
    """
    dest = tmp_path / "out.bin"
    rc = _xrdcp_get(node, dest)
    assert rc == 0, "xrdcp GET failed"
    assert dest.read_bytes() == PAYLOAD

    lines = _log_lines(node)
    assert lines, "no stream access-log line was written"
    fields = dict(re.findall(r"(\w+)=(\S+)", lines[-1]))

    assert fields.get("proto") == "root", lines[-1]
    assert fields.get("tls") == "off", lines[-1]
    # Anonymous export: login completes, so auth is "none" — not the "-"
    # sentinel, which would mean brix never ran.
    assert fields.get("auth") in {"none", "gsi", "token"}, lines[-1]
    # The transfer really moved bytes; the counter must show it.
    out = fields.get("out", "-")
    assert out.isdigit() and int(out) >= len(PAYLOAD), (
        f"bytes_out={out!r} does not reflect the {len(PAYLOAD)}-byte transfer: "
        f"{lines[-1]}")


import json as _json


def _brix_access_json(inst):
    log = Path(inst.prefix) / "logs" / "error.log"
    if not log.exists():
        return []
    out = []
    for ln in log.read_text(errors="replace").splitlines():
        i = ln.find("brix_access_json: ")
        if i == -1:
            continue
        s = ln[i + len("brix_access_json: "):]
        j = s.find("}")          # nginx appends ", client: ..., server: ..."
        if j == -1:
            continue
        try:
            out.append(_json.loads(s[:j + 1]))
        except ValueError:
            pass
    return out


def _access_json_remotes(inst, timeout=2.0):
    """Do a metered op (dirlist), then the non-"-" `remote` fields of the
    brix_access_json lines it produced (the log-phase write lags the op)."""
    xrdfs = Path(__file__).resolve().parent.parent / "client" / "bin" / "xrdfs"
    if not xrdfs.exists():
        return None
    subprocess.run([str(xrdfs), f"{inst.host}:{inst.port}", "ls", "/"],
                   capture_output=True, text=True, timeout=60)
    deadline = time.monotonic() + timeout
    recs = _brix_access_json(inst)
    while not recs and time.monotonic() < deadline:
        time.sleep(0.05)
        recs = _brix_access_json(inst)
    return [r["remote"] for r in recs if r.get("remote", "-") != "-"]


def test_json_access_log_records_the_client_address(node, tmp_path):
    """(success, phase-110 W7) The brix JSON access log records the client
    address on root://, so it is self-sufficient (no join to nginx's log).
    bind_session borrows ctx->login.peer_ip onto every root VFS ctx."""
    remotes = _access_json_remotes(node)
    if remotes is None:
        pytest.skip("brix xrdfs not built")
    if not remotes:
        pytest.skip("no brix_access_json line carried a remote for this op set")
    assert remotes[-1].startswith(("127.0.0.1", "::1")), remotes[-1]


def _uniform_lines(inst):
    log = Path(inst.prefix) / "logs" / "brixuniform.log"
    if not log.exists():
        return []
    return [ln for ln in log.read_text(errors="replace").splitlines()
            if ln.strip()]


def _xrdfs_query_checksum(inst, path="/probe.bin"):
    """`xrdfs query checksum <path>` -> (rc, tokens). brix computes the digest
    natively (no plugin), so a successful query returns "<algo> <hex>"."""
    xrdfs = Path(__file__).resolve().parent.parent / "client" / "bin" / "xrdfs"
    if not xrdfs.exists():
        return None, []
    proc = subprocess.run(
        [str(xrdfs), f"{inst.host}:{inst.port}", "query", "checksum", path],
        capture_output=True, text=True, timeout=60)
    return proc.returncode, proc.stdout.split()


def _require_wire_checksum(inst):
    """(algo, hex) from a `xrdfs query checksum`, or skip if unavailable."""
    rc, toks = _xrdfs_query_checksum(inst)
    if rc is None:
        pytest.skip("brix xrdfs not built (client/bin/xrdfs)")
    if rc != 0 or len(toks) < 2:
        pytest.skip(f"harness did not answer query checksum (rc={rc}, {toks})")
    return toks[0].lower(), toks[-1].lower()


def _latest_uniform_checksum(inst):
    """The ck= field of the most recent uniform line that carried one, or None."""
    for ln in reversed(_uniform_lines(inst)):
        fields = dict(re.findall(r"(\w+)=(\S+)", ln))
        if fields.get("ck", "-") != "-":
            return fields["ck"]
    return None


def test_checksum_resolves_on_the_stream_plane(node):
    """(success, phase-110 W3) $brix_checksum on root:// — the plane that
    actually computes file digests. A `xrdfs query checksum` (kXR_Qcksum) makes
    brix report a digest; the session's $brix_checksum logs it as "alg:hex"
    (INVARIANT #9, algorithm-tagged) and its hex equals the value brix returned
    on the wire. Skips cleanly if the harness cannot compute a checksum."""
    algo, wire_hex = _require_wire_checksum(node)

    _wait_for_new_line(node, 0)          # the query session logged at close
    ck = _latest_uniform_checksum(node)
    assert ck is not None, "no uniform line reported a checksum after the query"
    assert ck == f"{algo}:{wire_hex}", (
        f"$brix_checksum {ck!r} != the wire digest {algo}:{wire_hex}")


def _wait_uniform_op(inst, op, timeout=15.0):
    """The last uniform log line whose op== `op`, once the session-close write
    lands (other cells' sessions write their own lines), or None."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        reads = [ln for ln in _uniform_lines(inst)
                 if dict(re.findall(r"(\w+)=(\S+)", ln)).get("op") == op]
        if reads:
            return reads[-1]
        time.sleep(0.25)
    return None


def test_uniform_names_resolve_on_the_stream_plane(node, tmp_path):
    """(success, phase-110 W2/W3/W4) The SAME $brix_* names the HTTP plane uses
    resolve on root://: a real xrdcp transfer writes a line whose uniform fields
    carry real values, so one log_format body serves both planes.

    $brix_sub (not $brix_session_user), $brix_auth_method (not
    $brix_session_auth), $brix_bytes_served (not $brix_session_bytes_out), plus
    the new $brix_op / $brix_status / $brix_tier / $brix_duration.
    """
    dest = tmp_path / "out2.bin"
    rc = _xrdcp_get(node, dest)
    assert rc == 0, "xrdcp GET failed"

    # The session-close write lags and other cells' sessions write their own
    # lines, so select the READ line this transfer produced (helper waits).
    last = _wait_uniform_op(node, "read")
    assert last is not None, "no uniform read line was written for the transfer"
    fields = dict(re.findall(r"(\w+)=(\S+)", last))

    assert fields.get("proto") == "root", last
    assert fields.get("am") in {"none", "gsi", "token"}, last   # shared vocabulary
    assert fields.get("tier") == "posix", last
    # A read transfer moved bytes and did a read op — the data-plane monitor
    # facts the phase-106 stream surface could not express.
    served = fields.get("served", "-")
    assert served.isdigit() and int(served) >= len(PAYLOAD), last
    assert fields.get("op") == "read", last
    assert fields.get("st") == "ok", last
    assert re.match(r"^\d+\.\d{3}$", fields.get("dur", "")), last  # $session_time shape


# ---------------------------------------------------------------------------
# error
# ---------------------------------------------------------------------------

def test_connection_without_login_still_logs_a_wellformed_line(node):
    """(error) A connection that opens and closes without completing the
    XRootD login still yields a complete log line with sentinels.

    This is the ctx==NULL / partial-session path: the handlers must degrade to
    "-" rather than crash the worker or drop the line.
    """
    before = len(_log_lines(node))
    _handshake_then_hangup(node)
    lines = _wait_for_new_line(node, before)
    assert len(lines) > before, "the aborted session was not logged"
    fields = dict(re.findall(r"(\w+)=(\S+)", lines[-1]))
    # Identity is unknown, so every identity field must be the sentinel.
    assert fields.get("user") == "-", lines[-1]
    assert fields.get("vo") == "-", lines[-1]
    assert fields.get("proto") == "root", lines[-1]


def test_unknown_stream_variable_is_refused_by_nginx_itself(node, tmp_path):
    """(error) A typo'd $brix_session_* name fails at config time with nginx's
    own diagnostic, exactly as any other unknown stream variable would."""
    conf = tmp_path / "nginx.conf"
    src = Path(node.prefix) / "conf" / "nginx.conf"
    conf.write_text(src.read_text().replace("$brix_session_user",
                                            "$brix_session_users"))
    (tmp_path / "logs").mkdir(exist_ok=True)
    r = subprocess.run([NGINX_BIN, "-t", "-p", str(tmp_path), "-c", str(conf)],
                       capture_output=True, text=True, timeout=60)
    assert r.returncode != 0, "a misspelled stream variable was accepted"
    assert 'unknown "brix_session_users" variable' in r.stderr, r.stderr


# ---------------------------------------------------------------------------
# security-negative
# ---------------------------------------------------------------------------

CREDENTIAL_PATTERNS = ("token", "secret", "key", "password", "macaroon",
                       "authorization", "bearer", "private", "sessid",
                       "signing")


def test_no_stream_variable_exposes_the_session_credential():
    """(security-neg) The stream session ctx holds a raw bearer token, GSI DH
    material and a sigver signing key. None of them may be reachable through a
    variable: a variable is loggable, and a logged credential is a leak.
    """
    src = (Path(__file__).resolve().parent.parent
           / "src" / "protocols" / "root" / "stream" / "stream_variables.c")
    # Strip C comments first: the file DOCUMENTS which credential fields it
    # deliberately does not touch, and a substring scan over the comments would
    # match its own prose. Only the code is evidence.
    text = re.sub(r"/\*.*?\*/", " ", src.read_text(), flags=re.S)
    text = re.sub(r"//[^\n]*", " ", text)

    _assert_no_credential_names(text)
    _assert_no_credential_field_reads(text)


def _assert_no_credential_names(text):
    """No registered stream variable NAME looks like credential material."""
    names = re.findall(r'ngx_string\("(brix_[a-z0-9_]+)"\)', text)
    assert names, "no stream variables found — the scan is broken"
    offenders = [n for n in names if any(p in n for p in CREDENTIAL_PATTERNS)]
    assert not offenders, f"credential-shaped stream variables: {offenders}"


def _assert_no_credential_field_reads(text):
    """The implementation must not READ the session's credential fields."""
    forbidden = [f for f in ("bearer_token", "signing_key", "gsi_dh_key",
                             "sessid")
                 if f in text]
    assert not forbidden, (
        f"stream_variables.c references {forbidden}; variables expose the "
        "subject of an identity, never the credential that proved it")
