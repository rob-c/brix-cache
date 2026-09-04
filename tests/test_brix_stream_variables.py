"""The root:// stream variable surface (phase-106 W2, phase-110 W2 vocabulary).

Before phase 106 the stream plane registered NO nginx variables at all —
`ngx_stream_add_variable` appeared nowhere in the tree — so root://, the
flagship protocol, could not be written to a `stream {}` access_log. Operators
had aggregate Prometheus counters or unstructured error-log lines and nothing
in between.

Phase 110 gave the plane the SAME names the HTTP plane uses; phase 112 removed
the seven phase-106 `$brix_session_*` aliases that had covered the gap. The
canonical spellings are $brix_dn, $brix_vo, $brix_sub, $brix_auth_method,
$brix_tls, $brix_bytes_served and $brix_bytes_received.

Scope is deliberately SESSION, not per-op: a stream session carries many
XRootD ops, so "the path" or "the status" is ill-defined at log time, while
totals and session-stable identity are exactly what one access_log line at
session close should carry.

  * success   — a root:// session is logged through nginx's own stream
                access_log, and the byte counters reflect real transferred
                bytes rather than a constant
  * error     — an unknown stream variable, and each of the seven names phase
                112 removed, is refused at config time by nginx's OWN
                "unknown ... variable"; a connection that never completes
                login still logs a well-formed line, and (W6) still carries a
                real $brix_duration, never the "-" sentinel
  * security  — no stream variable exposes the credential that authenticated
                the session; and (W3, R-3) the per-session monitor never bleeds
                one session's byte total into another's under concurrency

Run:
    PYTHONPATH=tests pytest tests/test_brix_stream_variables.py -v
"""

from __future__ import annotations

import os
import re
import socket
import struct
import subprocess
import threading
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


def _xrdcp_get(inst, dest: Path, name: str = "probe.bin") -> int:
    """Pull an object with this repo's xrdcp; returns the exit code."""
    xrdcp = Path(__file__).resolve().parent.parent / "client" / "bin" / "xrdcp"
    if not xrdcp.exists():
        pytest.skip("brix xrdcp not built (client/bin/xrdcp)")
    r = subprocess.run(
        [str(xrdcp), "-f", f"root://{inst.host}:{inst.port}//{name}",
         str(dest)],
        capture_output=True, text=True, timeout=60)
    return r.returncode


def _export_dir(inst) -> Path:
    """The on-disk export root, read from the running node's own config
    (`brix_storage_backend posix:<path>`) — so a cell can seed a second object
    of a distinct size without reaching into the module fixture's internals."""
    conf = (Path(inst.prefix) / "conf" / "nginx.conf").read_text()
    m = re.search(r"brix_storage_backend\s+posix:(\S+?);", conf)
    assert m, "no posix storage backend in the node config"
    return Path(m.group(1))


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


def _access_json_records(inst, timeout=2.0):
    """Do a metered op (dirlist), then the brix_access_json records it produced
    (the log-phase write lags the op). None when the client is not built."""
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
    return recs


def _access_json_remotes(inst, timeout=2.0):
    """The non-"-" `remote` fields of the records a metered op produced."""
    recs = _access_json_records(inst, timeout)
    if recs is None:
        return None
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
    assert remotes[-1].startswith(("127.0.0.1", "::1")), remotes[-1]  # net-literal-allow: expected loopback address recorded by the test server


# phase-112 W3: the four facts that used to be spelled twice per record, as
# (canonical key, the pre-phase-110 spelling it replaced).
PHASE_112_JSON_PAIRS = [
    ("bytes_served", "bytes"),
    ("backend_time_us", "latency_us"),
    ("cache_status", "from_cache"),
    ("sub", "subject"),
]


def _assert_phase_112_json_shape(rec):
    for canonical, removed in PHASE_112_JSON_PAIRS:
        assert canonical in rec, (canonical, rec)
        assert removed not in rec, (
            f"phase-112 removed the {removed!r} key, but a record still "
            f"carries it beside {canonical!r}: {rec}")


def test_phase_112_access_json_carries_each_fact_exactly_once(node):
    """(success + security-neg, phase-112 W3) Every record the server emits
    carries the canonical key for each uniform fact and NONE of the four
    compatibility keys it replaced.

    Asserted over every record in the log, not just the last, so the op shapes
    the acceptance criteria call out are covered as they occur: a dirlist is a
    zero-byte op, a stat of a missing path is an error record, and an
    unauthenticated op renders auth_method "none" — a key that only appeared on
    some shapes would still be caught."""
    recs = _access_json_records(node)
    if recs is None:
        pytest.skip("brix xrdfs not built")
    if not recs:
        pytest.skip("no brix_access_json record was produced for this op set")
    for rec in recs:
        _assert_phase_112_json_shape(rec)


def _uniform_lines(inst):
    log = Path(inst.prefix) / "logs" / "brixuniform.log"
    if not log.exists():
        return []
    return [ln for ln in log.read_text(errors="replace").splitlines()
            if ln.strip()]


def _fields(line):
    """Parse one `k=v k=v` log line into a dict."""
    return dict(re.findall(r"(\w+)=(\S+)", line))


def _uniform_op_fields(inst, op):
    """Field dicts of every uniform line whose op== `op`, oldest first."""
    return [f for f in map(_fields, _uniform_lines(inst)) if f.get("op") == op]


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

    $brix_sub, $brix_auth_method and $brix_bytes_served are the canonical
    spellings phase 112 left as the only ones, plus the phase-110 additions
    $brix_op / $brix_status / $brix_tier / $brix_duration.
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


def _xrdfs_stat(inst, path):
    """`xrdfs stat <path>` — a metadata-only op that serves no client bytes."""
    xrdfs = Path(__file__).resolve().parent.parent / "client" / "bin" / "xrdfs"
    if not xrdfs.exists():
        pytest.skip("brix xrdfs not built (client/bin/xrdfs)")
    subprocess.run([str(xrdfs), f"{inst.host}:{inst.port}", "stat", path],
                   capture_output=True, text=True, timeout=60)


def test_metadata_op_serves_zero_bytes_with_its_own_outcome(node):
    """(error, phase-110 W3) The data-plane monitor fields are per-OP, and a
    metadata op is a real event that moves zero CLIENT bytes — so it logs
    served=0 (a MEASURED zero, the op ran), never a read's byte count, and st
    carries THAT op's outcome: ok for a hit, not_found for a miss.

    As-built deviation the doc's W3 error bullet predates: the doc drafted
    served=`-` for "nothing served", but the implementation reserves `-` for a
    fact that never occurred and books a real op that moved no bytes as `0`
    (INVARIANT: `-` = no event, `0` = measured zero). A stat is that measured
    zero. This also pins st as per-op: a missing-path stat logs its own
    not_found without disturbing the served accounting.
    """
    _xrdfs_stat(node, "/probe.bin")               # a hit
    _xrdfs_stat(node, "/does-not-exist.bin")      # a miss
    miss = _wait_uniform_op(node, "stat")
    assert miss is not None, "no uniform stat line was written"
    fields = _fields(miss)
    assert fields.get("op") == "stat", miss
    assert fields.get("served") == "0", (
        f"a metadata op moved no client bytes: served must be a measured 0, "
        f"not a read's count and not '-': {miss}")
    # Across the hit+miss pair the outcomes are distinct per op, so st is not a
    # session-global constant inherited from one op.
    all_stat_st = {f.get("st") for f in _uniform_op_fields(node, "stat")}
    assert {"ok", "not_found"} <= all_stat_st, (
        f"stat st must be per-op (ok for a hit, not_found for a miss); "
        f"saw {all_stat_st}")


def _wait_uniform_count(inst, before, timeout=15.0):
    """Poll until the uniform log grows past `before` lines (session-close
    write lags); return the lines. Unlike `_wait_uniform_op` this does not
    filter by op, so it catches an aborted session whose op is the sentinel."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        lines = _uniform_lines(inst)
        if len(lines) > before:
            return lines
        time.sleep(0.25)
    return _uniform_lines(inst)


def test_aborted_session_still_logs_a_duration(node):
    """(error, phase-110 W6) $brix_duration is the one transport twin, and wall
    time always exists — so even a session that hangs up before completing the
    XRootD login must log a real duration, never the "-" sentinel. A near-instant
    abort logs a MEASURED zero (dur=0.000, the $session_time shape), which is
    distinct from "-" (no such fact): the twin is defined for every session that
    ever opened a connection, including the ones that never authenticated.

    Contrast with op/st, which ARE "-" here (no operation was dispatched) —
    proving the duration field is populated on its own, not merely inherited
    from a fully-served session's line.
    """
    before = len(_uniform_lines(node))
    _handshake_then_hangup(node)
    lines = _wait_uniform_count(node, before)
    assert len(lines) > before, "the aborted session wrote no uniform line"
    fields = dict(re.findall(r"(\w+)=(\S+)", lines[-1]))
    dur = fields.get("dur", "-")
    assert dur != "-", (
        f"an aborted session logged dur=- ; wall time always exists: {lines[-1]}")
    assert re.match(r"^\d+\.\d{3}$", dur), (
        f"$brix_duration must render the $session_time shape even on an aborted "
        f"session, got dur={dur!r}: {lines[-1]}")
    # The op WAS unknown — this pins that dur is populated independently, not a
    # leftover from a served line.
    assert fields.get("op") == "-", lines[-1]


def _xrdcp_put(inst, src: Path, name: str = "upload.bin") -> int:
    """Push a local file with this repo's xrdcp; returns the exit code. On a
    read-only export the write-open is refused (kXR_fsReadOnly, nonzero rc)."""
    xrdcp = Path(__file__).resolve().parent.parent / "client" / "bin" / "xrdcp"
    if not xrdcp.exists():
        pytest.skip("brix xrdcp not built (client/bin/xrdcp)")
    r = subprocess.run(
        [str(xrdcp), "-f", str(src), f"root://{inst.host}:{inst.port}//{name}"],
        capture_output=True, text=True, timeout=60)
    return r.returncode


def _wait_uniform_status(inst, want, timeout=15.0):
    """The last uniform line whose st== `want`, once the session-close write
    lands, or None. A refused write books op=- (no VFS op ran), so this selects
    on the outcome word rather than the op."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        hits = [ln for ln in _uniform_lines(inst) if _fields(ln).get("st") == want]
        if hits:
            return hits[-1]
        time.sleep(0.25)
    return None


def test_readonly_write_refusal_logs_status_forbidden_on_root(node, tmp_path):
    """(security-neg, phase-110 W4) The refusal word is plane-neutral: a write to
    a read-only export logs st=forbidden on root:// exactly as WebDAV and S3 do
    (test_brix_http_variables.test_readonly_refusal_logs_status_forbidden is the
    WebDAV arm). This is the root:// arm — and the one the mechanism nearly
    missed: root:// refuses a write-open at the protocol gate
    (brix_open_mode_guard), BEFORE the VFS mutation gate that stamps the monitor
    for the HTTP planes. Without an explicit FORBIDDEN stamp there the session
    logged st=- while every other plane said forbidden. This pins the cross-plane
    invariant the doc's W4 headline promises: one refusal word, every plane.
    """
    src = tmp_path / "payload.bin"
    src.write_bytes(b"denied write\n")
    before = len(_uniform_lines(node))
    rc = _xrdcp_put(node, src, name="denied-upload.bin")
    assert rc != 0, "a write to a read-only root:// export was not refused"
    _wait_uniform_count(node, before)
    line = _wait_uniform_status(node, "forbidden")
    assert line is not None, (
        "a read-only write refusal on root:// logged no st=forbidden line; the "
        "refusal word must be identical on every plane (WebDAV/S3/root)")
    assert _fields(line).get("st") == "forbidden", line


def _nginx_t_with_substitution(node, tmp_path, old_name, new_name):
    """Copy the live config with one variable spelling swapped, run `nginx -t`
    against the copy, and return the CompletedProcess.

    The copy is essential: a guard that edited the running node's own config
    would corrupt the fixture for every later cell.
    """
    conf = tmp_path / "nginx.conf"
    src = Path(node.prefix) / "conf" / "nginx.conf"
    text = src.read_text()
    assert old_name in text, f"{old_name} is not in the fixture config"
    conf.write_text(text.replace(old_name, new_name))
    (tmp_path / "logs").mkdir(exist_ok=True)
    return subprocess.run([NGINX_BIN, "-t", "-p", str(tmp_path), "-c", str(conf)],
                          capture_output=True, text=True, timeout=60)


def test_unknown_stream_variable_is_refused_by_nginx_itself(node, tmp_path):
    """(error) A typo'd variable name fails at config time with nginx's own
    diagnostic, exactly as any other unknown stream variable would."""
    r = _nginx_t_with_substitution(node, tmp_path, "$brix_sub", "$brix_subs")
    assert r.returncode != 0, "a misspelled stream variable was accepted"
    assert 'unknown "brix_subs" variable' in r.stderr, r.stderr


# Every alias phase 112 removed, paired with the canonical name that replaced
# it. The canonical name must be one the fixture log_format actually uses, so
# the substitution has something to replace.
PHASE_112_REMOVED = [
    ("brix_session_dn", "$brix_vo"),          # $brix_dn is not in the format
    ("brix_session_vo", "$brix_vo"),
    ("brix_session_user", "$brix_sub"),
    ("brix_session_auth", "$brix_auth_method"),
    ("brix_session_tls", "$brix_tls"),
    ("brix_session_bytes_out", "$brix_bytes_served"),
    ("brix_session_bytes_in", "$brix_bytes_received"),
]


@pytest.mark.parametrize("removed,canonical", PHASE_112_REMOVED,
                         ids=[r for r, _ in PHASE_112_REMOVED])
def test_phase_112_removed_variable_is_now_unknown(node, tmp_path, removed,
                                                   canonical):
    """(error, phase-112 acceptance) Each removed $brix_session_* alias is now
    an UNKNOWN stream variable, so a config still using it fails `nginx -t`
    naming the variable.

    This is the acceptance criterion the phase asks for by name: the removal
    must be LOUD. A registration left behind would make this pass config
    validation and then silently log a duplicate of a canonical field; a
    registration removed without the deprecation being real would make nginx
    render "-" instead. Only nginx's own unknown-variable abort proves the name
    is gone from the variable namespace rather than merely undocumented.
    """
    r = _nginx_t_with_substitution(node, tmp_path, canonical, "$" + removed)
    assert r.returncode != 0, (
        f"${removed} was still accepted by nginx -t — the phase-106 alias "
        f"survived phase 112:\n{r.stdout}\n{r.stderr}")
    assert f'unknown "{removed}" variable' in r.stderr, r.stderr


# ---------------------------------------------------------------------------
# security-negative
# ---------------------------------------------------------------------------

def _wait_for_read_count(inst, want, timeout=20.0):
    """Poll until at least `want` uniform read lines exist (close-write lags)."""
    deadline = time.monotonic() + timeout
    reads = _uniform_op_fields(inst, "read")
    while len(reads) < want and time.monotonic() < deadline:
        time.sleep(0.25)
        reads = _uniform_op_fields(inst, "read")
    return reads


def _pull_session(node, destination, name, results, index):
    results[index] = _xrdcp_get(node, destination, name=name)


def _session_pull_threads(node, tmp_path, names, results):
    return [
        threading.Thread(
            target=_pull_session,
            args=(node, tmp_path / f"out_{index}_{name}", name,
                  results, index),
        )
        for index, name in enumerate(names)
    ]


def _start_threads(threads):
    for thread in threads:
        thread.start()


def _join_threads(threads):
    for thread in threads:
        thread.join(timeout=90)


def _assert_pulls_finished(threads, results, count):
    assert not any(thread.is_alive() for thread in threads), \
        "a concurrent xrdcp session did not finish"
    assert results == [0] * count, f"xrdcp session results: {results}"


def _run_session_pulls(node, tmp_path, names):
    results = [None] * len(names)
    threads = _session_pull_threads(node, tmp_path, names, results)
    _start_threads(threads)
    _join_threads(threads)
    _assert_pulls_finished(threads, results, len(names))


def _served_counts(records):
    values = [record.get("served", "") for record in records]
    return sorted(int(value) for value in values if value.isdigit())


def test_stream_monitor_is_per_session_no_byte_bleed(node, tmp_path):
    """(security-neg, phase-110 W3 / Appendix-B R-3) The per-session
    brix_io_monitor_t must not bleed one session's byte total into another's.
    Two transfers of DELIBERATELY different sizes run concurrently on the same
    single-worker instance; each session's uniform read line must report its
    OWN $brix_bytes_served, never the other's and never the sum.

    R-3 is the classic per-connection-monitor bug: a monitor allocated or
    accumulated on a shared ctx (rather than per session on the connection pool)
    would show one line carrying both transfers' bytes. Distinct sizes let the
    attribution be exact — a small line reading the large count, or either
    reading the total, is the failure this catches.
    """
    export = _export_dir(node)
    small = b"small stream probe\n" * 4                 # 76 B, != PAYLOAD
    large = b"large stream probe payload\n" * 4096       # ~108 KiB
    (export / "small_sess.bin").write_bytes(small)
    (export / "large_sess.bin").write_bytes(large)

    before = len(_uniform_op_fields(node, "read"))
    names = ("small_sess.bin", "large_sess.bin") * 2
    _run_session_pulls(node, tmp_path, names)

    new = _wait_for_read_count(node, before + 4)[before:]
    served = _served_counts(new)
    assert served.count(len(small)) == 2, (
        "each session must log its own byte count with no cross-session "
        f"accumulation; expected two {len(small)}B lines, got {served}")
    assert served.count(len(large)) == 2, (
        f"expected two {len(large)}B session lines, got {served}")


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
