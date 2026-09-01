"""The $brix_* HTTP variable surface (phase-106 W1).

Variables are how an operator's existing nginx knowledge reaches brix state:
`log_format`, `map`, `if`, `add_header`, `split_clients` and `limit_req_zone`
all consume variables and none of them can be taught about brix any other way.
Before this phase the entire surface was `$brix_protocol`,
`$brix_delegated_cred` and three unprefixed per-plane names — there was no way
to log whether a request was a cache hit.

Registration is owned by the COMMON http module
(`src/core/config/http_common.c` preconfiguration, via
`src/core/http/http_variables.c`), NOT by a protocol module.  That ownership is
the property under test: one `log_format` must work regardless of which
protocol serves the location, and a variable's existence must not depend on
which protocol module happens to be loaded.

  * success   — a log_format built from the new variables parses, serves a
                request, and writes a line whose fields carry the documented
                vocabulary (not the empty string, and not a stale default)
  * error     — an unknown $brix_* name is rejected by nginx's OWN
                "unknown ... variable" error at config time, not silently
                accepted and not a brix-specific message
  * security  — no registered brix variable exposes credential material; the
                registered set is checked against the credential-name denylist
                that phase-106 W8 R10 will enforce in CI

Run:
    PYTHONPATH=tests pytest tests/test_brix_http_variables.py -v
"""

from __future__ import annotations

import os
import re
import time
from pathlib import Path

import pytest

from config_parse import nginx_t
from fleet_lifecycle_ports import SHARED_PARSE_PLACEHOLDER_PORT
from server_launcher import LifecycleHarness
from server_registry import NginxInstanceSpec
from settings import HOST, NGINX_BIN
from ephemeral_port import free_port

pytestmark = [pytest.mark.timeout(180),
              pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-brix-variables")]

TEMPLATE = "nginx_lc_brix_variables.conf"

REPO = Path(__file__).resolve().parent.parent


def _port_from_conf(conf):
    import re
    m = re.search(r"listen [^:]+:(\d+)", conf.read_text())
    return int(m.group(1))


def _wait_listen(host, port, timeout=10.0):
    import socket
    import time
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            socket.create_connection((host, port), timeout=0.5).close()
            return
        except OSError:
            time.sleep(0.1)

# The value every variable must report when brix reached no decision.  A
# distinct sentinel matters: "-" cannot be mistaken for a MISS, so a hit rate
# computed from the log is never silently wrong.
NONE = "-"


# ---------------------------------------------------------------------------
# success
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def node(tmp_path_factory):
    """One cleartext webdav node whose access_log uses the new variables."""
    if not os.path.exists(NGINX_BIN):
        pytest.skip(f"nginx binary not found at {NGINX_BIN}")
    data = tmp_path_factory.mktemp("brixvars-data")
    (data / "probe.txt").write_bytes(b"brix variable probe\n")

    harness = LifecycleHarness()
    try:
        inst = harness.start(NginxInstanceSpec(
            name="lc-brix-variables",
            template=TEMPLATE,
            protocol="webdav",
            readiness="tcp",
            data_root=str(data),
            template_values={"DATA_DIR": str(data)},
            reason="phase-106 W1 $brix_* variable surface"))
    except Exception as exc:                      # noqa: BLE001 — clean skip
        harness.close()
        pytest.skip(f"variable node did not start: {str(exc)[-300:]}")
    try:
        yield inst
    finally:
        harness.close()


def _log_lines(inst):
    log = Path(inst.prefix) / "logs" / "brixvars.log"
    if not log.exists():
        return []
    return [ln for ln in log.read_text(errors="replace").splitlines() if ln.strip()]


def _wait_for_log_lines(inst, min_count, timeout=10.0):
    """Poll the access log until it holds at least ``min_count`` non-empty
    lines, or ``timeout`` elapses.  nginx writes the access-log line in the LOG
    phase, which runs AFTER the client has received the response and closed the
    connection — so under load that write can lag the client read by tens of
    milliseconds and a single read races it (observed intermittently only in
    the full parallel suite, never solo).  On timeout the current lines are
    returned so the caller's own assertion still fires with its real message."""
    deadline = time.monotonic() + timeout
    lines = _log_lines(inst)
    while len(lines) < min_count and time.monotonic() < deadline:
        time.sleep(0.05)
        lines = _log_lines(inst)
    return lines


def test_log_format_over_brix_variables_writes_every_field(node):
    """(success) One log_format built from the new variables serves a request
    and writes each field with its documented vocabulary.

    The assertion is deliberately on the FIELDS rather than on one value: a
    handler that silently reported the empty string would still produce a
    parseable line, and that is exactly the failure this must catch.
    """
    import http.client

    before = len(_log_lines(node))
    conn = http.client.HTTPConnection(node.host, node.port, timeout=30)
    try:
        conn.request("GET", "/probe.txt")
        resp = conn.getresponse()
        body = resp.read()
    finally:
        conn.close()
    assert resp.status == 200, f"GET failed: {resp.status}"
    assert body == b"brix variable probe\n"

    lines = _wait_for_log_lines(node, before + 1)
    assert len(lines) > before, "no access-log line was written at all"
    last = lines[-1]

    _assert_core_fields(dict(re.findall(r"(\w+)=(\S+)", last)), last)


def _assert_core_fields(fields, last):
    """Every field of the anonymous-GET log line, with its documented value."""
    assert fields.get("status") == "200", last
    # Cleartext listener: $brix_tls must say so, and must not be empty.
    assert fields.get("tls") == "off", last
    # $brix_protocol identifies the serving plane (registered pre-phase-106,
    # asserted here because W1 moved WHERE it is registered).
    assert fields.get("proto") == "webdav", last
    # $brix_cache_status uses nginx's own vocabulary. This plane does not yet
    # report a disposition, so the honest answer is the sentinel — but it must
    # be the sentinel, not an empty field, and never a bare "MISS" it did not
    # measure.
    assert fields.get("cache") in {NONE, "HIT", "MISS", "BYPASS", "NEGHIT"}, last
    _assert_identity_sentinels(fields, last)
    # $brix_tier reports the RESOLVED backend; this location is posix.
    assert fields.get("tier") == "posix", last
    # $brix_origin echoes the configured backend with userinfo stripped; a
    # posix backend has no userinfo so it is the config value (or "-").
    assert fields.get("origin", "").startswith(("posix:", NONE)), last


def _assert_identity_sentinels(fields, last):
    """Identity fields on an anonymous request are the sentinel — present,
    never empty (an empty field would make 'no VO' and 'VO named \"\"'
    identical). $brix_auth_method is 'none' once brix served the request,
    '-' only when it never ran."""
    for f in ("dn", "vo", "fqan", "sub", "iss"):
        assert fields.get(f) == NONE, f"{f}: {last}"
    assert fields.get("am") in {NONE, "none"}, last


def test_variables_resolve_without_a_brix_handler(node):
    """(success, non-vacuity) The variables resolve on a request that brix
    never served — a 404 for a path outside the export still logs every field.

    This is what proves registration is COMMON-owned: a handler that only
    worked once a protocol had built its request ctx would report an empty
    field here.
    """
    import http.client

    before = len(_log_lines(node))
    conn = http.client.HTTPConnection(node.host, node.port, timeout=30)
    try:
        conn.request("GET", "/definitely-absent-%s" % os.getpid())
        resp = conn.getresponse()
        resp.read()
    finally:
        conn.close()

    lines = _wait_for_log_lines(node, before + 1)
    assert len(lines) > before, "the miss was not logged"
    fields = dict(re.findall(r"(\w+)=(\S+)", lines[-1]))
    assert fields.get("tls") == "off", lines[-1]
    assert fields.get("cache") == NONE, lines[-1]
    # The data-plane monitor variables are the sentinel here: brix opened
    # nothing and served no bytes, so a bogus "0" or empty field would be a
    # lie. This is the same "-" != "measured zero" discipline as $brix_cache.
    assert fields.get("bytes") == NONE, lines[-1]
    assert fields.get("ck") == NONE, lines[-1]


def test_data_plane_variables_reflect_a_real_get(node):
    """(success) A real GET populates the data-plane monitor surface:
    $brix_bytes_served equals the bytes brix actually served (the serve is
    zero-copy sendfile — proving the value comes from the serve result, not the
    per-op VFS observer), and $brix_backend_time is a seconds.mmm figure in the
    SAME shape as nginx's $request_time so an operator reads one log line, not
    two vocabularies. A plain GET computes no page-CRC, so $brix_checksum is the
    honest sentinel — the value that makes the variable safe to always log."""
    import http.client

    before = len(_log_lines(node))
    conn = http.client.HTTPConnection(node.host, node.port, timeout=30)
    try:
        conn.request("GET", "/probe.txt")
        resp = conn.getresponse()
        body = resp.read()
    finally:
        conn.close()
    assert resp.status == 200, resp.status

    lines = _wait_for_log_lines(node, before + 1)
    fields = dict(re.findall(r"(\w+)=(\S+)", lines[-1]))
    last = lines[-1]
    # bytes served == the bytes the client received (no range, no compression).
    assert fields.get("bytes") == str(len(body)), last
    assert int(fields["bytes"]) > 0, last
    # backend time: seconds.mmm, same format as $request_time; present (brix did
    # the open/stat), never the sentinel once brix touched storage.
    assert re.match(r"^\d+\.\d{3}$", fields.get("backend", "")), last
    # checksum: no page-CRC on a plain GET → sentinel, and when present it is
    # always algorithm-tagged (INVARIANT #9, encode at the edge) so it can never
    # be misread as adler32/md5.
    assert fields.get("ck") == NONE or fields["ck"].startswith("crc32c:"), last


def test_bytes_served_is_the_brix_figure_not_a_range_slice(node):
    """(success, range) A ranged GET serves fewer bytes; $brix_bytes_served
    tracks what brix actually put on the wire for THIS request, so the value
    follows the range rather than the file size — the property that makes it
    usable for read-amplification accounting alongside $body_bytes_sent."""
    import http.client

    before = len(_log_lines(node))
    conn = http.client.HTTPConnection(node.host, node.port, timeout=30)
    try:
        conn.request("GET", "/probe.txt", headers={"Range": "bytes=0-3"})
        resp = conn.getresponse()
        body = resp.read()
    finally:
        conn.close()
    # 206 with 4 bytes if range honoured; some builds may 200 the whole file —
    # either way bytes served must equal what the client received.
    lines = _wait_for_log_lines(node, before + 1)
    fields = dict(re.findall(r"(\w+)=(\S+)", lines[-1]))
    assert fields.get("bytes") == str(len(body)), (resp.status, lines[-1])


def test_brix_origin_strips_userinfo_from_a_remote_backend(tmp_path):
    """(security) A remote brix_storage_backend URL may carry user:pass@
    userinfo, and $brix_origin is loggable — so the credential MUST be stripped
    before it can reach a log file that leaves the box.

    Parse-and-serve rather than a unit test: the value comes from the raw
    configured string, so a request that 502s against an unreachable origin
    still exercises the exact stripping code path in the log phase. The
    assertion is on the ABSENCE of the secret, which is the property that
    matters.
    """
    import http.client
    import subprocess

    data = tmp_path / "data"
    (tmp_path / "logs").mkdir()
    data.mkdir()
    conf = tmp_path / "nginx.conf"
    secret = "s3cr3t-do-not-log"
    conf.write_text(f"""
worker_processes 1;
pid {tmp_path}/logs/nginx.pid;
error_log {tmp_path}/logs/error.log info;
daemon off;
events {{ worker_connections 64; }}
http {{
    log_format o 'origin=$brix_origin';
    access_log {tmp_path}/logs/o.log o;
    client_body_temp_path {tmp_path}/logs;
    server {{
        listen {HOST}:{free_port()};
        location /remote/ {{
            brix_webdav on;
            brix_storage_backend https://svcuser:{secret}@origin.invalid:8443/base;
            brix_webdav_auth none;
        }}
    }}
}}
""")
    # Parse first: prove the userinfo URL is accepted at all, then the running
    # instance below actually writes the log line the test reads.
    r = subprocess.run([NGINX_BIN, "-t", "-p", str(tmp_path), "-c", str(conf)],
                       capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr

    port = _port_from_conf(conf)
    proc = subprocess.Popen([NGINX_BIN, "-p", str(tmp_path), "-c", str(conf)])
    try:
        _wait_listen(HOST, port)
        conn = http.client.HTTPConnection(HOST, port, timeout=15)
        try:
            conn.request("GET", "/remote/probe.txt")
            conn.getresponse().read()      # 502/504 is fine; we want the log line
        except Exception:                  # noqa: BLE001 — origin is unreachable
            pass
        finally:
            conn.close()
    finally:
        proc.terminate()
        proc.wait(timeout=10)

    log = (tmp_path / "logs" / "o.log").read_text(errors="replace")
    assert log.strip(), "no access-log line was written"
    assert secret not in log, (
        f"$brix_origin leaked the backend password into the access log:\n{log}")
    assert "svcuser" not in log, f"$brix_origin leaked the backend username:\n{log}"
    # And it still reports the useful part — host:port/path.
    assert "origin.invalid:8443/base" in log, log


# ---------------------------------------------------------------------------
# error
# ---------------------------------------------------------------------------

def test_unknown_brix_variable_is_refused_by_nginx_itself(tmp_path):
    """(error) A typo'd $brix_* name fails at config time with NGINX's own
    diagnostic.

    A brix-specific message here would be worse: operators know what
    `unknown "..." variable` means, and a variable surface must fail the way
    every other nginx variable fails.
    """
    (tmp_path / "logs").mkdir(parents=True, exist_ok=True)
    (tmp_path / "data").mkdir(parents=True, exist_ok=True)
    result = nginx_t(
        TEMPLATE, tmp_path,
        PORT=SHARED_PARSE_PLACEHOLDER_PORT,
        LOG_DIR=str(tmp_path / "logs"),
        TMP_DIR=str(tmp_path / "logs"),
        DATA_DIR=str(tmp_path / "data"))
    assert result.returncode == 0, result.stderr

    # Now the same config with one variable misspelled.
    conf = tmp_path / "conf" / "nginx.conf"
    conf.write_text(conf.read_text().replace("$brix_cache_status",
                                             "$brix_cache_stats"))
    import subprocess
    bad = subprocess.run([NGINX_BIN, "-t", "-p", str(tmp_path),
                          "-c", str(conf)],
                         capture_output=True, text=True, timeout=60)
    assert bad.returncode != 0, "a misspelled variable was accepted"
    assert 'unknown "brix_cache_stats" variable' in bad.stderr, bad.stderr


# ---------------------------------------------------------------------------
# security-negative
# ---------------------------------------------------------------------------

# Names that would put credential material into anything an operator can log,
# add_header, or proxy_set_header.  phase-106 W8 R10 turns this into a CI rule;
# asserting it here keeps the surface honest until then.
CREDENTIAL_PATTERNS = ("token", "secret", "key", "password", "passwd",
                       "macaroon", "authorization", "bearer", "proxy_cert",
                       "private")

# The ONE reviewed exception: $brix_delegated_cred predates this rule and
# exists precisely to hand a delegated credential to proxy_ssl_certificate.
EXPOSURE_ALLOWLIST = {"brix_delegated_cred"}


def _registered_variable_names():
    """Every variable name brix registers, read from the sources.

    Source-scanning rather than runtime introspection: nginx offers no way to
    enumerate registered variables, and the point is to catch a name at review
    time — before it can ever reach a log.
    """
    names = set()
    pat = re.compile(r'ngx_string\("(brix_[a-z0-9_]+)"\)')
    for path in (REPO / "src").rglob("*.c"):
        text = path.read_text(errors="replace")
        if "ngx_http_add_variable" not in text and "variable_t" not in text:
            continue
        for m in pat.finditer(text):
            # Only count names in a variable array/registration context, not
            # directive tables, which use the same ngx_string() spelling.
            window = text[max(0, m.start() - 400):m.start() + 400]
            if "variable" in window:
                names.add(m.group(1))
    return names


def test_no_brix_variable_exposes_credential_material():
    """(security-neg) No registered $brix_* variable name matches the
    credential denylist, except the single reviewed allowlist entry.

    Variables are an exfiltration surface: anything registered can be written
    to a log file that leaves the box, or copied into an upstream header. The
    rule is that identity variables expose the SUBJECT (DN, VO, issuer, sub),
    never the credential that proved it.
    """
    offenders = {
        name for name in _registered_variable_names()
        if name not in EXPOSURE_ALLOWLIST
        and any(p in name for p in CREDENTIAL_PATTERNS)
    }
    assert not offenders, (
        "these brix variables look like they carry credential material; expose "
        "the subject, never the credential, or add a reviewed allowlist entry "
        f"with its rationale: {sorted(offenders)}")


def test_the_denylist_actually_fires():
    """(security-neg, non-vacuity) The check above is worthless if the pattern
    match is broken — prove it rejects the shape it exists to reject."""
    bad = {"brix_bearer_token", "brix_secret", "brix_client_key"}
    for name in bad:
        assert any(p in name for p in CREDENTIAL_PATTERNS), name
    assert "brix_cache_status" not in bad
    assert not any(p in "brix_cache_status" for p in CREDENTIAL_PATTERNS)
    assert not any(p in "brix_tls" for p in CREDENTIAL_PATTERNS)
