"""Runtime, config-error and exposure contracts for ``$brix_*`` variables.

Registration belongs to the common HTTP module so the same variables work in
nginx log and routing directives independently of the protocol handler.
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
    # Cache-enabled (phase-110 W1): origin + a sibling cache dir (neither
    # beneath the other, satisfying the cache_root security check) so
    # $brix_cache_status reports a real HIT/MISS on the WebDAV data plane.
    origin = data / "origin"
    origin.mkdir()
    (origin / "probe.txt").write_bytes(b"brix variable probe\n")
    cache = data / "cache"
    cache.mkdir()

    harness = LifecycleHarness()
    try:
        inst = harness.start(NginxInstanceSpec(
            name="lc-brix-variables",
            template=TEMPLATE,
            protocol="webdav",
            readiness="tcp",
            data_root=str(origin),
            template_values={"DATA_DIR": str(origin), "CACHE_DIR": str(cache)},
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
    """Wait for nginx's post-response LOG phase without hiding timeout state."""
    deadline = time.monotonic() + timeout
    lines = _log_lines(inst)
    while len(lines) < min_count and time.monotonic() < deadline:
        time.sleep(0.05)
        lines = _log_lines(inst)
    return lines


def test_log_format_over_brix_variables_writes_every_field(node):
    """A variable-based log format writes every documented field."""
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
    # The data-plane monitor variables are the sentinel here: brix opened
    # nothing and served no bytes, so a bogus "0" or empty field would be a
    # lie. This is the same "-" != "measured zero" discipline as $brix_cache.
    assert fields.get("bytes") == NONE, lines[-1]
    assert fields.get("ck") == NONE, lines[-1]
    # A 404 GET consulted the cache and missed → MISS (a real disposition on
    # the WebDAV data plane, which before phase-110 W1 was always "-").
    assert fields.get("cache") in {NONE, "MISS"}, lines[-1]


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


def test_cache_status_reports_a_disposition_on_the_webdav_data_plane(node):
    """(success, phase-110 W1) The flagship fix: $brix_cache_status reports a
    real cache disposition on the WebDAV data plane, in the shared
    HIT/MISS/BYPASS/NEGHIT vocabulary — where before W1 it ALWAYS logged "-"
    (only cvmfs/oci/rpm reported). A GET against the cache-enabled export logs a
    genuine decision (MISS on a cold object), never the sentinel."""
    import http.client

    before = len(_log_lines(node))
    conn = http.client.HTTPConnection(node.host, node.port, timeout=30)
    try:
        conn.request("GET", "/probe.txt")
        resp = conn.getresponse()
        resp.read()
        assert resp.status == 200
    finally:
        conn.close()
    lines = _wait_for_log_lines(node, before + 1)
    fields = dict(re.findall(r"(\w+)=(\S+)", lines[-1]))
    assert fields.get("cache") in {"HIT", "MISS"}, (
        "WebDAV GET reported no cache disposition — phase-110 W1 gives the data "
        f"planes a real HIT/MISS instead of the pre-W1 sentinel:\n{lines[-1]}")


def test_op_path_status_describe_the_brix_operation(node):
    """(success, phase-110 W4) A GET populates the facts no nginx variable can
    express: $brix_op is the brix operation (read, not the HTTP verb), $brix_path
    is the confined export-relative path (not the URL), $brix_status is the
    plane-neutral outcome word, $brix_duration matches $request_time's shape, and
    $brix_user is the sentinel for an unmapped anonymous request."""
    import http.client

    before = len(_log_lines(node))
    conn = http.client.HTTPConnection(node.host, node.port, timeout=30)
    try:
        conn.request("GET", "/probe.txt")
        conn.getresponse().read()
    finally:
        conn.close()

    lines = _wait_for_log_lines(node, before + 1)
    fields = dict(re.findall(r"(\w+)=(\S+)", lines[-1]))
    last = lines[-1]
    assert fields.get("op") == "read", last          # the brix op, not "GET"
    assert int(fields.get("ops", "0")) >= 1, last
    assert fields.get("path", "").endswith("/probe.txt"), last  # confined resolved path
    assert ".." not in fields.get("path", ""), last            # never an escape
    assert fields.get("st") == "ok", last             # plane-neutral outcome
    assert re.match(r"^\d+\.\d{3}$", fields.get("dur", "")), last  # $request_time shape
    assert fields.get("user") == NONE, last           # anonymous → unmapped
    assert fields.get("recv") == NONE, last           # a GET receives no body


def test_monitor_is_per_request_not_per_connection(node):
    """(security-neg, phase-110 W1/W4 / Appendix-B R-3) The I/O monitor is
    per-REQUEST (r->pool), never per-connection. Two requests on ONE keepalive
    connection must each log their OWN op/path/status — a served GET and a 404 —
    with no bleed of the first request's facts into the second. If the monitor
    were pinned to the connection, the second line would inherit the first's
    path/op and every reused-connection log would be corrupt."""
    import http.client

    before = len(_log_lines(node))
    conn = http.client.HTTPConnection(node.host, node.port, timeout=30)
    absent = "/absent-%s.txt" % os.getpid()
    try:
        conn.request("GET", "/probe.txt")
        conn.getresponse().read()
        # Same connection, second request — keepalive reuse is the point.
        conn.request("GET", absent)
        r2 = conn.getresponse()
        r2.read()
    finally:
        conn.close()
    assert r2.status == 404, r2.status

    lines = _wait_for_log_lines(node, before + 2)
    assert len(lines) >= before + 2, "both requests were not logged"
    served = dict(re.findall(r"(\w+)=(\S+)", lines[-2]))
    missed = dict(re.findall(r"(\w+)=(\S+)", lines[-1]))
    # The served GET's facts.
    assert served.get("op") == "read", lines[-2]
    assert served.get("path", "").endswith("/probe.txt"), lines[-2]
    assert served.get("st") == "ok", lines[-2]
    # The 404 on the SAME connection carries its OWN facts — never the first
    # request's path or ok-status leaking through a connection-scoped monitor.
    assert missed.get("st") == "not_found", lines[-1]
    assert not missed.get("path", "").endswith("/probe.txt"), (
        f"the second request inherited the first request's path — the monitor "
        f"is per-connection, not per-request:\n{lines[-2]}\n{lines[-1]}")


def test_brix_path_never_leaks_outside_the_export_on_a_traversal(node):
    """(security-neg, phase-110 W4 / Appendix-B R-2 — Severe) $brix_path is
    loggable, so a `..`-traversal probe must NEVER put a string from outside the
    export into it: the source is the *confined* resolved path, never the raw
    client URL. A `GET /../../../../etc/passwd` is refused, and the logged
    `path=` field is either the sentinel or a path confined to the export — it
    contains neither `/etc/` nor `passwd`. This is the runtime half of R-2's
    mitigation (the userinfo half is test_brix_origin_strips_userinfo); without
    it a resolver regression could log the escaped target and ship it off-box."""
    import http.client

    before = len(_log_lines(node))
    conn = http.client.HTTPConnection(node.host, node.port, timeout=30)
    try:
        conn.request("GET", "/../../../../etc/passwd")
        resp = conn.getresponse()
        resp.read()
    finally:
        conn.close()
    # The escape is refused (nginx may 400 the request line, or brix 403/404 the
    # confined path); what matters is that no successful enumeration occurred.
    assert resp.status in (400, 403, 404), resp.status

    lines = _wait_for_log_lines(node, before + 1)
    fields = dict(re.findall(r"(\w+)=(\S+)", lines[-1]))
    path = fields.get("path", NONE)
    assert "/etc/" not in path and "passwd" not in path, (
        f"$brix_path leaked a traversal target outside the export: {lines[-1]}")
    assert ".." not in path, (
        f"$brix_path carried an unresolved escape sequence: {lines[-1]}")


def test_readonly_refusal_logs_status_forbidden(node):
    """(security-neg, phase-110 W4) The cross-plane headline: a write to a
    read-only export (the node has no brix_allow_write, so allow_write defaults
    off) is refused with EROFS, and $brix_status logs `forbidden` — the SAME
    plane-neutral outcome word a read-only refusal produces on S3 and root://,
    whatever HTTP code was sent. The mutation gate stamps the class on the
    monitor before any VFS op runs, so the word appears even though the write
    never happened."""
    import http.client

    before = len(_log_lines(node))
    conn = http.client.HTTPConnection(node.host, node.port, timeout=30)
    try:
        conn.request("PUT", "/rejected-%s.txt" % os.getpid(), body=b"nope")
        resp = conn.getresponse()
        resp.read()
    finally:
        conn.close()
    # A read-only export refuses the write (403 EROFS, or 405 if the method is
    # gated earlier); either way the brix outcome class is the same word.
    assert resp.status in (403, 405), resp.status

    lines = _wait_for_log_lines(node, before + 1)
    fields = dict(re.findall(r"(\w+)=(\S+)", lines[-1]))
    assert fields.get("st") == "forbidden", (
        "a read-only-export write did not log $brix_status=forbidden "
        f"(phase-110 W4, the cross-plane outcome word):\n{lines[-1]}")


def test_status_is_the_outcome_class_not_the_http_code(node):
    """(error, phase-110 W4) A 404 logs $brix_status=not_found — the brix
    outcome class, one word that means the same on every plane, distinct from
    the HTTP $status code."""
    import http.client

    before = len(_log_lines(node))
    conn = http.client.HTTPConnection(node.host, node.port, timeout=30)
    try:
        conn.request("GET", "/no-such-%s.txt" % os.getpid())
        conn.getresponse().read()
    finally:
        conn.close()

    lines = _wait_for_log_lines(node, before + 1)
    fields = dict(re.findall(r"(\w+)=(\S+)", lines[-1]))
    assert fields.get("status") == "404", lines[-1]     # nginx code
    assert fields.get("st") == "not_found", lines[-1]   # brix outcome class


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
    (tmp_path / "cache").mkdir(parents=True, exist_ok=True)
    result = nginx_t(
        TEMPLATE, tmp_path,
        PORT=SHARED_PARSE_PLACEHOLDER_PORT,
        LOG_DIR=str(tmp_path / "logs"),
        TMP_DIR=str(tmp_path / "logs"),
        DATA_DIR=str(tmp_path / "data"),
        CACHE_DIR=str(tmp_path / "cache"))
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
