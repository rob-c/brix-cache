"""
tests/test_audit15aa_default_tokens.py — the tokens that restate a default
(audit §Method step 2 at VALUE granularity, tranche 15, ninth file).

WHY THIS FILE EXISTS
--------------------
The tranche counts coverage per (directive, value) pair rather than per
directive, and after eight files the backlog of never-written pairs is down to
five.  Four of them are the same shape: the token an operator writes when they
want the behaviour the merge would have chosen anyway —

    brix_backend_s3_sts_flavor        aws
    brix_health_check_type            ping
    brix_webdav_checksum_xattr_format text
    brix_webdav_redirect_scheme       http

and the fifth, `brix_ssi_cta_executor prod`, is the one member of the set that
asks for a change.  It is here because it is the last unwritten pair in the
tranche, and it earns its place: it is the control that proves this file can see
a difference when there is one to see.

A token that restates a default looks like the least interesting thing a
configuration can contain, and that is exactly why nothing had ever written one.
The assumption underneath is that `X default_token;` and no `X` line at all are
the same configuration.  For three of the four they are.  For the fourth they
are not, and the reason generalises: a directive whose merge pushes its value
into a process-global can be raised by any block in the file and lowered by
none, so writing the default is not a statement the code has any way to hear.

WHAT THE TOKENS SELECT
----------------------
    directive                          token   value  merge default
    brix_backend_s3_sts_flavor         aws       0    0  (bare literal)
    brix_health_check_type             ping      0    BRIX_HC_TYPE_PING
    brix_ssi_cta_executor              prod      1    0  (bare literal)
    brix_webdav_checksum_xattr_format  text      0    BRIX_CKS_FMT_TEXT
    brix_webdav_redirect_scheme        http      0    BRIX_WEBDAV_RDR_HTTP

WHAT THE MEASUREMENT ESTABLISHED
--------------------------------
One process, five WebDAV locations, two SSI faces.  Every row below is a live
observation, not a reading of the source.

    the checksum xattr format — one PUT per location, then the raw xattr

      location            directive written   user.XrdCks.adler32
      /bin/  (subject)    xrdcks              binary XrdCksData
      /txt/  (subject)    text                binary XrdCksData      <-- inert
      /txt/  (control)    text                "5bf5127c 1786941171 563566789 2048"

    The control is a SECOND nginx.  It has to be: the format is a process-wide
    global, so no location in the subject process can show what `text` does.

    the redirect scheme — one GET per location, then the Location header

      location            directive written   Location
      /rdr-none/          (none)              http://…/rdr-none/probe.dat
      /rdr-http/          http                http://…/rdr-http/probe.dat
      /rdr-https/         https               https://…/rdr-https/probe.dat

    Three locations, three independent verdicts, one process — the same merge
    function, twelve lines apart from the checksum format, done correctly.

    the CTA executor — one archive request per row, response type + alerts

      submitted on   an open on          response          alerts
      test face      —                   SUCCESS           queued, writing to tape
      prod face      —                   ERR_CTA           no nearline backend
      test face      the prod face       ERR_CTA           no nearline backend
      prod face      the test face       SUCCESS           queued, writing to tape

    The last two rows are the same two servers, the same two configurations,
    and the opposite answers — decided by which face was opened last.

FINDING — DEFECT CANDIDATE #62
------------------------------
`brix_webdav_checksum_xattr_format` is declared NGX_HTTP_MAIN_CONF |
NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF (module_commands.c:448) and merged with a
real ngx_conf_merge_uint_value (config_merge.c:105) — the whole of nginx's
inheritance machinery is wired up for it.  Then config_merge.c:107 throws the
result away:

    ngx_conf_merge_uint_value(conf->checksum_xattr_format,
                              prev->checksum_xattr_format, BRIX_CKS_FMT_TEXT);
    if (conf->checksum_xattr_format != BRIX_CKS_FMT_TEXT) {
        brix_integrity_set_xattr_format(conf->checksum_xattr_format);
    }

Nothing else in src/ reads conf->checksum_xattr_format.  The value that decides
the on-disk record is the process-global s_xattr_format (integrity_info.c:209),
and this `if` is its only writer — an `if` with no `else`, so the global only
ever moves away from text.  brix_integrity_set_xattr_format() itself accepts
BRIX_CKS_FMT_TEXT perfectly well (integrity_info.c:214); it is the caller that
is guarded to never pass it.

Consequence, measured: a location that writes `text` writes the binary
XrdCksData record whenever any other location in the same nginx wrote `xrdcks`,
and there is no configuration that puts it back.  The operator's directive is
accepted, merged, and ignored.  Ordering does not rescue it — `text` never
reaches the setter in either merge order.

FINDING — DEFECT CANDIDATE #63
------------------------------
`brix_ssi_cta_executor` is a per-server directive (directives_tpc.h:89), but
ssi_open_cta_gate() pushes it into a per-worker global on EVERY SSI open:

    brix_ssi_cta_configure(jbuf, conf->ssi_cta_executor == 1);   /* ssi.c:97 */

g_cta_use_prod (cta_service.c:22) is then read at COMPLETION
(cta_exec_vtbl(), :52), which for a deferred request is a later event on a
different connection's timeline.  So the executor that runs a request is the one
selected by the most recent open on ANY server in that worker — and the journal
path aliases the same way, through the same call.

Both directions were measured, and they are not equally bad:

  * a `prod` face retargets a `test` face's in-flight request, which turns a
    working archive into "request failed";
  * a `test` face retargets a `prod` face's in-flight request, which is the
    serious one — a server an operator configured to talk to real tape answers
    CTA_RSP_SUCCESS, "request completed", with the simulated executor's
    "writing to tape" alert, for an archive that never touched tape.  Any
    client that can open the other face can cause it.

This is a storage-control surface, and the second direction fabricates a
durability guarantee.  The two globals want to be per-connection state carried
off the srv conf at open, not per-worker state written at open.

WHAT THIS FILE DOES NOT CLAIM
-----------------------------
  * It does not own the enabling tokens.  test_checksum_on_write.py owns
    `xrdcks` and the binary record's field layout; test_audit15c_ssi_knobs.py
    owns `executor test` and the CTA journal; test_webdav_redirect_ds.py owns
    the signed-CGI handoff a 307 carries; test_phase22_health_check.py owns the
    live health-check probe and the bad-token rejection.  Those tokens appear
    here only as controls, so that "writing the default changed nothing" is a
    measurement and not a constant.
  * It does not distinguish a kXR_ping probe from a kXR_stat probe on the wire.
    `ping` is reached here statically — as the else-branch of the only test of
    probe_type in the tree — and by parse.  A wire-level ping/stat split needs a
    listener that records the opcode it was probed with, which is a health-check
    harness concern and belongs beside the existing one.
  * It does not exercise `brix_backend_s3_sts_flavor aws` against a live STS
    endpoint.  The token is reached by parse on both planes and by the static
    agreement of the two enum tables and the post-merge fallback; the AWS
    dialect itself is phase-70 lab territory.
"""

import os
import re
import time
import urllib.error
import urllib.request
import uuid
import zlib
from pathlib import Path

import pytest

from config_parse import nginx_t
from fleet_lifecycle_ports import (PARSE_PLACEHOLDER_PORT,
                                   SHARED_PARSE_PLACEHOLDER_PORT)
from server_registry import NginxInstanceSpec
from settings import BIND_HOST, HOST
from test_ssi_async import _submit, kXR_waitresp
from test_ssi_cta import CTA_RSP_SUCCESS, _collect_pushed_response, build_request
from test_ssi_wire import _handshake_login, _open_ssi

def _expression_1(stripped):
    return (
        "offsetof(" in stripped or 'ngx_string("' in stripped
                                or "NGX_CONF_UNSET_UINT" in stripped
    )


def _check_test_an_unknown_token_is_refused_1(result, directive):
    assert result.returncode != 0, \
        f"{directive} accepted the token 'nosuchtoken'"

def _check_test_an_unknown_token_is_refused_2(result, out, directive):
    assert "invalid" in out or directive in out, _output(result)

def _check_test_nothing_else_reads_the_merged_field_3(hits):
    assert len(hits["src/protocols/webdav/config_merge.c"]) == 4, hits


pytestmark = [pytest.mark.timeout(300),
              pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-audit15aa-default")]

NAME = "lc-audit15aa-default"
CLEAN = "lc-audit15aa-clean"
ROOT = Path(__file__).resolve().parents[1]

CTA_RSP_ERR_CTA = 3
ALERT_NO_BACKEND = b"no nearline backend configured"
ALERT_TAPE = b"writing to tape"

# (directive, token, field, merge unit, merge-default spelling, enum table)
TOKENS = (
    ("brix_backend_s3_sts_flavor", "aws", "backend_sts_flavor",
     "src/core/config/shared_conf_merge.h", "0",
     ("src/core/config/http_common.c", "brix_sts_flavor_enum")),
    ("brix_health_check_type", "ping", "hc.type",
     "src/core/config/server_conf_merge_cluster.c", "BRIX_HC_TYPE_PING",
     ("src/protocols/root/stream/module_enums.c", "brix_hc_types")),
    ("brix_ssi_cta_executor", "prod", "ssi_cta_executor",
     "src/core/config/server_conf_merge_cluster.c", "0",
     ("src/protocols/root/stream/module.c", "brix_ssi_executor_enum")),
    ("brix_webdav_checksum_xattr_format", "text", "checksum_xattr_format",
     "src/protocols/webdav/config_merge.c", "BRIX_CKS_FMT_TEXT",
     ("src/protocols/webdav/module_commands.c", "brix_webdav_cks_xattr_formats")),
    ("brix_webdav_redirect_scheme", "http", "redirect_scheme",
     "src/protocols/webdav/config_merge.c", "BRIX_WEBDAV_RDR_HTTP",
     ("src/protocols/webdav/module_commands.c", "brix_webdav_redirect_schemes")),
)
TOKEN_IDS = [t[0] for t in TOKENS]

# The full token set of every table above, from the audit's own count.  A table
# that grows a sixth token silently grows the tranche's denominator with it.
EXPECTED_TOKENS = {
    "brix_backend_s3_sts_flavor": ("aws", "minio"),
    "brix_health_check_type": ("ping", "stat"),
    "brix_ssi_cta_executor": ("test", "prod"),
    "brix_webdav_checksum_xattr_format": ("text", "xrdcks"),
    "brix_webdav_redirect_scheme": ("http", "https"),
}

# The four that restate what the merge already chose, and the one that does not.
RESTATES_THE_DEFAULT = {d: d != "brix_ssi_cta_executor" for d in TOKEN_IDS}

STS_TABLES = (
    ("http", "src/core/config/http_common.c", "brix_sts_flavor_enum"),
    ("stream", "src/protocols/root/stream/module.c",
     "brix_stream_sts_flavor_enum"),
)


# --------------------------------------------------------------------------- #
# Reading the source.                                                          #
# --------------------------------------------------------------------------- #

def _source(relative):
    return (ROOT / relative).read_text(errors="replace")


def _flat(text):
    """Whitespace-flattened, so a regex is not hostage to the line breaks the
    formatter chose for a four-argument macro."""
    return re.sub(r"\s+", " ", text)


def _merge_default(unit, field):
    """The third argument of ngx_conf_merge_uint_value for `field`, verbatim."""
    hit = re.search(
        r"ngx_conf_merge_uint_value\( ?conf->" + re.escape(field)
        + r", ?prev->" + re.escape(field) + r", ?([A-Za-z0-9_]+) ?\)",
        _flat(_source(unit)))
    assert hit, f"no uint merge for conf->{field} in {unit}"
    return hit.group(1)


def _constant(name):
    """Resolve a C spelling to its integer value: a bare literal, a #define, or
    an enumerator.  The point is that the test never hard-codes what a named
    constant is worth — renaming or renumbering one has to show up here."""
    if name.isdigit():
        return int(name)
    for path in ("src/net/manager/health_check.h",
                 "src/core/compat/integrity_info.h",
                 "src/protocols/webdav/webdav_loc_conf.h",
                 "src/auth/s3/sts.h"):
        text = _source(path)
        hit = (re.search(rf"^#define\s+{re.escape(name)}\s+(\d+)", text,
                         re.MULTILINE)
               or re.search(rf"\b{re.escape(name)}\s*=\s*(\d+)", text))
        if hit:
            return int(hit.group(1))
    raise AssertionError(f"constant {name} not found in the headers searched")


def _enum_table(path, table):
    """{token: integer value} for one ngx_conf_enum_t, NUL row excluded."""
    text = _source(path)
    hit = re.search(rf"ngx_conf_enum_t\s+{re.escape(table)}\[\]\s*=\s*\{{(.*?)\}};",
                    text, re.DOTALL)
    assert hit, f"enum table {table} not found in {path}"
    return {tok: _constant(val)
            for tok, val in re.findall(
                r'\{\s*ngx_string\("([^"]+)"\)\s*,\s*([A-Za-z0-9_]+)\s*\}',
                hit.group(1))}


# --------------------------------------------------------------------------- #
# The running cluster.  Module-scoped with its own harness: both instances bind #
# fixed ledger ports, so a per-test start/stop cycle races the OS releasing     #
# them, and every test below is read-only against what is running.              #
# --------------------------------------------------------------------------- #

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None   # surface the 307 instead of following it


_OPENER = urllib.request.build_opener(_NoRedirect)


def _req(method, port, path, body=None):
    req = urllib.request.Request(f"http://{HOST}:{port}{path}", method=method,
                                 data=body)
    try:
        with _OPENER.open(req, timeout=15) as resp:
            return resp.status, dict(resp.headers), resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, dict(exc.headers), exc.read()


def _put(port, path, body):
    status, _headers, _body = _req("PUT", port, path, body)
    assert status in (200, 201, 204), f"PUT {path} -> {status}"


def _xattr(path):
    try:
        return os.getxattr(str(path), "user.XrdCks.adler32")
    except OSError:
        return None


@pytest.fixture(scope="module")
def cluster(tmp_path_factory):
    from server_launcher import LifecycleHarness  # noqa: PLC0415 — lazy

    base = tmp_path_factory.mktemp("audit15aa")
    data = base / "data"
    for sub in ("txt", "bin", "rdr-none", "rdr-http", "rdr-https"):
        (data / sub).mkdir(parents=True)
    clean_data = base / "clean"
    (clean_data / "txt").mkdir(parents=True)
    tmp = base / "tmp"
    tmp.mkdir()
    journal = base / "cta.journal"

    harness = LifecycleHarness()
    try:
        subject = harness.start(NginxInstanceSpec(
            name=NAME, template="nginx_audit15aa_default.conf",
            protocol="http", data_root=str(data),
            template_values={"BIND_HOST": BIND_HOST, "TMP_DIR": str(tmp),
                             "JOURNAL": str(journal)},
            reason="audit-15aa: the tokens that restate a default — five "
                   "WebDAV locations and two SSI faces in ONE worker"))
        control = harness.start(NginxInstanceSpec(
            name=CLEAN, template="nginx_audit15aa_clean.conf",
            protocol="http", data_root=str(clean_data),
            template_values={"BIND_HOST": BIND_HOST, "TMP_DIR": str(tmp)},
            reason="audit-15aa: the separate process in which `text` is the "
                   "only checksum format anyone asks for"))

        # The redirect arms need a registered member: brix_srv_select() finding
        # nothing is a local serve, not a 307, so poll until the CMS
        # registration lands rather than let the first arm eat the startup race.
        deadline = time.time() + 45
        while time.time() < deadline:
            status, _h, _b = _req("GET", subject.port, "/rdr-none/probe.dat")
            if status == 307:
                break
            time.sleep(0.5)
        else:
            pytest.fail("no cluster member registered: the CMS registry stayed "
                        "empty for 45s, so no Location header ever existed")

        # The control PUT happens once, here, because two §E tests need it and
        # because it decides whether this filesystem can answer at all.
        control_name = f"ctl_{uuid.uuid4().hex[:8]}.bin"
        payload = os.urandom(2048)
        _put(control.port, f"/txt/{control_name}", payload)
        control_xattr = _xattr(clean_data / "txt" / control_name)

        yield {"port": subject.port,
               "ssi": subject.extra_ports["SSI_PORT"],
               "ssi2": subject.extra_ports["SSI2_PORT"],
               "data": data,
               "journal": journal,
               "control_port": control.port,
               "control_xattr": control_xattr,
               "control_payload": payload}
    finally:
        harness.close()


def _archive(port, alias_open=None):
    """Submit one CTA archive on `port`, optionally opening the cta service on
    `alias_open` in between the open and the submit.  Returns (type, alerts).

    The interleave is the whole experiment, and it is deterministic: the
    executor is chosen at open and read at completion, and both are ordinary
    request-order events inside one worker.
    """
    request = build_request(4, "eosdev", "alice", "eosusers",
                            "/eos/a15aa/f1", 7)     # event 4 = CLOSEW = archive
    socks = []
    try:
        sock = _handshake_login(HOST, port)
        socks.append(sock)
        handle = _open_ssi(sock, "cta")
        if alias_open is not None:
            other = _handshake_login(HOST, alias_open)
            socks.append(other)
            _open_ssi(other, "cta")
        assert _submit(sock, handle, 1, request) == kXR_waitresp
        alerts, response = _collect_pushed_response(sock)
        return response.get(1), alerts
    finally:
        for sock in socks:
            sock.close()


def _parse(tmp_path, *, outer="", http_main="", loc="", stream=""):
    data = tmp_path / "data"
    data.mkdir(exist_ok=True)
    return nginx_t("nginx_audit15aaparse.conf", tmp_path,
                   BIND_HOST=BIND_HOST,
                   PORT=PARSE_PLACEHOLDER_PORT,
                   HTTP_PORT=SHARED_PARSE_PLACEHOLDER_PORT,
                   DATA_ROOT=str(data), LOG_DIR=str(tmp_path),
                   OUTER=outer, HTTP_MAIN=http_main, LOC=loc, STREAM=stream)


def _output(result):
    return (result.stdout or "") + (result.stderr or "")


def _line(directive, token, indent=8):
    return " " * indent + f"{directive} {token};\n"


# --------------------------------------------------------------------------- #
# A. The tokens parse where they are declared, and nowhere else.               #
# --------------------------------------------------------------------------- #

