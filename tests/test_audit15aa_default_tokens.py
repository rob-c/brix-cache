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
     "src/core/config/shared_conf.h", "0",
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

class TestTheTokensParse:
    """The cheapest thing that had never been established: that writing the
    default token at all is legal.  A directive whose default spelling is
    refused would be a defect nothing in the tree could have caught, because
    nothing in the tree wrote one."""

    STREAM_ONLY = ("brix_health_check_type", "brix_ssi_cta_executor")

    @pytest.mark.parametrize("directive,token", [(t[0], t[1]) for t in TOKENS],
                             ids=TOKEN_IDS)
    def test_the_token_parses_in_its_own_context(self, tmp_path, directive,
                                                 token):
        if directive in self.STREAM_ONLY:
            result = _parse(tmp_path, stream=_line(directive, token))
        elif directive == "brix_backend_s3_sts_flavor":
            # Declared on BOTH planes; the stream one is the copy under §C.
            result = _parse(tmp_path, stream=_line(directive, token),
                            loc=_line(directive, token, indent=12))
        else:
            result = _parse(tmp_path, loc=_line(directive, token, indent=12))
        assert result.returncode == 0, _output(result)

    @pytest.mark.parametrize("directive,token", [(t[0], t[1]) for t in TOKENS],
                             ids=TOKEN_IDS)
    def test_an_unknown_token_is_refused(self, tmp_path, directive, token):
        """error: an enum directive must reject what it does not know rather
        than fall through to its default — otherwise a typo in the token silently
        selects the very behaviour this file is about."""
        where = ("stream" if directive in self.STREAM_ONLY
                 or directive == "brix_backend_s3_sts_flavor" else "loc")
        indent = 8 if where == "stream" else 12
        result = _parse(tmp_path,
                        **{where: _line(directive, "nosuchtoken", indent)})
        assert result.returncode != 0, \
            f"{directive} accepted the token 'nosuchtoken'"
        out = _output(result).lower()
        assert "invalid" in out or directive in out, _output(result)

    @pytest.mark.parametrize("directive,token", [(t[0], t[1]) for t in TOKENS],
                             ids=TOKEN_IDS)
    def test_a_prefix_of_the_token_is_refused(self, tmp_path, directive, token):
        """security-negative: ngx_conf_set_enum_slot compares the whole name
        (name.len is tested before the bytes), so a truncated token must be an
        error.  A prefix match would make `brix_webdav_redirect_scheme http`
        and `... https` the same line, which is precisely the pair this file
        distinguishes."""
        where = ("stream" if directive in self.STREAM_ONLY
                 or directive == "brix_backend_s3_sts_flavor" else "loc")
        indent = 8 if where == "stream" else 12
        result = _parse(tmp_path,
                        **{where: _line(directive, token[:-1], indent)})
        assert result.returncode != 0, \
            f"{directive} accepted '{token[:-1]}', a prefix of '{token}'"

    @pytest.mark.parametrize("directive,token", [(t[0], t[1]) for t in TOKENS],
                             ids=TOKEN_IDS)
    def test_the_token_is_case_insensitive(self, tmp_path, directive, token):
        """ngx_conf_set_enum_slot matches with ngx_strcasecmp, so `AWS` and
        `aws` are one pair and not two.  The tranche's §Method counts pairs off
        the enum table for exactly this reason — counting spellings instead
        would inflate the denominator without adding a single behaviour."""
        where = ("stream" if directive in self.STREAM_ONLY
                 or directive == "brix_backend_s3_sts_flavor" else "loc")
        indent = 8 if where == "stream" else 12
        result = _parse(tmp_path,
                        **{where: _line(directive, token.upper(), indent)})
        assert result.returncode == 0, _output(result)

    def test_a_stream_token_is_refused_in_a_location(self, tmp_path):
        """error: brix_health_check_type is NGX_STREAM_SRV_CONF only."""
        result = _parse(tmp_path,
                        loc=_line("brix_health_check_type", "ping", 12))
        assert result.returncode != 0, \
            "brix_health_check_type was accepted in an http location"

    def test_the_redirect_scheme_is_refused_above_a_location(self, tmp_path):
        """error: brix_webdav_redirect_scheme is NGX_HTTP_LOC_CONF only, unlike
        brix_webdav_checksum_xattr_format three tables away, which is declared
        main|srv|loc.  The asymmetry is real and worth pinning: it is the reason
        the redirect arm below can only be built out of locations."""
        result = _parse(tmp_path,
                        http_main=_line("brix_webdav_redirect_scheme", "http", 4))
        assert result.returncode != 0, \
            "brix_webdav_redirect_scheme was accepted in the http main context"

    def test_the_xattr_format_parses_above_a_location(self, tmp_path):
        """success: the same directive that DEFECT CANDIDATE #62 shows to be
        inert is nonetheless accepted at the http main context, which is what
        makes the finding a contradiction rather than a limitation."""
        result = _parse(
            tmp_path,
            http_main=_line("brix_webdav_checksum_xattr_format", "text", 4))
        assert result.returncode == 0, _output(result)

    def test_a_token_at_the_top_level_is_refused(self, tmp_path):
        """security-negative: outside stream{} and http{} nginx knows none of
        these directives, and an unknown directive at the top level must be a
        parse error, never a silent no-op."""
        result = _parse(tmp_path,
                        outer=_line("brix_ssi_cta_executor", "prod", 0))
        assert result.returncode != 0, \
            "brix_ssi_cta_executor was accepted at the top level"


# --------------------------------------------------------------------------- #
# B. Where the default is, and which tokens restate it.                        #
# --------------------------------------------------------------------------- #

class TestWhereTheDefaultIs:

    @pytest.mark.parametrize("row", TOKENS, ids=TOKEN_IDS)
    def test_the_token_agrees_with_the_merge(self, row):
        directive, token, field, unit, spelling, table = row
        default = _constant(_merge_default(unit, field))
        value = _enum_table(*table)[token]
        if RESTATES_THE_DEFAULT[directive]:
            assert value == default, (
                f"{directive} {token} = {value} but the merge in {unit} "
                f"defaults conf->{field} to {spelling} = {default}; this file's "
                f"premise is that writing the token changes nothing")
        else:
            assert value != default, (
                f"{directive} {token} = {value} now equals the merge default "
                f"{spelling} = {default}; it was the one token in this set that "
                f"asked for a change, and it is this file's control")

    @pytest.mark.parametrize("row", TOKENS, ids=TOKEN_IDS)
    def test_the_merge_default_is_spelled_as_the_source_says(self, row):
        """The spelling, not just the value.  Two of the five merge to a bare
        `0` where the enum has a name for it (BRIX_STS_FLAVOR_AWS, and the SSI
        table has no names at all), so the default and the token agree only by
        the coincidence of two literals.  Pinning the spelling is what makes a
        future renumbering visible here instead of at a WLCG site."""
        _directive, _token, field, unit, spelling, _table = row
        assert _merge_default(unit, field) == spelling

    @pytest.mark.parametrize("row", TOKENS, ids=TOKEN_IDS)
    def test_the_table_carries_exactly_the_tokens_audited(self, row):
        """The tranche counts (directive, value) pairs off the enum table.  A
        sixth token in any table below means the audit's denominator moved and
        this file no longer closes the directive."""
        directive, _token, _field, _unit, _spelling, table = row
        assert tuple(_enum_table(*table)) == EXPECTED_TOKENS[directive]

    def test_the_ssi_reader_agrees_with_the_ssi_table(self):
        """brix_ssi_executor_enum spells its values as bare 0 and 1, and ssi.c
        compares against a bare 1.  Nothing links the two, so assert the link."""
        assert _enum_table("src/protocols/root/stream/module.c",
                           "brix_ssi_executor_enum")["prod"] == 1
        assert re.search(r"conf->ssi_cta_executor == 1", _source(
            "src/protocols/ssi/ssi.c")), \
            "ssi.c no longer selects the executor with `== 1`"


# --------------------------------------------------------------------------- #
# C. One directive name, two enum tables.                                      #
# --------------------------------------------------------------------------- #

class TestTheTwoStsTables:
    """brix_backend_s3_sts_flavor is declared on the http plane off
    brix_sts_flavor_enum and on the stream plane off a deliberate copy
    (module.c:69 says so in as many words, because the http table is
    file-static).  Two tables for one directive name is a sync hazard with no
    compiler behind it — these are the assertions that stand in for one."""

    def test_both_planes_carry_the_same_tokens(self):
        tables = {plane: _enum_table(path, name)
                  for plane, path, name in STS_TABLES}
        assert tables["http"] == tables["stream"], (
            "the stream copy of brix_backend_s3_sts_flavor has drifted from "
            f"the http original: {tables}")

    def test_the_tokens_resolve_to_the_documented_enum(self):
        table = _enum_table(*STS_TABLES[0][1:])
        assert table["aws"] == _constant("BRIX_STS_FLAVOR_AWS")
        assert table["minio"] == _constant("BRIX_STS_FLAVOR_MINIO")

    def test_the_post_merge_fallback_agrees_with_the_merge(self):
        """deleg_wire.c:40 re-tests backend_sts_flavor against
        NGX_CONF_UNSET_UINT after shared_conf.h:424 has already folded it, and
        falls back to BRIX_STS_FLAVOR_AWS.  The branch is unreachable while the
        merge runs, which makes it harmless and invisible — right up to the day
        the merge default changes and the two disagree.  Assert they agree."""
        default = _constant(_merge_default("src/core/config/shared_conf.h",
                                           "backend_sts_flavor"))
        flat = _flat(_source("src/protocols/shared/deleg_wire.c"))
        hit = re.search(r"cf->flavor = \(cc->backend_sts_flavor != "
                        r"NGX_CONF_UNSET_UINT\) \? \(int\) "
                        r"cc->backend_sts_flavor : ([A-Za-z0-9_]+);", flat)
        assert hit, "deleg_wire.c no longer picks the flavor with that ternary"
        assert _constant(hit.group(1)) == default, (
            f"deleg_wire.c falls back to {hit.group(1)} but the merge defaults "
            f"to {default}")


# --------------------------------------------------------------------------- #
# D. DEFECT CANDIDATE #63 — the CTA executor is decided by the last open.      #
# --------------------------------------------------------------------------- #

class TestTheCtaExecutorAliases:

    def test_the_test_face_completes_an_archive(self, cluster):
        """control: with only its own face opened, `executor test` runs the
        simulated executor and the archive completes.  Without this row the
        failures below could be the CTA service being broken."""
        rsp, alerts = _archive(cluster["ssi"])
        assert rsp == CTA_RSP_SUCCESS, (rsp, alerts)
        assert ALERT_TAPE in alerts, alerts

    def test_the_prod_face_fails_without_a_backend(self, cluster):
        """control: `executor prod` selects cta_exec.c's prod_vtbl, which in a
        build with no nearline backend fails cleanly.  This is the token under
        test reaching its own code for the first time in the tree."""
        rsp, alerts = _archive(cluster["ssi2"])
        assert rsp == CTA_RSP_ERR_CTA, (rsp, alerts)
        assert ALERT_NO_BACKEND in alerts, alerts

    def test_a_prod_open_breaks_the_test_faces_request(self, cluster):
        """DEFECT CANDIDATE #63, first direction: the request is submitted on
        the `executor test` face and answered by the production executor,
        because an open on the other face landed in between."""
        rsp, alerts = _archive(cluster["ssi"], alias_open=cluster["ssi2"])
        assert rsp == CTA_RSP_ERR_CTA, (
            "the prod face no longer retargets the test face — if "
            "brix_ssi_cta_configure() has moved off the open path, delete "
            "DEFECT CANDIDATE #63 from this module's docstring", rsp, alerts)
        assert ALERT_NO_BACKEND in alerts, alerts

    def test_a_test_open_fabricates_success_on_the_prod_face(self, cluster):
        """DEFECT CANDIDATE #63, the direction that matters: the request is
        submitted on the face an operator configured for real tape, and it is
        answered CTA_RSP_SUCCESS — "writing to tape" — by the simulated
        executor.  A durability guarantee, fabricated by an unrelated client's
        open on a different listener."""
        rsp, alerts = _archive(cluster["ssi2"], alias_open=cluster["ssi"])
        assert rsp == CTA_RSP_SUCCESS, (
            "the test face no longer retargets the prod face — if "
            "brix_ssi_cta_configure() has moved off the open path, delete "
            "DEFECT CANDIDATE #63 from this module's docstring", rsp, alerts)
        assert ALERT_TAPE in alerts, alerts

    def test_the_journal_aliases_through_the_same_call(self, cluster):
        """The journal path rides the same brix_ssi_cta_configure() call, so it
        aliases identically: the prod face writes no brix_ssi_cta_journal, and
        its open therefore clears the path the other face configured.  The
        journal is here because the executor's fix has to carry it."""
        assert cluster["journal"].exists(), \
            "the test face never opened its journal at all"
        flat = _flat(_source("src/protocols/ssi/ssi.c"))
        assert "brix_ssi_cta_configure(jbuf, conf->ssi_cta_executor == 1);" \
            in flat, "ssi.c no longer configures the service from the open path"

    def test_the_executor_lives_in_a_process_global(self, cluster):
        """The static half of #63: g_cta_use_prod is file-static per worker and
        is read at completion, not carried on the request."""
        text = _source("src/protocols/ssi/svc_cta/cta_service.c")
        assert re.search(r"^static int\s+g_cta_use_prod;", text, re.MULTILINE), \
            "g_cta_use_prod is no longer a file-static global"
        assert re.search(r"return g_cta_use_prod \? cta_exec_prod_vtbl\(\)",
                         text), "the vtbl is no longer chosen from the global"


# --------------------------------------------------------------------------- #
# E. DEFECT CANDIDATE #62 — `text` cannot be restored.                         #
# --------------------------------------------------------------------------- #

def _require_xattr(cluster):
    if cluster["control_xattr"] is None:
        pytest.skip("no user.* xattr support on this filesystem: the control "
                    "PUT left no user.XrdCks.adler32 to compare against")


class TestTheXattrFormatCannotBeRestored:

    def test_the_control_process_writes_the_text_record(self, cluster):
        """control: in a process where `text` is the only format anyone asks
        for, `text` is what lands — the text record is
        "<hex> <mtime_sec> <mtime_nsec> <size>" (integrity_info.h:122)."""
        _require_xattr(cluster)
        raw = cluster["control_xattr"]
        want = format(zlib.adler32(cluster["control_payload"]) & 0xffffffff,
                      "08x")
        assert raw.decode().split()[0] == want, raw
        assert raw.count(b" ") == 3, ("not the text record", raw)

    def test_the_xrdcks_location_writes_the_binary_record(self, cluster):
        """control: the sibling that DOES ask for a change gets it.  The record
        is the stock XrdCksData struct — test_checksum_on_write.py owns its
        field layout, so this only establishes that it is not text."""
        _require_xattr(cluster)
        name = f"bin_{uuid.uuid4().hex[:8]}.bin"
        payload = os.urandom(2048)
        _put(cluster["port"], f"/bin/{name}", payload)
        raw = _xattr(cluster["data"] / "bin" / name)
        assert raw is not None, "no checksum xattr on the xrdcks location"
        assert raw[:16].split(b"\x00", 1)[0] == b"adler32", raw[:16]
        assert b" " not in raw[:16], ("looks like the text record", raw)

    def test_the_text_location_writes_the_binary_record_anyway(self, cluster):
        """DEFECT CANDIDATE #62: the location writes `text`, and gets the
        binary record, because a location twelve lines away in the same file
        wrote `xrdcks` and config_merge.c:107 has no else."""
        _require_xattr(cluster)
        name = f"txt_{uuid.uuid4().hex[:8]}.bin"
        payload = os.urandom(2048)
        _put(cluster["port"], f"/txt/{name}", payload)
        raw = _xattr(cluster["data"] / "txt" / name)
        assert raw is not None, "no checksum xattr on the text location"
        assert b" " not in raw[:16], (
            "brix_webdav_checksum_xattr_format text now produces the text "
            "record even beside an xrdcks location — delete DEFECT CANDIDATE "
            "#62 from this module's docstring", raw)
        assert raw[:16].split(b"\x00", 1)[0] == b"adler32", raw[:16]

    def test_the_two_locations_are_byte_identical(self, cluster):
        """The sharpest statement of #62: PUT the SAME bytes through the
        location that asks for text and the location that asks for xrdcks, and
        the two xattrs are the same record.  The directive selects nothing."""
        _require_xattr(cluster)
        payload = os.urandom(2048)
        records = []
        for where in ("txt", "bin"):
            name = f"pair_{where}_{uuid.uuid4().hex[:8]}.bin"
            _put(cluster["port"], f"/{where}/{name}", payload)
            raw = _xattr(cluster["data"] / where / name)
            assert raw is not None, where
            records.append(raw)
        assert records[0] == records[1], (
            "the text and xrdcks locations now differ, which is what they "
            "should always have done — delete DEFECT CANDIDATE #62")

    def test_the_setter_accepts_text_but_the_caller_never_passes_it(self):
        """The static half of #62, and the reason it reads as an oversight
        rather than a design: brix_integrity_set_xattr_format() validates and
        accepts BRIX_CKS_FMT_TEXT.  Only the call site excludes it."""
        setter = _flat(_source("src/core/compat/integrity_info.c"))
        assert "if (fmt == BRIX_CKS_FMT_TEXT || fmt == BRIX_CKS_FMT_XRDCKS)" \
            in setter, "the setter no longer accepts BRIX_CKS_FMT_TEXT"

        merge = _flat(_source("src/protocols/webdav/config_merge.c"))
        guard = ("if (conf->checksum_xattr_format != BRIX_CKS_FMT_TEXT) { "
                 "/* §8.x: stock-interoperable binary XrdCksData write format "
                 "(process-wide). */ brix_integrity_set_xattr_format("
                 "conf->checksum_xattr_format); }")
        assert guard in merge, (
            "the guard around brix_integrity_set_xattr_format has changed — "
            "re-measure DEFECT CANDIDATE #62 before trusting this file")
        tail = merge[merge.index(guard) + len(guard):].lstrip()
        assert not tail.startswith("else"), (
            "config_merge.c has grown an else on the xattr-format guard, which "
            "is the fix — delete DEFECT CANDIDATE #62 from this docstring")

    def test_nothing_else_reads_the_merged_field(self):
        """conf->checksum_xattr_format is initialised, merged, addressed by a
        directive table — and read by exactly one statement, the one that
        throws it away.  Line numbers are deliberately not asserted; the claim
        is about which files can possibly consult the merged value, and it must
        survive an unrelated edit above it."""
        hits = {}
        for path in ROOT.joinpath("src").rglob("*.[ch]"):
            for line in path.read_text(errors="replace").splitlines():
                if "checksum_xattr_format" not in line:
                    continue
                stripped = line.lstrip()
                if stripped.startswith(("*", "/*", "//")):
                    continue
                if ("offsetof(" in stripped or 'ngx_string("' in stripped
                        or "NGX_CONF_UNSET_UINT" in stripped):
                    continue    # the directive table's name+offset, and the
                                # NGX_CONF_UNSET_UINT init in config.c
                hits.setdefault(str(path.relative_to(ROOT)), []).append(stripped)
        assert sorted(hits) == ["src/protocols/webdav/config_merge.c",
                                "src/protocols/webdav/webdav_loc_conf.h"], hits
        assert len(hits["src/protocols/webdav/webdav_loc_conf.h"]) == 1, hits
        # The merge macro (two lines), the guard, and the setter call.
        assert len(hits["src/protocols/webdav/config_merge.c"]) == 4, hits


# --------------------------------------------------------------------------- #
# F. The redirect scheme — the same merge, done correctly.                     #
# --------------------------------------------------------------------------- #

class TestTheRedirectSchemeIsPerLocation:
    """The contrast that makes #62 a defect and not a house style.
    brix_webdav_redirect_scheme is merged in the SAME function, twelve lines
    below the checksum format, and it is read off conf-> at request time — so
    three locations in one process give three answers."""

    @pytest.mark.parametrize("where,scheme", [
        ("rdr-none", "http"),     # no directive: the merge default
        ("rdr-http", "http"),     # the token under test
        ("rdr-https", "https"),   # the control
    ])
    def test_each_location_decides_its_own_scheme(self, cluster, where, scheme):
        status, headers, _body = _req("GET", cluster["port"],
                                      f"/{where}/probe.dat")
        assert status == 307, (status, headers)
        location = headers.get("Location", "")
        assert location.startswith(f"{scheme}://"), (where, location)
        assert f"/{where}/probe.dat" in location, location

    def test_writing_http_is_the_same_as_writing_nothing(self, cluster):
        """The file's thesis, in its one uncomplicated instance: the token and
        its absence produce the same Location but for the path."""
        _s, none_headers, _b = _req("GET", cluster["port"],
                                    "/rdr-none/probe.dat")
        _s, http_headers, _b = _req("GET", cluster["port"],
                                    "/rdr-http/probe.dat")
        none_loc = none_headers.get("Location", "").replace("/rdr-none/", "/X/")
        http_loc = http_headers.get("Location", "").replace("/rdr-http/", "/X/")
        assert none_loc == http_loc, (none_loc, http_loc)

    def test_the_scheme_is_read_from_the_conf_at_request_time(self):
        """Static: no global anywhere on this path — the ternary reads conf->
        inside the Location builder."""
        flat = _flat(_source("src/protocols/webdav/redirect.c"))
        assert ('conf->redirect_scheme == BRIX_WEBDAV_RDR_HTTPS ? "https" '
                ': "http"') in flat, \
            "redirect.c no longer chooses the scheme from the merged conf"
        assert _merge_default("src/protocols/webdav/config_merge.c",
                              "redirect_scheme") == "BRIX_WEBDAV_RDR_HTTP"


# --------------------------------------------------------------------------- #
# G. The health-check probe type.                                             #
# --------------------------------------------------------------------------- #

class TestTheHealthCheckProbeType:
    """`ping` is unusual in this set: it is not merely the default, it is the
    else-branch.  Nothing in src/ ever compares probe_type to BRIX_HC_TYPE_PING,
    so `ping`, the absent directive and any future third token that is not
    `stat` are one code path — which is why the parse tier in §A is the whole of
    what a token-level test can add, and the wire-level split belongs beside the
    live probe harness in test_phase22_health_check.py."""

    def test_ping_is_the_else_branch(self):
        probe = _source("src/net/manager/health_check_probe.c")
        assert "if (hc->probe_type == BRIX_HC_TYPE_STAT) {" in probe
        assert "BRIX_HC_TYPE_PING" not in probe, (
            "health_check_probe.c now names BRIX_HC_TYPE_PING — `ping` has "
            "stopped being the else-branch and deserves a wire-level test")

    def test_the_only_comparison_in_the_tree_is_against_stat(self):
        hits = [f"{path.relative_to(ROOT)}"
                for path in ROOT.joinpath("src").rglob("*.[ch]")
                if re.search(r"probe_type\s*==", path.read_text(errors="replace"))]
        assert hits == ["src/net/manager/health_check_probe.c"], hits

    def test_the_merge_default_is_the_ping_token(self):
        default = _constant(_merge_default(
            "src/core/config/server_conf_merge_cluster.c", "hc.type"))
        table = _enum_table("src/protocols/root/stream/module_enums.c",
                            "brix_hc_types")
        assert table["ping"] == default
        assert table["stat"] != default
