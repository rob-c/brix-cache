"""The six shared-http flags at VALUE granularity — audit §Method, 16th tranche.

WHY THIS FILE EXISTS
--------------------
The audit's Method (steps 1-2) counts directive NAMES.  Re-running the
measurement per (directive, VALUE) over the ``ngx_conf_set_flag_slot``
directives in ``src/`` left a residue of flags whose ``off`` arm had never been
written anywhere in the corpus — reachable only by leaving the directive out,
which is not the same configuration and, for four of these six, not even the
same code path.  Six of that residue live in ONE command table,
``brix_http_common_commands`` (src/core/config/http_common.c:63), and share one
declaration shape::

    { ngx_string("brix_backend_krb5_forwardable"),   :230
      BRIX_HTTP_ALL_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_common_conf_t, common.backend_krb5_forwardable),
      NULL },

    ... and the same five lines for brix_verify_write (:264),
        brix_read_only (:271), brix_compress (:278),
        brix_strict_security (:288) and brix_session_log (:311).

``BRIX_HTTP_ALL_CONF`` is ``NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|
NGX_HTTP_LOC_CONF`` (http_common.c:61), so each of the six has THREE legal
placements on the http plane and inheritance is half of what a value means.
They are taken together because they are one table, one setter, one merge and
one adopt list — and because the adopt list is where one of them dies.

WHAT THE VALUES SELECT
----------------------
Nothing in common except the plumbing; each is measured against its own face.

  brix_read_only         brix_shared_apply_read_only (shared_conf.h:145-158)
                         forces allow_write off, so every existing write gate
                         refuses.  Measured as the WebDAV write-method table.
  brix_compress          file_serve.c:325 ``if (!opts->compress) return
                         SERVE_CONTINUE;`` gates the negotiator at
                         http_compress.c:144.  Measured on the wire.
  brix_session_log       brix_sess_begin() returns NULL unless the flag is on
                         AND an access-log fd exists (sesslog_ngx.c:250).
                         Measured as records in the brix access log.
  brix_verify_write      put_setup.c:347 hands it to brix_vfs_writer_open() as
                         the read-back-verify argument.  Measured against an
                         origin that corrupts what it stored.
  brix_strict_security   promotes brix_shared_security_gate's [warn] to
                         [emerg] (shared_conf.h:305-313).  Parse-time only —
                         it has no runtime face at all.
  brix_backend_krb5_forwardable
                         drives the outbound Kerberos delegation SPN at
                         op_path.c:548 — on the STREAM plane.  On the http
                         plane it parses, merges, adopts, and is read by
                         nobody.

WHAT THE TABLES ESTABLISH
-------------------------
One listener, five ``server_name`` vhosts, twenty-two WebDAV locations
(nginx_audit16h_shared.conf), one http:// origin that lies on read-back, plus a
parse-only scaffold (nginx_audit16hparse.conf) for the two tiers that never
bind.  Measured, not assumed:

§A  read_only, as the write-method table (PUT/DELETE/MKCOL/COPY/MOVE, with
    GET/PROPFIND alongside to prove reads are untouched):

      rw          201 204 201 201 201   GET 200  PROPFIND 207
      ro-on       403 403 403 403 403   GET 200  PROPFIND 207
      ro-off      201 204 201 201 201   — identical to the absent value
      ro-bare     403 403 403 403 403   — `off` is not a write grant
      wi-inherit  201 204 201 201 201   — a server-level grant reaches a child
      ri-inherit  403 403 403 403 403   — a server-level lock reaches a child
      ri-off      201 204 201 201 201   — and a child can take the lock back
      ri-offaw    201 204 201 201 201

§B  strict_security, as `nginx -t`'s verdict on three already-insecure
    subjects × {absent, off, on} × {location, server, http}: 18 cells accept
    with [warn], 9 refuse with [emerg], and the text is identical either way.

§C  verify_write against an origin that flips the first byte of what it stored:
    all three arms answer PUT 204, GET 200, and hand back the corrupted body.
    The origin sees HEAD then PUT during the write and is never re-read.

§D  compress, on a 1410-byte compressible body:
      cz-on   + AE:gzip   -> Content-Encoding gzip, 80 bytes, chunked, no C-L,
                             Vary: Accept-Encoding, decodes byte-exact
      cz-off / cz-absent  -> identity, Content-Length 1410
      100-byte body       -> identity (below BRIX_COMPRESS_MIN_SIZE 256)
      AE identity / gzip;q=0 / empty -> identity
      AE zstd -> zstd (66)   AE br -> br (49)   AE gzip,deflate,br,zstd -> zstd
      HEAD -> identity 1410   Range bytes=0-99 -> 206 identity
      zi-inherit -> gzip      zi-off -> identity

§E  session_log, attributed by a unique object name because the log batches on
    a ~1 s timer: sl-on 3 records (ATTEMPT/RESULT/XFER), sl-off 0, sl-absent 3,
    al-off 0, qi-inherit 0 (server-level off), qi-on 3.

§G  the parse matrix.  All six accept on/off in location{}, server{} and
    http{}; all six are refused in the main context; four are accepted inside a
    stream server (brix_compress and brix_strict_security are not, being
    http-only) and none at stream{} level.  Every refusal reads ``directive is
    not allowed here`` — never ``unknown directive``, because nginx searches
    every module's table before it checks the context.

FINDING — DEFECT CANDIDATE #77
------------------------------
``brix_backend_krb5_forwardable`` is declared on the http plane and read only on
the stream plane.  The value is parsed (http_common.c:230), merged
(shared_conf.h:426) and adopted (http_common.c:438), and the single reader
anywhere in ``src/`` is ``op_path.c:548`` — inside the root:// stream protocol.
An operator who writes it in a ``location`` under ``http{}`` gets a config that
parses, reloads and does nothing, with no diagnostic at either time.  §F asserts
the parse and pins the reader; the honest label is that the http declaration has
no http face, not that the feature is broken.

FINDING — DEFECT CANDIDATE #79
------------------------------
``brix_session_log off`` does not silence a location reached over a connection
whose FIRST request hit a logging location.  ``brix_http_sess()``
(sesslog_conn.c:165-207) looks the record up per CONNECTION and returns the
cached session before it ever reads the new location's conf; only a fresh
record consults ``conf->session_log``.  Measured: one keep-alive connection,
``/sl-on/`` then ``/sl-off/``, produces one session id and nine lines — three of
them ATTEMPT/RESULT/XFER naming the object under ``/sl-off/``.  The reverse
order is clean, which is what makes it a leak rather than a mis-merge: the
decision belongs to whichever location the client happened to ask for first.
For an export whose whole reason for ``off`` is that its paths are sensitive,
the flag is honoured only for clients that open a fresh connection.

OBSERVATION — the read-only NOTICE outlives its scope
-----------------------------------------------------
A server-level ``brix_read_only on`` logs, at config time::

    brix: read_only on - the export is read-only; all write operations are
    rejected at the protocol edge (overrides allow_write)

and a child location that writes ``brix_read_only off`` then accepts writes
(§A: /ri-off/ answers 201/204).  That is not a merge bug — the adopt layer
copies the server's ``allow_write`` into the child before
``brix_shared_apply_read_only`` runs for that child and finds ``read_only 0`` —
but the sentence is absolute where the scope is a server, and nothing retracts
it per location.  It is recorded as an observation rather than a defect because
the endpoint-ready NOTICE does disclose the truth, one line per location:
14 of the twenty-two report ``(read-only)`` and 5 report ``(read-write)``, and
the opted-out children are in the second list.  §A asserts both halves so that
a future change to either sentence has to be deliberate.

WHAT THIS FILE DOES NOT CLAIM
-----------------------------
``brix_verify_write`` is inert on the http plane, and this file proves it on the
wire — but it does not mint a number for it.  ``brix_shared_adopt_unified()``
omits ``verify_write`` from its adopt list, which is DEFECT #34's family
(a common-module directive parsed but never adopted), and
test_audit15j_zero_coverage_stragglers.py already owns and enumerates that list.
§C contributes the first behavioural evidence — three arms, byte-identical
answers, against the one fault a read-back verify is for — and pins the owner.

Whether read-back verification SHOULD be reachable from a WebDAV export, and
what it would cost on a whole-object PUT, is a design question this file does
not answer.  It measures the flag as declared.

Ledger: lc-audit16h-shared (one http listener + ORIGIN_PORT for the lying
origin; five vhosts on the one listen, because a server-level arm needs a
server and a vhost is cheaper than a ledger slot).
"""

import gzip
import os
import re
from pathlib import Path

import pytest
import requests
import urllib3

from _test_audit15g_helpers import serve_paced, wait_until
from config_parse import nginx_t
from fleet_lifecycle_ports import (
    LIFECYCLE_SHARED_PORTS,
    PARSE_PLACEHOLDER_PORT,
    SHARED_PARSE_PLACEHOLDER_PORT,
)
from server_registry import NginxInstanceSpec
from settings import BIND_HOST, HOST, NGINX_BIN

pytestmark = [pytest.mark.timeout(900),
              pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-audit16h-shared")]

NAME = "lc-audit16h-shared"
ORIGIN_PORT = LIFECYCLE_SHARED_PORTS[NAME]["extra"]["ORIGIN_PORT"]

ROOT = Path(__file__).resolve().parents[1]
HTTP_COMMON_C = ROOT / "src/core/config/http_common.c"
SHARED_H = ROOT / "src/core/config/shared_conf.h"
PUT_SETUP_C = ROOT / "src/protocols/webdav/put_setup.c"
OP_PATH_C = ROOT / "src/protocols/root/path/op_path.c"
COMPRESS_H = ROOT / "src/core/http/http_compress.h"
COMPRESS_C = ROOT / "src/core/http/http_compress.c"
FILE_SERVE_C = ROOT / "src/protocols/shared/file_serve.c"
SESSLOG_CONN_C = ROOT / "src/core/http/sesslog_conn.c"
SESSLOG_NGX_C = ROOT / "src/observability/sesslog/sesslog_ngx.c"
STREAM_DIR = ROOT / "src/protocols/root/stream"
SRC_DIR = ROOT / "src"
OWNER_TEST = Path(__file__).with_name("test_audit15j_zero_coverage_stragglers.py")

# The six, as (directive, the common.* field its setter writes).
FLAGS = (
    ("brix_backend_krb5_forwardable", "backend_krb5_forwardable"),
    ("brix_verify_write", "verify_write"),
    ("brix_read_only", "read_only"),
    ("brix_compress", "compress"),
    ("brix_strict_security", "strict_security"),
    ("brix_session_log", "session_log"),
)
FLAG_NAMES = [name for name, _ in FLAGS]
# The four that also exist on the stream plane.  brix_compress and
# brix_strict_security are http-only, which is why a stream placement is the
# slot that tells the two command tables apart.
STREAM_FLAGS = ("brix_backend_krb5_forwardable", "brix_verify_write",
                "brix_read_only", "brix_session_log")
HTTP_ONLY_FLAGS = ("brix_compress", "brix_strict_security")

# One compressible body, well over the 256-byte floor, and one well under it.
LINE = b"a compressible line of ordinary text, repeated\n"
BIG = LINE * 30
SMALL = b"x" * 100
COMPRESSIBLE = "big.txt"
TINY = "small.txt"

# Every location of the shared template that is backed by posix:, and the vhost
# each is reached through.  The prefix before the dash is the arm family.
POSIX_ARMS = ("rw", "ro-on", "ro-off", "ro-bare",
              "cz-on", "cz-off", "cz-absent",
              "sl-on", "sl-off", "sl-absent", "al-off",
              "wi-inherit", "ri-inherit", "ri-off", "ri-offaw",
              "zi-inherit", "zi-off", "qi-inherit", "qi-on")
ORIGIN_ARMS = ("vw-on", "vw-off", "vw-absent")
VHOSTS = {"wi": "writable.test", "ri": "readonly.test",
          "zi": "zip.test", "qi": "quiet.test"}

# The write-method table, as the two verdicts it ever takes.
WRITABLE = {"PUT": 201, "DELETE": 204, "MKCOL": 201, "COPY": 201, "MOVE": 201}
REFUSED = dict.fromkeys(WRITABLE, 403)

READ_ONLY_NOTICE = ("brix: read_only on - the export is read-only; all write "
                    "operations are rejected at the protocol edge "
                    "(overrides allow_write)")
INSECURE_WEBDAV = ("WebDAV export permits unauthenticated writes "
                   "(brix_allow_write on but brix_webdav_auth is not required)")
INSECURE_S3 = ("S3 export accepts unauthenticated requests "
               "(no brix_s3_access_key and brix_s3_token off)")
INSECURE_DASH = ("dashboard served anonymously — client identities, paths and "
                 "IPs are readable without a login")

# A session record is one line per event, and the three a plain GET produces.
SESSION_EVENTS = ("ATTEMPT", "RESULT", "XFER")

_POOL = urllib3.PoolManager()
_needs_nginx = pytest.mark.skipif(
    not os.access(NGINX_BIN, os.X_OK), reason=f"nginx not executable: {NGINX_BIN}")


# --------------------------------------------------------------------------- #
# The instance, the origin, and the one way this file asks a question          #
# --------------------------------------------------------------------------- #

def _vhost(arm):
    """Which server_name serves this arm.  Server-level arms live on their own
    vhost because that is the cheapest server{} on a single listen.

    The names are Host: header values matched against the template's
    `server_name` lines — the routing key of the subject itself, not an address
    anything connects to (that is settings.HOST, in `url` below).
    """
    return VHOSTS.get(arm.split("-")[0], "localhost")  # net-literal-allow: the template's own server_name, matched not dialled


class _Flags:
    """The started listener, the seeded tree, and the lying origin behind the
    three verify_write arms."""

    def __init__(self, endpoint, data, origin):
        self.endpoint = endpoint
        self.data = data
        self.origin = origin
        self.port = endpoint.port
        self.logs = Path(endpoint.prefix) / "logs"
        self.access_log = self.logs / "brix_access.log"

    # -- addressing --------------------------------------------------------- #

    def url(self, arm, name=""):
        return f"http://{HOST}:{self.port}/{arm}/{name}"

    def request(self, method, arm, name="", **kwargs):
        headers = {"Host": _vhost(arm), **kwargs.pop("headers", {})}
        return requests.request(method, self.url(arm, name), headers=headers,
                                timeout=30, **kwargs)

    def raw(self, arm, name, accept_encoding):
        """A response whose body is left exactly as the wire delivered it —
        `requests` transparently gunzips, which would make every compress arm
        look identical."""
        return _POOL.request(
            "GET", self.url(arm, name),
            headers={"Host": _vhost(arm), "Accept-Encoding": accept_encoding},
            decode_content=False, preload_content=True, retries=False)

    # -- the tree ----------------------------------------------------------- #

    def seed(self, arm, name, body=BIG):
        target = self.data / arm / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(body)
        return target

    # -- the logs ----------------------------------------------------------- #

    def errlog(self):
        """Instance prefixes are wiped at teardown, so failures quote inline."""
        try:
            return (self.logs / "error.log").read_text(errors="replace")
        except OSError:                          # pragma: no cover - diagnostic
            return "(error log unavailable)"

    def records(self):
        try:
            return self.access_log.read_text(errors="replace").splitlines()
        except OSError:
            return []

    def records_for(self, arm, name):
        needle = f'path="/{arm}/{name}"'
        return [line for line in self.records() if needle in line]

    # -- the readings ------------------------------------------------------- #

    def write_probe(self, arm, tag):
        """Every write method WebDAV has, against one arm.

        `tag` names this probe's own objects: two probes against the same arm
        must not be able to fail each other by having consumed a source or
        created a collection first.
        """
        self.seed(arm, f"victim-{tag}.txt")
        self.seed(arm, f"src-{tag}.txt")
        copy_to = self.url(arm, f"copy-{tag}.txt")
        move_to = self.url(arm, f"move-{tag}.txt")
        return {
            "PUT": self.request("PUT", arm, f"put-{tag}.bin",
                                data=BIG).status_code,
            "DELETE": self.request("DELETE", arm,
                                   f"victim-{tag}.txt").status_code,
            "MKCOL": self.request("MKCOL", arm, f"dir-{tag}/").status_code,
            "COPY": self.request("COPY", arm, f"src-{tag}.txt",
                                 headers={"Destination": copy_to}).status_code,
            "MOVE": self.request("MOVE", arm, f"src-{tag}.txt",
                                 headers={"Destination": move_to}).status_code,
        }


@pytest.fixture
def flags(lifecycle, tmp_path):
    """Twenty-two locations, one listener, one seeded tree, one lying origin.

    Every posix arm is seeded identically, so a verdict that differs between two
    of them cannot be explained by their contents.  The origin is started before
    the listener because three locations name it as their storage backend and a
    refused connection at merge time is not the subject of any test here.
    """
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx binary not executable: {NGINX_BIN}")

    data = tmp_path / "data"
    for arm in POSIX_ARMS:
        (data / arm).mkdir(parents=True)
        (data / arm / COMPRESSIBLE).write_bytes(BIG)
        (data / arm / TINY).write_bytes(SMALL)

    origin = serve_paced(ORIGIN_PORT, BIG)
    try:
        endpoint = lifecycle.start(NginxInstanceSpec(
            name=NAME,
            template="nginx_audit16h_shared.conf",
            protocol="http",
            data_root=str(data),
            template_values={"BIND_HOST": BIND_HOST,
                             "ORIGIN": f"{HOST}:{ORIGIN_PORT}"},
            reason="audit-16h the six shared-http flags at value granularity"))
        yield _Flags(endpoint, data, origin)
    finally:
        origin.shutdown()
        origin.server_close()


# --------------------------------------------------------------------------- #
# §A — brix_read_only                                                          #
# --------------------------------------------------------------------------- #

class TestTheReadOnlySwitch:
    """``brix_shared_apply_read_only`` forces ``allow_write`` off when the flag
    is on (shared_conf.h:145-158), which is upstream of every protocol's own
    write gate — so the reading is the whole write-method table, not one verb."""

    def test_the_writable_control_accepts_every_write_method(self, flags):
        """The row every refusal below is measured against.  Without it a 403
        table proves only that something refused, not that the flag did."""
        assert flags.write_probe("rw", "control") == WRITABLE, flags.errlog()

    def test_on_refuses_every_write_method(self, flags):
        assert flags.write_probe("ro-on", "on") == REFUSED, flags.errlog()

    def test_on_leaves_reads_alone(self, flags):
        """Read-only is not closed: the export still serves and still enumerates.
        A flag that took the location off the air entirely would pass the
        refusal table above for the wrong reason."""
        assert flags.request("GET", "ro-on", COMPRESSIBLE).status_code == 200
        listing = flags.request("PROPFIND", "ro-on", headers={"Depth": "1"})
        assert listing.status_code == 207, listing.text[:400]

    def test_off_is_the_absent_value(self, flags):
        """The arm the corpus had never written.  ``off`` must land exactly
        where saying nothing lands — the control's table, verbatim."""
        assert flags.write_probe("ro-off", "off") == WRITABLE, flags.errlog()

    def test_off_is_not_a_write_grant(self, flags):
        """The security negative: ``brix_read_only off`` on a location that was
        never granted ``brix_allow_write`` must not open it.  ``off`` says "do
        not take writes away", never "give writes"."""
        assert flags.write_probe("ro-bare", "bare") == REFUSED, flags.errlog()

    def test_a_server_level_write_grant_reaches_a_child(self, flags):
        """The inheritance control.  Without this row, a 403 from the read-only
        vhost below would be indistinguishable from a location that simply
        never inherited its server's ``brix_allow_write``."""
        assert flags.write_probe("wi-inherit", "wi") == WRITABLE, flags.errlog()

    def test_a_server_level_lock_reaches_a_child(self, flags):
        assert flags.write_probe("ri-inherit", "ri") == REFUSED, flags.errlog()

    def test_a_child_can_take_the_inherited_lock_back(self, flags):
        """``brix_read_only off`` under a server that wrote ``on``: the child is
        writable again, because ``brix_shared_adopt_unified`` fills the child's
        unset ``allow_write`` from the server BEFORE
        ``brix_shared_apply_read_only`` runs for the child and finds
        ``read_only 0``.  Restating the grant explicitly changes nothing."""
        assert flags.write_probe("ri-off", "rioff") == WRITABLE, flags.errlog()
        assert flags.write_probe("ri-offaw", "riaw") == WRITABLE, flags.errlog()

    def test_the_notice_is_written_once_and_scoped_to_the_server(self, flags):
        """The observation in the header, half one: one sentence, absolute, and
        no per-location retraction anywhere in the log."""
        notices = [line for line in flags.errlog().splitlines()
                   if "read_only on" in line]
        assert notices, "a server-level read_only on logged nothing"
        bodies = {line.split("#", 1)[-1].split(":", 1)[-1].strip()
                  for line in notices}
        assert bodies == {READ_ONLY_NOTICE}, sorted(bodies)
        assert not [line for line in flags.errlog().splitlines()
                    if "ri-off" in line], \
            "a location that opted out of the lock is now named in the log — " \
            "the observation in this file's header needs rewriting"

    def test_the_readiness_line_is_where_the_opt_out_shows(self, flags):
        """The observation in the header, half two.  Every export announces its
        own writability at config time, so the truth IS available per location
        — 14 read-only, 5 read-write, plus the three origin-backed arms whose
        export is the origin's root."""
        census = {}
        for line in flags.errlog().splitlines():
            if "endpoint ready" not in line:
                continue
            pid = re.search(r"\]\s+(\d+)#", line)
            if pid is None:                      # pragma: no cover - diagnostic
                continue
            mode = "read-only" if "(read-only)" in line else "read-write"
            root = "origin" if 'export "/"' in line else "posix"
            census.setdefault(pid.group(1), {})
            key = f"{root}/{mode}"
            census[pid.group(1)][key] = census[pid.group(1)].get(key, 0) + 1
        assert census, flags.errlog()
        expected = {"posix/read-only": 14, "posix/read-write": 5,
                    "origin/read-write": 3}
        for pid, seen in census.items():
            assert seen == expected, f"pid {pid} announced {seen}"


# --------------------------------------------------------------------------- #
# §B — brix_strict_security (parse tier: it has no runtime face)               #
# --------------------------------------------------------------------------- #

def _block(text, indent):
    if not text:
        return ""
    return "".join(f"{indent}{line}\n" for line in text.splitlines())


def _parse(tmp_path, *, knobs="", srv="", http="", outer="", stream="",
           stream_main="", subject=""):
    """``nginx -t`` the scaffold with one slot filled.

    The scaffold writes none of the six itself: a second occurrence would be
    diagnosed as a duplicate, and that error arrives before the one a value or
    arity negative is reaching for.
    """
    data = tmp_path / "data"
    data.mkdir(exist_ok=True)
    return nginx_t(
        "nginx_audit16hparse.conf", tmp_path,
        PORT=SHARED_PARSE_PLACEHOLDER_PORT,
        SUBJ_PORT=PARSE_PLACEHOLDER_PORT,
        STREAM_PORT=PARSE_PLACEHOLDER_PORT,
        LOG_DIR=str(tmp_path), DATA=str(data),
        KNOBS=_block(knobs, " " * 12),
        SRV_KNOBS=_block(srv, " " * 8),
        HTTP_KNOBS=_block(http, " " * 4),
        OUTER=_block(outer, ""),
        STREAM_KNOBS=_block(stream, " " * 8),
        STREAM_MAIN=_block(stream_main, " " * 4),
        SUBJECT=_block(subject, " " * 4))


def _subject_server(body, srv_flag=""):
    """An insecure export in a server of its own.

    Its own, and not a location beside the scaffold's probe, because
    ``brix_s3`` and ``brix_webdav`` may not share a listen port — the
    co-residency check would refuse the S3 subject before the security gate
    was ever consulted, and the refusal would look like the flag's.
    """
    lines = "".join(f"    {line}\n" for line in body.splitlines())
    return (f"server {{\n    listen {PARSE_PLACEHOLDER_PORT};\n"
            + (f"    {srv_flag}\n" if srv_flag else "") + lines + "}\n")


def _insecure_webdav(data, loc_flag="", srv_flag=""):
    return _subject_server(
        "location /insecure/ {\n"
        "    brix_webdav on;\n"
        f"    brix_storage_backend posix:{data};\n"
        "    brix_webdav_auth none;\n"
        "    brix_allow_write on;\n"
        + (f"    {loc_flag}\n" if loc_flag else "") + "}", srv_flag)


def _insecure_s3(data, loc_flag="", srv_flag=""):
    return _subject_server(
        "location /bucket/ {\n"
        "    brix_s3 on;\n"
        "    brix_s3_bucket b;\n"
        f"    brix_storage_backend posix:{data};\n"
        + (f"    {loc_flag}\n" if loc_flag else "") + "}", srv_flag)


def _insecure_dashboard(_data, loc_flag="", srv_flag=""):
    return _subject_server(
        "location /dash/ {\n"
        "    brix_dashboard on;\n"
        "    brix_dashboard_anonymous on;\n"
        + (f"    {loc_flag}\n" if loc_flag else "") + "}", srv_flag)


SUBJECTS = {"webdav": (_insecure_webdav, INSECURE_WEBDAV),
            "s3": (_insecure_s3, INSECURE_S3),
            "dashboard": (_insecure_dashboard, INSECURE_DASH)}


def _gate(tmp_path, subject, *, arm=None, where="loc"):
    """Run one cell of the §B matrix: a subject, a value, and a scope."""
    build, needle = SUBJECTS[subject]
    flag = "" if arm is None else f"brix_strict_security {arm};"
    data = tmp_path / "data"
    data.mkdir(exist_ok=True)
    result = _parse(
        tmp_path,
        subject=build(str(data),
                      flag if where == "loc" else "",
                      flag if where == "srv" else ""),
        http=flag if where == "http" else "")
    return result, needle


@_needs_nginx
class TestTheStrictSecurityGate:
    """The flag has no runtime behaviour whatsoever: its entire effect is the
    severity ``brix_shared_security_gate`` uses (shared_conf.h:305-313), so it
    can only be measured against a configuration that is already insecure."""

    @pytest.mark.parametrize("subject", sorted(SUBJECTS))
    @pytest.mark.parametrize("where", ["loc", "srv", "http"])
    def test_on_refuses_the_insecure_export(self, tmp_path, subject, where):
        result, needle = _gate(tmp_path, subject, arm="on", where=where)
        assert result.returncode != 0, \
            f"{subject} accepted an insecure export with strict_security on " \
            f"in {where}:\n{result.stderr}"
        assert "[emerg]" in result.stderr and needle in result.stderr, \
            result.stderr

    @pytest.mark.parametrize("subject", sorted(SUBJECTS))
    @pytest.mark.parametrize("where", ["loc", "srv", "http"])
    @pytest.mark.parametrize("arm", ["off", None], ids=["off", "absent"])
    def test_the_open_arms_warn_and_start(self, tmp_path, subject, where, arm):
        """``off`` written out must land where saying nothing lands — and the
        advisory must still be issued, because the flag decides severity, not
        whether the configuration is examined."""
        result, needle = _gate(tmp_path, subject, arm=arm, where=where)
        assert result.returncode == 0, result.stderr
        assert "[warn]" in result.stderr and needle in result.stderr, \
            result.stderr

    @pytest.mark.parametrize("subject", sorted(SUBJECTS))
    def test_the_two_verdicts_carry_the_same_sentence(self, tmp_path, subject):
        """Only the severity changes.  An operator who turns the flag on gets
        the diagnosis they had been ignoring, not a new one."""
        refused, _ = _gate(tmp_path, subject, arm="on")
        warned, needle = _gate(tmp_path, subject, arm="off")
        assert needle in refused.stderr and needle in warned.stderr
        assert "(refused: brix_strict_security on)" in refused.stderr
        assert "(refused: brix_strict_security on)" not in warned.stderr

    @pytest.mark.parametrize("http,srv,loc,refused", [
        ("on", None, "off", False),
        ("on", "off", None, False),
        (None, "on", "off", False),
        ("off", None, "on", True),
    ], ids=["http-on-loc-off", "http-on-srv-off", "srv-on-loc-off",
            "http-off-loc-on"])
    def test_the_nearest_scope_decides(self, tmp_path, http, srv, loc, refused):
        """Inheritance, in the direction that matters: the export's own scope
        wins, so a site-wide ``on`` in http{} is retractable per location and a
        site-wide ``off`` does not protect a location that opts in."""
        as_flag = lambda v: f"brix_strict_security {v};" if v else ""
        data = tmp_path / "data"
        data.mkdir(exist_ok=True)
        result = _parse(
            tmp_path,
            subject=_insecure_webdav(str(data), as_flag(loc), as_flag(srv)),
            http=as_flag(http))
        assert (result.returncode != 0) is refused, result.stderr

    def test_the_scaffolds_own_probe_raises_nothing(self, tmp_path):
        """The control: every refusal above belongs to the subject, not to the
        anonymous read-only export the scaffold always carries."""
        result = _parse(tmp_path)
        assert result.returncode == 0, result.stderr
        assert "insecure configuration" not in result.stderr, result.stderr


# --------------------------------------------------------------------------- #
# §C — brix_verify_write                                                       #
# --------------------------------------------------------------------------- #

class TestTheWriteVerificationGate:
    """The only fault a read-back verify catches that a Content-Length check
    cannot: an origin that stores the object at the right length and hands back
    different bytes.  ``brix_stage off`` on these three arms is what makes the
    question reach the origin at all — a writable whole-object http:// backend
    with no stage tier is otherwise given a brix-managed local store
    (runtime_server_backend.c:256-267), and the read-back comes off local disk.
    """

    @pytest.mark.parametrize("arm", ORIGIN_ARMS)
    def test_the_honest_case_round_trips(self, flags, arm):
        """The control.  A write that never reached the origin would answer the
        corruption test below identically and for the wrong reason."""
        flags.origin.written.clear()
        flags.origin.corrupt.clear()
        stored = flags.request("PUT", arm, "honest.bin", data=BIG)
        assert stored.status_code == 204, stored.text[:400]
        served = flags.request("GET", arm, "honest.bin")
        assert served.status_code == 200 and served.content == BIG

    def test_no_arm_notices_a_corrupting_origin(self, flags):
        """The finding, on the wire: ``on``, ``off`` and absent are one
        behaviour.  The gate is unreachable from an http export because
        ``brix_shared_adopt_unified`` never adopts the value — DEFECT #34's
        family, owned by test_audit15j_zero_coverage_stragglers.py."""
        verdicts = {}
        for arm in ORIGIN_ARMS:
            flags.origin.written.clear()
            flags.origin.corrupt.clear()
            flags.origin.corrupt.add(f"/{arm}/lie.bin")
            stored = flags.request("PUT", arm, "lie.bin", data=BIG)
            served = flags.request("GET", arm, "lie.bin")
            verdicts[arm] = (stored.status_code, served.status_code,
                             served.content == BIG)
        assert verdicts == {arm: (204, 200, False) for arm in ORIGIN_ARMS}, \
            verdicts

    def test_the_origin_is_never_re_read_during_the_write(self, flags):
        """Verification would have to ask the origin for what it stored, and on
        the arm that asks for it the origin sees exactly the requests any
        unverified write makes."""
        flags.origin.written.clear()
        flags.origin.corrupt.clear()
        flags.origin.recorded.clear()
        assert flags.request("PUT", "vw-on", "probe.bin",
                             data=BIG).status_code == 204
        assert [entry["method"] for entry in flags.origin.recorded] \
            == ["HEAD", "PUT"], flags.origin.recorded

    def test_the_gap_is_in_the_adopt_list_and_already_has_an_owner(self):
        """Source, not wire: the five siblings are adopted and this one is not,
        which is why the value never reaches the location that wrote it.  The
        enumeration — and the defect number — belong to the 15j straggler
        test; asserting it here keeps the two from drifting apart."""
        adopt = SHARED_H.read_text()
        common = HTTP_COMMON_C.read_text()
        for _, field in FLAGS:
            assert f"conf->{field}" in adopt or f"conf->{field}," in adopt, field
        for field in ("read_only", "compress", "strict_security", "session_log",
                      "backend_krb5_forwardable"):
            assert f"BRIX_ADOPT_VAL({field}," in common, field
        assert "BRIX_ADOPT_VAL(verify_write" not in common, \
            "verify_write is adopted now — §C's finding and the 15j straggler " \
            "list both need revisiting"
        assert "verify_write" in OWNER_TEST.read_text(), \
            "the owning straggler test no longer names verify_write"


# --------------------------------------------------------------------------- #
# §D — brix_compress                                                           #
# --------------------------------------------------------------------------- #

class TestTheCompressSwitch:
    """``file_serve.c:325`` returns before the negotiator when the flag is off,
    so the value decides whether Accept-Encoding is read at all."""

    def test_on_compresses_and_the_body_survives_it(self, flags):
        response = flags.raw("cz-on", COMPRESSIBLE, "gzip")
        assert response.status == 200
        assert response.headers.get("Content-Encoding") == "gzip"
        assert len(response.data) < len(BIG)
        assert gzip.decompress(response.data) == BIG
        assert response.headers.get("Vary") == "Accept-Encoding", \
            "a compressed answer that does not vary poisons every shared cache"
        assert response.headers.get("Transfer-Encoding") == "chunked"
        assert response.headers.get("Content-Length") is None, \
            "a Content-Length alongside a chunked compressed body would be the " \
            "uncompressed length"

    @pytest.mark.parametrize("arm", ["cz-off", "cz-absent"],
                             ids=["off", "absent"])
    def test_the_closed_arms_serve_identity(self, flags, arm):
        """``off`` written out, against the arm that never mentions the flag."""
        response = flags.raw(arm, COMPRESSIBLE, "gzip")
        assert response.status == 200
        assert response.headers.get("Content-Encoding") is None
        assert response.headers.get("Content-Length") == str(len(BIG))
        assert response.data == BIG

    def test_a_body_below_the_floor_is_left_alone(self, flags):
        """Compression is refused under BRIX_COMPRESS_MIN_SIZE even with the
        flag on — otherwise the arm above would be measuring the body size."""
        floor = int(re.search(r"BRIX_COMPRESS_MIN_SIZE\s+(\d+)",
                              COMPRESS_H.read_text()).group(1))
        assert len(SMALL) < floor <= len(BIG)
        response = flags.raw("cz-on", TINY, "gzip")
        assert response.headers.get("Content-Encoding") is None
        assert response.headers.get("Content-Length") == str(len(SMALL))
        assert response.data == SMALL

    @pytest.mark.parametrize("accept", ["identity", "gzip;q=0", ""],
                             ids=["identity", "q-zero", "empty"])
    def test_the_client_can_still_refuse(self, flags, accept):
        """The flag enables negotiation; it does not impose an encoding."""
        response = flags.raw("cz-on", COMPRESSIBLE, accept)
        assert response.headers.get("Content-Encoding") is None
        assert response.data == BIG

    @pytest.mark.parametrize("accept,expected", [
        ("zstd", "zstd"), ("br", "br"), ("gzip, deflate, br, zstd", "zstd")],
        ids=["zstd", "brotli", "all-four"])
    def test_the_server_preference_order_decides_among_offers(
            self, flags, accept, expected):
        """``brix_codec_pref`` puts zstd first, so a client that offers
        everything gets zstd rather than the first name it listed."""
        response = flags.raw("cz-on", COMPRESSIBLE, accept)
        assert response.headers.get("Content-Encoding") == expected
        assert len(response.data) < len(BIG)

    def test_a_head_is_answered_uncompressed(self, flags):
        """``r->header_only`` short-circuits the negotiator (http_compress.c:144)
        so that the advertised length is the length a body would have."""
        response = flags.request("HEAD", "cz-on", COMPRESSIBLE,
                                 headers={"Accept-Encoding": "gzip"})
        assert response.headers.get("Content-Encoding") is None
        assert response.headers.get("Content-Length") == str(len(BIG))

    def test_a_range_request_is_answered_uncompressed(self, flags):
        """Ranges are offsets into the stored object; compressing one would
        make the range meaningless."""
        response = flags.request("GET", "cz-on", COMPRESSIBLE,
                                 headers={"Accept-Encoding": "gzip",
                                          "Range": "bytes=0-99"})
        assert response.status_code == 206
        assert response.headers.get("Content-Encoding") is None
        assert response.content == BIG[:100]

    def test_a_server_level_value_reaches_a_child_and_is_retractable(self, flags):
        inherited = flags.raw("zi-inherit", COMPRESSIBLE, "gzip")
        assert inherited.headers.get("Content-Encoding") == "gzip"
        assert gzip.decompress(inherited.data) == BIG
        retracted = flags.raw("zi-off", COMPRESSIBLE, "gzip")
        assert retracted.headers.get("Content-Encoding") is None
        assert retracted.data == BIG


# --------------------------------------------------------------------------- #
# §E — brix_session_log (and the brix_access_log sentinel it depends on)       #
# --------------------------------------------------------------------------- #

def _fetch(flags, arm, name, *, keep_alive=None):
    """One GET, on a connection of its own unless a session is handed in.

    Fresh by default because the connection is the instrument of the leak
    below: a request that reuses an earlier one's connection is answered by
    whatever that connection decided first.
    """
    flags.seed(arm, name)
    headers = {"Host": _vhost(arm)}
    if keep_alive is None:
        headers["Connection"] = "close"
        response = requests.get(flags.url(arm, name), headers=headers,
                                timeout=30)
    else:
        response = keep_alive.get(flags.url(arm, name), headers=headers,
                                  timeout=30)
    assert response.status_code == 200, response.text[:400]
    return response


def _record_parts(line):
    """(session id, event) out of one record, read by shape rather than by
    column: the line carries a timestamp prefix whose width is not this file's
    business (sesslog.c:328-450 writes ``SESS <id> <EVENT> ...``)."""
    matched = re.search(r"SESS ([0-9a-f]+) (\w+)", line)
    assert matched is not None, f"not a session record: {line!r}"
    return matched.group(1), matched.group(2)


def _events(records):
    return {_record_parts(line)[1] for line in records}


def _session_ids(records):
    return {_record_parts(line)[0] for line in records}


def _await_records(flags, arm, name, count=len(SESSION_EVENTS)):
    """Wait for one object's records to land.  The session log batches and
    flushes on a ~1 s timer, so the arrival of a record is the signal — never a
    line count, which every other arm's traffic also moves."""
    return wait_until(lambda: flags.records_for(arm, name)
                      if len(flags.records_for(arm, name)) >= count else None,
                      timeout=20,
                      what=f"session records for /{arm}/{name}")


def _await_silence(flags, arm, name, control_arm, control_name):
    """Drive the silent arm, then a logging one, and wait for the LOGGING
    object's records.  A negative that waited on a clock would pass on a slow
    flush; this one only passes once the log has demonstrably caught up past
    the request it is supposed to have ignored."""
    _fetch(flags, arm, name)
    _fetch(flags, control_arm, control_name)
    _await_records(flags, control_arm, control_name)
    return flags.records_for(arm, name)


class TestTheSessionLog:
    """``brix_sess_begin`` refuses unless the flag is on AND an access-log fd
    exists (sesslog_ngx.c:250), so the value is measured as records naming a
    per-test object in the one log every vhost inherits."""

    def test_on_records_the_transfer(self, flags):
        _fetch(flags, "sl-on", "sess-on.txt")
        records = _await_records(flags, "sl-on", "sess-on.txt")
        assert _events(records) == set(SESSION_EVENTS), records

    def test_off_is_silent_and_absent_is_not(self, flags):
        """The pair the corpus had never written together: ``off`` is the only
        silence, and a location that says nothing logs like ``on`` because the
        merge default is 1 (shared_conf.h:376)."""
        assert _await_silence(flags, "sl-off", "quiet.txt",
                              "sl-absent", "loud.txt") == []
        assert len(flags.records_for("sl-absent", "loud.txt")) \
            == len(SESSION_EVENTS)

    def test_the_access_log_sentinel_silences_a_logging_location(self, flags):
        """``brix_access_log off`` is a path that is never opened, so there is
        no fd for the session log to write to — ``brix_session_log on`` in the
        same location produces nothing, and no file called "off" is created."""
        assert _await_silence(flags, "al-off", "nofd.txt",
                              "sl-on", "witness.txt") == []
        created = {entry.name for entry in flags.logs.iterdir()} \
            | {entry.name for entry in Path(flags.endpoint.prefix).iterdir()}
        assert "off" not in created, sorted(created)

    def test_a_server_level_off_reaches_a_child_and_is_retractable(self, flags):
        assert _await_silence(flags, "qi-inherit", "hush.txt",
                              "qi-on", "speak.txt") == []
        assert len(flags.records_for("qi-on", "speak.txt")) \
            == len(SESSION_EVENTS)

    def test_a_kept_alive_connection_carries_the_first_decision(self, flags):
        """DEFECT #79.  ``brix_http_sess`` looks the record up per CONNECTION
        and returns it before reading the new location's conf
        (sesslog_conn.c:178-181), so a second request on the same connection is
        logged under the first location's value."""
        with requests.Session() as session:
            _fetch(flags, "sl-on", "ka-first.txt", keep_alive=session)
            _fetch(flags, "sl-off", "ka-second.txt", keep_alive=session)
        leaked = _await_records(flags, "sl-off", "ka-second.txt")
        assert _events(leaked) == set(SESSION_EVENTS), leaked
        opened = _await_records(flags, "sl-on", "ka-first.txt")
        assert _session_ids(leaked) == _session_ids(opened), \
            "the leaked records are a session of their own — the finding is " \
            "not per-connection caching"

    def test_the_reverse_order_leaks_nothing(self, flags):
        """The control that makes the row above a leak of the FIRST location's
        decision rather than a mis-merge: reached first, the silent location
        stays silent AND leaves nothing cached — the logging location that
        follows on the same connection opens a session of its own."""
        with requests.Session() as session:
            _fetch(flags, "sl-off", "ctl-first.txt", keep_alive=session)
            _fetch(flags, "sl-on", "ctl-second.txt", keep_alive=session)
        records = _await_records(flags, "sl-on", "ctl-second.txt")
        assert _events(records) == set(SESSION_EVENTS), records
        assert flags.records_for("sl-off", "ctl-first.txt") == []


# --------------------------------------------------------------------------- #
# §F — brix_backend_krb5_forwardable                                           #
# --------------------------------------------------------------------------- #

@_needs_nginx
class TestTheKrb5ForwardableFlag:
    """DEFECT CANDIDATE #77: an http-plane directive with no http reader."""

    @pytest.mark.parametrize("where", ["knobs", "srv", "http"])
    @pytest.mark.parametrize("value", ["on", "off"])
    def test_it_parses_in_every_http_scope(self, tmp_path, where, value):
        result = _parse(tmp_path,
                        **{where: f"brix_backend_krb5_forwardable {value};"})
        assert result.returncode == 0, result.stderr

    def test_its_only_reader_is_on_the_stream_plane(self):
        """Where the value is consumed, counted across the whole tree: one
        call site, inside the root:// stream protocol's path handler.  The
        http declaration is parse-only, and nothing says so at either config
        time or run time."""
        readers = []
        for path in sorted(SRC_DIR.rglob("*.c")) + sorted(SRC_DIR.rglob("*.h")):
            text = path.read_text(errors="replace")
            for number, line in enumerate(text.splitlines(), start=1):
                if "backend_krb5_forwardable" not in line:
                    continue
                if any(token in line for token in
                       ("ngx_string(", "offsetof(", "NGX_CONF_UNSET",
                        "ngx_conf_merge_value", "BRIX_ADOPT_VAL",
                        "prev->backend_krb5_forwardable", "ngx_flag_t")):
                    continue
                if line.lstrip().startswith(("*", "/*", "//", "#")):
                    continue
                readers.append(f"{path.relative_to(ROOT)}:{number}")
        assert readers == ["src/protocols/root/path/op_path.c:548"], readers
        assert "brix_krb5_deleg_origin_spn" in OP_PATH_C.read_text()


# --------------------------------------------------------------------------- #
# §G — the parse matrix                                                        #
# --------------------------------------------------------------------------- #

@_needs_nginx
class TestTheParseMatrix:
    """Where each of the six may be written, and what it may be written as."""

    @pytest.mark.parametrize("name", FLAG_NAMES)
    @pytest.mark.parametrize("where", ["knobs", "srv", "http"])
    @pytest.mark.parametrize("value", ["on", "off"])
    def test_both_arms_parse_in_all_three_http_scopes(self, tmp_path, name,
                                                      where, value):
        """BRIX_HTTP_ALL_CONF spelled out on the wire of the parser: three
        scopes, both values, six directives."""
        result = _parse(tmp_path, **{where: f"{name} {value};"})
        assert result.returncode == 0, \
            f"{name} {value} was refused in {where}:\n{result.stderr}"

    @pytest.mark.parametrize("name", FLAG_NAMES)
    def test_none_is_accepted_in_the_main_context(self, tmp_path, name):
        result = _parse(tmp_path, outer=f"{name} on;")
        assert result.returncode != 0, f"{name} was accepted outside http{{}}"
        assert f'"{name}" directive is not allowed here' in result.stderr, \
            result.stderr

    @pytest.mark.parametrize("name", STREAM_FLAGS)
    def test_the_four_shared_names_are_accepted_in_a_stream_server(
            self, tmp_path, name):
        """The stream plane declares its own entries for these four
        (root/stream/directives_tpc.h:228,249 and root/stream/module.c:366,429),
        so the same word is legal in two grammars with two backing structs."""
        result = _parse(tmp_path, stream=f"{name} on;")
        assert result.returncode == 0, result.stderr

    @pytest.mark.parametrize("name", HTTP_ONLY_FLAGS)
    def test_the_two_http_only_names_are_refused_in_a_stream_server(
            self, tmp_path, name):
        result = _parse(tmp_path, stream=f"{name} on;")
        assert result.returncode != 0, f"{name} was accepted in stream{{}}"
        assert f'"{name}" directive is not allowed here' in result.stderr, \
            result.stderr

    @pytest.mark.parametrize("name", FLAG_NAMES)
    def test_none_is_accepted_at_stream_level(self, tmp_path, name):
        """Even the four are server-scoped there — NGX_STREAM_SRV_CONF only."""
        result = _parse(tmp_path, stream_main=f"{name} on;")
        assert result.returncode != 0, f"{name} was accepted at stream level"
        assert f'"{name}" directive is not allowed here' in result.stderr, \
            result.stderr

    @pytest.mark.parametrize("name", FLAG_NAMES)
    def test_a_misplaced_name_is_never_reported_as_unknown(self, tmp_path, name):
        """The diagnostic an operator actually reads.  nginx searches every
        module's command table before it checks the context, so a stream-only
        placement of an http-only flag is a scope error, not a typo — and a
        future move between planes must not silently turn one into the other."""
        result = _parse(tmp_path, outer=f"{name} off;")
        assert "unknown directive" not in result.stderr, result.stderr

    @pytest.mark.parametrize("name", FLAG_NAMES)
    @pytest.mark.parametrize("value", ["ON", "OFF", "On", "oFf"])
    def test_the_value_is_case_insensitive(self, tmp_path, name, value):
        result = _parse(tmp_path, knobs=f"{name} {value};")
        assert result.returncode == 0, \
            f"{name} refused {value}:\n{result.stderr}"

    @pytest.mark.parametrize("name", FLAG_NAMES)
    @pytest.mark.parametrize("value", ["maybe", "1", "0", "yes", "true", '""'],
                             ids=["word", "one", "zero", "yes", "true", "empty"])
    def test_a_non_boolean_value_is_refused(self, tmp_path, name, value):
        """``1`` and ``0`` included: the flag setter takes the two words and
        nothing else, and an operator who writes the C value is told."""
        result = _parse(tmp_path, knobs=f"{name} {value};")
        assert result.returncode != 0, f"{name} accepted {value}"
        assert "invalid value" in result.stderr and 'it must be "on" or "off"' \
            in result.stderr, result.stderr

    @pytest.mark.parametrize("name", FLAG_NAMES)
    @pytest.mark.parametrize("line", ["{name};", "{name} on off;"],
                             ids=["no-argument", "two-arguments"])
    def test_the_arity_is_exactly_one(self, tmp_path, name, line):
        result = _parse(tmp_path, knobs=line.format(name=name))
        assert result.returncode != 0, f"{name} accepted the wrong arity"
        assert "invalid number of arguments" in result.stderr, result.stderr

    @pytest.mark.parametrize("name", FLAG_NAMES)
    def test_a_second_occurrence_is_a_duplicate(self, tmp_path, name):
        """The two arms in one scope are refused rather than last-one-wins, so
        an operator who writes both is told instead of silently resolved."""
        result = _parse(tmp_path, knobs=f"{name} on;\n{name} off;")
        assert result.returncode != 0 and "is duplicate" in result.stderr, \
            result.stderr

    @pytest.mark.parametrize("where", ["knobs", "srv", "http"])
    def test_the_access_log_slot_takes_a_path_or_the_off_sentinel(
            self, tmp_path, where):
        """The str-slot the session log depends on, in the same three scopes.
        ``off`` is a VALUE of the path, not a flag — which is why it is the one
        extra row this file carries."""
        for text in (f"brix_access_log {tmp_path}/audit.log;",
                     "brix_access_log off;"):
            result = _parse(tmp_path, **{where: text})
            assert result.returncode == 0, result.stderr

    @pytest.mark.parametrize("line", ["brix_access_log;", "brix_access_log a b;"],
                             ids=["no-argument", "two-arguments"])
    def test_the_access_log_arity_is_exactly_one(self, tmp_path, line):
        result = _parse(tmp_path, knobs=line)
        assert result.returncode != 0, "brix_access_log accepted a bad arity"
        assert "invalid number of arguments" in result.stderr, result.stderr


# --------------------------------------------------------------------------- #
# §H — the C the tables above are a reading of                                 #
# --------------------------------------------------------------------------- #

def _command_entry(text, name):
    """The one command-table entry for `name`, from its ngx_string to the
    NULL that closes it."""
    start = text.index(f'{{ ngx_string("{name}")')
    return text[start:text.index("},", start)]


def _squashed(text):
    return " ".join(text.split())


class TestTheDeclarationsAndTheMerge:
    """Source pins for the claims the wire cannot make: what the six share,
    what they merge to, and in which order the two layers run."""

    @pytest.mark.parametrize("name,field", FLAGS,
                             ids=[name for name, _ in FLAGS])
    def test_the_six_share_one_declaration_shape(self, name, field):
        entry = _command_entry(HTTP_COMMON_C.read_text(), name)
        assert "BRIX_HTTP_ALL_CONF|NGX_CONF_FLAG" in entry, entry
        assert "ngx_conf_set_flag_slot" in entry, entry
        assert "NGX_HTTP_LOC_CONF_OFFSET" in entry, entry
        assert f"common.{field})" in entry, entry

    def test_the_scope_macro_is_the_three_http_contexts(self):
        """The parse matrix in §G is a reading of this one line."""
        assert _squashed("#define BRIX_HTTP_ALL_CONF \\\n"
                         "    (NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|"
                         "NGX_HTTP_LOC_CONF)") \
            in _squashed(HTTP_COMMON_C.read_text())

    @pytest.mark.parametrize("field,default", [
        ("verify_write", 0), ("read_only", 0), ("compress", 0),
        ("strict_security", 0), ("session_log", 1),
        ("backend_krb5_forwardable", 0)])
    def test_the_merge_defaults_are_what_the_absent_arm_measures(
            self, field, default):
        """``session_log`` is the one that defaults ON, which is why its absent
        arm logs and every other absent arm is inert."""
        assert (f"ngx_conf_merge_value(conf->{field}, prev->{field}, "
                f"{default});") in _squashed(SHARED_H.read_text())

    def test_the_access_log_path_is_compared_against_the_word_off(self):
        """Not a flag: the sentinel is a path value that is never opened, which
        is why §E can silence a location without turning the session log off."""
        squashed = _squashed(SHARED_H.read_text())
        assert 'ngx_conf_merge_str_value(conf->access_log, prev->access_log, "");' \
            in squashed
        assert 'ngx_strcmp(conf->access_log.data, (u_char *) "off") != 0' \
            in squashed
        assert "conf->access_log_file = NULL;" in squashed

    def test_the_common_module_adopts_and_leaves_enforcement_to_the_protocols(self):
        """The ordering behind §A's opt-out: the common module's merge does
        nothing but fill unset fields from the parent, and
        ``brix_shared_apply_read_only`` runs later, per location, inside each
        protocol's own shared merge — by which time an inherited
        ``allow_write`` is already the child's own."""
        merge = HTTP_COMMON_C.read_text()
        # The definition, not the forward declaration: the return type sits on
        # its own line only where the function is defined.
        body_start = merge.index(
            "static char *\nbrix_http_common_merge_loc_conf(")
        body = merge[body_start:merge.index("\n}", body_start)]
        assert "brix_shared_adopt_unified(&conf->common, &prev->common);" in body
        assert "apply_read_only" not in body
        assert "brix_shared_apply_read_only(conf, cf->log);" \
            in _squashed(SHARED_H.read_text())

    def test_apply_read_only_is_silent_unless_it_takes_a_grant_away(self):
        """Which is why §A's log assertions count exactly one sentence: the
        NOTICE is emitted where a write grant is being overridden, and nowhere
        else."""
        text = SHARED_H.read_text()
        body = text[text.index("brix_shared_apply_read_only(ngx_http_brix"):]
        body = body[:body.index("\n}")]
        assert "if (common->read_only != 1) {" in body
        assert "common->allow_write = 0;" in body
        # The sentence §A reads off the log, reassembled from the C literals it
        # is split across — so a reword in either place is caught in both.
        assert "".join(re.findall(r'"((?:[^"\\]|\\.)*)"', body)) \
            == READ_ONLY_NOTICE, body

    def test_the_security_gate_has_exactly_three_callers(self):
        """§B's three subjects are not a sample — they are the whole set of
        configurations ``brix_strict_security`` can refuse."""
        callers = []
        for path in sorted(SRC_DIR.rglob("*.c")):
            text = path.read_text(errors="replace")
            if "brix_shared_security_gate(" in text:
                callers.append(str(path.relative_to(ROOT)))
        assert callers == ["src/observability/dashboard/module.c",
                           "src/protocols/s3/module.c",
                           "src/protocols/webdav/config_merge.c"], callers
        assert 'strict ? " (refused: brix_strict_security on)" : ""' \
            in SHARED_H.read_text()

    def test_the_compress_flag_gates_the_negotiator(self):
        assert "if (!opts->compress) {" in FILE_SERVE_C.read_text()
        assert ("if (is_range || r->header_only || "
                "file_size < BRIX_COMPRESS_MIN_SIZE) {") \
            in COMPRESS_C.read_text()
        assert "#define BRIX_COMPRESS_MIN_SIZE  256" in COMPRESS_H.read_text()

    def test_the_session_record_is_cached_per_connection(self):
        """DEFECT #79 in the C: the lookup and its early return come BEFORE the
        conf is read for an access-log fd, so a second location on the same
        connection never gets its own decision."""
        text = SESSLOG_CONN_C.read_text()
        body = text[text.index("brix_http_sess(ngx_http_request_t *r,"):]
        body = body[:body.index("\n}")]
        lookup = body.index("record = brix_http_sess_lookup(c);")
        early = body.index("return record->sess;")
        reads_conf = body.index("brix_http_shared_access_log_fd(conf)")
        begins = body.index("brix_sess_begin(conf->session_log")
        assert lookup < early < reads_conf < begins, body
        assert "if (!enabled || log_fd == NGX_INVALID_FILE) {" \
            in SESSLOG_NGX_C.read_text()

    def test_the_put_path_hands_verify_write_to_the_writer(self):
        """The one http reader the flag has — which is exactly why §C's three
        arms being identical is a finding and not a tautology."""
        assert _squashed("brix_vfs_writer_open(vctx, BRIX_VFS_O_ATOMIC,\n"
                         "                                    "
                         "conf->common.verify_write, &staged_err);") \
            in _squashed(PUT_SETUP_C.read_text())

    def test_exactly_four_of_the_six_are_declared_on_the_stream_plane(self):
        """The asymmetry §G's stream rows are a reading of."""
        declared = set()
        for path in sorted(STREAM_DIR.rglob("*.c")) + \
                sorted(STREAM_DIR.rglob("*.h")):
            text = path.read_text(errors="replace")
            for name in FLAG_NAMES:
                if f'ngx_string("{name}")' in text:
                    declared.add(name)
        assert declared == set(STREAM_FLAGS), sorted(declared)
        assert not declared & set(HTTP_ONLY_FLAGS)
