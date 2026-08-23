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

from split_continuation import load as _load_continuations
_load_continuations(
    globals(), __file__,
    "_test_audit16h_shared_http_flags_part2.py",
    "_test_audit16h_shared_http_flags_part3.py",
    "_test_audit16h_shared_http_flags_part4.py",
)
