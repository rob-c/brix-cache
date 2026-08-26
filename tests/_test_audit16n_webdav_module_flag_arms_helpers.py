"""The five location-scoped WebDAV flags at VALUE granularity — audit §Method,
16th tranche, file 14.

WHY THIS FILE EXISTS
--------------------
The audit's Method (steps 1-2) counts directive NAMES.  Re-running the same
measurement per (directive, VALUE) over every ``ngx_conf_set_flag_slot``
directive in ``src/`` leaves a residue of flags whose ``off`` arm no config, test
or document in the tree has ever written — reachable only by leaving the
directive out, which is not the same configuration and, as three of these five
show, not always the same behaviour either.

``brix_webdav_commands`` (src/protocols/webdav/module_commands.c) holds nine such
arms.  Five of them share one declaration shape — one legal context, one setter,
one merge — and need nothing but a posix export and an anonymous auth mode to
read, so they are taken together::

    { ngx_string("brix_webdav"),                 :49
      NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_webdav_loc_conf_t, common.enable),
      NULL },

    ... and the same five lines for brix_webdav_upload_resume (:270),
        brix_webdav_tape_rest (:294), brix_delegation_endpoint (:303)
        and brix_webdav_cors_credentials (:377).

The remaining four (``brix_webdav_zip_access``, ``brix_webdav_require_digest``,
``brix_webdav_dig``, ``brix_webdav_proxy_certs``) are declared in wider scopes or
need a TLS client-verify listener, and are not this file's subject.

WHY "OFF" IS NOT THE SAME QUESTION AS "ABSENT" — TWICE OVER
-----------------------------------------------------------
Four of the five merge to 0 and one merges to 1, and both halves of that matter:

  brix_webdav                   shared_conf.h:339          merge default 0
  brix_webdav_tape_rest         webdav/config_merge.c:88   merge default 0
  brix_delegation_endpoint      webdav/config_merge.c:124  merge default 0
  brix_webdav_cors_credentials  webdav/config_merge.c:95   merge default 0
  brix_webdav_upload_resume     webdav/config_merge.c:91   merge default 1

For ``upload_resume`` the arm the corpus writes is the redundant one: ``on`` is
what absence already gives, and ``off`` is the only spelling that turns the
feature off at all.  Every resumable-upload test in the tree therefore measures a
value it did not need to write, and nobody had ever measured the value that does
something.  §B is that measurement.

For ``brix_webdav`` the merge is against the PARENT LOCATION — the flag is legal
in no scope above a location, so a nested location is the only place its parent
value can be anything but zero.  Inside a parent that wrote ``on``, absent
inherits ``on`` and only ``off`` disables the child.  §A measures that: it is the
one case in this file where ``off`` and saying nothing are not interchangeable,
and it is unreachable without writing the arm.

WHAT THE TABLES ESTABLISH
-------------------------
One listener, five ``server_name`` vhosts, twenty locations
(nginx_audit16n_webdav.conf), plus a parse-only scaffold
(nginx_audit16nparse.conf) for the tier that never binds.  Measured, not assumed:

§A  brix_webdav, as what is left of a location when the protocol is switched off:

      /ref/                 GET 200   PUT 201   PROPFIND 207
      /wd-off/              GET 404   PUT 405   PROPFIND 405   (fell through)
      /wd-bare/             GET 404   PUT 405   PROPFIND 405   — off == absent
      /wd-parent/           GET 200   PUT 201   PROPFIND 207
      .../child-bare/       GET 200   PUT 201   — absent INHERITS the parent's on
      .../child-off/        GET 404   PUT 405   — off is the only way to opt out

    and the bytes: a 404 from the fall-through must not carry the object.

§B  brix_webdav_upload_resume, on one Content-Range PUT:

      /ur-on/     bytes 0-4/10  -> 200 + X-Upload-Offset: 5, target NOT created
      /ur-off/    bytes 0-4/10  -> 201, target created, 5 bytes, no X-Upload-Offset
      /ur-bare/   bytes 0-4/10  -> 200 + X-Upload-Offset: 5  — absent == on
      /ur-on/     "bytes junk"  -> 400        /ur-off/  -> 201 (header ignored)
      /ur-on/     bytes 0-9/10  -> 201, committed whole
      /ur-on/     bytes 5-9/10 on a fresh name -> 409 + X-Upload-Offset: 0
      /ur-off/    the same request onto a seeded 10-byte object -> 201 and the
                  object is now FIVE bytes: the range was not honoured, it was
                  overwritten.  That is the hazard the unwritten arm carries.

§C  brix_webdav_tape_rest, on the WLCG Tape REST surface:

      abs-on      POST /api/v1/archiveinfo -> 200 {"files":[...]}
      abs-off     -> 405      abs-bare -> 405      abs-mixed (on) -> 200
      abs-on      POST with {"paths":[]} -> 400 {"detail":"body must contain..."}
      abs-on      GET /api/v1/plain.txt -> 404 {"detail":"unknown endpoint"}
      abs-off     GET /api/v1/plain.txt -> 200 and the file's bytes

    The 405 is the sharper reading and it was measured, not predicted: with the
    router off the request is handled by the location it is actually in, and POST
    is not a method a WebDAV export implements.  A 404 could have meant either
    "the router declined this endpoint" or "the router never ran"; 405 can only
    come from the method table of something that answered itself.

§D  brix_delegation_endpoint, on both of its URI forms:

      /de-on/.well-known/brix-delegation      PUT -> 401, no file created
      /de-off/ same                           PUT -> 201, file created
      /de-bare/ same                           PUT -> 201            — off == absent
      abs-on  GET /.well-known/brix-delegation/request -> 401
      abs-off / abs-bare / abs-mixed(off)      -> 200 and the file's bytes

§E  brix_webdav_cors_credentials, over a wildcard and a concrete allowlist:

      /cc-on/   Origin: X -> Allow-Credentials: true, Allow-Origin: X   (not "*")
      /cc-off/  Origin: X -> no Allow-Credentials,    Allow-Origin: *
      /cc-bare/ Origin: X -> the same as off
      /cx-on/   Origin: O -> Allow-Credentials: true, Allow-Origin: O
      /cx-off/  Origin: O -> no Allow-Credentials,    Allow-Origin: O
      no Origin at all -> no CORS headers on any arm
      a disallowed Origin -> no Allow-Origin, no Allow-Credentials

§J  the parse matrix: all five accept ``on`` and ``off`` in ``location{}`` and are
    refused in ``server{}``, ``http{}``, the main context, a stream server and
    ``stream{}`` — always with ``directive is not allowed here``, never ``unknown
    directive``, because nginx searches every module's table before it checks the
    context.  Plus the gate that ``off`` opens: a location whose ``brix_export``
    names a directory that does not exist is refused under ``brix_webdav on`` and
    accepted in silence under ``off``.

FINDING — DEFECT CANDIDATE #89
------------------------------
The delegation UPLOAD endpoint is matched by URI SUFFIX, not prefix::

    if (!conf->delegation_endpoint
        || r->uri.len < sizeof(delegation_path) - 1
        || ngx_memcmp(r->uri.data + r->uri.len - (sizeof(delegation_path) - 1),
                      delegation_path, sizeof(delegation_path) - 1) != 0)
                                                    dispatch.c:184-190

so a PUT to ANY path in the namespace that happens to end in
``/.well-known/brix-delegation`` is taken as a delegated-credential upload — the
body is parsed as a proxy chain and stored in the delegation store — rather than
written as a file.  Its sibling, the gridsite form, is anchored at the start of
the URI (dispatch.c:203-207, ``/.well-known/brix-delegation/``), which is what
makes the asymmetry a defect rather than a design: one of the two believes the
endpoint lives at a fixed place and the other believes it lives everywhere.
Measured in §D: ``PUT /de-on/deep/nested/.well-known/brix-delegation`` is answered
401 by the credential endpoint and creates nothing, while the byte-identical PUT
under ``/de-off/`` is stored as an object.  The cure is the anchored comparison
the gridsite form already uses.

OBSERVATION — an enabled prefix flag captures part of the export namespace
--------------------------------------------------------------------------
``brix_webdav_tape_rest on`` makes ``/api/v1/`` the Tape REST router's, and
``brix_delegation_endpoint on`` makes ``/.well-known/brix-delegation/`` the
delegation endpoint's, for every request in the location — including requests for
objects that really are on disk under those paths.  §C and §D measure it: the same
seeded file answers 200 with its bytes on the ``off`` arm and 404
``{"detail":"unknown endpoint"}`` / 401 on the ``on`` arm.  It is recorded as an
observation rather than a defect because both prefixes are fixed by the protocols
they implement (WLCG Tape REST v1, RFC 8615) and shadowing is the only way to
serve them; what is missing is the config-time advisory, since the export root is
known at merge time and could be probed for a colliding subtree.  The ``off`` arm
is the only way to see the capture at all, which is why it is measured here.

WHAT THIS FILE DOES NOT CLAIM
-----------------------------
§D reaches the delegation endpoint over cleartext and is answered 401 by
``delegation_client_authenticated()`` — that is the whole point of the reading
(the arm decides whether the endpoint is REACHED), not a claim about what the
endpoint does with a real GSI chain, which test_t4_delegation_handshake.py owns.
Likewise §C's archiveinfo answers from a posix backend, so the localities it
reports are ONLINE/NONE; the tape-locality semantics belong to test_tape_rest.py.

Ledger: lc-audit16n-webdav (one http listener; five vhosts on the one listen,
because two of the five flags gate an absolute URI prefix and a URI space holds
exactly one arm per server).

Run:
    PYTHONPATH=tests pytest tests/test_audit16n_webdav_module_flag_arms.py -v
"""

import json
import os
from pathlib import Path

import pytest
import requests

from config_parse import nginx_t
from fleet_lifecycle_ports import LIFECYCLE_SHARED_PORTS, PARSE_PLACEHOLDER_PORT
from server_registry import NginxInstanceSpec
from settings import BIND_HOST, HOST, NGINX_BIN
# The diagnostic filter belongs to tranche file 10; a substring search over the
# whole `nginx -t` output would match the temp directory rather than a message.
from test_audit16j_root_caps_flags import _diagnostics

def _guard_wd_1():
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx binary not executable: {NGINX_BIN}")


pytestmark = [pytest.mark.timeout(900),
              pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-audit16n-webdav")]

NAME = "lc-audit16n-webdav"
PORT = LIFECYCLE_SHARED_PORTS[NAME]["port"]

ROOT = Path(__file__).resolve().parents[1]
MODULE_COMMANDS_C = ROOT / "src/protocols/webdav/module_commands.c"
CONFIG_MERGE_C = ROOT / "src/protocols/webdav/config_merge.c"
DISPATCH_C = ROOT / "src/protocols/webdav/dispatch.c"
PUT_SETUP_C = ROOT / "src/protocols/webdav/put_setup.c"
CORS_C = ROOT / "src/protocols/webdav/cors.c"

# The five, and the loc_conf field each setter writes.
FLAGS = (
    ("brix_webdav", "common.enable"),
    ("brix_webdav_upload_resume", "upload_resume"),
    ("brix_webdav_tape_rest", "tape_rest"),
    ("brix_delegation_endpoint", "delegation_endpoint"),
    ("brix_webdav_cors_credentials", "cors_credentials"),
)
FLAG_NAMES = [name for name, _ in FLAGS]

# The reserved URI spaces two of the five take over, spelled once.
DELEG_SUFFIX = "/.well-known/brix-delegation"
DELEG_REQUEST = "/.well-known/brix-delegation/request"
TAPE_ARCHIVEINFO = "/api/v1/archiveinfo"
TAPE_SHADOW = "/api/v1/plain.txt"

# One CORS origin the template allowlists concretely, and one it never does.
CORS_ORIGIN = "https://cors-allowed.test"
CORS_OTHER = "https://cors-denied.test"

# Every location of the template that is reached through the default vhost, and
# is backed by the one posix export.  Seeded identically, so a verdict that
# differs between two of them cannot be explained by their contents.
POSIX_ARMS = ("ref", "wd-off", "wd-bare",
              "wd-parent", "wd-parent/child-bare", "wd-parent/child-off",
              "ur-on", "ur-off", "ur-bare",
              "de-on", "de-off", "de-bare",
              "cc-on", "cc-off", "cc-bare", "cx-on", "cx-off")

# The four `location /` vhosts, keyed by the arm they carry.
ABS_VHOSTS = {
    "abs-on": "abs-on.test",        # net-literal-allow: the template's own server_name, matched not dialled
    "abs-off": "abs-off.test",      # net-literal-allow: the template's own server_name, matched not dialled
    "abs-bare": "abs-bare.test",    # net-literal-allow: the template's own server_name, matched not dialled
    "abs-mixed": "abs-mixed.test",  # net-literal-allow: the template's own server_name, matched not dialled
}
DEFAULT_VHOST = "localhost"         # net-literal-allow: the template's own server_name, matched not dialled

PAYLOAD = b"sixteen-n reference payload\n"
# Ten bytes, so a five-byte chunk is exactly half an upload.
WHOLE = b"0123456789"
CHUNK = b"56789"

_needs_nginx = pytest.mark.skipif(
    not os.access(NGINX_BIN, os.X_OK),
    reason=f"nginx not executable: {NGINX_BIN}")


# --------------------------------------------------------------------------- #
# The instance, the seeded export, and the one way this file asks a question    #
# --------------------------------------------------------------------------- #

class _Webdav:
    """The started listener and the single posix export behind all twenty
    locations."""

    def __init__(self, endpoint, data):
        self.endpoint = endpoint
        self.data = data
        self.port = endpoint.port
        self.logs = Path(endpoint.prefix) / "logs"

    # -- addressing --------------------------------------------------------- #

    def request(self, method, uri, host=DEFAULT_VHOST, **kwargs):
        headers = {"Host": host, **kwargs.pop("headers", {})}
        return requests.request(method, f"http://{HOST}:{self.port}{uri}",
                                headers=headers, timeout=30,
                                allow_redirects=False, **kwargs)

    # -- the tree ----------------------------------------------------------- #

    def seed(self, relpath, body=PAYLOAD):
        """Put `body` at `relpath` under the export root, creating parents."""
        target = self.data / relpath.lstrip("/")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(body)
        return target

    def stored(self, relpath):
        """What is on disk at `relpath`, or None when nothing is."""
        target = self.data / relpath.lstrip("/")
        return target.read_bytes() if target.exists() else None

    # -- the logs ----------------------------------------------------------- #

    def errlog(self):
        """Instance prefixes are wiped at teardown, so failures quote inline."""
        try:
            return (self.logs / "error.log").read_text(errors="replace")
        except OSError:                          # pragma: no cover - diagnostic
            return "(error log unavailable)"


@pytest.fixture
def wd(lifecycle, tmp_path):
    """Twenty locations, one listener, one seeded export.

    Every location-scoped arm gets the same object under its own prefix, and the
    four absolute-prefix vhosts share the export root — so the shadowing readings
    in §C and §D compare four verdicts against ONE file on disk.
    """
    _guard_wd_1()

    data = tmp_path / "data"
    data.mkdir()
    for arm in POSIX_ARMS:
        (data / arm).mkdir(parents=True, exist_ok=True)
        (data / arm / "f.bin").write_bytes(PAYLOAD)
    # §D writes objects at and below the reserved delegation suffix, and WebDAV
    # answers a PUT whose parent collection does not exist with 409 (RFC 4918
    # §9.7.1).  Every delegation arm therefore gets the collections in advance —
    # INCLUDING the `on` arm, whose 401 would otherwise be indistinguishable from
    # the 409 an unprepared namespace produces.
    for arm in ("de-on", "de-off", "de-bare"):
        for parent in (DELEG_SUFFIX, f"/deep/nested{DELEG_SUFFIX}"):
            (data / arm / parent.lstrip("/")).parent.mkdir(parents=True,
                                                          exist_ok=True)
    # The abs vhosts serve from the root of the same export, including the two
    # reserved subtrees the on-arms take over.
    (data / "f.bin").write_bytes(PAYLOAD)
    for shadow in (TAPE_SHADOW, DELEG_REQUEST):
        target = data / shadow.lstrip("/")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(PAYLOAD)

    endpoint = lifecycle.start(NginxInstanceSpec(
        name=NAME,
        template="nginx_audit16n_webdav.conf",
        protocol="http",
        data_root=str(data),
        template_values={"BIND_HOST": BIND_HOST, "CORS_ORIGIN": CORS_ORIGIN},
        reason="audit-16n the five location-scoped webdav flags at value "
               "granularity"))
    return _Webdav(endpoint, data)


# --------------------------------------------------------------------------- #
# §A — brix_webdav                                                             #
# --------------------------------------------------------------------------- #

