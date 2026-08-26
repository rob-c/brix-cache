"""tests/test_audit16aj_cache_store_endpoint_arms.py — audit tranche 16, file 36.

WHY THIS FILE EXISTS
    `brix_cache_store_endpoint` is the only directive in the tree declared under
    ONE name on BOTH planes, by TWO declarations, with TWO different setters:

        webdav/module_commands.c:74   NGX_HTTP_MAIN_CONF|SRV_CONF|LOC_CONF|FLAG
                                      -> brix_http_set_cache_store_endpoint, a
                                         CUSTOM setter that writes
                                         common.cache_store_endpoint on the
                                         WebDAV loc-conf AND on the S3 one
        root/stream/module.c:239      NGX_STREAM_SRV_CONF|NGX_CONF_FLAG
                                      -> ngx_conf_set_flag_slot, the stock one

    What the corpus had written of it, in its entirety:

        configs/nginx_mu_sidecar_store.conf:25   `on`, in one STREAM server
        cmdscripts/tier_remote.py:42             `on`, programmatically, likewise

    The token `off` appears in no configuration in this tree, on either plane.
    The HTTP declaration — three legal scopes, a custom setter, eleven runtime
    call sites across WebDAV and S3 — had never been written AT ALL, which means
    the custom setter had never run and the dual write it exists to perform had
    never happened anywhere in this suite.

WHAT THE FLAG DOES
    It is the sole `allow_internal` argument of the reserved-name guard:

        core/compat/path.c:61        brix_http_resolve_path_ex, for WebDAV and S3
        root/read/open_request.c:205 kXR_open
        root/read/stat.c:316         kXR_stat
        root/read/statx.c:232        kXR_statx

    With it off, a request that NAMES an internal artifact — the suffixes
    `.cinfo` `.xrdcinfo` `.meta` `.xrdt` `.commit` and the infixes `.xrd-tmp.`
    `.xrdresume.`, matched against the FINAL PATH COMPONENT only
    (fs/path/reserved_names.h) — is answered as if the path did not exist.  With
    it on, the same name is an ordinary object, which is what a cache node
    writing `brix_cache_meta sidecar` over root:// or https:// needs of its
    origin.

    path.c:50-58 states the intent in so many words: the answer is "404 (not
    403) so the response does not distinguish an internal name from a genuinely
    absent one", and it claims to cover "WebDAV + S3 (both route client URIs
    through here)".

WHAT THE MEASUREMENT FOUND
    On WebDAV the claim holds exactly: every refusal is byte-for-byte the 404
    a genuinely absent path gets.  Four other planes do not keep it.

      #138  The S3 plane cannot express the refusal the resolver specifies.
            s3_resolve_key (s3/util.c:129-152) reduces resolve_path_ex's
            403/404/414 to a BOOLEAN, and handler_dispatch.c:287-303 maps that
            boolean to 403 AccessDenied.  A reserved name that does NOT exist
            answers 403 where a plain absent key answers 404 NoSuchKey — so the
            S3 response discloses the reserved-name policy the WebDAV response
            is careful to hide.  §D.
      #139  The same refusal books the wrong diagnostic event: `access_denied`
            rather than `no_such_key`.  §E.
      #140  kXR_stat's refusal TEXT is a policy oracle — a reserved name says
            "file not found" where a genuinely absent one says "No such file or
            directory", both under 3011.  kXR_open says "file not found" for
            both and does NOT disclose, which is the control.  §F.
      #141  kXR_rm is not gated at all.  On the disarmed arm a client that
            cannot stat, open, statx or list a sidecar can still UNLINK it —
            while WebDAV's DELETE of the same name on the same export is 404.
            §F.
      #142  The http declaration accepts a duplicate the stream declaration
            refuses, and lands on the permissive arm.  The custom setter fills
            the slot itself and so never runs ngx_conf_set_flag_slot's
            `if (*fp != NGX_CONF_UNSET) return "is duplicate";`.  §G/§J.
      #143  Two diagnostics for one directive name — http says `must be "on" or
            "off"`, stream says `it must be`.  §J.
      #144  A reserved DIRECTORY hides only itself: /adir.meta/ is 404 on the
            disarmed arm and /adir.meta/inside.txt is 200 on it, because the
            predicate tests the final component only.  §I.
      #145  Three files include fs/path/reserved_names.h with a "hide sidecars"
            comment and never call the predicate.  §K.

THE SHAPE OF THE MEASUREMENT
    Thirteen faces over ONE export directory, so a row that differs between two
    faces differs because of the directive and not because of the bytes: same
    inode, same size, same mtime.  Six WebDAV vhosts and five S3 vhosts on two
    listeners (config_merge refuses both protocols under one `listen`), three
    stream servers, and one metrics vhost.  `keep.dat` is the genuine sibling
    that keeps every "absent" reading from being a claim about the export.
"""

import hashlib
import hmac
import os
import re
import socket
import struct
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote

import pytest
import requests

from config_parse import nginx_t
from fleet_lifecycle_ports import LIFECYCLE_SHARED_PORTS, PARSE_PLACEHOLDER_PORT
from metrics_helpers import value as metric_value
from server_launcher import LifecycleHarness
from server_registry import NginxInstanceSpec
from settings import BIND_HOST, HOST, NGINX_BIN, url_host

from _test_conf_dirlist_helpers import _DirlistError, _wire_plain_names
from _test_conf_stattypes_helpers import _stat_fields, _stat_path, _statx
from _test_conf_write_helpers import (_connect, _err, _login, _open, _resp,
                                      kXR_new, kXR_ok, kXR_open_read,
                                      kXR_open_updt)

NAME = "lc-audit16aj-storeep"
_L = LIFECYCLE_SHARED_PORTS[NAME]

ROOT_ON = _L["port"]
ROOT_OFF = _L["extra"]["OFF_PORT"]
ROOT_ABS = _L["extra"]["ABS_PORT"]
HTTP_PORT = _L["extra"]["HTTP_PORT"]
S3_PORT = _L["extra"]["S3_PORT"]

FLAG = "brix_cache_store_endpoint"
TIMEOUT = 20

ACCESS_KEY, SECRET_KEY, REGION = "AKIAAUDIT16AJ", "audit16aj-secret-key", "us-east-1"

# The one file every arm can see, and the bytes every reserved fixture carries.
KEEP, KEEP_BYTES = "keep.dat", b"K" * 2048
SECRET = b"SECRET-METADATA"

# `.xrd-tmp.<pid>.<rand>` is reaped at startup when the pid is dead
# (core/config/process.c:43-72), so the live temp fixture has to name a pid that
# is alive — this process.  DEAD_TMP is seeded beside it as the control that
# says the reaper, and not the guard, is what removes the other one.
def _dead_pid():
    """A pid number no process holds.  Small numbers are the kernel's own
    threads (2 is kthreadd, which never exits), so the search starts above
    anything a running system would have handed out."""
    for candidate in range(4_000_000, 4_000_400):
        if not Path(f"/proc/{candidate}").exists():
            return candidate
    raise RuntimeError("no free pid found")


LIVE_TMP = f"keep.dat.xrd-tmp.{os.getpid()}.9"
DEAD_TMP = f"keep.dat.xrd-tmp.{_dead_pid()}.9"

# One fixture per pattern in fs/path/reserved_names.h, five suffixes and two
# infixes, all carrying the same fifteen bytes so a served body is unambiguous.
RESERVED = ("keep.dat.cinfo", "keep.dat.xrdcinfo", "keep.dat.meta",
            "keep.dat.xrdt", "note.commit", LIVE_TMP,
            "keep.dat.xrdresume.abcd1234.part")

# Every parametrization over RESERVED pins these ids rather than deriving them
# from the values, because one value carries this process's pid — and under
# xdist each worker is a different process, so a derived id makes two workers
# collect different node ids and the run dies before it starts.
RESERVED_IDS = ("cinfo", "xrdcinfo", "meta", "xrdt", "commit", "xrd-tmp",
                "xrdresume")

# Names one character away from a pattern, plus the two the predicate's shape
# makes interesting: `cinfo` with no dot at all, and `keep.dat.CINFO`, which
# only a case-insensitive comparison would catch (the predicate uses memcmp).
NEAR_MISS = ("keep.dat.CINFO", "keep.dat.cinfoX", "keep.dat.cinf", "cinfo",
             "keep.dat.commitX", "keep.datxrd-tmp.1.2", "keep.dat.meta.txt")
NEAR_BYTES = b"NEARMISS-BYTES"

# The subtrees the server-scope vhost's three children address.
SUBTREES = ("optout", "reassert")

# The faces, by the Host: header that selects them.
DAV_ON, DAV_OFF, DAV_ABS = "dav-on.test", "dav-off.test", "dav-abs.test"
DAV_SRVON, DAV_SRVOFF, DAV_DUP = "dav-srvon.test", "dav-srvoff.test", "dav-dup.test"
S3_ON, S3_OFF, S3_ABS, S3_SRVON = "s3-on.test", "s3-off.test", "s3-abs.test", "s3-srvon.test"
S3_METRICS = "metrics.test"

# The pair every section A cell exists to compare: the written token against the
# omission that has always stood in for it.
DISARMED_DAV = (DAV_OFF, DAV_ABS)
DISARMED_S3 = (S3_OFF, S3_ABS)
ARMED_S3 = (S3_ON, S3_SRVON)

pytestmark = [pytest.mark.timeout(600),
              pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group(NAME)]


# --------------------------------------------------------------------------- #
# The instance                                                                 #
# --------------------------------------------------------------------------- #

def _seed(directory):
    directory.mkdir(parents=True, exist_ok=True)
    (directory / KEEP).write_bytes(KEEP_BYTES)
    for name in RESERVED + (DEAD_TMP,):
        (directory / name).write_bytes(SECRET)
    for name in NEAR_MISS:
        (directory / name).write_bytes(NEAR_BYTES)
    # A dot-file whose WHOLE basename is a reserved suffix: the predicate is a
    # suffix test on the final component, not a "stem plus extension" test.
    (directory / ".cinfo").write_bytes(NEAR_BYTES)


@pytest.fixture(scope="module")
def srv(tmp_path_factory):
    """MODULE-scoped with its own harness, for the reason files 27-35 give: the
    ports are fixed by the ledger, so a per-test start/stop races the OS
    releasing them.

    ONE export for all thirteen faces.  Every mutating cell names its fixtures
    after itself so the shared tree needs no cleanup between cells, and the
    read-only fixtures above are never touched by any of them.
    """
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx binary not executable: {NGINX_BIN}")

    root = tmp_path_factory.mktemp("audit16aj") / "export"
    _seed(root)
    for sub in SUBTREES:
        _seed(root / sub)
    (root / "adir.meta").mkdir()
    (root / "adir.meta" / "inside.txt").write_bytes(b"INSIDE-A-RESERVED-DIR")
    (root / "plaindir").mkdir()
    (root / "plaindir" / "inside.txt").write_bytes(b"INSIDE-A-PLAIN-DIRRR")

    harness = LifecycleHarness()
    try:
        harness.start(NginxInstanceSpec(
            name=NAME,
            template="nginx_audit16aj_store_endpoint.conf",
            protocol="root",
            readiness="root",
            data_root=str(root),
            template_values={"BIND_HOST": BIND_HOST,
                             "ACCESS_KEY": ACCESS_KEY,
                             "SECRET_KEY": SECRET_KEY,
                             "REGION": REGION},
            reason=f"audit-16aj {FLAG} — the one directive declared on both "
                   "planes under one name, whose disarming token no config in "
                   "the tree writes and whose http declaration none writes at "
                   "all."))
        yield root
    finally:
        harness.close()


# --------------------------------------------------------------------------- #
# WebDAV helpers                                                               #
# --------------------------------------------------------------------------- #

def _dav_url():
    return f"http://{url_host(HOST)}:{HTTP_PORT}"


def _dav(vhost, method, path, headers=None, **kw):
    """One request against one vhost.  The Host: header is the only thing that
    selects between the six WebDAV faces, so it is never optional."""
    hdrs = {"Host": vhost}
    hdrs.update(headers or {})
    return requests.request(method, _dav_url() + path, headers=hdrs,
                            timeout=TIMEOUT, **kw)


def _fingerprint(response):
    """Status, length and body digest — the three things a refusal that must be
    indistinguishable from another refusal has to match on."""
    return (response.status_code, len(response.content),
            hashlib.md5(response.content).hexdigest())


def _hrefs(propfind_body):
    """The last path segment of every href in a multistatus, namespace-agnostic
    (the D: prefix is a serialization choice, not a contract)."""
    found = re.findall(r"<(?:\w+:)?href>([^<]*)</(?:\w+:)?href>", propfind_body)
    return {segment.rstrip("/").rsplit("/", 1)[-1] for segment in found}


# --------------------------------------------------------------------------- #
# S3 helpers — SigV4 over the same export                                      #
# --------------------------------------------------------------------------- #

def _signing_key(secret, date):
    key = hmac.new(f"AWS4{secret}".encode(), date.encode(), hashlib.sha256).digest()
    for part in (REGION.encode(), b"s3", b"aws4_request"):
        key = hmac.new(key, part, hashlib.sha256).digest()
    return key


def _sign(vhost, method, path, query=""):
    """A SigV4 v4 header set for one request, UNSIGNED-PAYLOAD throughout.

    The canonical URI is re-encoded from `path`, so a cell that wants to probe a
    percent-encoded key cannot express it here — that negative lives on the
    WebDAV plane (§I), where the client sends the bytes the test wrote.
    """
    now = datetime.now(timezone.utc)
    stamp, date = now.strftime("%Y%m%dT%H%M%SZ"), now.strftime("%Y%m%d")
    host = f"{vhost}:{S3_PORT}"
    signed = "host;x-amz-date"
    canonical = (f"{method}\n{quote(path, safe='/-_.~')}\n{query}\n"
                 f"host:{host}\nx-amz-date:{stamp}\n\n{signed}\nUNSIGNED-PAYLOAD")
    scope = f"{date}/{REGION}/s3/aws4_request"
    to_sign = (f"AWS4-HMAC-SHA256\n{stamp}\n{scope}\n"
               f"{hashlib.sha256(canonical.encode()).hexdigest()}")
    signature = hmac.new(_signing_key(SECRET_KEY, date), to_sign.encode(),
                         hashlib.sha256).hexdigest()
    return {"Host": host, "x-amz-date": stamp,
            "x-amz-content-sha256": "UNSIGNED-PAYLOAD",
            "Authorization": (f"AWS4-HMAC-SHA256 Credential={ACCESS_KEY}/{scope}, "
                              f"SignedHeaders={signed}, Signature={signature}")}


def _s3(vhost, method, key, query="", **kw):
    path = "/cas/" + key
    url = f"http://{url_host(HOST)}:{S3_PORT}{path}"
    if query:
        url += "?" + query
    return requests.request(method, url, headers=_sign(vhost, method, path, query),
                            timeout=TIMEOUT, **kw)


def _s3_code(response):
    """The <Code> of an S3 XML error, or "" for a success with no error body."""
    match = re.search(rb"<Code>([^<]*)</Code>", response.content)
    return match.group(1).decode() if match else ""


def _scrape():
    url = f"http://{url_host(HOST)}:{S3_PORT}/metrics"
    return requests.get(url, headers={"Host": S3_METRICS}, timeout=TIMEOUT).text


def _events(text):
    """The whole brix_s3_events_total family as {event: value}, so a cell can
    assert on what did NOT move as easily as on what did."""
    labels = ("invalid_uri", "access_denied", "no_such_key", "write_disabled",
              "method_not_allowed", "internal_error", "dir_sentinel",
              "delete_missing")
    return {name: metric_value(text, "brix_s3_events_total", {"event": name})
            for name in labels}


# --------------------------------------------------------------------------- #
# root:// helpers                                                              #
# --------------------------------------------------------------------------- #

kXR_rm = 3014
kXR_rmdir = 3015


def _session(port):
    session = _connect(HOST, port)
    _login(session)
    return session


def _pathop(session, opcode, path, sid=b"\x00\x21"):
    """Any opcode whose request is kXR_statx's generic framing: streamid[2]
    requestid[2] reserved[16] dlen[4] + path.  kXR_rm and kXR_rmdir both are."""
    encoded = path.encode()
    session.sendall(struct.pack("!2sH16sI", sid, opcode, b"\x00" * 16,
                                len(encoded)) + encoded)
    return _resp(session)[1:]


def _rm(session, path, sid=b"\x00\x21"):
    return _pathop(session, kXR_rm, path, sid)


def _rmdir(session, path, sid=b"\x00\x21"):
    return _pathop(session, kXR_rmdir, path, sid)


def _reason(body):
    """The human-readable half of a kXR_error body, after the four-byte code."""
    return body[4:].rstrip(b"\x00")


# --------------------------------------------------------------------------- #
# A. The written `off`, against the omission it has always stood in for        #
# --------------------------------------------------------------------------- #

