#!/usr/bin/env python3
"""e2e_redteam.py — full-stack privilege-escalation red-team for phase-40
impersonation.  RUNS AS IN-NS ROOT (launched by userns_exec_launcher inside an
unprivileged user namespace with a subuid range + bind-mounted fake passwd/group).

This is the pseudo-production permissions test: it boots the REAL nginx binary
with `brix_impersonation map` (so the real master spawns the real broker, real
svc-uid workers connect, and the real auth->identity->dispatch->broker->setfsuid
chain runs), then drives it over the network with token-authenticated WebDAV
requests as many identities and tries to break the permissions model.

It asserts the model holds end-to-end: files owned by the MAPPED user (not the
worker/broker), DAC enforced, every escalation/forbidden identity denied,
confinement intact, and no credential leak under concurrency.

argv[1] = work dir (pre-created by the pytest wrapper, holds nothing required —
this script generates keys/tokens/config/export tree itself as in-ns root).
Prints "PASS:"/"FAIL:" per check and "ALL PASSED" + exit 0 on success.
"""

import base64
import datetime as dt
import hashlib
import hmac
import json
import os
import re
import socket
import struct
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from http.client import HTTPConnection   # imported by name: the http() helper below
from urllib.parse import quote           # would otherwise shadow the `http` module

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from settings import BIND_HOST, HOST

WORK = sys.argv[1] if len(sys.argv) > 1 else "/tmp/e2e_redteam"
NGINX = os.environ.get("TEST_NGINX_BIN", "/tmp/nginx-1.28.3/objs/nginx")
# repo root = .../tests/userns/e2e_redteam.py -> up 3.  The native root:// clients
# (built under client/) drive the stream server with a bearer token (BEARER_TOKEN).
REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
# The native CLI binaries are built into client/bin/ (the Makefile's BINDIR), not
# client/ directly — an older layout this path lagged behind.
NATIVE_XRDFS = os.path.join(REPO, "client", "bin", "xrdfs")
NATIVE_XRDCP = os.path.join(REPO, "client", "bin", "xrdcp")
# set in main(): the JWT signing key + the impersonation stream port, so the
# root:// helpers can mint a per-subject token without threading them everywhere.
_jwt_key = None
_stream_port = 0
ISSUER = "https://redteam.example"
AUDIENCE = "nginx-xrootd"
KID = "rt-es256"
WRITE_SCOPE = "storage.create:/ storage.modify:/ storage.read:/"

# S3 SigV4: access_key == the UNIX user the broker maps to (subject = access key).
S3_BUCKET = "testbucket"
S3_REGION = "us-east-1"
S3_SECRET = "rt-s3-secret-0123456789"

# in-ns uids (match the fake /etc/passwd the launcher bind-mounted).
UID_ALICE, UID_BOB, UID_SVC = 1001, 1002, 1500
UID_CAROL, UID_DAVE, UID_ERIN, UID_FRANK = 1003, 1004, 1005, 1006
UID_MANYU, UID_FLOOR, UID_LOW = 1008, 1000, 999
# supplementary groups (match the fake /etc/group): staff={alice,carol},
# research={bob,dave}, shared={alice,bob,carol}, proj={carol,dave,erin}.
GID_STAFF, GID_RESEARCH, GID_SHARED, GID_PROJ = 2001, 2002, 2003, 2004

_pass = _fail = 0


def run_webdav_undispatched_methods(key, data, port, s3port):
    """Undispatched/exotic HTTP+WebDAV methods and HTTP-method-override smuggling
    under impersonation: every method nginx-xrootd does NOT route (REPORT, SEARCH,
    PATCH, the DeltaV/CalDAV/RFC-5842 verbs, TRACE, CONNECT, a bogus verb, and
    lowercase get/put) must either be cleanly REJECTED or, if dispatched, enforce
    the broker DAC -- and NO override header (X-HTTP-Method-Override / X-Method-
    Override / X-HTTP-Method) may smuggle a DELETE/MOVE/PUT past the visible verb to
    mutate, delete, escalate, escape, or create an svc/root-owned artifact.  WHY:
    the verb is the first dispatch key; a method the router silently treats as a
    mutating op, or an override header the router honours, bypasses the entire
    auth->impersonation->DAC chain.  Distinct from run_webdav_methods (HEAD/OPTIONS/
    UNLOCK/COPY/Overwrite/Depth -- all ROUTED verbs) and run_webdav_method_state
    (LOCK-state x conditional x PUT/MKCOL/MOVE edge matrix on ROUTED verbs): this
    batch attacks the UN-routed verb space + override smuggling, a surface neither
    touches.  All fixtures prefixed `und_`."""
    ta, tb = mint(key, "alice"), mint(key, "bob")
    base = f"http://{HOST}:{port}"
    bpriv = os.path.join(data, "bob", "private.txt")
    adir = os.path.join(data, "alice")

    def snap(p):
        """(exists, content_or_None, uid_or_-1, mode_or_-1) for a path."""
        try:
            stt = os.stat(p)
        except OSError:
            return (False, None, -1, -1)
        try:
            c = open(p, "rb").read()
        except OSError:
            c = None
        return (True, c, stt.st_uid, stt.st_mode & 0o7777)

    def not_svc_root(p):
        """True iff p is absent or owned by neither svc(1500) nor root(0)."""
        try:
            if not os.path.lexists(p):
                return True
            return os.lstat(p).st_uid not in (UID_SVC, 0)
        except OSError:
            return True

    # Clean-rejection status family: nginx core 400 for unknown method tokens,
    # 405 for TRACE/CONNECT, plus the other honest refusals a router might emit.
    REJECT = (400, 401, 403, 404, 405, 411, 415, 501, 505)

    SECRET = b"BOB-PRIVATE-SECRET"

    # Canonical snapshot of bob's 0600 secret (reset_fixtures ran first), used to
    # prove NO undispatched method / override smuggling mutated or deleted it.
    b0 = snap(bpriv)
    ok(b0[0] and b0[1] == b"BOB-PRIVATE-SECRET\n" and b0[2] == UID_BOB
       and b0[3] == 0o600,
       "control: bob/private.txt canonical 0600 bob-owned secret before attack")

    # ============================================================ READ-CLASS VERBS
    # Methods that, IF the router mistook them for a read, would expose bytes.
    # Each must NOT return bob's secret body (the read would run as alice=other).
    for m in ("REPORT", "SEARCH", "ACL", "LABEL", "PROPPATCH-NOPE"):
        st, b = http(m, "/bob/private.txt", port, ta)
        ok(st in REJECT + (207, 200, 422) and SECRET not in (b or b""),
           f"undispatched {m} on bob's 0600 leaks no secret body (HTTP {st})")
    # The same read-class probe must also not leak via the world-readable name in
    # bob's 0700 secret DIR (directory-listing confusion): bobsecret/s.txt body.
    st, b = http("SEARCH", "/bobsecret/", port, ta,
                 data=b"<?xml version='1.0'?><searchrequest/>",
                 hdrs={"Content-Type": "application/xml"})
    ok(SECRET not in (b or b"") and b"bob-only" not in (b or b""),
       f"undispatched SEARCH of bob's 0700 dir enumerates/leaks nothing (HTTP {st})")

    # ============================================================ MUTATE-CLASS VERBS
    # Methods that, IF routed as a write/patch, would alter or destroy bob's file.
    # After each, bob's secret must be byte-identical, mode 0600, still bob-owned.
    for m, body in (("PATCH", b"PATCHED-BY-ATTACKER\n"),
                    ("ORDERPATCH", b"REORDERED\n"),
                    ("MERGE", b"MERGED\n"),
                    ("UPDATEREDIRECTREF", b"REDIR\n")):
        st, _ = http(m, "/bob/private.txt", port, ta, body,
                     hdrs={"Content-Type": "application/xml"})
        now = snap(bpriv)
        ok(st in REJECT + (422,) and now[1] == b"BOB-PRIVATE-SECRET\n"
           and now[2] == UID_BOB and now[3] == 0o600,
           f"undispatched {m} did NOT mutate bob's 0600 secret (HTTP {st})")

    # A mutate-class verb aimed at DELETING bob's readable.txt must not unlink it.
    bread = os.path.join(data, "bob", "readable.txt")
    r0 = snap(bread)
    st, _ = http("UNBIND", "/bob/readable.txt", port, ta,
                 data=(b'<?xml version="1.0"?><D:unbind xmlns:D="DAV:">'
                       b"<D:segment>readable.txt</D:segment></D:unbind>"),
                 hdrs={"Content-Type": "application/xml"})
    ok(st in REJECT + (422,) and snap(bread) == r0 and os.path.exists(bread),
       f"undispatched UNBIND did NOT delete bob's readable.txt (HTTP {st})")

    # ============================================================ ARTIFACT-CREATE VERBS
    # DeltaV/CalDAV "make-something" verbs: if the router runs them they must (a) be
    # confined to the export and (b) never leave an svc(1500)/root(0)-owned object.
    create_verbs = ("MKCALENDAR", "MKWORKSPACE", "MKACTIVITY", "VERSION-CONTROL",
                    "CHECKOUT", "CHECKIN", "UNCHECKOUT", "MKREDIRECTREF",
                    "BIND", "REBIND")
    for m in create_verbs:
        tgt = f"und_{m.lower().replace('-', '_')}"
        st, _ = http(m, f"/alice/{tgt}", port, ta)
        fp = os.path.join(adir, tgt)
        # Either cleanly refused (nothing created) OR, if created, owned by the
        # MAPPED user alice -- never the worker/root, and never escaping the dir.
        created_ok = (not os.path.lexists(fp)) or (
            os.lstat(fp).st_uid == UID_ALICE and os.lstat(fp).st_uid not in (UID_SVC, 0))
        ok(st in REJECT + (200, 201, 204) and created_ok and not_svc_root(fp),
           f"undispatched {m} in alice's dir: no worker/root artifact (HTTP {st})")
    # An artifact verb pointed at the world-writable pub dir must NOT yield a file
    # owned by the worker uid masquerading as a tenant write.
    st, _ = http("MKACTIVITY", "/pub/und_act", port, ta)
    pubp = os.path.join(data, "pub", "und_act")
    ok(st in REJECT + (200, 201, 204) and not_svc_root(pubp),
       f"undispatched MKACTIVITY in world-writable pub creates no svc/root file (HTTP {st})")

    # ============================================================ METHOD-OVERRIDE SMUGGLING
    # POST/PUT carrying X-HTTP-Method-Override: DELETE on bob/private.txt -- the
    # server must NOT honour the header to delete/mutate bob's file.  Snapshot the
    # file around EACH override-header variant (each is a distinct parse path).
    override_hdrs = ("X-HTTP-Method-Override", "X-Method-Override", "X-HTTP-Method")
    for oh in override_hdrs:
        pre = snap(bpriv)
        st, _ = http("POST", "/bob/private.txt", port, ta, b"",
                     hdrs={oh: "DELETE"})
        post = snap(bpriv)
        ok(post == pre and post[0] and post[1] == b"BOB-PRIVATE-SECRET\n",
           f"POST + {oh}: DELETE did NOT delete/alter bob's 0600 (HTTP {st})")
    # PUT body carrying an override to MOVE bob's file into alice's space (theft):
    # the override must be ignored -> no copy/move lands in alice's dir.
    stolen = os.path.join(adir, "und_stolen_via_override.txt")
    st, _ = http("PUT", "/bob/private.txt", port, ta, b"x\n",
                 hdrs={"X-HTTP-Method-Override": "MOVE",
                       "Destination": f"{base}/alice/und_stolen_via_override.txt"})
    ok(not os.path.exists(stolen) and snap(bpriv)[1] == b"BOB-PRIVATE-SECRET\n",
       f"PUT + override MOVE did NOT steal bob's file into alice's dir (HTTP {st})")
    # Override pointed at alice's OWN file: even if a server honoured override, the
    # result must stay alice-owned and the privilege must not change (no escalation).
    http("PUT", "/alice/und_ov_self.txt", port, ta, b"self\n")
    selfp = os.path.join(adir, "und_ov_self.txt")
    st, _ = http("POST", "/alice/und_ov_self.txt", port, ta, b"",
                 hdrs={"X-HTTP-Method-Override": "DELETE"})
    # If the override were honoured as a real DELETE-by-alice it would be legal, so
    # we don't forbid removal; we forbid the file becoming worker/root-owned and we
    # forbid a smuggled override from creating a DIFFERENT-owner artifact.
    ok(not_svc_root(selfp),
       f"override on alice's OWN file never yields a worker/root artifact (HTTP {st})")
    # Override DELETE on bob via the keep-alive-free path must also not work when
    # the visible verb is itself a write the server DOES route (PUT) -- targeting a
    # path alice cannot write: bob's 0700 secret dir child.
    sx = os.path.join(data, "bobsecret", "s.txt")
    sx0 = snap(sx)
    st, _ = http("PUT", "/bobsecret/s.txt", port, ta, b"OVERRIDE-PWN\n",
                 hdrs={"X-HTTP-Method": "PUT"})
    ok(snap(sx) == sx0 and sx0[0],
       f"override-tagged PUT into bob's 0700 dir DENIED, child unchanged (HTTP {st})")

    # ============================================================ CASE-FOLDING VERBS
    # Lowercase get/put must NOT be silently upcased into a routed GET/PUT.  Even if
    # the server case-folds, the DAC still applies: lowercase get on bob's 0600 must
    # not leak; lowercase put into alice's dir must (if honoured) stay alice-owned.
    st, b = http("get", "/bob/private.txt", port, ta)
    ok(st in REJECT + (200,) and SECRET not in (b or b""),
       f"lowercase 'get' on bob's 0600 leaks no secret (HTTP {st})")
    st, _ = http("put", "/alice/und_lower.txt", port, ta, b"lower\n")
    lp = os.path.join(adir, "und_lower.txt")
    ok((not os.path.lexists(lp)) or (os.lstat(lp).st_uid == UID_ALICE),
       f"lowercase 'put' into alice's dir is rejected or stays alice-owned (HTTP {st})")
    # lowercase 'put' into BOB's dir must never write a file there.
    lbob = os.path.join(data, "bob", "und_lower_bob.txt")
    http("put", "/bob/und_lower_bob.txt", port, ta, b"x\n")
    ok(not os.path.exists(lbob),
       "lowercase 'put' into bob's dir created no file (case-fold cannot bypass DAC)")

    # ============================================================ BOGUS VERB
    # A wholly-unknown verb must be cleanly rejected and mutate nothing.
    st, b = http("FOOBAR", "/alice/und_foobar.txt", port, ta, b"x\n")
    ok(st in REJECT and not os.path.exists(os.path.join(adir, "und_foobar.txt")),
       f"bogus FOOBAR verb cleanly rejected, nothing created (HTTP {st})")
    # Bogus verb against the /etc-symlink escape must not read /etc/passwd.
    st, b = http("FOOBAR", "/escape/passwd", port, ta)
    ok(b"root:x:0:0" not in (b or b""),
       f"bogus verb on /escape symlink does not read /etc/passwd (HTTP {st})")

    # ============================================================ TRACE / CONNECT (raw)
    # TRACE must NOT reflect the request (Cross-Site-Tracing): the bearer token and
    # a marker header must be absent from the response body.  Use raw_http so we can
    # plant the Authorization header verbatim and inspect the raw bytes.
    trace_raw = (
        "TRACE /alice/und_trace HTTP/1.1\r\n"
        f"Host: {HOST}\r\n"
        f"Authorization: Bearer {ta}\r\n"
        "X-Reflect-Marker: UND-XST-REFLECT-7Q\r\n"
        "Connection: close\r\n\r\n"
    )
    resp = raw_http(trace_raw, port)
    ok(b"UND-XST-REFLECT-7Q" not in resp and ta.encode() not in resp,
       "TRACE does not reflect the bearer token / marker header (no XST leak)")
    ok(b"200" not in resp.split(b"\r\n", 1)[0],
       f"TRACE is not answered 200 (refused: {resp.split(chr(13).encode(),1)[0][:40]!r})")
    # CONNECT (authority-form) must not open a tunnel / be answered 2xx -- the
    # worker must refuse to become a forward proxy.
    connect_raw = (
        "CONNECT 169.254.169.254:80 HTTP/1.1\r\n"
        "Host: 169.254.169.254:80\r\n"
        "Connection: close\r\n\r\n"
    )
    cresp = raw_http(connect_raw, port)
    first = cresp.split(b"\r\n", 1)[0] if cresp else b""
    ok(b"200" not in first and b"Connection established" not in cresp,
       f"CONNECT tunnel refused (no SSRF forward-proxy): {first[:40]!r}")

    # ============================================================ WORKER SURVIVAL
    # After the whole undispatched/override barrage a legit op must still work and
    # land owned by the mapped user -> no verb wedged or crashed the worker/broker.
    st, _ = http("PUT", "/alice/und_survivor.txt", port, ta, b"alive\n")
    sp = os.path.join(adir, "und_survivor.txt")
    ok(st in (200, 201, 204) and os.path.exists(sp)
       and os.stat(sp).st_uid == UID_ALICE,
       f"worker SURVIVED undispatched/override barrage; legit PUT owned alice (HTTP {st})")
    st, b = http("GET", "/alice/und_survivor.txt", port, ta)
    ok(st == 200 and b == b"alive\n",
       f"post-barrage GET returns the survivor body (worker healthy) (HTTP {st})")
    # Final sweep: nothing und_* in alice's dir may be owned by svc(1500)/root(0).
    bad = []
    try:
        for f in os.listdir(adir):
            if not f.startswith("und_"):
                continue
            fp = os.path.join(adir, f)
            try:
                if os.lstat(fp).st_uid in (UID_SVC, 0):
                    bad.append(f)
            except OSError:
                pass
    except OSError:
        pass
    ok(not bad,
       f"no und_ artifact in alice's tree is worker(1500)/root(0)-owned: {bad[:4]}")
    # And bob's secret is STILL canonical after everything (end-to-end invariant).
    bend = snap(bpriv)
    ok(bend[1] == b"BOB-PRIVATE-SECRET\n" and bend[2] == UID_BOB and bend[3] == 0o600,
       "bob's 0600 secret unchanged end-to-end after the full undispatched barrage")


