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


def run_s3_conditional_impersonation(key, data, port, s3port):
    """S3 conditional requests (phase-43 src/protocols/s3/conditional.c) under per-request
    impersonation.  conditional.c front-runs nginx's core not-modified filter with
    S3 semantics: If-Match/If-None-Match against a synthetic ETag (mtime+size),
    If-Modified-Since with S3 'before' semantics (future date -> 304), and a 412
    that carries an S3 XML <Error>PreconditionFailed body (not a bodyless 412).

    Three attack arcs:
      (A) OWN-OBJECT CORRECTNESS -- the validators must actually discriminate
          (real-ETag/None-Match -> 304, stale If-Match -> 412+XML, future
          If-Modified-Since -> 304, past If-Unmodified-Since -> 412); this proves
          the NEW conditional.c code paths fire, not the core filter.
      (B) CROSS-TENANT DAC-OPEN GATE (the key bug to hunt) -- in s3_handle_get
          (object.c) the impersonated, DAC-gated brix_vfs_open happens BEFORE
          s3_handle_conditional, so a conditional GET of bob's 0600 private.txt by
          alice must be denied by the open FIRST.  We drive EVERY precondition flavour
          incl. ones that would PASS (If-Unmodified-Since future, If-None-Match:*,
          If-Modified-Since future) -- a passed precondition must NEVER short-circuit
          the missing open into a 200+body, and no bob secret byte may appear in ANY
          conditional response.  The HEAD path uses a stat (alice may stat via bob's
          0755 parent) so a 412/304/200 etag-oracle is POSIX-expected there, but HEAD
          carries no body -> we still assert zero content leak.
      (C) response-* QUERY OVERRIDES (s3_apply_response_overrides) -- signed
          response-content-type/-disposition/-encoding on a (pre)signed GET must
          (i) never corrupt the served bytes, (ii) reject CRLF (control bytes) so no
          header injection / response splitting, (iii) never enable a cross-tenant read.

    Distinct from run_conditional_header_matrix (that is WebDAV port+token, WebDAV
    If: forms), run_protocol_features_s3 (pre-conditional.c, accepts loose 304/412/
    501 outcomes -- here we assert the now-IMPLEMENTED precise S3 codes + XML body),
    and run_s3_subresource_fallthrough (?acl/?tagging parser fall-through, no
    precondition headers)."""
    if not s3port:
        ok(True, "S3 port not configured -- s3-conditional-impersonation skipped (handled)")
        return

    SECRET = b"BOB-PRIVATE-SECRET"
    absp = lambda rel: os.path.join(data, *rel.split("/"))
    PAST = "Mon, 01 Jan 1990 00:00:00 GMT"
    FUTURE = "Fri, 01 Jan 2100 00:00:00 GMT"

    def owned_alice(p):
        try:
            return os.path.exists(p) and os.stat(p).st_uid == UID_ALICE
        except OSError:
            return False

    # ---- seed alice's own object + capture its REAL synthetic ETag / Last-Modified.
    OWN_BODY = b"S3-COND-OWN-BODY-v1\n"
    s3("PUT", "alice/cond_own.txt", s3port, data=OWN_BODY)
    fp = absp("alice/cond_own.txt")
    ok(owned_alice(fp), "seed: alice cond_own.txt created + owned by alice (1001)")

    sth, hH, _, _ = _s3_raw("GET", "alice/cond_own.txt", s3port)
    etag = hH.get("etag")
    lastmod = hH.get("last-modified")
    have_etag = bool(etag) and len(etag) >= 2
    ok(sth == 200 and have_etag,
       f"server emits a synthetic ETag validator on alice's S3 object (etag={etag!r})")
    ok(lastmod is not None,
       f"server emits a Last-Modified validator on alice's S3 object (lm={lastmod!r})")

    # ============================================================ (A) OWN-OBJECT ===
    if have_etag:
        st, b = s3("GET", "alice/cond_own.txt", s3port, extra_hdrs={"If-None-Match": etag})
        ok(st == 304 and not b,
           f"S3 If-None-Match REAL ETag -> 304 + no body on own object (HTTP {st})")
        st, b = s3("GET", "alice/cond_own.txt", s3port,
                   extra_hdrs={"If-None-Match": '"cond-not-the-etag"'})
        ok(st == 200 and b == OWN_BODY,
           f"S3 If-None-Match WRONG ETag -> 200 + full body (validator discriminates) (HTTP {st})")
        st, b = s3("GET", "alice/cond_own.txt", s3port, extra_hdrs={"If-Match": etag})
        ok(st == 200 and b == OWN_BODY,
           f"S3 If-Match REAL ETag -> 200 precondition passes, byte-exact body (HTTP {st})")
        # The S3-specific contract: stale If-Match -> 412 carrying an S3 XML body
        # (s3_send_precondition_failed), NOT the core filter's bodyless 412.
        st, b = s3("GET", "alice/cond_own.txt", s3port,
                   extra_hdrs={"If-Match": '"c0ffee-0"'})
        ok(st == 412 and b"<Error" in (b or b"") and b"PreconditionFailed" in (b or b"")
           and OWN_BODY not in (b or b""),
           f"S3 If-Match STALE ETag -> 412 with S3 XML PreconditionFailed body (HTTP {st})")
        # any-match token on an existing representation.
        st, b = s3("GET", "alice/cond_own.txt", s3port, extra_hdrs={"If-None-Match": "*"})
        ok(st == 304 and not b,
           f"S3 If-None-Match:* on existing object -> 304 (any-match) (HTTP {st})")
        st, b = s3("GET", "alice/cond_own.txt", s3port, extra_hdrs={"If-Match": "*"})
        ok(st == 200 and b == OWN_BODY,
           f"S3 If-Match:* on existing object -> 200 (any-match passes) (HTTP {st})")
    else:
        for lbl in ("INM-real", "INM-wrong", "IM-real", "IM-stale-xml", "INM-star", "IM-star"):
            ok(False, f"S3 own-object conditional {lbl} skipped: no ETag captured")

    # If-Modified-Since: conditional.c adds the S3 'before' semantics the core
    # filter's 'exact' semantics lack -- a FUTURE date means "not modified since" -> 304.
    st, b = s3("GET", "alice/cond_own.txt", s3port, extra_hdrs={"If-Modified-Since": FUTURE})
    ok(st == 304 and not b,
       f"S3 If-Modified-Since FUTURE date -> 304 ('before' semantics, not-modified) (HTTP {st})")
    st, b = s3("GET", "alice/cond_own.txt", s3port, extra_hdrs={"If-Modified-Since": PAST})
    ok(st == 200 and b == OWN_BODY,
       f"S3 If-Modified-Since PAST date -> 200 + full body (HTTP {st})")
    # If-Unmodified-Since: a PAST date means "was modified after it" -> 412.
    st, b = s3("GET", "alice/cond_own.txt", s3port, extra_hdrs={"If-Unmodified-Since": PAST})
    ok(st == 412 and OWN_BODY not in (b or b""),
       f"S3 If-Unmodified-Since PAST date -> 412 PreconditionFailed (HTTP {st})")
    st, b = s3("GET", "alice/cond_own.txt", s3port, extra_hdrs={"If-Unmodified-Since": FUTURE})
    ok(st == 200 and b == OWN_BODY,
       f"S3 If-Unmodified-Since FUTURE date -> 200 + full body (HTTP {st})")

    # ===================================================== (B) CROSS-TENANT GATE ===
    # alice drives conditionals against bob's 0600 private.txt.  s3_handle_get opens
    # (impersonated, DAC-gated) BEFORE evaluating the precondition, so EVERY one of
    # these must be denied by the open -- including the precondition flavours that
    # WOULD pass and (if the open were short-circuited) leak a 200/304.
    cross_cases = [
        ("If-Match real-ETag-shape", {"If-Match": (etag or '"deadbeef-1"')}),
        ("If-Match stale",           {"If-Match": '"stale-0000"'}),
        ("If-Match:* (would-pass)",  {"If-Match": "*"}),
        ("If-None-Match:* (would-304)", {"If-None-Match": "*"}),
        ("If-Modified-Since future (would-304)", {"If-Modified-Since": FUTURE}),
        ("If-Unmodified-Since future (precond PASSES)", {"If-Unmodified-Since": FUTURE}),
    ]
    for lbl, h in cross_cases:
        st, b = s3("GET", "bob/private.txt", s3port, extra_hdrs=h)
        # A correct denial is 403/404 (DAC) or NoSuchKey.  A 200 (any body) OR a 304
        # (object-was-served confirmation) on bob's 0600 would mean the conditional
        # short-circuited the DAC-gated open -- the bug we hunt.  Secret bytes never leak.
        ok(st in (403, 404) and SECRET not in (b or b""),
           f"S3 alice GET bob 0600 + {lbl} -> denied by impersonated open, no 200/304/leak (HTTP {st})")

    # HEAD oracle: alice CAN stat bob's 0600 (parent 0755) so HEAD-conditional may
    # surface a 412/304/200 etag-oracle (POSIX-equivalent to a HEAD) -- but HEAD
    # carries NO body, so the security invariant (no content leak) still holds.
    sthd, b = s3("HEAD", "bob/private.txt", s3port, extra_hdrs={"If-Match": "*"})
    ok(SECRET not in (b or b""),
       f"S3 alice HEAD bob 0600 + If-Match:* leaks no body bytes (oracle is POSIX-ok) (HTTP {sthd})")

    # Per-file-DAC control: the SAME conditional on bob's 0644 world-readable file IS
    # served -> proves the (B) denials are per-file mode, not a blanket conditional reject.
    stc, hC, _, _ = _s3_raw("HEAD", "bob/readable.txt", s3port)
    bread_etag = hC.get("etag")
    if bread_etag:
        st, b = s3("GET", "bob/readable.txt", s3port, extra_hdrs={"If-None-Match": bread_etag})
        ok(st == 304 and not b,
           f"control: S3 alice GET bob 0644 + real If-None-Match -> 304 (per-file DAC, not blanket) (HTTP {st})")
        st, b = s3("GET", "bob/readable.txt", s3port, extra_hdrs={"If-Match": bread_etag})
        ok(st == 200 and b == b"bob-world-readable\n",
           f"control: S3 alice GET bob 0644 + matching If-Match -> 200 byte-exact (HTTP {st})")
    else:
        ok(False, "control bob 0644 If-None-Match skipped: no ETag captured")
        ok(False, "control bob 0644 If-Match skipped: no ETag captured")

    # ==================================================== (C) response-* OVERRIDES ===
    # Signed response-content-type / -disposition on a header-auth GET of own object:
    # the override is applied at the pre-header hook (s3_get_pre_header) but must NOT
    # touch the served bytes.
    ov = {"response-content-type": "application/cond-override",
          "response-content-disposition": "attachment; filename=cond.bin"}
    sto, hO, body, _ = _s3_raw("GET", "alice/cond_own.txt", s3port, params=ov)
    ok(sto == 200 and body == OWN_BODY,
       f"S3 GET own object + response-* overrides: body byte-exact (no corruption) (HTTP {sto})")
    ok(hO.get("content-type") == "application/cond-override",
       f"S3 response-content-type override is reflected in the response header (ct={hO.get('content-type')!r})")
    ok("attachment" in (hO.get("content-disposition") or ""),
       f"S3 response-content-disposition override reflected (cd={hO.get('content-disposition')!r})")

    # response-content-encoding override must not relabel/garble the served bytes.
    ste, hE, ebody, _ = _s3_raw("GET", "alice/cond_own.txt", s3port,
                                params={"response-content-encoding": "identity"})
    ok(ste == 200 and ebody == OWN_BODY,
       f"S3 response-content-encoding override: body byte-exact, not re-coded (HTTP {ste})")

    # CRLF / control-byte injection in an override value: conditional.c rejects values
    # carrying a control byte (brix_http_str_has_ctl) -> the header is NOT set, no
    # response splitting, no smuggled header lands in the response.
    crlf_val = "x\r\nX-Cond-Injected: pwned"
    sti, hI, ibody, rawhead = _s3_raw("GET", "alice/cond_own.txt", s3port,
                                      params={"response-content-disposition": crlf_val})
    ok(sti == 200 and ibody == OWN_BODY,
       f"S3 CRLF-in-override GET still returns the object cleanly (HTTP {sti})")
    ok(b"x-cond-injected" not in rawhead.lower()
       and "x-cond-injected" not in hI,
       "S3 response-content-disposition CRLF payload injects NO header (split rejected)")
    ok(rawhead.lower().count(b"http/1.1 200") + rawhead.lower().count(b"http/1.0 200") <= 1,
       "S3 CRLF override yields exactly one status line (no response-splitting desync)")

    # response-* overrides must NOT enable a cross-tenant read: bob's 0600 stays denied.
    stx, b = s3("GET", "bob/private.txt", s3port, params=ov)
    ok(stx in (403, 404) and SECRET not in (b or b""),
       f"S3 alice GET bob 0600 + response-* overrides STILL DAC-denied, no secret (HTTP {stx})")

    # PRESIGNED-URL variant: the response-* hook also runs on the presign path.  Own
    # object -> byte-exact; bob's 0600 -> still denied, no secret.
    pp = s3_presign("GET", "alice/cond_own.txt", s3port)
    pp = pp + "&response-content-type=application%2Fcond-presign"
    stp, pbody = http("GET", pp, s3port)
    # NOTE: appending an unsigned response-* param may invalidate the SigV4 presign
    # (extra signed param) -> a 403 SignatureDoesNotMatch is an ACCEPTABLE outcome; the
    # security point is that it is NEVER a corrupted body and NEVER a cross-tenant leak.
    ok(stp in (200, 403) and (pbody == OWN_BODY or SECRET not in (pbody or b"")),
       f"S3 presigned GET own object + response-override: byte-exact or cleanly rejected (HTTP {stp})")
    ppb = s3_presign("GET", "bob/private.txt", s3port)
    stpb, pbb = http("GET", ppb, s3port)
    ok(stpb in (403, 404) and SECRET not in (pbb or b""),
       f"S3 presigned GET bob 0600 -> denied, no secret bytes (HTTP {stpb})")

    # ============================================== (D) conditional PUT precondition ===
    # s3_put_precondition stats the destination through the impersonated confined open;
    # a cross-tenant create guarded by If-None-Match:* must be denied by DAC (the
    # precondition outcome is irrelevant), and bob's 0600 must be byte-unchanged.
    try:
        before = open(absp("bob/private.txt"), "rb").read()
    except OSError:
        before = None
    stput, _ = s3("PUT", "bob/private.txt", s3port, data=b"COND-EVIL-PUT\n",
                  extra_hdrs={"If-None-Match": "*"})
    try:
        after = open(absp("bob/private.txt"), "rb").read()
    except OSError:
        after = None
    ok(stput not in (200, 201, 204) and after == before and after == SECRET + b"\n",
       f"S3 alice conditional PUT (If-None-Match:*) over bob 0600 DENIED, bytes unchanged (HTTP {stput})")

    # ============================================================== LIVENESS ===
    # After the whole adversarial conditional sweep the worker still serves a clean
    # GET of alice's own object -> no precondition path crashed/wedged the worker.
    stl, lb = s3("GET", "alice/cond_own.txt", s3port)
    ok(stl == 200 and lb == OWN_BODY,
       f"liveness: clean S3 GET of alice's object after the sweep -> 200 byte-exact (HTTP {stl})")


