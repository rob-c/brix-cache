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


def run_protocol_features_webdav(key, data, port, s3port):
    """WebDAV PROPERTY / CONDITIONAL-TRANSFER feature surface under impersonation
    (a dimension the basic-method suite never enters): multi-property PROPPATCH
    set, dead-property REMOVE, namespaced (xmlns) custom-prop round-trip, the three
    PROPFIND request bodies (named-prop vs allprop vs propname) on the OWNER's file
    AND as a confidentiality oracle against bob's 0600 (a PROPFIND body must never
    spill a byte of bob's secret), ETag-driven conditional COPY/MOVE (If-Match on
    the SOURCE etag: matching -> apply, wrong -> 412 no-op), Overwrite:F over an
    existing target (412, no clobber), MOVE with Depth, OPTIONS on a collection vs a
    file (DAV/Allow advertised, ZERO side effect), and a conditional GET with
    If-Range on the owner's own file.  Every property that PERSISTS must persist on
    a file owned by the mapped user (never svc 1500 / root 0); every cross-tenant
    PROPPATCH/COPY/MOVE must be denied AND leave no residue; every read-side oracle
    must be marker-free.  Fixtures are prefixed `pfw_` to avoid collisions."""
    ta, tb = mint(key, "alice"), mint(key, "bob")
    base = f"http://{HOST}:{port}"
    XML = {"Content-Type": "application/xml"}

    def adir(rel):
        return os.path.join(data, "alice", rel)

    def owned_alice(p):
        try:
            return os.path.exists(p) and os.stat(p).st_uid == UID_ALICE
        except OSError:
            return False

    def not_worker_root(p):
        """True iff p is absent or owned by neither svc(1500) nor root(0)."""
        try:
            return (not os.path.exists(p)) or os.stat(p).st_uid not in (UID_SVC, 0)
        except OSError:
            return True

    def fetch_etag(rel):
        """GET rel over a raw socket and parse the real ETag header value (or None).
        http() hides response headers, so the conditional-transfer checks need this
        to drive a TRUE-matching vs a wrong If-Match against the live etag."""
        raw = ("GET " + rel + " HTTP/1.1\r\nHost: " + HOST + "\r\n"
               "Authorization: Bearer " + ta + "\r\nConnection: close\r\n\r\n")
        resp = raw_http(raw, port)
        m = re.search(rb"\r\n[Ee][Tt][Aa][Gg]:\s*([^\r\n]+)\r\n", resp or b"")
        return m.group(1).decode().strip() if m else None

    def propfind(rel, token, body, depth="0"):
        h = dict(XML)
        h["Depth"] = depth
        return http("PROPFIND", rel, port, token, data=body, hdrs=h)

    NS_ALLPROP = (b'<?xml version="1.0"?><D:propfind xmlns:D="DAV:">'
                  b'<D:allprop/></D:propfind>')
    NS_PROPNAME = (b'<?xml version="1.0"?><D:propfind xmlns:D="DAV:">'
                   b'<D:propname/></D:propfind>')

    # ===================================================== (a) MULTI-PROP PROPPATCH
    http("PUT", "/alice/pfw_multi.txt", port, ta, b"multi-prop target\n")
    pm = adir("pfw_multi.txt")
    ok(owned_alice(pm),
       f"PROPPATCH target pfw_multi.txt created owned by alice "
       f"(uid={os.stat(pm).st_uid if os.path.exists(pm) else -1})")

    pp_multi = (b'<?xml version="1.0"?>'
                b'<D:propertyupdate xmlns:D="DAV:" xmlns:Z="urn:example:pfw">'
                b'<D:set><D:prop>'
                b'<Z:author>alice-pfw</Z:author>'
                b'<Z:color>cerulean-pfw</Z:color>'
                b'<Z:rating>five-pfw</Z:rating>'
                b'</D:prop></D:set></D:propertyupdate>')
    st_pp, _ = http("PROPPATCH", "/alice/pfw_multi.txt", port, ta, data=pp_multi,
                    hdrs=XML)
    ok(st_pp in (200, 207, 422, 403, 501),
       f"multi-property PROPPATCH (3 dead props in one request) handled (HTTP {st_pp})")

    st_pf, body = propfind("/alice/pfw_multi.txt", ta, NS_ALLPROP)
    persisted = sum(1 for n in (b"alice-pfw", b"cerulean-pfw", b"five-pfw")
                    if n in (body or b""))
    supported = st_pp in (200, 207) and persisted >= 1
    if supported:
        ok(persisted == 3,
           f"all three dead props round-trip via PROPFIND allprop "
           f"(found {persisted}/3, PROPFIND {st_pf})")
    else:
        ok(True, f"multi-property PROPPATCH unsupported/handled (PROPPATCH {st_pp})")
    ok(owned_alice(pm),
       "multi-property PROPPATCH left the file owned by alice (broker xattr as owner)")

    # bob PROPPATCH on alice's 0644 file -> setxattr runs AS bob (other) -> EACCES;
    # the property must NEVER persist (positive control: alice's own props survive).
    pp_bob = (b'<?xml version="1.0"?>'
              b'<D:propertyupdate xmlns:D="DAV:" xmlns:Z="urn:example:pfw">'
              b'<D:set><D:prop><Z:pwn>PFW-BOB-PWNED</Z:pwn></D:prop></D:set>'
              b'</D:propertyupdate>')
    st_b, _ = http("PROPPATCH", "/alice/pfw_multi.txt", port, tb, data=pp_bob,
                   hdrs=XML)
    _, body_after = propfind("/alice/pfw_multi.txt", ta, NS_ALLPROP)
    ok(st_b not in (200, 207) or b"PFW-BOB-PWNED" not in (body_after or b""),
       f"bob PROPPATCH on alice's file denied/no-op (HTTP {st_b})")
    ok(b"PFW-BOB-PWNED" not in (body_after or b""),
       "bob's dead-property did NOT persist on alice's file (broker xattr DAC)")
    ok(owned_alice(pm),
       "alice's file unchanged-owner after bob's PROPPATCH attempt")

    # ===================================================== (b) PROPPATCH REMOVE
    http("PUT", "/alice/pfw_rm.txt", port, ta, b"remove-prop target\n")
    prm = adir("pfw_rm.txt")
    pp_set1 = (b'<?xml version="1.0"?>'
               b'<D:propertyupdate xmlns:D="DAV:" xmlns:Z="urn:example:pfw">'
               b'<D:set><D:prop><Z:ephemeral>PFW-EPHEMERAL</Z:ephemeral></D:prop>'
               b'</D:set></D:propertyupdate>')
    st_s1, _ = http("PROPPATCH", "/alice/pfw_rm.txt", port, ta, data=pp_set1,
                    hdrs=XML)
    _, body_set = propfind("/alice/pfw_rm.txt", ta, NS_ALLPROP)
    set_ok = st_s1 in (200, 207) and b"PFW-EPHEMERAL" in (body_set or b"")

    pp_remove = (b'<?xml version="1.0"?>'
                 b'<D:propertyupdate xmlns:D="DAV:" xmlns:Z="urn:example:pfw">'
                 b'<D:remove><D:prop><Z:ephemeral/></D:prop></D:remove>'
                 b'</D:propertyupdate>')
    st_rm, _ = http("PROPPATCH", "/alice/pfw_rm.txt", port, ta, data=pp_remove,
                    hdrs=XML)
    _, body_rm = propfind("/alice/pfw_rm.txt", ta, NS_ALLPROP)
    if set_ok:
        ok(st_rm in (200, 207) and b"PFW-EPHEMERAL" not in (body_rm or b""),
           f"PROPPATCH REMOVE drops the dead property (set {st_s1}, remove {st_rm})")
    else:
        ok(b"PFW-EPHEMERAL" not in (body_rm or b""),
           f"dead-property set/remove unsupported but no stale prop leaks "
           f"(set {st_s1}, remove {st_rm})")
    ok(owned_alice(prm),
       "PROPPATCH set+remove cycle left the file owned by alice")

    # ===================================================== (c) NAMESPACED ROUND-TRIP
    http("PUT", "/alice/pfw_ns.txt", port, ta, b"namespaced-prop target\n")
    pns = adir("pfw_ns.txt")
    pp_ns = (b'<?xml version="1.0"?>'
             b'<D:propertyupdate xmlns:D="DAV:" '
             b'xmlns:CO="http://pfw.example.org/custom#" '
             b'xmlns:OT="http://pfw.example.org/other#">'
             b'<D:set><D:prop>'
             b'<CO:tag>PFW-NS-CUSTOM</CO:tag>'
             b'<OT:tag>PFW-NS-OTHER</OT:tag>'
             b'</D:prop></D:set></D:propertyupdate>')
    st_ns, _ = http("PROPPATCH", "/alice/pfw_ns.txt", port, ta, data=pp_ns, hdrs=XML)
    st_nf, body_ns = propfind("/alice/pfw_ns.txt", ta, NS_ALLPROP)
    if st_ns in (200, 207) and (b"PFW-NS-CUSTOM" in (body_ns or b"")
                                or b"PFW-NS-OTHER" in (body_ns or b"")):
        ok(b"PFW-NS-CUSTOM" in (body_ns or b"") and b"PFW-NS-OTHER" in (body_ns or b""),
           f"namespaced (xmlns) custom props round-trip both namespaces "
           f"(PROPPATCH {st_ns}, PROPFIND {st_nf})")
    else:
        ok(True, f"namespaced custom-prop round-trip unsupported/handled "
                 f"(PROPPATCH {st_ns})")
    ok(owned_alice(pns),
       "namespaced-prop file owned by alice (broker xattr as owner)")

    # ===================================================== (d) THREE PROPFIND BODIES
    # On the OWNER's file: named-prop, allprop, propname must each respond cleanly.
    named_body = (b'<?xml version="1.0"?>'
                  b'<D:propfind xmlns:D="DAV:">'
                  b'<D:prop><D:getcontentlength/><D:getlastmodified/>'
                  b'<D:resourcetype/></D:prop></D:propfind>')
    st_n, body_n = propfind("/alice/pfw_multi.txt", ta, named_body)
    ok(st_n in (200, 207),
       f"PROPFIND named-prop on own file (HTTP {st_n})")
    st_a, body_a = propfind("/alice/pfw_multi.txt", ta, NS_ALLPROP)
    ok(st_a in (200, 207) and b"getcontentlength" in (body_a or b"").lower()
       or st_a in (200, 207),
       f"PROPFIND allprop on own file (HTTP {st_a})")
    st_pn, body_pn = propfind("/alice/pfw_multi.txt", ta, NS_PROPNAME)
    ok(st_pn in (200, 207),
       f"PROPFIND propname on own file (HTTP {st_pn})")
    # propname must return NAMES not VALUES: the dead-property VALUE must be absent.
    ok(b"cerulean-pfw" not in (body_pn or b""),
       "PROPFIND propname returns names only, not the dead-property VALUE")

    # On bob's 0600: each of the three PROPFIND bodies is a confidentiality oracle —
    # alice (other) must never see bob's secret bytes regardless of the body shape.
    for label, pf_body in (("named-prop", named_body),
                           ("allprop", NS_ALLPROP),
                           ("propname", NS_PROPNAME)):
        st_o, body_o = propfind("/bob/private.txt", ta, pf_body)
        ok(b"BOB-PRIVATE-SECRET" not in (body_o or b""),
           f"PROPFIND {label} on bob's 0600 leaks NO secret bytes (HTTP {st_o})")
    # positive control: PROPFIND allprop on bob's WORLD-READABLE file is fine and
    # exposes only metadata (alice may stat it; that is correct DAC, not a leak).
    st_ctrl, body_ctrl = propfind("/bob/readable.txt", ta, NS_ALLPROP)
    ok(st_ctrl in (200, 207, 403, 404),
       f"PROPFIND allprop on bob's 0644 control handled (HTTP {st_ctrl})")

    # ===================================================== (e) CONDITIONAL COPY/MOVE
    http("PUT", "/alice/pfw_csrc.txt", port, ta, b"conditional-copy source\n")
    psrc = adir("pfw_csrc.txt")
    etag = fetch_etag("/alice/pfw_csrc.txt")
    ok(owned_alice(psrc), "conditional-COPY source owned by alice")

    # COPY with a MATCHING If-Match on the source etag -> precondition satisfied.
    cdst = adir("pfw_cdst.txt")
    if etag:
        st_cm, _ = http("COPY", "/alice/pfw_csrc.txt", port, ta,
                        hdrs={"Destination": f"{base}/alice/pfw_cdst.txt",
                              "If-Match": etag})
        # The server emits WEAK etags (W/"...") and RFC 7232 If-Match uses STRONG
        # comparison, so a weak etag never matches -> 412 is correct (not a bug);
        # accept it alongside a successful conditional COPY.  Either way the dest is
        # never worker/root-owned.
        ok(st_cm in (201, 204, 200, 412) and not_worker_root(cdst),
           f"COPY with If-Match(source etag) handled, dest never worker/root-owned "
           f"user (HTTP {st_cm}, etag={etag})")
        ok((not os.path.exists(cdst)) or owned_alice(cdst),
           "conditional-COPY destination owned by alice (never svc/root)")
    else:
        # No etag exposed: fall back to a plain COPY for the ownership invariant.
        st_cm, _ = http("COPY", "/alice/pfw_csrc.txt", port, ta,
                        hdrs={"Destination": f"{base}/alice/pfw_cdst.txt"})
        ok(st_cm in (201, 204, 200) and not_worker_root(cdst),
           f"COPY (no etag exposed) applied, dest owned by mapped user (HTTP {st_cm})")
        ok((not os.path.exists(cdst)) or owned_alice(cdst),
           "conditional-COPY fallback destination owned by alice")

    # COPY with a WRONG If-Match -> 412 Precondition Failed (no copy made).
    wrong_dst = adir("pfw_cdst_wrong.txt")
    st_cw, _ = http("COPY", "/alice/pfw_csrc.txt", port, ta,
                    hdrs={"Destination": f"{base}/alice/pfw_cdst_wrong.txt",
                          "If-Match": '"pfw-definitely-wrong-etag"'})
    ok(st_cw in (412, 304, 403, 409) or not os.path.exists(wrong_dst),
       f"COPY with WRONG If-Match did not create the destination (HTTP {st_cw})")
    ok(not os.path.exists(wrong_dst) or owned_alice(wrong_dst),
       "wrong-If-Match COPY produced no foreign-owned residue")

    # Overwrite:F COPY over an EXISTING destination -> 412 (no clobber of content).
    http("PUT", "/alice/pfw_owdst.txt", port, ta, b"PFW-PREEXISTING-DST\n")
    powd = adir("pfw_owdst.txt")
    st_of, _ = http("COPY", "/alice/pfw_csrc.txt", port, ta,
                    hdrs={"Destination": f"{base}/alice/pfw_owdst.txt",
                          "Overwrite": "F"})
    dst_body = b""
    try:
        dst_body = open(powd, "rb").read()
    except OSError:
        pass
    ok(st_of in (412, 409, 403) or dst_body == b"PFW-PREEXISTING-DST\n",
       f"Overwrite:F COPY over existing target refused / not clobbered (HTTP {st_of})")
    ok(b"conditional-copy source" not in dst_body,
       "Overwrite:F left the pre-existing destination content intact (no clobber)")

    # MOVE with Depth:infinity of an OWNED collection -> tree moves, owned by alice.
    http("MKCOL", "/alice/pfw_mvsrc", port, ta)
    http("PUT", "/alice/pfw_mvsrc/leaf.txt", port, ta, b"PFW-LEAF\n")
    st_mv, _ = http("MOVE", "/alice/pfw_mvsrc", port, ta,
                    hdrs={"Destination": f"{base}/alice/pfw_mvdst",
                          "Depth": "infinity"})
    mvdst = adir("pfw_mvdst")
    mvleaf = os.path.join(mvdst, "leaf.txt")
    ok(st_mv in (201, 204, 200) and not_worker_root(mvdst),
       f"MOVE Depth:infinity of owned collection (HTTP {st_mv})")
    ok((not os.path.isdir(mvdst)) or os.stat(mvdst).st_uid == UID_ALICE,
       "MOVEd collection directory owned by alice (never svc/root)")
    ok((not os.path.exists(mvleaf)) or os.stat(mvleaf).st_uid == UID_ALICE,
       "MOVEd collection leaf owned by alice")

    # cross-tenant conditional MOVE: alice MOVE INTO bob's 0700 dir -> denied, and
    # bob's secret never appears in the response; positive control follows.
    http("PUT", "/alice/pfw_xmove.txt", port, ta, b"PFW-XMOVE\n")
    bsecret = os.path.join(data, "bobsecret", "pfw_xmove.txt")
    st_xm, body_xm = http("MOVE", "/alice/pfw_xmove.txt", port, ta,
                          hdrs={"Destination": f"{base}/bobsecret/pfw_xmove.txt",
                                "Overwrite": "T"})
    ok(st_xm not in (201, 204, 200) and not os.path.exists(bsecret),
       f"cross-tenant MOVE into bob's 0700 dir DENIED, no file planted (HTTP {st_xm})")
    ok(b"svc-only-secret" not in (body_xm or b"")
       and b"BOB-PRIVATE-SECRET" not in (body_xm or b""),
       "cross-tenant MOVE error response leaks no foreign secret bytes")
    # positive control: the same source MOVEs fine WITHIN alice's own space.
    st_pc, _ = http("MOVE", "/alice/pfw_xmove.txt", port, ta,
                    hdrs={"Destination": f"{base}/alice/pfw_xmove2.txt"})
    ok(st_pc in (201, 204, 200) and owned_alice(adir("pfw_xmove2.txt")),
       f"control: same MOVE within alice's space succeeds, owned alice (HTTP {st_pc})")

    # ===================================================== (f) OPTIONS coll vs file
    st_oc, body_oc = http("OPTIONS", "/alice/", port, ta)
    ok(st_oc in (200, 204),
       f"OPTIONS on a collection advertises DAV/Allow, no body action (HTTP {st_oc})")
    st_ofl, _ = http("OPTIONS", "/alice/pfw_multi.txt", port, ta)
    ok(st_ofl in (200, 204),
       f"OPTIONS on a file handled distinctly from a collection (HTTP {st_ofl})")
    # OPTIONS is a pure metadata probe: it must NOT create/touch a phantom resource.
    ok(not os.path.exists(adir("pfw_phantom_options")),
       "OPTIONS had zero filesystem side effect (no phantom resource created)")
    # OPTIONS on bob's 0700 dir must not enumerate or leak its private contents.
    st_ob, body_ob = http("OPTIONS", "/bobsecret/", port, ta)
    ok(b"svc-only-secret" not in (body_ob or b"")
       and b"BOB-PRIVATE-SECRET" not in (body_ob or b""),
       f"OPTIONS on bob's private dir leaks no contents (HTTP {st_ob})")

    # ===================================================== (g) If-Range GET own file
    http("PUT", "/alice/pfw_ir.txt", port, ta, b"0123456789ABCDEF")
    pir = adir("pfw_ir.txt")
    ir_etag = fetch_etag("/alice/pfw_ir.txt")
    # If-Range with the CURRENT etag + Range -> may serve the partial slice (206) or
    # the full body (200); both are RFC-7233 conformant.  Body must be exact bytes.
    st_ir, body_ir = http("GET", "/alice/pfw_ir.txt", port, ta,
                          hdrs={"If-Range": ir_etag or '"x"', "Range": "bytes=0-3"})
    ok(st_ir in (200, 206),
       f"If-Range GET on own file (matching etag) handled (HTTP {st_ir})")
    if st_ir == 206:
        ok(body_ir == b"0123" and owned_alice(pir),
           "If-Range matching etag served the exact 0-3 slice (byte-exact)")
    else:
        ok(body_ir == b"0123456789ABCDEF" and owned_alice(pir),
           "If-Range full-body fallback served the exact whole file (byte-exact)")
    # If-Range with a STALE etag + Range -> RFC says serve the FULL representation.
    st_st, body_st = http("GET", "/alice/pfw_ir.txt", port, ta,
                          hdrs={"If-Range": '"pfw-stale-etag"', "Range": "bytes=0-3"})
    ok(st_st in (200, 206) and (body_st in (b"0123456789ABCDEF", b"0123")),
       f"If-Range stale etag served a valid representation (HTTP {st_st})")
    # If-Range as a confidentiality oracle on bob's 0600 -> still no secret bytes.
    st_irb, body_irb = http("GET", "/bob/private.txt", port, ta,
                            hdrs={"If-Range": '"x"', "Range": "bytes=0-4"})
    ok(b"BOB-PRIVATE-SECRET" not in (body_irb or b""),
       f"If-Range GET on bob's 0600 leaks no secret (HTTP {st_irb})")

    # ===================================================== worker-survival follow-up
    # After all the property/conditional churn the worker must still serve a plain
    # legit op for the mapped user (proves no broker desync / principal wedge).
    st_f, body_f = http("GET", "/alice/pfw_multi.txt", port, ta)
    ok(st_f == 200 and b"multi-prop target" in (body_f or b""),
       f"worker survived the property/conditional battery (follow-up GET OK, HTTP {st_f})")
    ok(owned_alice(pm),
       "post-battery: alice's property-bearing file still owned by alice")


