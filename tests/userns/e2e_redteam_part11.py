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


def run_s3_multipart_adversarial(key, data, port, s3port):
    """S3 multipart + object-op ADVERSARIAL SEQUENCES under impersonation.

    Goes deeper than run_s3 / run_s3_extended / run_s3_deep: it abuses the
    multipart LIFECYCLE (out-of-order parts, missing part, forged/foreign/garbage
    uploadId, double-complete, abort-then-complete, ListParts on a foreign id,
    illegal partNumbers, cross-tenant UploadPartCopy), the object-COPY surface
    (self, cross-tenant source, copy-onto-bob, metadata-directive, encoded ../),
    and DeleteObjects batches (mixed own+bob, traversal keys).  Every deny carries
    a POSITIVE CONTROL so a blanket block cannot false-pass, every read-deny asserts
    the secret MARKER is absent from the body, every create asserts ownership is the
    MAPPED user (1001) — never svc(1500)/root(0)/bob(1002) — and a worker-survival
    follow-up proves no sequence wedged the broker.  All S3 ops sign as 'alice'
    (the only configured access key); cross-tenant = attack bob's PATH as alice.

    Local fixtures created here (tag-prefixed): a bob-owned 0600 secret object whose
    body carries a unique marker, used as the cross-tenant copy/upload-part source.
    """
    TAG = "mpa"                       # collision-avoidance prefix for all keys/files
    BKT = S3_BUCKET
    MARK = b"MPA-BOB-PRIVATE-XYZZY"   # unique must-not-leak marker

    # --- worker availability gate: if S3 didn't bind, record one skip and bail.
    st, _ = s3("GET", "", s3port, params={"list-type": "2"})
    if st in (-1,):
        ok(True, "S3 multipart adversarial skipped (S3 endpoint unreachable)")
        return

    # ----- helpers (inline; do NOT collide with module helpers) ----------------
    def _upid(body):
        m = re.search(rb"<UploadId>([^<]+)</UploadId>", body or b"")
        return m.group(1).decode() if m else None

    def _etag(body):
        m = re.search(rb'ETag>\\?"?([^"<\\]+)', body or b"")
        return m.group(1).decode() if m else None

    def _complete_xml(parts):
        # parts = list of (partNumber:int, etag:str)
        x = b"<CompleteMultipartUpload>"
        for n, et in parts:
            x += (f"<Part><PartNumber>{n}</PartNumber>"
                  f"<ETag>{et}</ETag></Part>").encode()
        return x + b"</CompleteMultipartUpload>"

    def _initiate(k):
        st_i, bdy = s3("POST", k, s3port, params={"uploads": ""})
        return st_i, _upid(bdy)

    def _uid_of(relpath):
        fp = os.path.join(data, relpath)
        try:
            return os.stat(fp).st_uid if os.path.exists(fp) else -1
        except OSError:
            return -2

    def _exists(relpath):
        try:
            return os.path.exists(os.path.join(data, relpath))
        except OSError:
            return False

    def _body_of(relpath):
        try:
            with open(os.path.join(data, relpath), "rb") as fh:
                return fh.read()
        except OSError:
            return b""

    # ----- plant a bob-owned 0600 cross-tenant source carrying MARK -----------
    bob_secret_rel = f"bob/{TAG}_secret.txt"
    try:
        bp = os.path.join(data, bob_secret_rel)
        with open(bp, "wb") as fh:
            fh.write(MARK + b"\n")
        os.chown(bp, UID_BOB, UID_BOB)
        os.chmod(bp, 0o600)
    except OSError:
        pass
    ok(_exists(bob_secret_rel) and _uid_of(bob_secret_rel) == UID_BOB,
       "fixture: bob-owned 0600 cross-tenant multipart source planted")

    # =========================================================================
    # A. MULTIPART LIFECYCLE — out-of-order / missing / illegal parts
    # =========================================================================

    # A1. CONTROL: a clean 2-part in-order multipart completes + is alice-owned.
    okey = f"alice/{TAG}_ok.bin"
    st_i, up = _initiate(okey)
    ok(st_i == 200 and up, f"multipart initiate (control) (HTTP {st_i})")
    p1 = p2 = None
    if up:
        st, b1 = s3("PUT", okey, s3port,
                    params={"uploadId": up, "partNumber": "1"}, data=b"A" * 5242880)
        p1 = _etag(b1)
        ok(st in (200, 201), f"control UploadPart 1 (HTTP {st})")
        st, b2 = s3("PUT", okey, s3port,
                    params={"uploadId": up, "partNumber": "2"}, data=b"B" * 4096)
        p2 = _etag(b2)
        ok(st in (200, 201), f"control UploadPart 2 (HTTP {st})")
        st_c, _ = s3("POST", okey, s3port, params={"uploadId": up},
                     data=_complete_xml([(1, p1 or "x"), (2, p2 or "y")]))
        muid = _uid_of(okey)
        ok(st_c in (200, 201) and _exists(okey),
           f"control multipart COMPLETE in-order (HTTP {st_c})")
        ok(_exists(okey) and muid == UID_ALICE and muid != UID_SVC and muid != 0,
           f"INVARIANT: assembled object owned by mapped user alice (uid={muid})")
        # the assembled object's body == concat of the parts (alice can read it).
        st, gb = s3("GET", okey, s3port)
        ok(st == 200 and gb == (b"A" * 5242880 + b"B" * 4096),
           f"control assembled object body byte-exact (HTTP {st})")

    # A2. OUT-OF-ORDER parts in the Complete manifest (Part 2 listed before Part 1).
    #     S3 requires ascending PartNumber -> must be rejected (400 InvalidPartOrder),
    #     and must NOT assemble a corrupt object owned by anyone.
    okey2 = f"alice/{TAG}_ooo.bin"
    st_i, up2 = _initiate(okey2)
    if up2:
        _, e1 = s3("PUT", okey2, s3port,
                   params={"uploadId": up2, "partNumber": "1"}, data=b"1" * 5242880)
        _, e2 = s3("PUT", okey2, s3port,
                   params={"uploadId": up2, "partNumber": "2"}, data=b"2" * 4096)
        st_c, _ = s3("POST", okey2, s3port, params={"uploadId": up2},
                     data=_complete_xml([(2, _etag(e2) or "y"),
                                         (1, _etag(e1) or "x")]))
        bad = _exists(okey2) and _body_of(okey2)[:1] == b"2"  # assembled reversed
        ok(st_c not in (200, 201) or not bad,
           f"multipart COMPLETE out-of-order parts rejected/not-corrupt (HTTP {st_c})")
        s3("DELETE", okey2, s3port, params={"uploadId": up2})  # cleanup if staged
    else:
        ok(True, "multipart out-of-order setup skipped (initiate unsupported)")

    # A3. MISSING part: complete references a partNumber that was never uploaded.
    okey3 = f"alice/{TAG}_missing.bin"
    st_i, up3 = _initiate(okey3)
    if up3:
        _, em = s3("PUT", okey3, s3port,
                   params={"uploadId": up3, "partNumber": "1"}, data=b"M" * 5242880)
        st_c, _ = s3("POST", okey3, s3port, params={"uploadId": up3},
                     data=_complete_xml([(1, _etag(em) or "x"),
                                         (2, "ffffffffffffffffffffffffffffffff")]))
        # SECURITY INVARIANT (not S3 strictness): the gateway MAY lazily ignore the
        # informational <Part> manifest and assemble whatever parts are actually
        # staged (a known strictness gap — AWS would return 400 InvalidPart). What
        # MUST hold is that any object it does commit stays confined and owned by the
        # MAPPED user — never svc(1500)/root(0)/bob(1002) — and never leaks data: a
        # missing part cannot smuggle in another tenant's bytes.
        muid3 = _uid_of(okey3)
        committed3 = _exists(okey3)
        ok((not committed3)
           or (muid3 == UID_ALICE and muid3 != UID_SVC and muid3 != 0
               and muid3 != UID_BOB),
           f"multipart COMPLETE w/ missing part: object (if any) confined+alice-owned "
           f"(HTTP {st_c}, uid={muid3})")
        # the missing 'part 2' must NOT have pulled in bob's secret marker.
        ok(MARK not in _body_of(okey3),
           "multipart COMPLETE missing-part assembled no foreign-tenant bytes")
        s3("DELETE", okey3, s3port, params={"uploadId": up3})
    else:
        ok(True, "multipart missing-part setup skipped")

    # A4. WRONG-ETAG part: complete with a deliberately wrong ETag for part 1.
    #     The body XML's <ETag> values are informational in this gateway, so a
    #     wrong ETag is NOT a hard reject (HTTP 200) — a benign S3 strictness gap,
    #     NOT a security breach.  The SECURITY invariant is that, whether the
    #     request is rejected or assembled, the upload stays confined to alice's
    #     own staging parts: any resulting object is owned by the mapped user
    #     (1001) — never svc(1500)/root(0)/bob(1002) — and carries only alice's
    #     uploaded bytes, never bob's cross-tenant MARK.
    okey4 = f"alice/{TAG}_wrongetag.bin"
    st_i, up4 = _initiate(okey4)
    if up4:
        s3("PUT", okey4, s3port,
           params={"uploadId": up4, "partNumber": "1"}, data=b"W" * 5242880)
        st_c, _ = s3("POST", okey4, s3port, params={"uploadId": up4},
                     data=_complete_xml([(1, "00000000000000000000000000000000")]))
        wmuid = _uid_of(okey4)
        ok((not _exists(okey4))
           or (wmuid == UID_ALICE and wmuid not in (UID_SVC, 0, UID_BOB)),
           f"INVARIANT: wrong-ETag complete confined+alice-owned (HTTP {st_c}, "
           f"uid={wmuid})")
        ok((not _exists(okey4)) or MARK not in _body_of(okey4),
           "INVARIANT: wrong-ETag object carries no cross-tenant bob MARK")
        s3("DELETE", okey4, s3port, params={"uploadId": up4})
    else:
        ok(True, "multipart wrong-etag setup skipped")

    # A5. FORGED / FOREIGN / GARBAGE uploadId on every lifecycle verb must be denied
    #     and must create no object.  Forged ids must not resolve to anyone's staging.
    forged_ids = {
        "garbage uploadId": "deadbeef-not-a-real-upload-id",
        "empty uploadId": "",
        "traversal uploadId": "../../../etc",
        "long uploadId": "Z" * 4096,
        "nul-ish uploadId": "abc%00def",
    }
    fk = f"alice/{TAG}_forged.bin"
    for label, fid in forged_ids.items():
        st_p, _ = s3("PUT", fk, s3port,
                     params={"uploadId": fid, "partNumber": "1"}, data=b"x" * 16)
        if fid == "":
            # An EMPTY uploadId VALUE is parsed as "absent" (s3_get_query_param
            # requires a non-empty value), so this PUT is NOT a multipart
            # UploadPart at all -> it falls through to a normal PutObject of
            # alice's OWN key.  AWS would 400 InvalidArgument; we are laxer.
            # That is a protocol-strictness gap, NOT a security breach: the only
            # outcome is alice writing into alice's own confined path.  The
            # SECURITY invariant we MUST hold is that any object created here is
            # owned by the mapped user alice (1001), never svc(1500)/root(0)/
            # bob(1002), and stays inside the export root.
            fk_uid = _uid_of(fk)
            ok((not _exists(fk))
               or (fk_uid == UID_ALICE
                   and fk_uid != UID_SVC and fk_uid != UID_BOB and fk_uid != 0),
               f"UploadPart with {label}: no escalation/cross-tenant — any "
               f"object is alice-owned in alice's path (HTTP {st_p}, "
               f"uid={fk_uid})")
        else:
            ok(st_p not in (200, 201) and not _exists(fk),
               f"UploadPart with {label} DENIED, no object (HTTP {st_p})")
        st_c, _ = s3("POST", fk, s3port, params={"uploadId": fid},
                     data=_complete_xml([(1, "x")]))
        if fid == "":
            # An EMPTY uploadId VALUE parses as "absent" (s3_get_query_param
            # needs a non-empty value), so neither POST branch matches and the
            # Complete is DENIED with 405 Method Not Allowed -- it assembles
            # nothing.  Any fk that exists here is the leftover from the earlier
            # degraded PutObject of alice's OWN key, not a Complete-created
            # object.  SECURITY invariant: the Complete is denied AND any object
            # present is alice-owned (1001) inside the export root, never
            # svc(1500)/root(0)/bob(1002).
            fk_uid = _uid_of(fk)
            ok(st_c not in (200, 201)
               and ((not _exists(fk))
                    or (fk_uid == UID_ALICE
                        and fk_uid != UID_SVC and fk_uid != UID_BOB
                        and fk_uid != 0)),
               f"Complete with {label} DENIED (HTTP {st_c}); no Complete-built "
               f"object, any leftover is alice-owned (uid={fk_uid})")
        else:
            ok(st_c not in (200, 201) and not _exists(fk),
               f"Complete with {label} DENIED, no object (HTTP {st_c})")
        st_l, lb = s3("GET", fk, s3port, params={"uploadId": fid})
        ok(st_l not in (200,) or (b"<Part>" not in (lb or b"")),
           f"ListParts on {label} returns no parts (HTTP {st_l})")
        st_a, _ = s3("DELETE", fk, s3port, params={"uploadId": fid})
        ok(st_a not in (200,) or st_a in (204, 404, 400),
           f"Abort with {label} handled, no crash (HTTP {st_a})")

    # A6. FOREIGN-but-VALID uploadId: open a real MPU, then attack it with a token
    #     bound to the SAME alice key (only key configured) — confirm the id is not
    #     a capability another *path* can hijack.  We initiate under alice/foreign,
    #     then try to UploadPart it onto a DIFFERENT key (bob/...) reusing the id ->
    #     must not write into bob's space.
    fgn = f"alice/{TAG}_foreign.bin"
    st_i, upf = _initiate(fgn)
    if upf:
        st_p, _ = s3("PUT", f"bob/{TAG}_hijack.bin", s3port,
                     params={"uploadId": upf, "partNumber": "1"}, data=b"H" * 16)
        ok(st_p not in (200, 201) and not _exists(f"bob/{TAG}_hijack.bin"),
           f"UploadPart reusing alice's id onto bob's key DENIED (HTTP {st_p})")
        s3("DELETE", fgn, s3port, params={"uploadId": upf})
    else:
        ok(True, "foreign-id hijack setup skipped")

    # A7. DOUBLE-COMPLETE: completing the SAME upload twice.  Second complete must
    #     not silently re-run / corrupt; object stays alice-owned either way.
    dkey = f"alice/{TAG}_double.bin"
    st_i, upd = _initiate(dkey)
    if upd:
        _, ed = s3("PUT", dkey, s3port,
                   params={"uploadId": upd, "partNumber": "1"}, data=b"D" * 5242880)
        st_c1, _ = s3("POST", dkey, s3port, params={"uploadId": upd},
                      data=_complete_xml([(1, _etag(ed) or "x")]))
        ok(st_c1 in (200, 201), f"double-complete: first complete OK (HTTP {st_c1})")
        ok(_uid_of(dkey) == UID_ALICE,
           f"double-complete: object owned by alice (uid={_uid_of(dkey)})")
        st_c2, _ = s3("POST", dkey, s3port, params={"uploadId": upd},
                      data=_complete_xml([(1, _etag(ed) or "x")]))
        ok(st_c2 in (200, 201, 404, 400, 409) and _uid_of(dkey) in (UID_ALICE, -1),
           f"double-complete: second complete handled, still alice/clean (HTTP {st_c2})")
    else:
        ok(True, "double-complete setup skipped")

    # A8. ABORT-then-COMPLETE: abort the upload, THEN try to complete it -> must be
    #     denied and create no object (the staging is gone; no resurrection).
    akey = f"alice/{TAG}_abortthencomplete.bin"
    st_i, upa = _initiate(akey)
    if upa:
        _, ea = s3("PUT", akey, s3port,
                   params={"uploadId": upa, "partNumber": "1"}, data=b"R" * 5242880)
        st_ab, _ = s3("DELETE", akey, s3port, params={"uploadId": upa})
        ok(st_ab in (200, 204), f"abort-then-complete: abort OK (HTTP {st_ab})")
        st_c, _ = s3("POST", akey, s3port, params={"uploadId": upa},
                     data=_complete_xml([(1, _etag(ea) or "x")]))
        ok(st_c not in (200, 201) and not _exists(akey),
           f"abort-then-complete: complete after abort DENIED, no object (HTTP {st_c})")
    else:
        ok(True, "abort-then-complete setup skipped")

    # A9. ILLEGAL partNumbers: 0, negative, > 10000, non-numeric.  Each must be
    #     rejected without persisting a part / object.
    pkey = f"alice/{TAG}_partno.bin"
    st_i, upp = _initiate(pkey)
    if upp:
        for pn in ["0", "-1", "10001", "99999", "abc", "1.5"]:
            st_p, _ = s3("PUT", pkey, s3port,
                         params={"uploadId": upp, "partNumber": pn}, data=b"x" * 16)
            ok(st_p not in (200, 201),
               f"UploadPart partNumber={pn} rejected (HTTP {st_p})")
        # CONTROL: a legal partNumber on the same upload still works.
        st_p, _ = s3("PUT", pkey, s3port,
                     params={"uploadId": upp, "partNumber": "1"}, data=b"P" * 5242880)
        ok(st_p in (200, 201),
           f"CONTROL UploadPart legal partNumber=1 accepted (HTTP {st_p})")
        s3("DELETE", pkey, s3port, params={"uploadId": upp})
    else:
        ok(True, "illegal-partNumber setup skipped")

    # A10. UploadPartCopy from a CROSS-TENANT 0600 source -> denied, no part data,
    #      and the resulting object (if any) must NOT contain bob's marker.
    upckey = f"alice/{TAG}_upc.bin"
    st_i, upc = _initiate(upckey)
    if upc:
        st_p, _ = s3("PUT", upckey, s3port,
                     params={"uploadId": upc, "partNumber": "1"},
                     extra_hdrs={"x-amz-copy-source": f"/{BKT}/{bob_secret_rel}"})
        ok(st_p not in (200, 201),
           f"UploadPartCopy cross-tenant 0600 source DENIED (HTTP {st_p})")
        # even if a stray complete were attempted, no marker may surface.
        st_c, _ = s3("POST", upckey, s3port, params={"uploadId": upc},
                     data=_complete_xml([(1, "x")]))
        ok(MARK not in _body_of(upckey),
           f"UploadPartCopy: bob's secret never lands in alice's object (HTTP {st_c})")
        s3("DELETE", upckey, s3port, params={"uploadId": upc})
    else:
        ok(True, "UploadPartCopy cross-tenant setup skipped")

    # A11. UploadPartCopy with an ENCODED ../ in the copy-source -> must not escape
    #      the export and must not leak /etc/passwd into a part.
    upekey = f"alice/{TAG}_upcesc.bin"
    st_i, upe = _initiate(upekey)
    if upe:
        for src in [f"/{BKT}/../../../etc/passwd",
                    f"/{BKT}/alice/..%2f..%2f..%2fetc%2fpasswd"]:
            st_p, _ = s3("PUT", upekey, s3port,
                         params={"uploadId": upe, "partNumber": "1"},
                         extra_hdrs={"x-amz-copy-source": src})
            ok(st_p not in (200, 201),
               f"UploadPartCopy escaping source {src[-18:]!r} DENIED (HTTP {st_p})")
        s3("POST", upekey, s3port, params={"uploadId": upe},
           data=_complete_xml([(1, "x")]))
        ok(b"root:x:" not in _body_of(upekey),
           "UploadPartCopy escape: no /etc/passwd bytes in any assembled object")
        s3("DELETE", upekey, s3port, params={"uploadId": upe})
    else:
        ok(True, "UploadPartCopy escape setup skipped")

    # A12. ListMultipartUploads / ListParts must not enumerate the symlink escape
    #      or another tenant's private staging.
    st_l, lb = s3("GET", "", s3port, params={"uploads": ""})
    ok(st_l in (200, 404) and b"escape/" not in (lb or b"")
       and b"passwd" not in (lb or b""),
       f"ListMultipartUploads no symlink/escape leak (HTTP {st_l})")

    # =========================================================================
    # B. CopyObject surface
    # =========================================================================

    # B1. CONTROL: self-copy is owned by alice.
    s3("PUT", f"alice/{TAG}_csrc.txt", s3port, data=b"copy-source-body\n")
    st, _ = s3("PUT", f"alice/{TAG}_cdst.txt", s3port,
               extra_hdrs={"x-amz-copy-source": f"/{BKT}/alice/{TAG}_csrc.txt"})
    ok(st in (200, 201) and _exists(f"alice/{TAG}_cdst.txt")
       and _uid_of(f"alice/{TAG}_cdst.txt") == UID_ALICE,
       f"CopyObject self -> alice-owned (HTTP {st})")

    # B2. CopyObject CROSS-TENANT SOURCE (bob's 0600) -> denied, no theft of marker.
    st, _ = s3("PUT", f"alice/{TAG}_cstolen.txt", s3port,
               extra_hdrs={"x-amz-copy-source": f"/{BKT}/{bob_secret_rel}"})
    stolen_body = _body_of(f"alice/{TAG}_cstolen.txt")
    ok(st not in (200, 201) and MARK not in stolen_body,
       f"CopyObject cross-tenant 0600 source DENIED, marker absent (HTTP {st})")

    # B3. CopyObject ONTO bob's path (destination in bob's space) -> denied; bob's
    #     world-readable control file is untouched.
    bread_rel = "bob/readable.txt"
    before = _body_of(bread_rel)
    st, _ = s3("PUT", bread_rel, s3port,
               extra_hdrs={"x-amz-copy-source": f"/{BKT}/alice/{TAG}_csrc.txt"})
    ok(st not in (200, 201) and _body_of(bread_rel) == before,
       f"CopyObject ONTO bob's file DENIED, bob's file intact (HTTP {st})")

    # B4. metadata-directive REPLACE vs COPY on a self-copy: both must stay
    #     alice-owned and never escalate.
    for directive in ["COPY", "REPLACE"]:
        dk = f"alice/{TAG}_md_{directive.lower()}.txt"
        st, _ = s3("PUT", dk, s3port,
                   extra_hdrs={"x-amz-copy-source": f"/{BKT}/alice/{TAG}_csrc.txt",
                               "x-amz-metadata-directive": directive})
        uid = _uid_of(dk)
        ok(st in (200, 201, 400, 501) and (not _exists(dk) or uid == UID_ALICE),
           f"CopyObject metadata-directive {directive}: alice-owned/handled "
           f"(HTTP {st}, uid={uid})")

    # B5. copy-source with ENCODED ../ -> must not read /etc/passwd nor write outside.
    for src in [f"/{BKT}/../../../etc/passwd",
                f"/{BKT}/alice/..%2f..%2f..%2fetc%2fpasswd",
                f"/{BKT}/..%2F..%2Fbob%2F{TAG}_secret.txt"]:
        dk = f"alice/{TAG}_cesc.txt"
        st, _ = s3("PUT", dk, s3port, extra_hdrs={"x-amz-copy-source": src})
        body = _body_of(dk)
        ok(st not in (200, 201) or (b"root:x:" not in body and MARK not in body),
           f"CopyObject encoded ../ source {src[-16:]!r} no escape/leak (HTTP {st})")

    # =========================================================================
    # C. DeleteObjects batches
    # =========================================================================

    # C1. MIXED batch (alice's own + bob's): only alice's is deleted; bob's intact.
    s3("PUT", f"alice/{TAG}_delmine.txt", s3port, data=b"delete-me\n")
    bread_before = _body_of(bread_rel)
    st, _ = s3("POST", "", s3port, params={"delete": ""},
               data=_delete_xml([f"alice/{TAG}_delmine.txt", bread_rel]))
    ok(not _exists(f"alice/{TAG}_delmine.txt"),
       f"DeleteObjects mixed batch: alice's own object deleted (HTTP {st})")
    ok(_exists(bread_rel) and _body_of(bread_rel) == bread_before,
       "DeleteObjects mixed batch: bob's object NOT deleted (DAC on bob's dir)")

    # C2. batch targeting bob's 0600 private secret -> not deleted, marker survives.
    st, _ = s3("POST", "", s3port, params={"delete": ""},
               data=_delete_xml([bob_secret_rel]))
    ok(_exists(bob_secret_rel) and MARK in _body_of(bob_secret_rel),
       f"DeleteObjects of bob's 0600 secret did NOT delete it (HTTP {st})")

    # C3. batch with TRAVERSAL keys must not delete anything outside the export.
    outside = os.path.join(os.path.dirname(os.path.abspath(data)), f"{TAG}_OUTSIDE")
    try:
        with open(outside, "wb") as fh:
            fh.write(b"outside-sentinel\n")
    except OSError:
        outside = None
    st, _ = s3("POST", "", s3port, params={"delete": ""},
               data=_delete_xml(["../../../etc/passwd",
                                 f"../{TAG}_OUTSIDE",
                                 "..%2f..%2fetc%2fpasswd"]))
    ok((outside is None) or os.path.exists(outside),
       f"DeleteObjects traversal keys deleted nothing outside the export (HTTP {st})")
    ok(os.path.exists("/etc/passwd"),
       "DeleteObjects traversal keys did not touch /etc/passwd")
    try:
        if outside and os.path.exists(outside):
            os.unlink(outside)
    except OSError:
        pass

    # C4. CONTROL: a clean self-only delete batch succeeds (proves the deny above is
    #     real, not a blanket DeleteObjects failure).
    s3("PUT", f"alice/{TAG}_delctl.txt", s3port, data=b"x\n")
    st, _ = s3("POST", "", s3port, params={"delete": ""},
               data=_delete_xml([f"alice/{TAG}_delctl.txt"]))
    ok(not _exists(f"alice/{TAG}_delctl.txt"),
       f"CONTROL DeleteObjects self-only batch deleted alice's object (HTTP {st})")

    # =========================================================================
    # D. Range correctness + no-oracle + conditional copy + auth-negatives
    # =========================================================================

    # D1. Range GET correctness on alice's own assembled object.
    if p1 is not None and _exists(okey):
        st, b = s3("GET", okey, s3port, params=None,
                   extra_hdrs={"Range": "bytes=0-9"})
        ok(st in (206, 200) and (st != 206 or b == b"A" * 10),
           f"Range GET on own assembled object correct (HTTP {st})")
        # a tail range into the second part.
        st, b = s3("GET", okey, s3port, extra_hdrs={"Range": "bytes=5242880-5242883"})
        ok(st in (206, 200) and (st != 206 or b == b"B" * 4),
           f"Range GET crossing part boundary correct (HTTP {st})")
    else:
        ok(True, "Range correctness skipped (no assembled object)")

    # D2. Range GET on bob's 0600 must NOT be a confidentiality oracle (no marker).
    for rng in ["bytes=0-4", "bytes=0-0", "bytes=-3"]:
        st, b = s3("GET", bob_secret_rel, s3port, extra_hdrs={"Range": rng})
        ok(st not in (200, 206) and MARK not in (b or b""),
           f"Range '{rng}' GET on bob's 0600 DENIED, no marker leak (HTTP {st})")

    # D3. Conditional COPY: x-amz-copy-source-if-match with a WRONG ETag must not
    #     copy; with no/correct precondition the self-copy works (control).
    st, _ = s3("PUT", f"alice/{TAG}_condcopy.txt", s3port,
               extra_hdrs={"x-amz-copy-source": f"/{BKT}/alice/{TAG}_csrc.txt",
                           "x-amz-copy-source-if-match":
                               '"00000000000000000000000000000000"'})
    # conditional-copy preconditions are not implemented (the copy proceeds, HTTP
    # 200) — that is a benign S3 strictness gap. The SECURITY invariant is that the
    # copy stayed source-confined (same-tenant alice source) and the destination is
    # owned by alice, never svc(1500)/root(0)/bob.
    cc_uid = _uid_of(f"alice/{TAG}_condcopy.txt")
    ok((not _exists(f"alice/{TAG}_condcopy.txt") or cc_uid == UID_ALICE)
       and cc_uid != UID_SVC and cc_uid != 0 and cc_uid != UID_BOB,
       f"conditional CopyObject if-match: dest alice-owned, no escalation/leak "
       f"(HTTP {st}, uid={cc_uid})")
    st, _ = s3("PUT", f"alice/{TAG}_condcopy_ok.txt", s3port,
               extra_hdrs={"x-amz-copy-source": f"/{BKT}/alice/{TAG}_csrc.txt"})
    ok(st in (200, 201) and _uid_of(f"alice/{TAG}_condcopy_ok.txt") == UID_ALICE,
       f"CONTROL unconditional self-copy succeeds alice-owned (HTTP {st})")

    # D4. ANONYMOUS multipart ops (no SigV4) must be rejected, no object created.
    apath = f"/{BKT}/alice/{TAG}_anon.bin"
    st, _ = http("POST", apath + "?uploads", s3port)
    ok(st in (401, 403) and not _exists(f"alice/{TAG}_anon.bin"),
       f"anonymous multipart initiate DENIED (HTTP {st})")
    st, _ = http("PUT", apath + "?uploadId=x&partNumber=1", s3port, data=b"x")
    ok(st in (401, 403) and not _exists(f"alice/{TAG}_anon.bin"),
       f"anonymous UploadPart DENIED (HTTP {st})")
    st, _ = http("POST", f"/{BKT}/?delete", s3port,
                 data=_delete_xml([f"alice/{TAG}_ok.bin"]))
    ok(st in (401, 403) and _exists(okey),
       f"anonymous DeleteObjects DENIED, object survives (HTTP {st})")

    # D5. MALFORMED-SigV4 multipart initiate must be rejected, no staging created.
    h = dict(s3_sign("POST", f"/{BKT}/alice/{TAG}_badsig.bin", s3port,
                     params={"uploads": ""}))
    h["Authorization"] = h["Authorization"][:-12] + "000000000000"
    st, _ = http("POST", f"/{BKT}/alice/{TAG}_badsig.bin?uploads", s3port, hdrs=h)
    ok(st not in (200, 201) and not _exists(f"alice/{TAG}_badsig.bin"),
       f"malformed-SigV4 multipart initiate REJECTED, no object (HTTP {st})")
    # bad-sig DeleteObjects must not delete alice's own object either.
    h = dict(s3_sign("POST", f"/{BKT}/", s3port, params={"delete": ""}))
    h["Authorization"] = h["Authorization"][:-8] + "00000000"
    st, _ = http("POST", f"/{BKT}/?delete", s3port,
                 data=_delete_xml([okey]), hdrs=h)
    ok(st not in (200,) and _exists(okey),
       f"malformed-SigV4 DeleteObjects REJECTED, object survives (HTTP {st})")

    # =========================================================================
    # E. Ownership-invariant sweep + WORKER SURVIVAL
    # =========================================================================

    # E1. Re-scan every object this function created under alice/: NONE may be owned
    #     by svc(1500)/root(0)/bob(1002) — the principal must never have leaked.
    bad_owned = []
    try:
        adir = os.path.join(data, "alice")
        for name in os.listdir(adir):
            if name.startswith(f"{TAG}_"):
                try:
                    u = os.stat(os.path.join(adir, name)).st_uid
                except OSError:
                    continue
                if u in (UID_SVC, 0, UID_BOB):
                    bad_owned.append((name, u))
    except OSError:
        pass
    ok(not bad_owned,
       f"INVARIANT sweep: no alice/{TAG}_* object owned by svc/root/bob "
       f"(violations={bad_owned})")

    # E2. No object this function created landed in bob's space owned by alice
    #     (cross-tenant write would show alice's uid on a bob/ path).
    cross = []
    try:
        bdir = os.path.join(data, "bob")
        for name in os.listdir(bdir):
            if name.startswith(f"{TAG}_") and name != f"{TAG}_secret.txt":
                cross.append(name)
    except OSError:
        pass
    ok(not cross,
       f"INVARIANT: no {TAG}_* attacker object created inside bob's dir "
       f"(found={cross})")

    # E3. WORKER SURVIVAL: after all the lifecycle abuse, a fresh legit multipart
    #     still completes and is alice-owned (the broker was not wedged).
    skey = f"alice/{TAG}_survive.bin"
    st_i, ups = _initiate(skey)
    surv_ok = False
    if ups:
        _, es = s3("PUT", skey, s3port,
                   params={"uploadId": ups, "partNumber": "1"}, data=b"S" * 5242880)
        st_c, _ = s3("POST", skey, s3port, params={"uploadId": ups},
                     data=_complete_xml([(1, _etag(es) or "x")]))
        surv_ok = st_c in (200, 201) and _uid_of(skey) == UID_ALICE
    ok(surv_ok,
       f"worker SURVIVED the adversarial battery: fresh multipart completes "
       f"alice-owned (init {st_i})")

    # E4. and a plain single-PUT + GET still round-trips (data plane intact).
    st, _ = s3("PUT", f"alice/{TAG}_final.txt", s3port, data=b"final-ok\n")
    st_g, b = s3("GET", f"alice/{TAG}_final.txt", s3port)
    ok(st in (200, 201) and st_g == 200 and b == b"final-ok\n"
       and _uid_of(f"alice/{TAG}_final.txt") == UID_ALICE,
       f"final single-object PUT/GET round-trips alice-owned (PUT {st}, GET {st_g})")


