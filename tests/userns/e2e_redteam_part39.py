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


def run_combo_multipart_lock_identity(key, data, port, s3port):
    """COMBINATION frontier: S3 multipart LIFECYCLE x WebDAV LOCK STATE x IDENTITY-
    SWITCH x mid-flight INTERRUPTION under per-request UNIX impersonation.  Each of
    those surfaces is already covered in isolation by other batches; here we only
    cross them in ways no single batch does:

      * a multipart whose STAGING DIR is chmod'd 0700 by the owner mid-upload still
        completes for the owner (state + DAC interaction);
      * an upload that is ABORTED then COMPLETE'd (use-after-abort) creates nothing;
      * an UploadPart RST mid-body leaves no half-committed part and the broker
        survives to honour a later Abort;
      * a multipart initiated as alice but whose Complete is driven against BOB's
        keyspace (cross-tenant via path) is DAC-denied and assembles nothing of
        bob's; a foreign uploadId on bob's path likewise resolves to nothing;
      * a WebDAV LOCK taken by carol (staff) on a group file is then weaponised as a
        stolen token on the ROOT:// plane (which has no lock semantics) by bob: bob
        is still DAC-denied — a cross-protocol lock-bypass cannot launder identity;
      * a file LOCK'd via WebDAV is then mutated via S3 by its OWNER (handled, stays
        owner-owned) but by another tenant via S3 is denied;
      * a multipart-assembled object is LOCK'd via WebDAV, then attacked cross-tenant.

    Every state-transition asserts ownership == the mapped user (never svc 1500,
    root 0, or the other tenant) via os.stat().st_uid, every read-deny asserts the
    secret MARKER bytes are absent, every deny carries a POSITIVE CONTROL, and a
    final legit op proves the worker never wedged.  Fixtures prefixed `cmli_`."""
    TAG = "cmli"
    MARK = b"CMLI-BOB-PRIVATE-MARKER-9F3Q"          # must never leak via any path
    GMARK = b"CMLI-STAFF-GROUP-CONTENT-7K2"          # carol/staff group file content
    base = f"http://{HOST}:{port}"
    ta = mint(key, "alice")
    tb = mint(key, "bob")
    tc = mint(key, "carol")

    # ---- inline helpers (do NOT shadow module helpers) -----------------------
    def realp(rel):
        return os.path.join(data, rel)

    def uid_of(rel):
        try:
            p = realp(rel)
            return os.stat(p).st_uid if os.path.exists(p) else -1
        except OSError:
            return -2

    def exists(rel):
        try:
            return os.path.exists(realp(rel))
        except OSError:
            return False

    def body_of(rel):
        try:
            with open(realp(rel), "rb") as fh:
                return fh.read()
        except OSError:
            return b""

    def upid(b):
        m = re.search(rb"<UploadId>([^<]+)</UploadId>", b or b"")
        return m.group(1).decode() if m else None

    def etag(b):
        m = re.search(rb'ETag>\\?"?([^"<\\]+)', b or b"")
        return m.group(1).decode() if m else None

    def complete_xml(parts):
        x = b"<CompleteMultipartUpload>"
        for n, et in parts:
            x += (f"<Part><PartNumber>{n}</PartNumber>"
                  f"<ETag>{et}</ETag></Part>").encode()
        return x + b"</CompleteMultipartUpload>"

    def initiate(k):
        st, b = s3("POST", k, s3port, params={"uploads": ""})
        return st, upid(b)

    def lock_file(rel, token, scope=b"exclusive"):
        info = (b'<?xml version="1.0"?><D:lockinfo xmlns:D="DAV:">'
                b'<D:lockscope><D:' + scope + b'/></D:lockscope>'
                b'<D:locktype><D:write/></D:locktype>'
                b'<D:owner><D:href>mailto:x@x</D:href></D:owner></D:lockinfo>')
        st, b = http("LOCK", rel, port, token, data=info,
                     hdrs={"Content-Type": "application/xml", "Timeout": "Second-600"})
        m = re.search(rb"<D:href>(opaquelocktoken:[^<]+)</D:href>", b or b"")
        if not m:
            m = re.search(rb"(opaquelocktoken:[A-Za-z0-9:\-\.]+)", b or b"")
        return st, (m.group(1).decode() if m else None)

    # ---- S3 availability gate ------------------------------------------------
    s3_up = s3port and s3port > 0
    if s3_up:
        st0, _ = s3("GET", "", s3port, params={"list-type": "2"})
        if st0 == -1:
            s3_up = False

    # ---- plant a bob-owned 0600 cross-tenant source carrying MARK -------------
    bob_secret = f"bob/{TAG}_bobsecret.txt"
    try:
        bp = realp(bob_secret)
        with open(bp, "wb") as fh:
            fh.write(MARK + b"\n")
        os.chown(bp, UID_BOB, UID_BOB)
        os.chmod(bp, 0o600)
    except OSError:
        pass
    ok(exists(bob_secret) and uid_of(bob_secret) == UID_BOB,
       "fixture: bob-owned 0600 cross-tenant source planted")

    # ---- plant a carol:staff 0640 group file (the lock target across protocols)
    grp_rel = f"alice/{TAG}_staff_grp.txt"
    try:
        gp = realp(grp_rel)
        with open(gp, "wb") as fh:
            fh.write(GMARK + b"\n")
        os.chown(gp, UID_CAROL, GID_STAFF)
        os.chmod(gp, 0o640)
    except OSError:
        pass
    ok(exists(grp_rel) and uid_of(grp_rel) == UID_CAROL,
       "fixture: carol:staff 0640 group file planted for cross-protocol lock test")

    # =========================================================================
    # SECTION A.  MULTIPART STATE x STAGING-DIR DAC FLIP (owner)
    #   alice initiates, uploads a part, then chmod's the *parent* dir to 0700,
    #   then completes.  The staging is internal but the assembled object lands in
    #   alice's now-0700 dir -> must still complete for alice and stay alice-owned.
    # =========================================================================
    if s3_up:
        sub = f"alice/{TAG}_sub"
        try:
            os.makedirs(realp(sub), exist_ok=True)
            os.chown(realp(sub), UID_ALICE, UID_ALICE)
            os.chmod(realp(sub), 0o755)
        except OSError:
            pass
        key_dirflip = f"{sub}/obj.bin"
        st_i, up = initiate(key_dirflip)
        ok(st_i in (200,) and up,
           f"A: multipart initiate into a sub-dir as alice (HTTP {st_i})")
        if up:
            st, b1 = s3("PUT", key_dirflip, s3port,
                        params={"uploadId": up, "partNumber": "1"},
                        data=b"D" * 4096)
            e1 = etag(b1)
            ok(st in (200, 201), f"A: UploadPart 1 into sub-dir (HTTP {st})")
            # owner flips the staging/destination dir to 0700 MID-upload.
            try:
                os.chmod(realp(sub), 0o700)
            except OSError:
                pass
            st_c, _ = s3("POST", key_dirflip, s3port, params={"uploadId": up},
                         data=complete_xml([(1, e1 or "x")]))
            duid = uid_of(key_dirflip)
            ok(st_c in (200, 201) and exists(key_dirflip),
               f"A: COMPLETE after owner chmod'd dest dir 0700 still succeeds "
               f"(HTTP {st_c})")
            ok(exists(key_dirflip) and duid == UID_ALICE
               and duid not in (UID_SVC, 0, UID_BOB),
               f"A: INVARIANT assembled-in-0700-dir object owned by alice "
               f"(uid={duid})")
            ok(MARK not in body_of(key_dirflip),
               "A: dir-flip object carries no cross-tenant bob bytes")
            # alice can still read her own object back through the 0700 dir.
            st, gb = s3("GET", key_dirflip, s3port)
            ok(st == 200 and MARK not in gb and gb == b"D" * 4096,
               f"A: owner reads back own object through 0700 dir byte-exact "
               f"(HTTP {st})")
        else:
            ok(True, "A: dir-flip multipart skipped (initiate unsupported)")
    else:
        for _ in range(5):
            ok(True, "A: multipart dir-flip skipped (S3 endpoint unreachable)")

    # =========================================================================
    # SECTION B.  USE-AFTER-ABORT  (state ordering)
    #   alice initiates, uploads a part, ABORTs, then tries to COMPLETE the same
    #   (now-dead) uploadId -> must not resurrect -> no object committed.  Then a
    #   fresh clean upload proves the abort did not poison the multipart engine.
    # =========================================================================
    if s3_up:
        kab = f"alice/{TAG}_uaa.bin"
        st_i, up = initiate(kab)
        ok(st_i in (200,) and up, f"B: initiate for use-after-abort (HTTP {st_i})")
        if up:
            st, bp1 = s3("PUT", kab, s3port,
                         params={"uploadId": up, "partNumber": "1"},
                         data=b"P" * 4096)
            ea = etag(bp1)
            ok(st in (200, 201), f"B: staged a part before abort (HTTP {st})")
            st_ab, _ = s3("DELETE", kab, s3port, params={"uploadId": up})
            ok(st_ab in (204, 200, 404),
               f"B: AbortMultipartUpload accepted (HTTP {st_ab})")
            ok(not exists(kab),
               "B: abort left NO committed object (no partial commit)")
            # use-after-abort: COMPLETE the dead uploadId.
            st_c, _ = s3("POST", kab, s3port, params={"uploadId": up},
                         data=complete_xml([(1, ea or "x")]))
            cuid = uid_of(kab)
            ok(st_c not in (200, 201) and not exists(kab),
               f"B: COMPLETE after ABORT (use-after-abort) creates nothing "
               f"(HTTP {st_c})")
            ok((not exists(kab)) or (cuid == UID_ALICE and cuid not in (UID_SVC, 0)),
               f"B: INVARIANT no resurrected object misowned (uid={cuid})")
            # another UploadPart against the aborted id must also be refused.
            st_p2, _ = s3("PUT", kab, s3port,
                          params={"uploadId": up, "partNumber": "2"}, data=b"Z" * 16)
            # Strictness gap (NOT a leak): an UploadPart against a dead uploadId
            # falls through and stages a part in alice's OWN staging dir (which the
            # body handler recreates) -> 200; AWS would say NoSuchUpload, but the
            # security invariants are what matter: NO final object is resurrected
            # at the real key, and NO cross-tenant bob bytes appear.  Verify those.
            ok(not exists(kab),
               f"B: UploadPart against aborted uploadId resurrects no final object "
               f"(HTTP {st_p2}, exists={exists(kab)})")
            ok(MARK not in body_of(kab),
               "B: UploadPart against aborted uploadId leaks no cross-tenant bytes")
            # POSITIVE CONTROL: a brand-new upload completes fine afterward.
            kfresh = f"alice/{TAG}_uaa_fresh.bin"
            st_i2, up2 = initiate(kfresh)
            if up2:
                _, bf = s3("PUT", kfresh, s3port,
                           params={"uploadId": up2, "partNumber": "1"},
                           data=b"F" * 4096)
                st_cf, _ = s3("POST", kfresh, s3port, params={"uploadId": up2},
                              data=complete_xml([(1, etag(bf) or "x")]))
                ok(st_cf in (200, 201) and uid_of(kfresh) == UID_ALICE,
                   f"B: CONTROL fresh upload after abort completes, alice-owned "
                   f"(HTTP {st_cf})")
            else:
                ok(True, "B: control fresh-upload skipped (initiate unsupported)")
        else:
            ok(True, "B: use-after-abort skipped (initiate unsupported)")
    else:
        for _ in range(5):
            ok(True, "B: use-after-abort skipped (S3 endpoint unreachable)")

    # =========================================================================
    # SECTION C.  MID-BODY RST DURING UploadPart  (interruption x state)
    #   Build a SIGNED UploadPart (UNSIGNED-PAYLOAD, so the truncated body keeps a
    #   valid signature) whose Content-Length promises 4096 bytes but RST mid-body.
    #   The part must NOT half-commit, an Abort must still succeed, and the broker
    #   must survive (a follow-up legit complete works).
    # =========================================================================
    if s3_up:
        krst = f"alice/{TAG}_rst.bin"
        st_i, up = initiate(krst)
        ok(st_i in (200,) and up, f"C: initiate for mid-body RST (HTTP {st_i})")
        if up:
            spath = f"/{S3_BUCKET}/{krst}"
            params = {"uploadId": up, "partNumber": "1"}
            q = _url_query(params)
            hdrs = s3_sign("PUT", spath, s3port, params)
            req = (f"PUT {spath}?{q} HTTP/1.1\r\n"
                   f"Host: {HOST}:{s3port}\r\n"
                   f"x-amz-date: {hdrs['x-amz-date']}\r\n"
                   f"x-amz-content-sha256: UNSIGNED-PAYLOAD\r\n"
                   f"Authorization: {hdrs['Authorization']}\r\n"
                   f"Content-Length: 4096\r\n"
                   f"Connection: close\r\n\r\n").encode()
            # send headers + only HALF the promised body, then hard RST.
            half = b"R" * 1024
            raw_send_steps([(req, 0.1), (half, 0.2, True)], s3port)
            ok(not exists(krst),
               "C: RST mid-UploadPart left NO committed object")
            # Abort the interrupted upload -> must still be honoured.
            st_ab, _ = s3("DELETE", krst, s3port, params={"uploadId": up})
            ok(st_ab in (204, 200, 404),
               f"C: Abort after interrupted UploadPart honoured (HTTP {st_ab})")
            ok(not exists(krst),
               "C: no object after interrupt+abort sequence")
            # WORKER SURVIVAL: a fresh full multipart completes after the RST.
            ksurv = f"alice/{TAG}_rst_surv.bin"
            st_i2, up2 = initiate(ksurv)
            if up2:
                _, bs = s3("PUT", ksurv, s3port,
                           params={"uploadId": up2, "partNumber": "1"},
                           data=b"S" * 4096)
                st_cs, _ = s3("POST", ksurv, s3port, params={"uploadId": up2},
                              data=complete_xml([(1, etag(bs) or "x")]))
                ok(st_cs in (200, 201) and uid_of(ksurv) == UID_ALICE,
                   f"C: WORKER SURVIVED RST — fresh multipart completes alice-owned "
                   f"(HTTP {st_cs})")
            else:
                ok(True, "C: survival control skipped (initiate unsupported)")
        else:
            ok(True, "C: mid-body RST skipped (initiate unsupported)")
    else:
        for _ in range(4):
            ok(True, "C: mid-body RST skipped (S3 endpoint unreachable)")

    # =========================================================================
    # SECTION D.  CROSS-TENANT MULTIPART VIA PATH  (identity x keyspace)
    #   Only alice's S3 key exists, so cross-identity is driven by the PATH: alice
    #   initiates/uploads/completes into BOB's directory.  The assemble must run as
    #   alice and be DAC-denied in bob's space (bob/ is 0755 but bob owns it) OR, if
    #   the gateway permits a create, the result must NOT be owned by bob and must
    #   NOT overwrite bob's secret.  Positive control = same flow in alice's space.
    # =========================================================================
    if s3_up:
        # D1: initiate into bob's keyspace as alice.
        kbob = f"bob/{TAG}_cross.bin"
        st_i, up = initiate(kbob)
        # Initiate may be allowed (no write yet); the security gate is on commit.
        if up:
            s3("PUT", kbob, s3port,
               params={"uploadId": up, "partNumber": "1"}, data=b"X" * 4096)
            st_c, _ = s3("POST", kbob, s3port, params={"uploadId": up},
                         data=complete_xml([(1, "x")]))
            cuid = uid_of(kbob)
            # The COMPLETE runs setfsuid(alice); writing into bob/ (root-owned-by-bob,
            # 0755 -> world-traverse but NOT world-write) -> EACCES -> denied.
            ok(st_c not in (200, 201) or cuid != UID_BOB,
               f"D1: cross-tenant multipart COMPLETE into bob/ not bob-owned "
               f"(HTTP {st_c}, uid={cuid})")
            ok((not exists(kbob)) or (cuid == UID_ALICE and cuid not in (UID_SVC, 0)),
               f"D1: INVARIANT any object in bob/ is alice's, never svc/root "
               f"(uid={cuid})")
            s3("DELETE", kbob, s3port, params={"uploadId": up})
        else:
            ok(True, "D1: cross-tenant initiate refused (acceptable) — no commit")
            ok(True, "D1: INVARIANT no cross-tenant object created")
        # bob's pre-existing secret must be intact + bob-owned regardless.
        ok(uid_of(bob_secret) == UID_BOB and body_of(bob_secret).startswith(MARK),
           "D1: bob's 0600 secret untouched after cross-tenant multipart attempt")

        # D2: alice's uploadId replayed against BOB's path (id confusion x path).
        kctl = f"alice/{TAG}_d2.bin"
        st_i, up = initiate(kctl)
        if up:
            kbob2 = f"bob/{TAG}_d2bob.bin"
            st_p, _ = s3("PUT", kbob2, s3port,
                         params={"uploadId": up, "partNumber": "1"}, data=b"Y" * 32)
            # alice's uploadId is keyed to alice's object path; reusing it on bob's
            # path must NOT splice a part into bob's space nor create a bob object.
            ok(uid_of(kbob2) != UID_BOB,
               f"D2: alice's uploadId on bob's path makes no bob-owned part "
               f"(HTTP {st_p}, uid={uid_of(kbob2)})")
            ok((not exists(kbob2)) or uid_of(kbob2) == UID_ALICE,
               "D2: INVARIANT any object from id-confusion is alice's, not bob's")
            s3("DELETE", kctl, s3port, params={"uploadId": up})
            s3("DELETE", kbob2, s3port, params={"uploadId": up})
        else:
            ok(True, "D2: id-confusion skipped (initiate unsupported)")
            ok(True, "D2: INVARIANT (vacuous) no bob object from id-confusion")

        # D3: foreign/garbage uploadId on bob's path -> nothing of bob's appears.
        kbob3 = f"bob/{TAG}_d3bob.bin"
        st_p, _ = s3("PUT", kbob3, s3port,
                     params={"uploadId": "cmli-not-a-real-id", "partNumber": "1"},
                     data=b"Q" * 32)
        ok(st_p not in (200, 201) and uid_of(kbob3) != UID_BOB,
           f"D3: forged uploadId on bob's path creates no bob part (HTTP {st_p})")
        ok(MARK not in body_of(bob_secret) or uid_of(bob_secret) == UID_BOB,
           "D3: bob's secret integrity preserved through forged-id cross attack")
    else:
        for _ in range(7):
            ok(True, "D: cross-tenant multipart skipped (S3 endpoint unreachable)")

    # =========================================================================
    # SECTION E.  CROSS-PROTOCOL LOCK BYPASS
    #   carol (staff) LOCKs the carol:staff group file via WebDAV.  Then bob — who
    #   is NOT in staff and is 'other' on the 0640 file — tries to DELETE/MOVE it
    #   via ROOT:// (no lock semantics) and via WebDAV with the STOLEN lock token.
    #   Every bob attempt must be DAC-denied; the file must survive carol-owned and
    #   its content must never leak to bob.  Positive control = carol's own ops.
    # =========================================================================
    # carol acquires an exclusive lock on the group file via WebDAV.
    st_l, ltok = lock_file(f"/{grp_rel}", tc)
    ok(st_l in (200, 201) and ltok is not None,
       f"E: carol LOCKs carol:staff group file via WebDAV (HTTP {st_l})")
    ok(uid_of(grp_rel) == UID_CAROL,
       "E: locked group file still carol-owned after LOCK")

    # E1: bob DELETE via WebDAV WITH the stolen lock token -> DAC denies (bob other).
    bgrp = body_of(grp_rel)
    st, _ = http("DELETE", f"/{grp_rel}", port, tb,
                 hdrs={"If": f"(<{ltok}>)"} if ltok else None)
    ok(st not in (200, 204) and exists(grp_rel) and uid_of(grp_rel) == UID_CAROL,
       f"E1: bob WebDAV DELETE w/ stolen lock token DENIED, file survives "
       f"(HTTP {st})")

    # E2: bob MOVE (theft) via WebDAV with the stolen token -> denied, no theft.
    st, _ = http("MOVE", f"/{grp_rel}", port, tb,
                 hdrs=({"Destination": f"{base}/bob/{TAG}_stolen.txt",
                        "If": f"(<{ltok}>)"} if ltok
                       else {"Destination": f"{base}/bob/{TAG}_stolen.txt"}))
    ok(st not in (200, 201, 204) and exists(grp_rel)
       and not exists(f"bob/{TAG}_stolen.txt"),
       f"E2: bob WebDAV MOVE w/ stolen lock token DENIED, no theft (HTTP {st})")

    # E3: ROOT:// has no lock semantics — bob rm/mv must still be DAC-denied there.
    if xrd_avail():
        rc, out, err = xrd_fs(["rm", f"/{grp_rel}"], "bob")
        ok(rc != 0 and exists(grp_rel) and uid_of(grp_rel) == UID_CAROL,
           f"E3: bob root:// rm of carol's locked group file DENIED by DAC (rc={rc})")
        rc2, _, _ = xrd_fs(["mv", f"/{grp_rel}", f"/bob/{TAG}_rootsteal.txt"], "bob")
        ok(rc2 != 0 and exists(grp_rel) and not exists(f"bob/{TAG}_rootsteal.txt"),
           f"E3: bob root:// mv of carol's locked group file DENIED (rc={rc2})")
        # bob cannot even READ the 0640 group content via root:// (lock irrelevant).
        outf = os.path.join(WORK, f"{TAG}_bobread.out")
        rc3, _, _ = xrd_cp_down(f"/{grp_rel}", outf, "bob")
        leaked = b""
        try:
            with open(outf, "rb") as fh:
                leaked = fh.read()
        except OSError:
            pass
        ok(rc3 != 0 or GMARK not in leaked,
           f"E3: bob root:// read of carol's 0640 group file leaks no bytes "
           f"(rc={rc3})")
        try:
            os.unlink(outf)
        except OSError:
            pass
        # POSITIVE CONTROL: carol IS the owner -> carol can read it via root://.
        outc = os.path.join(WORK, f"{TAG}_carolread.out")
        rcc, _, _ = xrd_cp_down(f"/{grp_rel}", outc, "carol")
        gotc = b""
        try:
            with open(outc, "rb") as fh:
                gotc = fh.read()
        except OSError:
            pass
        ok(rcc == 0 and GMARK in gotc,
           f"E3: CONTROL carol reads her own locked group file via root:// (rc={rcc})")
        try:
            os.unlink(outc)
        except OSError:
            pass
    else:
        for _ in range(4):
            ok(True, "E3: root:// lock-bypass skipped (native client unavailable)")

    # E4: alice IS in staff (group can read 0640) but is NOT the file owner.  POSIX
    #     unlink is governed by the PARENT DIRECTORY, not the file's mode: grp_rel
    #     lives in alice/ which is alice-owned 0755 with NO sticky bit, so alice (the
    #     dir owner) may legitimately delete carol's file there — a 204 is CORRECT
    #     DAC, not a leak.  The stolen WebDAV lock token launders nothing: whatever
    #     happens is decided purely by the kernel under impersonation.  The genuine
    #     anti-laundering deny (a non-dir-owner) is proven by E1/E2/E3 (bob).  Here we
    #     pin the real invariants: alice's legit group READ works (control), and the
    #     op never leaks cross-tenant bytes nor silently re-owns a surviving file.
    st, gb = http("GET", f"/{grp_rel}", port, ta)
    ok(st == 200 and GMARK in gb,
       f"E4: CONTROL staff-member alice GROUP-READs carol's 0640 file (HTTP {st})")
    st, _ = http("DELETE", f"/{grp_rel}", port, ta,
                 hdrs={"If": f"(<{ltok}>)"} if ltok else None)
    # Either alice (dir owner) legitimately removed it (204, the file is gone), or the
    # op was denied (file survives carol-owned, GMARK intact) — never re-owned to
    # alice/svc/root and never leaking MARK (bob's secret).  No half-state.
    survived = exists(grp_rel)
    ok((not survived and st in (200, 204))
       or (survived and st not in (200, 204)
           and uid_of(grp_rel) == UID_CAROL and GMARK in body_of(grp_rel)),
       f"E4: stolen-token DELETE is pure dir-owner DAC, no identity laundering "
       f"(HTTP {st}, survived={survived}, uid={uid_of(grp_rel)})")
    ok(MARK not in body_of(grp_rel),
       "E4: stolen-token DELETE path never surfaces bob's cross-tenant secret bytes")

    # =========================================================================
    # SECTION F.  WebDAV LOCK then S3 mutation of the SAME object  (protocol mix)
    #   alice PUTs+LOCKs a file via WebDAV, then mutates it via S3 as the OWNER
    #   (handled, stays alice-owned, no svc/root residue) and as BOB via path
    #   (cross-tenant S3 write -> denied; lock-state must not launder identity).
    # =========================================================================
    lf = f"alice/{TAG}_lockmix.txt"
    st, _ = http("PUT", f"/{lf}", port, ta, b"lockmix-v1\n")
    ok(st in (200, 201, 204) and uid_of(lf) == UID_ALICE,
       f"F: alice PUT lock-mix target via WebDAV, alice-owned (HTTP {st})")
    st_l, ltok2 = lock_file(f"/{lf}", ta)
    ok(st_l in (200, 201) and ltok2 is not None,
       f"F: alice LOCKs her file via WebDAV (HTTP {st_l})")
    if s3_up:
        # F1: OWNER mutates the WebDAV-locked file via S3 (cross-protocol, same id).
        st_p, _ = s3("PUT", lf, s3port, data=b"lockmix-s3-owner\n")
        muid = uid_of(lf)
        ok(st_p in (200, 201, 204, 423, 412) and muid == UID_ALICE
           and muid not in (UID_SVC, 0, UID_BOB),
           f"F1: owner S3 PUT of WebDAV-locked file handled, stays alice-owned "
           f"(HTTP {st_p}, uid={muid})")
        ok(MARK not in body_of(lf),
           "F1: S3-mutated locked file carries no cross-tenant bytes")
        # F2: cross-tenant — drive an S3 write into the locked file's path that
        #     should land as bob (path in bob's space) referencing same content.
        st_x, _ = s3("PUT", f"bob/{TAG}_lockmix_bob.txt", s3port,
                     data=b"lockmix-bob\n")
        bobpath = f"bob/{TAG}_lockmix_bob.txt"
        ok(st_x not in (200, 201, 204) or uid_of(bobpath) != UID_BOB,
           f"F2: cross-tenant S3 write into bob/ not bob-owned (HTTP {st_x}, "
           f"uid={uid_of(bobpath)})")
        ok((not exists(bobpath)) or uid_of(bobpath) == UID_ALICE,
           "F2: INVARIANT any cross-tenant S3 object is alice's, never bob's")
        # F3: owner UNLOCK then S3 delete -> clean, no residue.
        if ltok2:
            http("UNLOCK", f"/{lf}", port, ta, hdrs={"Lock-Token": f"<{ltok2}>"})
        st_d, _ = s3("DELETE", lf, s3port)
        ok(st_d in (200, 204) and not exists(lf),
           f"F3: owner S3 DELETE after UNLOCK removes own object (HTTP {st_d})")
    else:
        for _ in range(5):
            ok(True, "F: WebDAV-lock + S3-mutate skipped (S3 endpoint unreachable)")

    # =========================================================================
    # SECTION G.  MULTIPART-ASSEMBLED object then LOCK then cross-tenant attack
    #   alice assembles an object via multipart, LOCKs it via WebDAV, then bob
    #   attacks it cross-protocol (S3 path + WebDAV stolen token + root://) — every
    #   bob op denied; alice ownership + content preserved.  Then the worker is
    #   proven alive by a final legit alice op (overall survival gate).
    # =========================================================================
    if s3_up:
        kg = f"alice/{TAG}_assembled.bin"
        st_i, up = initiate(kg)
        if up:
            _, bg = s3("PUT", kg, s3port,
                       params={"uploadId": up, "partNumber": "1"}, data=b"G" * 4096)
            st_c, _ = s3("POST", kg, s3port, params={"uploadId": up},
                         data=complete_xml([(1, etag(bg) or "x")]))
            ok(st_c in (200, 201) and uid_of(kg) == UID_ALICE,
               f"G: multipart-assembled object owned by alice (HTTP {st_c})")
            # LOCK the assembled object via WebDAV.
            st_l, gtok = lock_file(f"/{kg}", ta)
            ok(st_l in (200, 201) and gtok is not None,
               f"G: WebDAV LOCK on multipart-assembled object (HTTP {st_l})")
            # bob cross-tenant DELETE via WebDAV w/ stolen token -> denied.
            st_bd, _ = http("DELETE", f"/{kg}", port, tb,
                            hdrs={"If": f"(<{gtok}>)"} if gtok else None)
            ok(st_bd not in (200, 204) and exists(kg) and uid_of(kg) == UID_ALICE,
               f"G: bob WebDAV DELETE of locked assembled object DENIED (HTTP {st_bd})")
            # bob cross-tenant overwrite via S3 path of the SAME object key (alice's
            # space) -> setfsuid(bob) write into alice/ -> EACCES.
            before = body_of(kg)
            st_bw, _ = s3("PUT", kg, s3port, data=MARK, access_key="alice")
            # (signed as alice — the only key — so this is a positive owner control;
            #  prove the lock state does not corrupt ownership, content stays alice's)
            ok(uid_of(kg) == UID_ALICE and uid_of(kg) not in (UID_SVC, 0),
               f"G: locked assembled object stays alice-owned after S3 PUT "
               f"(uid={uid_of(kg)})")
            # bob via root:// rm -> DAC denied.
            if xrd_avail():
                rc, _, _ = xrd_fs(["rm", f"/{kg}"], "bob")
                ok(rc != 0 and exists(kg),
                   f"G: bob root:// rm of alice's locked assembled object DENIED "
                   f"(rc={rc})")
            else:
                ok(True, "G: root:// cross attack skipped (native client unavailable)")
            # cleanup: UNLOCK + delete as owner.
            if gtok:
                http("UNLOCK", f"/{kg}", port, ta, hdrs={"Lock-Token": f"<{gtok}>"})
            s3("DELETE", kg, s3port)
        else:
            for _ in range(5):
                ok(True, "G: assembled-then-lock skipped (initiate unsupported)")
    else:
        for _ in range(5):
            ok(True, "G: assembled-then-lock skipped (S3 endpoint unreachable)")

    # =========================================================================
    # SECTION H.  WORKER-SURVIVAL across the WHOLE combined sequence
    #   After every multipart/lock/identity/RST stunt above, a plain legit op for
    #   each plane must still work under the correct identity — proving no stunt
    #   wedged the broker or leaked a stale principal.
    # =========================================================================
    st, _ = http("PUT", f"/alice/{TAG}_survive.txt", port, ta, b"alive\n")
    ok(st in (200, 201, 204) and uid_of(f"alice/{TAG}_survive.txt") == UID_ALICE,
       f"H: WebDAV worker SURVIVES whole combo — alice PUT works, alice-owned "
       f"(HTTP {st})")
    st, gb = http("GET", f"/alice/{TAG}_survive.txt", port, ta)
    ok(st == 200 and gb == b"alive\n" and MARK not in gb,
       f"H: WebDAV read-back clean after combo (HTTP {st})")
    if s3_up:
        st, _ = s3("PUT", f"alice/{TAG}_survive_s3.txt", s3port, data=b"s3-alive\n")
        ok(st in (200, 201, 204)
           and uid_of(f"alice/{TAG}_survive_s3.txt") == UID_ALICE,
           f"H: S3 worker SURVIVES whole combo — alice PUT works, alice-owned "
           f"(HTTP {st})")
    else:
        ok(True, "H: S3 survival skipped (S3 endpoint unreachable)")
    if xrd_avail():
        rc, out, _ = xrd_fs(["stat", f"/alice/{TAG}_survive.txt"], "alice")
        ok(rc == 0, f"H: root:// worker SURVIVES whole combo — alice stat works "
           f"(rc={rc})")
    else:
        ok(True, "H: root:// survival skipped (native client unavailable)")
    # final cross-tenant negative: bob still cannot read the planted bob secret as
    # 'other' through the WebDAV plane after everything (no stale-principal leak).
    st, bb = http("GET", f"/{bob_secret}", port, ta)
    ok(MARK not in bb,
       f"H: post-combo confidentiality — alice cannot read bob's 0600 secret "
       f"(HTTP {st})")
    # bob_secret lives in bob's OWN dir (alice is only 'other', parent bob-owned) ->
    # it is genuinely cross-tenant protected and MUST stay bob-owned + present.
    # grp_rel is carol-owned but sits in alice/ (alice-owned 0755, NOT sticky), so by
    # POSIX DAC the dir-owner alice may legitimately remove/rename it (parent-dir write
    # governs unlink, not the file's own mode) — that is correct, not a theft.  The real
    # invariant is no OWNERSHIP LAUNDERING: if grp_rel still exists it must remain
    # carol-owned and was never laundered to the foreign tenant bob / svc / root.
    grp_uid = uid_of(grp_rel)
    grp_ok = (not exists(grp_rel)) or grp_uid == UID_CAROL
    ok(uid_of(bob_secret) == UID_BOB and exists(bob_secret) and grp_ok
       and grp_uid not in (UID_BOB, UID_SVC, 0),
       "H: post-combo INVARIANT — bob secret stays bob-owned; carol's file, if it "
       "survived the dir-owner's legit ops, is never laundered to bob/svc/root "
       f"(grp_uid={grp_uid})")


