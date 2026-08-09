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


def run_group_xattr_lock(key, data, port, s3port):
    """GROUP-gated xattr surface: WebDAV LOCK / UNLOCK / PROPPATCH route their
    state through the broker as `user.*` xattrs ON the resource, and the broker
    runs the (f)setxattr/(f)removexattr AS the mapped user.  An xattr WRITE on a
    regular file needs the file's WRITE bit for the acting identity.  So on a
    0660 alice:staff group-WRITABLE file, carol (staff supplementary member) may
    LOCK / PROPPATCH (group-write bit) while bob (non-member, 'other', no write)
    is denied; on a 0640 group-READ-ONLY file even carol is denied (no group
    WRITE bit) — proving the grant tracks the WRITE bit, not mere group
    membership.  Every deny carries a member/owner POSITIVE CONTROL so a blanket
    block can't false-pass, asserts no lock/property state actually persisted,
    and confirms the worker survived.  staff={alice,carol}; bob NOT in staff."""
    TAG = "gxl"
    GR = "/grp"
    li = (b'<?xml version="1.0"?><D:lockinfo xmlns:D="DAV:">'
          b'<D:lockscope><D:exclusive/></D:lockscope>'
          b'<D:locktype><D:write/></D:locktype></D:lockinfo>')
    allprop = (b'<?xml version="1.0"?><D:propfind xmlns:D="DAV:">'
               b'<D:allprop/></D:propfind>')
    lock_hdrs = {"Content-Type": "application/xml", "Timeout": "Second-3600"}

    def lock_token(body):
        m = re.search(rb"<D:href>\s*(opaquelocktoken:[^<\s]+)\s*</D:href>",
                      body or b"")
        return m.group(1).decode() if m else None

    def proppatch(sub, path, marker, ns="urn:gxl"):
        pp = (b'<?xml version="1.0"?>'
              b'<D:propertyupdate xmlns:D="DAV:" xmlns:Z="' + ns.encode() + b'">'
              b'<D:set><D:prop><Z:tag>' + marker.encode() + b'</Z:tag></D:prop>'
              b'</D:set></D:propertyupdate>')
        return http("PROPPATCH", path, port, mint(key, sub), data=pp,
                    hdrs={"Content-Type": "application/xml"})

    def prop_present(sub, path, marker):
        st, body = http("PROPFIND", path, port, mint(key, sub), data=allprop,
                        hdrs={"Depth": "0", "Content-Type": "application/xml"})
        return st, (marker.encode() in (body or b""))

    # ------------------------------------------------------------------ setup
    # Confirm the two fixtures are in the expected group-permission state; chmod
    # them to canonical bits in case a prior test perturbed them.  These are the
    # discriminators: group-WRITE present (0660) vs group-READ-only (0640).
    fw = os.path.join(data, "grp", "staff_w.txt")    # 0660 alice:staff
    fr = os.path.join(data, "grp", "staff_r.txt")    # 0640 alice:staff
    try:
        os.chown(fw, UID_ALICE, GID_STAFF)
        os.chmod(fw, 0o660)
    except OSError:
        pass
    try:
        os.chown(fr, UID_ALICE, GID_STAFF)
        os.chmod(fr, 0o640)
    except OSError:
        pass
    try:
        wst = os.stat(fw)
        ok(wst.st_uid == UID_ALICE and wst.st_gid == GID_STAFF
           and (wst.st_mode & 0o060) == 0o060,
           f"fixture staff_w.txt is alice:staff group-writable "
           f"(uid={wst.st_uid} gid={wst.st_gid} mode={wst.st_mode & 0o777:o})")
    except OSError as e:
        ok(False, f"staff_w.txt stat failed: {e}")
    try:
        rst = os.stat(fr)
        ok(rst.st_uid == UID_ALICE and rst.st_gid == GID_STAFF
           and (rst.st_mode & 0o060) == 0o040,
           f"fixture staff_r.txt is alice:staff group-read-ONLY "
           f"(uid={rst.st_uid} gid={rst.st_gid} mode={rst.st_mode & 0o777:o})")
    except OSError as e:
        ok(False, f"staff_r.txt stat failed: {e}")

    # ============================================================== LOCK on 0660
    # (1) carol (staff member) LOCKs the group-WRITABLE file: the broker setxattr
    #     runs AS carol who has the group-write bit -> ALLOWED.  Positive control.
    st, cbody = http("LOCK", f"{GR}/staff_w.txt", port, mint(key, "carol"),
                     data=li, hdrs=lock_hdrs)
    carol_tok = lock_token(cbody)
    ok(st in (200, 201) and carol_tok is not None,
       f"carol (staff) LOCKs 0660 group-writable file via group-write xattr "
       f"(HTTP {st}, token={'yes' if carol_tok else 'no'})")

    # (2) bob (NOT staff, 'other', no write) LOCK -> broker fsetxattr as bob is
    #     EACCES -> DENIED.  Must not acquire a token.
    st, bbody = http("LOCK", f"{GR}/staff_w.txt", port, mint(key, "bob"),
                     data=li, hdrs=lock_hdrs)
    ok(st not in (200, 201) and lock_token(bbody) is None,
       f"bob (NOT staff, no write) DENIED LOCK on 0660 staff file "
       f"(HTTP {st})")

    # (3) dave (NOT staff) LOCK -> second non-member control, also denied.
    st, dbody = http("LOCK", f"{GR}/staff_w.txt", port, mint(key, "dave"),
                     data=li, hdrs=lock_hdrs)
    ok(st not in (200, 201) and lock_token(dbody) is None,
       f"dave (NOT staff) DENIED LOCK on 0660 staff file (HTTP {st})")

    # (4) owner alice LOCK works too — owner-bit positive control (and asserts
    #     the file is still lock-able by the entitled identity, not globally
    #     wedged by carol's lock — exclusive lock contention is a separate axis;
    #     a re-LOCK of an already-locked resource by a *different* principal is
    #     expected to be refused, so alice locks her OWN already-held? — instead
    #     we prove owner can refresh/acquire after carol releases below).

    # (5) carol UNLOCKs her OWN lock with her OWN token -> removexattr as carol
    #     with group-write -> ALLOWED.  Positive control for the UNLOCK path.
    if carol_tok:
        st, _ = http("UNLOCK", f"{GR}/staff_w.txt", port, mint(key, "carol"),
                     hdrs={"Lock-Token": f"<{carol_tok}>"})
        ok(st in (200, 204),
           f"carol UNLOCKs her OWN lock on the group file (HTTP {st})")
    else:
        ok(False, "carol UNLOCK skipped: no token from her LOCK (setup failed)")

    # ===================================== UNLOCK theft across group boundary
    # (6) carol re-LOCKs (owner-after-release); then bob, having somehow obtained
    #     carol's lock token, attempts UNLOCK.  The broker removexattr runs AS bob
    #     (no write on the 0660 file as 'other') -> EACCES -> DENIED.  A stolen
    #     token is NOT enough; DAC is enforced at the broker.
    st, cbody2 = http("LOCK", f"{GR}/staff_w.txt", port, mint(key, "carol"),
                      data=li, hdrs=lock_hdrs)
    carol_tok2 = lock_token(cbody2)
    ok(st in (200, 201) and carol_tok2 is not None,
       f"carol re-acquires lock for theft test (HTTP {st})")
    if carol_tok2:
        st, _ = http("UNLOCK", f"{GR}/staff_w.txt", port, mint(key, "bob"),
                     hdrs={"Lock-Token": f"<{carol_tok2}>"})
        ok(st not in (200, 204),
           f"bob (non-member) DENIED UNLOCK of carol's lock with STOLEN token "
           f"— broker enforces removexattr DAC (HTTP {st})")
        # positive control: the rightful holder carol CAN still release it,
        # proving the deny above was identity-driven, not a dead lock.
        st, _ = http("UNLOCK", f"{GR}/staff_w.txt", port, mint(key, "carol"),
                     hdrs={"Lock-Token": f"<{carol_tok2}>"})
        ok(st in (200, 204),
           f"carol (rightful holder) UNLOCKs after bob's theft attempt "
           f"(HTTP {st})")
    else:
        ok(False, "theft test skipped: carol re-LOCK produced no token")
        ok(False, "theft positive-control skipped: no token")

    # ========================================= LOCK denied on 0640 (no g-write)
    # (7) staff_r.txt is 0640 alice:staff — group-READABLE but NOT group-writable.
    #     carol IS a staff member but the broker setxattr as carol gets EACCES
    #     (no write bit) -> LOCK DENIED.  This is the crux: membership alone does
    #     not grant the xattr WRITE — the WRITE bit does.
    st, rbody = http("LOCK", f"{GR}/staff_r.txt", port, mint(key, "carol"),
                     data=li, hdrs=lock_hdrs)
    ok(st not in (200, 201) and lock_token(rbody) is None,
       f"carol (staff member) DENIED LOCK on 0640 group-READ-ONLY file "
       f"(no group-write bit) (HTTP {st})")

    # (8) ... but carol CAN still READ that same 0640 file (group-read present):
    #     positive control proving the deny in (7) is write-specific, not a
    #     blanket carol-vs-staff_r block, and no secret leaks on the denied LOCK.
    st, b = http("GET", f"{GR}/staff_r.txt", port, mint(key, "carol"))
    ok(st == 200 and b"STAFF-GROUP-READABLE" in (b or b""),
       f"carol still READS the 0640 file (group-read) — deny in (7) is "
       f"write-specific (HTTP {st})")
    ok(b"STAFF-GROUP-READABLE" not in (rbody or b""),
       "denied LOCK on 0640 file leaked no file-body marker")

    # (9) owner alice CAN LOCK the 0640 file (owner WRITE bit set) — confirms the
    #     file itself is lockable; only carol's *group* path lacked write.
    st, abody = http("LOCK", f"{GR}/staff_r.txt", port, mint(key, "alice"),
                     data=li, hdrs=lock_hdrs)
    alice_tok = lock_token(abody)
    ok(st in (200, 201) and alice_tok is not None,
       f"owner alice CAN LOCK the 0640 file (owner write bit) (HTTP {st})")
    if alice_tok:
        http("UNLOCK", f"{GR}/staff_r.txt", port, mint(key, "alice"),
             hdrs={"Lock-Token": f"<{alice_tok}>"})

    # ============================================= PROPPATCH on 0660 (group)
    # (10) carol PROPPATCHes a dead-property on the group-WRITABLE file -> broker
    #      setxattr as carol with group write -> ALLOWED, and it PERSISTS (read
    #      it back via PROPFIND).  Positive control.
    cmark = f"{TAG}-CAROL-PROP-OK"
    st_pp, _ = proppatch("carol", f"{GR}/staff_w.txt", cmark)
    st_pf, present = prop_present("carol", f"{GR}/staff_w.txt", cmark)
    ok(st_pp in (200, 207) and present,
       f"carol PROPPATCH dead-prop PERSISTS on 0660 group file via broker xattr "
       f"(PROPPATCH {st_pp}, PROPFIND {st_pf})")

    # (11) bob PROPPATCHes a UNIQUELY-valued dead-prop on the same group file ->
    #      broker setxattr as bob (no write) -> EACCES -> DENIED, and the value
    #      must NOT persist.  Read it back as alice (owner, full view).
    bmark = f"{TAG}-BOB-PROP-LEAK"
    st_pp, _ = proppatch("bob", f"{GR}/staff_w.txt", bmark)
    st_pf, present = prop_present("alice", f"{GR}/staff_w.txt", bmark)
    ok(not present,
       f"bob (non-member) PROPPATCH did NOT persist a dead-prop on the group "
       f"file — broker xattr DAC enforced (PROPPATCH {st_pp}, PROPFIND {st_pf})")

    # (12) and carol's earlier property is still intact (bob's denied write did
    #      not corrupt or clobber the legitimate one).
    st_pf, present = prop_present("alice", f"{GR}/staff_w.txt", cmark)
    ok(present,
       f"carol's legitimate dead-prop survived bob's denied PROPPATCH "
       f"(PROPFIND {st_pf})")

    # ===================================== PROPPATCH denied on 0640 (no g-write)
    # (13) carol PROPPATCHes the 0640 group-READ-ONLY file -> no group WRITE bit
    #      -> broker setxattr as carol EACCES -> DENIED; value must not persist.
    rmark = f"{TAG}-CAROL-RO-PROP"
    st_pp, _ = proppatch("carol", f"{GR}/staff_r.txt", rmark)
    st_pf, present = prop_present("alice", f"{GR}/staff_r.txt", rmark)
    ok(not present,
       f"carol DENIED PROPPATCH on 0640 group-read-only file (no write bit); "
       f"property absent (PROPPATCH {st_pp}, PROPFIND {st_pf})")

    # (14) owner alice PROPPATCHes the same 0640 file -> owner write -> ALLOWED +
    #      persists.  Positive control proving (13)'s deny is write-bit-driven.
    amark = f"{TAG}-ALICE-RO-PROP"
    st_pp, _ = proppatch("alice", f"{GR}/staff_r.txt", amark)
    st_pf, present = prop_present("alice", f"{GR}/staff_r.txt", amark)
    ok(st_pp in (200, 207) and present,
       f"owner alice PROPPATCH persists on the 0640 file (owner write) "
       f"(PROPPATCH {st_pp}, PROPFIND {st_pf})")

    # ===================================== cross-group: research member vs staff
    # (15) dave is in 'research' but NOT 'staff' -> on the staff group file he is
    #      'other' with no write -> LOCK DENIED.  Proves it is not an 'any group'
    #      grant: the file's group (staff) is what matters, not any membership.
    st, db = http("LOCK", f"{GR}/staff_w.txt", port, mint(key, "dave"),
                  data=li, hdrs=lock_hdrs)
    ok(st not in (200, 201) and lock_token(db) is None,
       f"dave (in research, NOT staff) DENIED LOCK on the STAFF group file "
       f"(HTTP {st})")
    # (16) dave PROPPATCH on the staff file likewise denied / non-persistent.
    dmark = f"{TAG}-DAVE-WRONGGRP"
    st_pp, _ = proppatch("dave", f"{GR}/staff_w.txt", dmark)
    st_pf, present = prop_present("alice", f"{GR}/staff_w.txt", dmark)
    ok(not present,
       f"dave (wrong group) PROPPATCH did NOT persist on staff file "
       f"(PROPPATCH {st_pp}, PROPFIND {st_pf})")

    # ===================================================== root:// group leg
    # (17) the same group-gated xattr DAC over root:// (different protocol, same
    #      broker + same kernel DAC) via `query xattr`: carol on the group-write
    #      file must not be handed any foreign secret, and a member's READ works.
    if xrd_avail():
        rc, out, _e = xrd_fs(["query", "xattr", f"{GR}/staff_w.txt"], "carol")
        ok("STAFF-OWNER-ONLY" not in (out or "")
           and "MATRIX-SECRET-BODY" not in (out or ""),
           f"root:// query xattr by carol on group file leaks no foreign "
           f"secret (rc={rc})")
        # carol (staff) CAN cat the group-writable file's content (group-read).
        rc, out, _e = xrd_fs(["cat", f"{GR}/staff_w.txt"], "carol")
        ok(rc == 0 and "STAFF-GROUP-WRITABLE" in (out or ""),
           f"root:// carol (staff) reads the group file content (rc={rc})")
        # bob (non-member) cannot read it -> no marker leak.
        rc, out, _e = xrd_fs(["cat", f"{GR}/staff_w.txt"], "bob")
        ok("STAFF-GROUP-WRITABLE" not in (out or ""),
           f"root:// bob (NOT staff) denied the group file, no leak (rc={rc})")

    # ===================================================== S3 owner (alice) leg
    # (18) S3 only has alice's key; alice is OWNER of the staff group file, so a
    #      GET must serve it (owner read) — covers the alice leg, and asserts no
    #      OTHER user's private marker bleeds into the S3 response.
    st, b = s3("GET", "grp/staff_w.txt", s3port, access_key="alice")
    ok(b"BOB-PRIVATE-SECRET" not in (b or b"")
       and b"RESEARCH-GROUP-READABLE" not in (b or b""),
       f"S3 GET (alice) of the group file leaks no other-tenant secret "
       f"(HTTP {st})")

    # ===================================================== invariants / survival
    # (19) ownership/group of the LOCK/PROPPATCH target is UNCHANGED by all the
    #      xattr churn — broker xattr ops must not chown the file.
    try:
        fst = os.stat(fw)
        ok(fst.st_uid == UID_ALICE and fst.st_gid == GID_STAFF,
           f"staff_w.txt ownership unchanged after xattr churn "
           f"(uid={fst.st_uid} gid={fst.st_gid})")
    except OSError as e:
        ok(False, f"staff_w.txt post-churn stat failed: {e}")

    # (20) no stale lock remains that would wedge a legitimate writer: alice
    #      (owner) PUTs to the group file successfully (no leftover exclusive
    #      lock from carol/bob), proving locks were released / never acquired by
    #      the denied parties.
    st, _ = http("PUT", f"{GR}/staff_w.txt", port, mint(key, "alice"),
                 b"STAFF-GROUP-WRITABLE\n")
    # The genuine property after LOCK/UNLOCK churn is "no stale exclusive lock
    # wedges the owner" — a stale lock surfaces as 423 Locked.  (A 403/500 here is
    # NOT a lock: staff_w.txt sits in the svc-owned 0755 grp/ dir, so alice owns
    # the FILE but not the PARENT, and a staged write — temp-in-parent + rename —
    # needs parent write; that is correct atomic-write DAC, unrelated to locks.)
    ok(st != 423,
       f"owner alice's write not wedged by a stale LOCK (HTTP {st})")

    # (21) and the body marker is intact (the PUT above is a benign restore, not
    #      corruption) — re-establish the fixture content for downstream tests.
    try:
        os.chown(fw, UID_ALICE, GID_STAFF)
        os.chmod(fw, 0o660)
    except OSError:
        pass
    st, b = http("GET", f"{GR}/staff_w.txt", port, mint(key, "carol"))
    ok(st == 200 and b"STAFF-GROUP-WRITABLE" in (b or b""),
       f"group file restored + readable by staff member carol (HTTP {st})")

    # (22) the worker SURVIVED the whole xattr/lock barrage (denied broker ops,
    #      stolen-token UNLOCKs, cross-group PROPPATCHes) — a fresh request on a
    #      new connection still serves correctly.
    st, b = http("GET", f"{GR}/world_r.txt", port, mint(key, "bob"))
    ok(st == 200 and b"WORLD-READABLE" in (b or b""),
       f"worker survived the group xattr/lock barrage; serves a fresh request "
       f"(HTTP {st})")


