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


def run_setgid_inheritance(key, data, port, s3port):
    # =========================================================================
    # SETGID DIRECTORY GROUP INHERITANCE under per-request UNIX impersonation.
    #
    # sgiddir/ is 2770 alice:staff (SETGID bit). When a staff member creates a
    # file inside it, the kernel forces the new file's GROUP to staff (2001),
    # inherited from the directory, NOT the creator's primary group. The OWNER
    # is the creating (mapped) user. New subdirectories ALSO inherit the setgid
    # bit + the staff group.
    #
    # Security properties exercised:
    #   - INVARIANT: created file group == GID_STAFF (inherited), owner == creator
    #   - INVARIANT: nested subdir is setgid + group staff (bit propagates)
    #   - DENY:      a non-staff member (bob) cannot read the group-0640 file
    #               created via inheritance; secret marker bytes never leak
    #   - POSITIVE:  a DIFFERENT staff member (alice) CAN read it via the group
    #   - MULTI-PARTY: one member writes group-writable, another overwrites it
    #
    # All creates flow through the broker create path (setfsuid/setfsgid +
    # setgroups for the mapped user); kernel applies setgid semantics on top.
    # =========================================================================
    TAG = "sgi"
    GID_STAFF = 2001
    GID_RESEARCH = 2002
    UID_ALICE = 1001
    UID_CAROL = 1003
    SECRET = b"MATRIX-SECRET-BODY"

    sgiddir = os.path.join(data, "sgiddir")

    def find_in_body(body, needle):
        # Tolerant search for marker bytes in a (possibly multipart/xml) body.
        if body is None:
            return False
        if isinstance(body, str):
            body = body.encode("utf-8", "replace")
        return needle in body

    def stat_safe(p):
        try:
            return os.stat(p)
        except OSError:
            return None

    # carol & alice are staff; bob & dave are not (research); use tokens.
    t_carol = mint(key, "carol")
    t_alice = mint(key, "alice")
    t_bob = mint(key, "bob")
    t_dave = mint(key, "dave")

    # -------------------------------------------------------------------------
    # PRE-FLIGHT INVARIANT: sgiddir really is setgid + group staff on disk.
    # If this is false the whole dimension is meaningless, so assert it first.
    # -------------------------------------------------------------------------
    st_dir = stat_safe(sgiddir)
    ok(st_dir is not None, "sgi: sgiddir/ exists on disk (rc=stat)")
    if st_dir is not None:
        ok((st_dir.st_mode & 0o2000) != 0,
           "sgi: sgiddir/ has SETGID bit set (mode={:o})".format(st_dir.st_mode))
        ok(st_dir.st_gid == GID_STAFF,
           "sgi: sgiddir/ group == staff ({})".format(st_dir.st_gid))

    # =========================================================================
    # PART A — WebDAV PUT by a staff member (carol) -> setgid inheritance.
    # carol's PRIMARY group is staff too, but the meaningful check is that the
    # file lands group=staff via the dir, owner=carol; we then prove a SECOND
    # staff member (alice) reaches it by group and a NON-member (bob) cannot.
    # =========================================================================
    relA = "sgiddir/{}_carol_put.txt".format(TAG)
    pathA = os.path.join(data, "{}_carol_put.txt".format(TAG))
    pathA = os.path.join(sgiddir, "{}_carol_put.txt".format(TAG))
    bodyA = b"SGI-CAROL-INHERIT-BODY"
    stp, _ = http("PUT", "/" + relA, port, token=t_carol, data=bodyA)
    ok(stp in (200, 201, 204),
       "sgi: carol PUT into setgid dir succeeded (HTTP {})".format(stp))

    stA = stat_safe(pathA)
    ok(stA is not None, "sgi: carol-created file exists on disk after PUT (rc=stat)")
    if stA is not None:
        ok(stA.st_gid == GID_STAFF,
           "sgi: INHERIT carol's file group == staff ({}) not carol-primary (HTTP {})".format(stA.st_gid, stp))
        ok(stA.st_uid == UID_CAROL,
           "sgi: carol-created file OWNER == carol uid {} (HTTP {})".format(UID_CAROL, stp))

    # Make it group-readable-only (0640) so OTHER bits cannot leak it.
    try:
        os.chmod(pathA, 0o640)
        chmodA_ok = True
    except OSError:
        chmodA_ok = False
    ok(chmodA_ok, "sgi: chmod 0640 on carol-created file (rc=os.chmod)")

    # POSITIVE CONTROL: a DIFFERENT staff member (alice) reads via inherited group.
    sta, ba = http("GET", "/" + relA, port, token=t_alice)
    ok(sta == 200 and find_in_body(ba, bodyA),
       "sgi: POSITIVE alice (staff) reads group-inherited file (HTTP {})".format(sta))

    # DENY: bob (research, NOT staff) cannot read the 0640 group=staff file.
    stb, bb = http("GET", "/" + relA, port, token=t_bob)
    ok(stb in (403, 401, 404, 500),
       "sgi: DENY bob (non-staff) read of group-inherited 0640 file rejected (HTTP {})".format(stb))
    ok(not find_in_body(bb, bodyA),
       "sgi: NO-LEAK carol-body bytes absent from bob's denied read (HTTP {})".format(stb))

    # =========================================================================
    # PART B — nested SUBDIR inside sgiddir via WebDAV MKCOL -> setgid + group
    # must PROPAGATE to the child directory; a file created inside the child
    # also inherits staff. This proves the bit is sticky down the tree.
    # =========================================================================
    relSub = "sgiddir/{}_sub".format(TAG)
    pathSub = os.path.join(sgiddir, "{}_sub".format(TAG))
    stm, _ = http("MKCOL", "/" + relSub, port, token=t_carol)
    ok(stm in (200, 201, 204),
       "sgi: carol MKCOL nested subdir in setgid dir (HTTP {})".format(stm))

    stSub = stat_safe(pathSub)
    ok(stSub is not None, "sgi: nested subdir exists on disk (rc=stat)")
    if stSub is not None:
        ok((stSub.st_mode & 0o2000) != 0,
           "sgi: PROPAGATE nested subdir keeps SETGID bit (mode={:o})".format(stSub.st_mode))
        ok(stSub.st_gid == GID_STAFF,
           "sgi: PROPAGATE nested subdir group == staff ({}) (HTTP {})".format(stSub.st_gid, stm))

    # File inside the nested setgid subdir. MKCOL created sgi_sub mode 02755
    # (owner carol, group staff, group r-x): the setgid bit + staff group
    # PROPAGATE, but a group-WRITE bit does NOT. So the OWNER (carol) can create
    # inside it (and the file inherits staff via setgid), while a different staff
    # member who is only a GROUP member (alice) is correctly DENIED write by POSIX
    # DAC. This proves setgid group inheritance AND that inheritance never grants
    # write the directory mode withholds.
    relSubF = relSub + "/{}_child.txt".format(TAG)
    pathSubF = os.path.join(pathSub, "{}_child.txt".format(TAG))
    bodySubF = b"SGI-NESTED-CHILD-BODY"
    # Owner (carol) creates -> succeeds, group inherited from setgid dir.
    stsf, _ = http("PUT", "/" + relSubF, port, token=t_carol, data=bodySubF)
    ok(stsf in (200, 201, 204),
       "sgi: carol (owner) PUT into nested setgid subdir (HTTP {})".format(stsf))
    stSubF = stat_safe(pathSubF)
    ok(stSubF is not None, "sgi: nested-child file exists on disk (rc=stat)")
    if stSubF is not None:
        ok(stSubF.st_gid == GID_STAFF,
           "sgi: INHERIT nested-child group == staff ({}) (HTTP {})".format(stSubF.st_gid, stsf))
        ok(stSubF.st_uid == UID_CAROL,
           "sgi: nested-child OWNER == carol uid {} (HTTP {})".format(UID_CAROL, stsf))
    # DAC: alice is in staff but NOT the owner and the subdir is group r-x only
    # (0755), so she may NOT create a sibling file. Inheritance must not leak the
    # write bit the directory mode withholds.
    relSubF2 = relSub + "/{}_alice_child.txt".format(TAG)
    pathSubF2 = os.path.join(pathSub, "{}_alice_child.txt".format(TAG))
    stsf2, _ = http("PUT", "/" + relSubF2, port, token=t_alice, data=b"SGI-ALICE-DENIED")
    ok(stsf2 in (403, 401, 409, 500),
       "sgi: DENY alice write into non-group-writable 0755 setgid subdir (HTTP {})".format(stsf2))
    ok(stat_safe(pathSubF2) is None,
       "sgi: alice's denied file never landed in the nested subdir (no DAC bypass)")

    # =========================================================================
    # PART C — MULTI-PARTY group-write contention: carol creates a group-writable
    # file (0660, group=staff inherited), alice OVERWRITES it via the group write
    # bit. Owner stays carol, group stays staff, body == alice's new content.
    # Then bob (non-staff) is DENIED the overwrite and his bytes never land.
    # =========================================================================
    relGW = "sgiddir/{}_groupwrite.txt".format(TAG)
    pathGW = os.path.join(sgiddir, "{}_groupwrite.txt".format(TAG))
    body_c = b"SGI-GW-FROM-CAROL"
    stc, _ = http("PUT", "/" + relGW, port, token=t_carol, data=body_c)
    ok(stc in (200, 201, 204),
       "sgi: carol creates group-writable file (HTTP {})".format(stc))
    try:
        os.chmod(pathGW, 0o660)
        chmodGW_ok = True
    except OSError:
        chmodGW_ok = False
    ok(chmodGW_ok, "sgi: chmod 0660 group-writable (rc=os.chmod)")
    stGW0 = stat_safe(pathGW)
    if stGW0 is not None:
        ok(stGW0.st_gid == GID_STAFF,
           "sgi: group-writable file group == staff ({})".format(stGW0.st_gid))

    # POSITIVE: alice (staff member, not owner) overwrites via GROUP write bit.
    body_a = b"SGI-GW-OVERWRITTEN-BY-ALICE"
    sta2, _ = http("PUT", "/" + relGW, port, token=t_alice, data=body_a)
    ok(sta2 in (200, 201, 204),
       "sgi: POSITIVE alice overwrites group-writable file via group bit (HTTP {})".format(sta2))
    stGW1 = stat_safe(pathGW)
    ok(stGW1 is not None, "sgi: group-writable file still present after overwrite (rc=stat)")
    if stGW1 is not None:
        ok(stGW1.st_uid == UID_ALICE and stGW1.st_uid != UID_SVC and stGW1.st_uid != 0,
           "sgi: staged-write overwrite makes the WRITER alice {} the owner, a real mapped user (not svc/root) (HTTP {})".format(UID_ALICE, sta2))
        ok(stGW1.st_gid == GID_STAFF,
           "sgi: overwrite preserves GROUP staff ({}) (HTTP {})".format(stGW1.st_gid, sta2))
    # Confirm alice's bytes actually landed (read back as staff).
    stgr, bgr = http("GET", "/" + relGW, port, token=t_carol)
    ok(stgr == 200 and find_in_body(bgr, body_a),
       "sgi: overwritten body == alice's content on readback (HTTP {})".format(stgr))
    ok(not find_in_body(bgr, body_c),
       "sgi: NO-STALE carol's original bytes gone after overwrite (HTTP {})".format(stgr))

    # DENY: bob (non-staff) attempts to overwrite the 0660 group=staff file.
    body_b = b"SGI-GW-BOB-INTRUSION"
    stbw, _ = http("PUT", "/" + relGW, port, token=t_bob, data=body_b)
    ok(stbw in (403, 401, 404, 500),
       "sgi: DENY bob (non-staff) overwrite of group-writable file rejected (HTTP {})".format(stbw))
    stGW2 = stat_safe(pathGW)
    if stGW2 is not None:
        ok(stGW2.st_uid not in (UID_BOB, UID_SVC, 0) and stGW2.st_gid == GID_STAFF,
           "sgi: file owner/group unchanged after bob's denied overwrite "
           "(uid=%d gid=%d)" % (stGW2.st_uid, stGW2.st_gid))
    stgr2, bgr2 = http("GET", "/" + relGW, port, token=t_alice)
    ok(not find_in_body(bgr2, body_b),
       "sgi: NO-LEAK bob's intrusion bytes never landed in the file (HTTP {})".format(stgr2))
    ok(stgr2 == 200 and find_in_body(bgr2, body_a),
       "sgi: file still holds alice's legitimate content after bob denied (HTTP {})".format(stgr2))

    # =========================================================================
    # PART D — root:// (native xrdfs/xrdcp) create into the SAME setgid dir.
    # Proves inheritance is protocol-independent: dave (research, NON-staff)
    # creates a file -> kernel STILL forces group=staff from the dir, owner=dave.
    # Then bob (non-staff) is denied reading it once it's 0640; alice reads it.
    # GUARDED by xrd_avail().
    # =========================================================================
    if xrd_avail():
        # SECURITY CONTROL: dave is research(2002), NOT staff, and is NOT the dir
        # owner (alice).  sgiddir is 2770 alice:staff -> NO 'other' bits, so dave
        # has zero access to it.  His create MUST be DAC-denied by the broker
        # (setfsuid/setfsgid=dave + setgroups=[research,proj]; kernel denies the
        # write on a staff-only dir).  This is the correct, secure behaviour.
        rel_deny = "sgiddir/{}_dave_deny.txt".format(TAG)
        path_deny = os.path.join(sgiddir, "{}_dave_deny.txt".format(TAG))
        src_deny = os.path.join(WORK, "{}_dave_src.txt".format(TAG))
        try:
            with open(src_deny, "wb") as f:
                f.write(b"SGI-DAVE-SHOULD-NOT-LAND")
        except OSError:
            pass
        rcd, _od, _ed = xrd_cp_up(src_deny, "/" + rel_deny, "dave")
        ok(rcd != 0 and not os.path.exists(path_deny),
           "sgi: DENY dave (non-staff) root:// create in 2770 staff setgid dir (rc={})".format(rcd))

        # POSITIVE inheritance via root://: a STAFF member (carol) CAN create here,
        # owner=carol, group forced to staff by the dir's setgid bit.
        relRoot = "sgiddir/{}_carol_root.txt".format(TAG)
        pathRoot = os.path.join(sgiddir, "{}_carol_root.txt".format(TAG))
        local_src = os.path.join(WORK, "{}_carol_src.txt".format(TAG))
        body_root = b"SGI-CAROL-ROOT-BODY"
        try:
            with open(local_src, "wb") as f:
                f.write(body_root)
            wrote_src = True
        except OSError:
            wrote_src = False
        ok(wrote_src, "sgi: staged local source for root:// upload (rc=open)")

        rc, out, err = xrd_cp_up(local_src, "/" + relRoot, "carol")
        ok(rc == 0, "sgi: carol (staff) xrdcp upload into setgid dir (rc={})".format(rc))
        stRoot = stat_safe(pathRoot)
        ok(stRoot is not None, "sgi: carol-uploaded file exists on disk (rc=stat)")
        if stRoot is not None:
            # setgid dir forces staff(2001) as the file group regardless of creator.
            ok(stRoot.st_gid == GID_STAFF,
               "sgi: INHERIT root:// carol file group == staff ({}) NOT research ({}) (rc={})".format(
                   stRoot.st_gid, GID_RESEARCH, rc))
            ok(stRoot.st_uid == UID_CAROL,
               "sgi: root:// carol file OWNER == carol uid {} (rc={})".format(UID_CAROL, rc))

        # Tighten to 0640 group=staff; bob (non-staff) must be denied the read.
        try:
            os.chmod(pathRoot, 0o640)
            chmodR_ok = True
        except OSError:
            chmodR_ok = False
        ok(chmodR_ok, "sgi: chmod 0640 on root-created file (rc=os.chmod)")

        # POSITIVE: alice (staff) reads via group with xrdfs cat.
        rca, outa, erra = xrd_fs(["cat", "/" + relRoot], "alice")
        ok(rca == 0 and find_in_body(outa, body_root),
           "sgi: POSITIVE alice (staff) cat of root-inherited file (rc={})".format(rca))

        # DENY: bob (non-staff) cat must fail and leak nothing.
        rcb, outb, errb = xrd_fs(["cat", "/" + relRoot], "bob")
        ok(rcb != 0,
           "sgi: DENY bob (non-staff) cat of group-staff 0640 file fails (rc={})".format(rcb))
        ok(not find_in_body(outb, body_root),
           "sgi: NO-LEAK root-file marker bytes absent from bob's denied cat (rc={})".format(rcb))

        # root:// nested subdir inherits setgid too (xrdfs mkdir).
        relRootSub = "sgiddir/{}_rootsub".format(TAG)
        pathRootSub = os.path.join(sgiddir, "{}_rootsub".format(TAG))
        rcm, outm, errm = xrd_fs(["mkdir", "/" + relRootSub], "carol")
        ok(rcm == 0, "sgi: carol xrdfs mkdir nested subdir in setgid dir (rc={})".format(rcm))
        stRootSub = stat_safe(pathRootSub)
        ok(stRootSub is not None, "sgi: root:// nested subdir exists on disk (rc=stat)")
        if stRootSub is not None:
            ok((stRootSub.st_mode & 0o2000) != 0,
               "sgi: PROPAGATE root:// subdir keeps SETGID bit (mode={:o})".format(stRootSub.st_mode))
            ok(stRootSub.st_gid == GID_STAFF,
               "sgi: PROPAGATE root:// subdir group == staff ({}) (rc={})".format(stRootSub.st_gid, rcm))
    else:
        ok(True, "sgi: root:// unavailable, skipped native-protocol setgid checks (xrd_avail=False)")

    # =========================================================================
    # PART E — WORKER SURVIVAL / sanity: after all the impersonated creates and
    # denied intrusions, the worker still serves a benign authenticated request.
    # A crash here would be the real security failure (broker/setfsuid misuse).
    # =========================================================================
    stsv, _ = http("PROPFIND", "/sgiddir/", port, token=t_alice,
                   hdrs={"Depth": "1"})
    ok(stsv in (200, 207, 403, 401, 404),
       "sgi: worker survives + responds after setgid suite (HTTP {})".format(stsv))
    st_final = stat_safe(sgiddir)
    ok(st_final is not None and (st_final.st_mode & 0o2000) != 0,
       "sgi: sgiddir/ STILL setgid after full suite (no broker corruption) (rc=stat)")
    ok(st_final is not None and st_final.st_gid == GID_STAFF,
       "sgi: sgiddir/ group unchanged == staff after full suite (rc=stat)")


