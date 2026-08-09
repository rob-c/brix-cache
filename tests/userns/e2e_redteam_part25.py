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


def run_chown_chgrp_dac(key, data, port, s3port):
    """OWNERSHIP / GROUP-CHANGE anti-escalation matrix.  The broker holds NO
    CAP_CHOWN, so NO protocol sequence may reassign a file's OWNER to another uid
    (root 0 / svc 1500 / another tenant) and NO sequence may GROUP a file to a
    group the creator is not a member of.  The ONLY legitimate group-set path is
    SETGID-directory inheritance, which still only grants a group the actor (or the
    dir) already carries.  We verify: (a) created files keep the creator's uid
    across WebDAV/S3/root MOVE/COPY/recreate; (b) a member creating in a 2770
    setgid staff dir inherits group=staff ONLY when a member (carol yes, bob's
    create denied outright); (c) WebDAV PROPPATCH cannot set owner/group/mode
    dead-properties to escalate; (d) no op yields uid 0/1500/other-tenant or a
    non-member group.  Each cell is one ok()."""
    TAG = "chgr"
    ta = mint(key, "alice")
    tb = mint(key, "bob")
    tc = mint(key, "carol")
    td = mint(key, "dave")
    have_s3 = bool(s3port)
    have_root = xrd_avail()

    def rel(*parts):
        return os.path.join(data, *parts)

    def uid_of(p):
        try:
            return os.stat(p).st_uid
        except OSError:
            return -1

    def gid_of(p):
        try:
            return os.stat(p).st_gid
        except OSError:
            return -1

    def body_of(p):
        try:
            with open(p, "rb") as fh:
                return fh.read()
        except OSError:
            return b""

    # st_uid invariant: a created file must be owned by the EXPECTED mapping user
    # and NEVER by root(0) / svc(1500) / any other tenant uid.
    OTHER = {0, UID_SVC}

    def owned_by(p, want, *forbid):
        u = uid_of(p)
        bad = OTHER | set(forbid)
        return os.path.exists(p) and u == want and u not in bad

    # ===================================================================
    # SECTION A — SETGID-DIR GROUP INHERITANCE is the only chgrp path, and it
    # only grants a group the actor is a MEMBER of.  sgiddir is 2770 alice:staff;
    # a staff member (carol) who creates there gets a file owned BY carol with
    # group INHERITED = staff (a group carol is genuinely in).  A non-member
    # (bob) cannot even enter the 2770 dir, so no inheritance can leak staff to him.
    # ===================================================================
    # (A1) carol (staff member) PUTs into the setgid staff dir -> created, owned carol.
    st, _ = http("PUT", "/sgiddir/%s_carol.txt" % TAG, port, tc,
                 b"carol-in-setgid\n")
    cp = rel("sgiddir", "%s_carol.txt" % TAG)
    ok(st in (200, 201, 204) and owned_by(cp, UID_CAROL, UID_ALICE, UID_BOB),
       "setgid dir: carol's file owned by carol 1003, not svc/root/alice "
       "(HTTP %s, uid=%s)" % (st, uid_of(cp)))
    # (A2) ...and the file INHERITED group=staff (2001) via the setgid bit — a
    #      group carol is a legit member of, so this is NOT an escalation.
    ok(os.path.exists(cp) and gid_of(cp) == GID_STAFF,
       "setgid dir: carol's created file inherited group=staff 2001 (legit member) "
       "(gid=%s)" % gid_of(cp))
    # (A3) carol is genuinely IN staff, so the inherited gid is a group she holds —
    #      assert the inherited group is one of carol's groups {staff, shared, proj},
    #      never a group she is not in (research 2002).
    ok(gid_of(cp) in (GID_STAFF, GID_SHARED, GID_PROJ)
       and gid_of(cp) != GID_RESEARCH,
       "setgid inheritance only granted a group carol is a member of, not research "
       "(gid=%s)" % gid_of(cp))
    # (A4) alice (owner of the dir, in staff) also inherits staff there, owned alice.
    st, _ = http("PUT", "/sgiddir/%s_alice.txt" % TAG, port, ta, b"alice-in-setgid\n")
    ap = rel("sgiddir", "%s_alice.txt" % TAG)
    ok(st in (200, 201, 204) and owned_by(ap, UID_ALICE, UID_BOB)
       and gid_of(ap) == GID_STAFF,
       "setgid dir: alice's file owned alice 1001 + group staff inherited "
       "(HTTP %s, uid=%s, gid=%s)" % (st, uid_of(ap), gid_of(ap)))
    # (A5) DENY CONTROL — bob is NOT in staff -> cannot enter the 2770 dir at all,
    #      so he can NEVER acquire group=staff via setgid inheritance.
    st, _ = http("PUT", "/sgiddir/%s_bob.txt" % TAG, port, tb, b"bob-escalate\n")
    bsg = rel("sgiddir", "%s_bob.txt" % TAG)
    ok(not os.path.exists(bsg),
       "setgid dir: bob (NOT staff) cannot create -> no staff-group inheritance "
       "escalation (HTTP %s, exists=%s)" % (st, os.path.exists(bsg)))
    # (A5b) and if any byte WERE written it must not be staff-grouped (defence-in-depth).
    ok(not (os.path.exists(bsg) and gid_of(bsg) == GID_STAFF),
       "setgid dir: no bob-owned file ended up grouped to staff (gid=%s)"
       % gid_of(bsg))
    # (A6) dave (research, not staff/shared) also cannot enter the 2770 staff dir.
    st, _ = http("PUT", "/sgiddir/%s_dave.txt" % TAG, port, td, b"dave-escalate\n")
    dsg = rel("sgiddir", "%s_dave.txt" % TAG)
    ok(not os.path.exists(dsg),
       "setgid dir: dave (NOT staff) cannot create -> no inheritance escalation "
       "(HTTP %s)" % st)

    # ===================================================================
    # SECTION B — RE-CREATE / OVERWRITE never reassigns OWNER to the prior owner.
    # carol creates a file (owned carol); alice then PUT-overwrites it in the
    # staff dir (alice has dir-write via group) -> staged replace makes the file
    # ALICE-owned.  Neither user could chown it to the other; ownership tracks the
    # ACTOR who created the inode, never a stale owner and never root/svc.
    # ===================================================================
    st, _ = http("PUT", "/staffdir/%s_b.txt" % TAG, port, tc, b"by-carol\n")
    bf = rel("staffdir", "%s_b.txt" % TAG)
    first_owner = uid_of(bf)
    ok(st in (200, 201, 204) and first_owner == UID_CAROL,
       "staff dir: file first created by carol owned carol 1003 (HTTP %s, uid=%s)"
       % (st, first_owner))
    st, _ = http("PUT", "/staffdir/%s_b.txt" % TAG, port, ta, b"rewritten-by-alice\n")
    ok(uid_of(bf) == UID_ALICE and uid_of(bf) not in OTHER,
       "staff dir: alice's staged overwrite made the inode alice-owned, NOT "
       "chowned to carol/svc/root (uid=%s)" % uid_of(bf))
    # the body is alice's; no stale carol bytes, and never owned by svc/root.
    ok(b"rewritten-by-alice" in body_of(bf) and uid_of(bf) not in OTHER,
       "staff dir: overwritten body is alice's and owner is a real tenant uid "
       "(uid=%s)" % uid_of(bf))

    # ===================================================================
    # SECTION C — WebDAV MOVE / COPY preserve the ACTOR as owner; a tenant cannot
    # use MOVE/COPY to launder a file into another uid's or root's/svc's ownership.
    # ===================================================================
    http("PUT", "/alice/%s_mv_src.txt" % TAG, port, ta, b"alice-move-src\n")
    st, _ = http("MOVE", "/alice/%s_mv_src.txt" % TAG, port, ta,
                 hdrs={"Destination": "http://%s:%d/alice/%s_mv_dst.txt"
                                      % (HOST, port, TAG)})
    mvd = rel("alice", "%s_mv_dst.txt" % TAG)
    ok(st in (201, 204) and owned_by(mvd, UID_ALICE, UID_BOB),
       "MOVE dest stays alice-owned, not laundered to svc/root/bob (HTTP %s, uid=%s)"
       % (st, uid_of(mvd)))
    st, _ = http("COPY", "/alice/%s_mv_dst.txt" % TAG, port, ta,
                 hdrs={"Destination": "http://%s:%d/alice/%s_cp_dst.txt"
                                      % (HOST, port, TAG)})
    cpd = rel("alice", "%s_cp_dst.txt" % TAG)
    ok(st in (201, 204) and owned_by(cpd, UID_ALICE, UID_BOB),
       "COPY dest owned by the copying actor alice, never svc/root/bob "
       "(HTTP %s, uid=%s)" % (st, uid_of(cpd)))
    # carol COPYing alice's file (carol can read it via staff? no — it's in /alice
    # 0755, file is 0644 world-readable after copy chain) into HER OWN dir would be
    # owned by CAROL, not alice — but more importantly never root/svc.  Use a
    # world-readable source so the read leg is allowed and we isolate the chown
    # invariant: the resulting inode is the actor's, regardless of source owner.
    st, _ = http("COPY", "/grp/world_r.txt", port, tc,
                 hdrs={"Destination": "http://%s:%d/staffdir/%s_carol_cp.txt"
                                      % (HOST, port, TAG)})
    ccp = rel("staffdir", "%s_carol_cp.txt" % TAG)
    if os.path.exists(ccp):
        ok(uid_of(ccp) == UID_CAROL and uid_of(ccp) not in OTHER,
           "COPY of alice's world-readable file by carol -> owned CAROL (actor), "
           "not alice/svc/root (uid=%s)" % uid_of(ccp))
    else:
        ok(st not in (200, 201, 204),
           "carol COPY into staff dir refused cleanly (no svc/root-owned inode) "
           "(HTTP %s)" % st)

    # ===================================================================
    # SECTION D — WebDAV PROPPATCH cannot set owner / group / unix-mode dead
    # properties to escalate.  We PROPPATCH a uniquely-named set of properties that
    # NAME ownership concepts (owner, group, unix mode), then assert the file's
    # REAL st_uid / st_gid did not move to root/svc/another tenant or a non-member
    # group.  PROPPATCH stores DEAD properties as user.* xattrs; it must never be
    # wired to chown/chgrp/chmod the inode.
    # ===================================================================
    http("PUT", "/alice/%s_pp.txt" % TAG, port, ta, b"proppatch-target\n")
    ppf = rel("alice", "%s_pp.txt" % TAG)
    before_uid, before_gid = uid_of(ppf), gid_of(ppf)
    escalate_pp = (
        b'<?xml version="1.0"?>'
        b'<D:propertyupdate xmlns:D="DAV:" xmlns:U="urn:unix">'
        b'<D:set><D:prop>'
        b'<U:owner>root</U:owner>'
        b'<U:uid>0</U:uid>'
        b'<U:group>docker</U:group>'
        b'<U:gid>50</U:gid>'
        b'<U:mode>06777</U:mode>'
        b'</D:prop></D:set>'
        b'</D:propertyupdate>')
    st_pp, _ = http("PROPPATCH", "/alice/%s_pp.txt" % TAG, port, ta,
                    data=escalate_pp, hdrs={"Content-Type": "application/xml"})
    ok(uid_of(ppf) == before_uid == UID_ALICE and uid_of(ppf) not in OTHER,
       "PROPPATCH naming owner=root/uid=0 did NOT chown the inode "
       "(PROPPATCH %s, uid=%s)" % (st_pp, uid_of(ppf)))
    ok(gid_of(ppf) == before_gid,
       "PROPPATCH naming group=docker/gid=50 did NOT chgrp the inode "
       "(gid=%s, was=%s)" % (gid_of(ppf), before_gid))
    try:
        ppmode = os.stat(ppf).st_mode & 0o7777
    except OSError:
        ppmode = -1
    ok(ppmode != -1 and (ppmode & 0o4000) == 0 and (ppmode & 0o2000) == 0,
       "PROPPATCH naming mode=06777 did NOT set setuid/setgid bits on the inode "
       "(mode=%o)" % ppmode)
    # carol (staff, can dir-write via group) PROPPATCHes alice's-group file naming
    # group=research (a group NEITHER she nor the file is in) -> no chgrp.
    http("PUT", "/staffdir/%s_pp2.txt" % TAG, port, tc, b"carol-pp\n")
    pp2 = rel("staffdir", "%s_pp2.txt" % TAG)
    g_before = gid_of(pp2)
    pp_grp = (b'<?xml version="1.0"?>'
              b'<D:propertyupdate xmlns:D="DAV:" xmlns:U="urn:unix">'
              b'<D:set><D:prop><U:gid>2002</U:gid><U:group>research</U:group>'
              b'</D:prop></D:set></D:propertyupdate>')
    http("PROPPATCH", "/staffdir/%s_pp2.txt" % TAG, port, tc,
         data=pp_grp, hdrs={"Content-Type": "application/xml"})
    ok(gid_of(pp2) == g_before and gid_of(pp2) != GID_RESEARCH,
       "PROPPATCH cannot move a file into the research group carol isn't in "
       "(gid=%s, was=%s)" % (gid_of(pp2), g_before))

    # ===================================================================
    # SECTION E — pub/ (0777 svc:svc) creation: the writer owns the file, never
    # svc, and the file does NOT inherit svc's group (no setgid on pub).  This is
    # the classic shared-spool chown trap.
    # ===================================================================
    st, _ = http("PUT", "/pub/%s_pub.txt" % TAG, port, ta, b"alice-in-pub\n")
    pubf = rel("pub", "%s_pub.txt" % TAG)
    ok(st in (200, 201, 204) and owned_by(pubf, UID_ALICE, UID_BOB),
       "pub 0777: alice's file owned alice, NEVER the svc dir-owner 1500 "
       "(HTTP %s, uid=%s)" % (st, uid_of(pubf)))
    ok(os.path.exists(pubf) and gid_of(pubf) != UID_SVC,
       "pub 0777 (not setgid): file did NOT inherit svc's group (gid=%s)"
       % gid_of(pubf))
    st, _ = http("PUT", "/pub/%s_pub_bob.txt" % TAG, port, tb, b"bob-in-pub\n")
    pubb = rel("pub", "%s_pub_bob.txt" % TAG)
    ok(st in (200, 201, 204) and owned_by(pubb, UID_BOB, UID_ALICE),
       "pub 0777: bob's file owned bob 1002, not alice/svc/root "
       "(HTTP %s, uid=%s)" % (st, uid_of(pubb)))

    # ===================================================================
    # SECTION F — S3 (alice leg only) ownership invariant under copy/recreate.
    # A CopyObject and an overwrite must keep the object owned by alice (1001),
    # never svc/root — S3 has no chown verb the tenant could abuse either.
    # ===================================================================
    if have_s3:
        s3("PUT", "alice/%s_s3.txt" % TAG, s3port, data=b"s3-alice\n")
        sf = rel("alice", "%s_s3.txt" % TAG)
        ok(owned_by(sf, UID_ALICE, UID_BOB),
           "S3 PUT object owned alice 1001, not svc/root/bob (uid=%s)" % uid_of(sf))
        st, _ = s3("PUT", "alice/%s_s3_cp.txt" % TAG, s3port,
                   extra_hdrs={"x-amz-copy-source":
                               "/%s/alice/%s_s3.txt" % (S3_BUCKET, TAG)})
        scp = rel("alice", "%s_s3_cp.txt" % TAG)
        ok(st in (200, 201) and owned_by(scp, UID_ALICE, UID_BOB),
           "S3 CopyObject result owned alice, never chowned to svc/root "
           "(HTTP %s, uid=%s)" % (st, uid_of(scp)))
        # overwrite keeps the actor's uid (no ownership carry-over to svc/root).
        s3("PUT", "alice/%s_s3.txt" % TAG, s3port, data=b"s3-alice-v2\n")
        ok(owned_by(sf, UID_ALICE, UID_BOB) and b"s3-alice-v2" in body_of(sf),
           "S3 overwrite keeps object alice-owned, body updated (uid=%s)"
           % uid_of(sf))
    else:
        ok(True, "S3 ownership-invariant leg skipped (S3 endpoint down)")
        ok(True, "S3 CopyObject ownership leg skipped (S3 endpoint down)")
        ok(True, "S3 overwrite ownership leg skipped (S3 endpoint down)")

    # ===================================================================
    # SECTION G — root:// (native stream) ownership invariant.  root:// exposes NO
    # chown subcommand, so the only test is that every create / mv keeps the
    # mapped user's uid and never lands as svc/root.  Also a cross-tenant MV must
    # not relabel ownership.  GUARDED by xrd_avail().
    # ===================================================================
    if have_root:
        lf = os.path.join(WORK, "%s_root_up.bin" % TAG)
        try:
            with open(lf, "wb") as fh:
                fh.write(b"root-alice-create\n")
        except OSError:
            lf = None
        if lf:
            rc, _o, _e = xrd_cp_up(lf, "/alice/%s_root.bin" % TAG, "alice")
            rf = rel("alice", "%s_root.bin" % TAG)
            ok(rc == 0 and owned_by(rf, UID_ALICE, UID_BOB),
               "root:// xrdcp create owned alice 1001, not svc/root/bob "
               "(rc=%s, uid=%s)" % (rc, uid_of(rf)))
            # carol creates in the setgid staff dir via root:// -> owned carol,
            # group staff inherited (a group carol is in) — cross-protocol parity
            # with the WebDAV setgid leg above.
            rc, _o, _e = xrd_cp_up(lf, "/sgiddir/%s_root_carol.bin" % TAG, "carol")
            rcf = rel("sgiddir", "%s_root_carol.bin" % TAG)
            if rc == 0 and os.path.exists(rcf):
                ok(owned_by(rcf, UID_CAROL, UID_ALICE, UID_BOB)
                   and gid_of(rcf) == GID_STAFF,
                   "root:// setgid dir: carol's file owned carol + group staff "
                   "inherited (legit) (uid=%s, gid=%s)"
                   % (uid_of(rcf), gid_of(rcf)))
            else:
                ok(rc != 0 or not os.path.exists(rcf),
                   "root:// carol create in setgid dir refused cleanly (rc=%s)" % rc)
            # bob (NOT staff) cannot create in the 2770 staff dir via root:// either.
            rc, _o, _e = xrd_cp_up(lf, "/sgiddir/%s_root_bob.bin" % TAG, "bob")
            rbf = rel("sgiddir", "%s_root_bob.bin" % TAG)
            ok(rc != 0 and not os.path.exists(rbf),
               "root:// setgid dir: bob (NOT staff) denied -> no staff inheritance "
               "escalation (rc=%s)" % rc)
        else:
            ok(True, "root:// create ownership leg skipped (scratch write failed)")
            ok(True, "root:// setgid carol leg skipped (scratch write failed)")
            ok(True, "root:// setgid bob-deny leg skipped (scratch write failed)")
        # MV via root:// keeps the actor's uid (alice moves her own file).
        if lf and os.path.exists(rel("alice", "%s_root.bin" % TAG)):
            rc, _o, _e = xrd_fs(["mv", "/alice/%s_root.bin" % TAG,
                                 "/alice/%s_root_mv.bin" % TAG], "alice")
            mvf = rel("alice", "%s_root_mv.bin" % TAG)
            ok(rc == 0 and owned_by(mvf, UID_ALICE, UID_BOB),
               "root:// mv keeps alice-owned, never relabelled to svc/root/bob "
               "(rc=%s, uid=%s)" % (rc, uid_of(mvf)))
        else:
            ok(True, "root:// mv ownership leg skipped (source absent)")
    else:
        ok(True, "root:// create ownership leg skipped (native client absent)")
        ok(True, "root:// setgid carol leg skipped (native client absent)")
        ok(True, "root:// setgid bob-deny leg skipped (native client absent)")
        ok(True, "root:// mv ownership leg skipped (native client absent)")

    # ===================================================================
    # SECTION H — GLOBAL SWEEP: after every op above, NO file under any of the
    # exercised dirs may be owned by uid 0 or svc(1500).  This is the broad
    # anti-escalation backstop (a single leaked chown anywhere trips it), plus a
    # worker-survival check that the run did not crash the worker.
    # ===================================================================
    leaked_owner = []
    for sub in ("alice", "bob", "pub", "sgiddir", "staffdir"):
        d = rel(sub)
        try:
            names = os.listdir(d)
        except OSError:
            names = []
        for n in names:
            if not n.startswith(TAG):
                continue
            u = uid_of(os.path.join(d, n))
            if u in (0, UID_SVC):
                leaked_owner.append("%s/%s=%d" % (sub, n, u))
    ok(not leaked_owner,
       "global: no %s-tagged file ended up owned by root(0)/svc(1500) (leaks=%s)"
       % (TAG, leaked_owner or "none"))
    # worker still serving (a chown/PROPPATCH abuse must not desync/crash it).
    st, b = http("GET", "/grp/world_r.txt", port, ta)
    ok(st == 200 and b"WORLD-READABLE" in (b or b""),
       "worker survived the chown/chgrp/PROPPATCH battery; still serving (HTTP %s)"
       % st)


