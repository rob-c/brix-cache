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


def run_group_dir_dac(key, data, port, s3port):
    """DIRECTORY group-permission DAC through the real protocols (the dir-perm twin
    of the existing FILE group-read tests).  Exercises the broker's setgroups() on
    the DIRECTORY access path: a directory's group bits decide whether a mapped
    user may ENTER (x), LIST (r) or only TRAVERSE-to-a-known-child (x without r).
    Covered surfaces: WebDAV PROPFIND/GET, root:// ls/cat, S3 ListObjects (alice
    leg).  Every deny has a paired positive control (the entitled member/owner
    SUCCEEDS) so a blanket block cannot false-pass, and every read-deny also asserts
    the secret marker bytes never appear in the body."""
    TAG = "gdd"
    PF = (b'<?xml version="1.0"?><propfind xmlns="DAV:">'
          b'<prop><displayname/></prop></propfind>')

    def propfind(path, sub, depth="1"):
        return http("PROPFIND", path, port, mint(key, sub),
                    data=PF, hdrs={"Depth": depth, "Content-Type": "application/xml"})

    def uid_gid(p):
        try:
            s = os.stat(p)
            return s.st_uid, s.st_gid
        except OSError:
            return -1, -1

    def mkdir_chown(rel, uid, gid, mode):
        p = os.path.join(data, rel)
        try:
            os.makedirs(p, exist_ok=True)
            os.chown(p, uid, gid)
            os.chmod(p, mode)
        except OSError:
            pass
        return p

    def write_child(rel, content, uid, gid, mode):
        p = os.path.join(data, rel)
        try:
            with open(p, "w") as fh:
                fh.write(content)
            os.chown(p, uid, gid)
            os.chmod(p, mode)
        except OSError:
            pass
        return p

    # ============================================================ 0770 STAFF DIR
    # staffdir is 0770 alice:staff (alice,carol enter+list; bob is OTHER -> no x,
    # so bob cannot even STAT a child by name).  inside.txt is the 0640 child.
    INSIDE = b"INSIDE-STAFF-DIR"
    INSIDE_NAME = b"inside.txt"

    # (1) carol (staff member) LISTS the 0770 staff dir via PROPFIND -> sees inside.txt.
    st, b = propfind("/staffdir/", "carol")
    ok(st in (200, 207) and INSIDE_NAME in (b or b""),
       f"carol (staff) lists 0770 staffdir, sees child (HTTP {st})")
    # (2) carol READS the child file through the group-traversable dir.  An
    #     earlier batch (run_group_write_dac) legitimately rewrites this shared
    #     fixture's CONTENT, so assert the genuine access property — carol (staff)
    #     gets 200 with a real, non-empty body she could read through the 0770
    #     group-traversable dir — not the stale exact bytes.  A wrong DENY still
    #     fails here (she'd get 403/404 or an empty body).
    st, b = http("GET", "/staffdir/inside.txt", port, mint(key, "carol"))
    ok(st == 200 and bool(b),
       f"carol (staff) reads child of 0770 staffdir (HTTP {st})")
    # (3) bob (OTHER, no dir x) cannot LIST the dir -> no child name leaks.
    st, b = propfind("/staffdir/", "bob")
    leaked = (st in (200, 207) and INSIDE_NAME in (b or b""))
    ok(not leaked,
       f"bob (non-staff) PROPFIND of 0770 staffdir leaks no entries (HTTP {st}, leaked={leaked})")
    # (4) bob cannot even STAT/GET a known child by name (dir x is required to
    #     resolve the leaf) -> denied + marker bytes absent.
    st, b = http("GET", "/staffdir/inside.txt", port, mint(key, "bob"))
    ok(INSIDE not in (b or b""),
       f"bob (non-staff) denied known child of 0770 staffdir, no leak (HTTP {st})")
    st, b = http("PROPFIND", "/staffdir/inside.txt", port, mint(key, "bob"),
                 data=PF, hdrs={"Depth": "0", "Content-Type": "application/xml"})
    ok(not (st in (200, 207) and INSIDE_NAME in (b or b"")),
       f"bob (non-staff) cannot PROPFIND-stat a child of 0770 staffdir (HTTP {st})")
    # (5) dave (also non-staff) -> second independent non-member control.
    st, b = http("GET", "/staffdir/inside.txt", port, mint(key, "dave"))
    ok(INSIDE not in (b or b""),
       f"dave (non-staff) denied child of 0770 staffdir, no leak (HTTP {st})")
    # (6) alice (OWNER) lists + reads -> owner control.
    st, b = propfind("/staffdir/", "alice")
    ok(st in (200, 207) and INSIDE_NAME in (b or b""),
       f"owner alice lists her 0770 staffdir (HTTP {st})")

    # staffdir leg over root:// (same kernel DAC, different protocol).
    if xrd_avail():
        rc, out, _e = xrd_fs(["ls", "/staffdir/"], "carol")
        ok(rc == 0 and "inside.txt" in (out or ""),
           f"carol lists 0770 staffdir via root:// (rc={rc})")
        rc, out, _e = xrd_fs(["cat", "/staffdir/inside.txt"], "carol")
        # content is rewritten by an earlier batch (shared fixture) — assert the
        # ACCESS (carol the staff member can read it), not the stale bytes.
        ok(rc == 0,
           f"carol reads staffdir child via root:// (rc={rc})")
        rc, out, _e = xrd_fs(["ls", "/staffdir/"], "bob")
        ok(rc != 0 or "inside.txt" not in (out or ""),
           f"bob (non-staff) root:// ls of 0770 staffdir leaks nothing (rc={rc})")
        rc, out, _e = xrd_fs(["cat", "/staffdir/inside.txt"], "bob")
        ok(rc != 0 and INSIDE.decode() not in (out or ""),
           f"bob (non-staff) root:// cat of staffdir child denied (rc={rc})")

    # ===================================================== 0750 MEMBER-LIST DIR
    # A 0750 dir owned carol:proj (proj={carol,dave,erin}).  Group members LIST
    # (r+x); a non-member (bob/alice) has OTHER=0 -> denied entirely.
    LIST750 = b"PROJ-0750-CHILD-MARKER"
    d750 = mkdir_chown(f"{TAG}_proj750", UID_CAROL, GID_PROJ, 0o750)
    c750 = write_child(f"{TAG}_proj750/{TAG}_p750.txt", LIST750.decode() + "\n",
                       UID_CAROL, GID_PROJ, 0o640)
    u, g = uid_gid(d750)
    ok(u == UID_CAROL and g == GID_PROJ,
       f"fixture 0750 dir owned carol:proj (uid={u}, gid={g})")

    # (7) erin (proj member) LISTS the 0750 dir -> sees child.
    st, b = propfind(f"/{TAG}_proj750/", "erin")
    ok(st in (200, 207) and (TAG + "_p750.txt").encode() in (b or b""),
       f"erin (proj) lists 0750 proj dir (HTTP {st})")
    # (8) dave (proj member, via supplementary group) also LISTS -> setgroups proof.
    st, b = propfind(f"/{TAG}_proj750/", "dave")
    ok(st in (200, 207) and (TAG + "_p750.txt").encode() in (b or b""),
       f"dave (proj, supplementary) lists 0750 proj dir (HTTP {st})")
    # (9) bob (NOT in proj) cannot list -> no child name leaks.
    st, b = propfind(f"/{TAG}_proj750/", "bob")
    ok(not (st in (200, 207) and (TAG + "_p750.txt").encode() in (b or b"")),
       f"bob (non-proj) PROPFIND of 0750 proj dir leaks nothing (HTTP {st})")
    # (10) bob cannot read the child (no dir x to resolve it) + no marker leak.
    st, b = http("GET", f"/{TAG}_proj750/{TAG}_p750.txt", port, mint(key, "bob"))
    ok(LIST750 not in (b or b""),
       f"bob (non-proj) denied 0750 proj child, no leak (HTTP {st})")
    # (11) alice (NOT in proj) also denied -> second non-member control.
    st, b = http("GET", f"/{TAG}_proj750/{TAG}_p750.txt", port, mint(key, "alice"))
    ok(LIST750 not in (b or b""),
       f"alice (non-proj) denied 0750 proj child, no leak (HTTP {st})")
    # (12) erin (proj member) READS the child -> positive control for the deny.
    st, b = http("GET", f"/{TAG}_proj750/{TAG}_p750.txt", port, mint(key, "erin"))
    ok(st == 200 and LIST750 in (b or b""),
       f"erin (proj member) reads 0750 proj child (HTTP {st})")
    # (13) frank (in NO test group) -> belt-and-braces non-member deny.
    st, b = http("GET", f"/{TAG}_proj750/{TAG}_p750.txt", port, mint(key, "frank"))
    ok(LIST750 not in (b or b""),
       f"frank (no group) denied 0750 proj child, no leak (HTTP {st})")

    # ============================================ 0710 EXEC-ONLY (TRAVERSE != LIST)
    # execonly is 0710 alice:staff (group --x, NO group r).  A staff MEMBER can
    # TRAVERSE to a KNOWN child (x) but a LISTING/PROPFIND of the dir must be
    # denied/empty (no r).  This is the traverse-vs-list distinction.
    KNOWN = b"EXECONLY-KNOWN"

    # (14) carol (staff) GETs the KNOWN child by name (group --x permits traverse).
    st, b = http("GET", "/execonly/known.txt", port, mint(key, "carol"))
    ok(st == 200 and KNOWN in (b or b""),
       f"carol (staff) traverses 0710 execonly to KNOWN child (HTTP {st})")
    # (15) but carol's PROPFIND/LIST of the dir must NOT enumerate it (no group r).
    st, b = propfind("/execonly/", "carol")
    listed = (st in (200, 207) and b"known.txt" in (b or b""))
    ok(not listed,
       f"carol (staff) cannot LIST 0710 execonly (group --x, no r) (HTTP {st}, listed={listed})")
    # (16) alice (OWNER, 0710 -> owner rwx) CAN list -> proves the dir is not just
    #      globally unreadable (the deny in 15 is bit-driven, not blanket).
    st, b = propfind("/execonly/", "alice")
    ok(st in (200, 207) and b"known.txt" in (b or b""),
       f"owner alice lists her 0710 execonly dir (owner r) (HTTP {st})")
    # (17) bob (OTHER, no x at all) cannot even traverse to the known child.
    st, b = http("GET", "/execonly/known.txt", port, mint(key, "bob"))
    ok(KNOWN not in (b or b""),
       f"bob (non-staff) cannot traverse 0710 execonly to child, no leak (HTTP {st})")
    # (18) bob's PROPFIND likewise leaks nothing.
    st, b = propfind("/execonly/", "bob")
    ok(not (st in (200, 207) and b"known.txt" in (b or b"")),
       f"bob (non-staff) PROPFIND of 0710 execonly leaks nothing (HTTP {st})")

    # execonly traverse-vs-list over root:// (the ls vs cat distinction).
    if xrd_avail():
        rc, out, _e = xrd_fs(["cat", "/execonly/known.txt"], "carol")
        ok(rc == 0 and KNOWN.decode() in (out or ""),
           f"carol traverses 0710 execonly to KNOWN child via root:// cat (rc={rc})")
        rc, out, _e = xrd_fs(["ls", "/execonly/"], "carol")
        ok(rc != 0 or "known.txt" not in (out or ""),
           f"carol root:// ls of 0710 execonly denied/empty (no group r) (rc={rc})")
        rc, out, _e = xrd_fs(["cat", "/execonly/known.txt"], "bob")
        ok(rc != 0 and KNOWN.decode() not in (out or ""),
           f"bob (non-staff) root:// cat of execonly child denied (rc={rc})")

    # ====================================================== 0700 PER-USER PRIVATE
    # A self-made 0700 dir per user: the OWNER accesses (list+read child); every
    # other user is denied EVERYTHING including a metadata stat of a child.
    PRIV_C = b"CAROL-0700-PRIVATE-BODY"
    PRIV_D = b"DAVE-0700-PRIVATE-BODY"
    dc = mkdir_chown(f"{TAG}_carol700", UID_CAROL, GID_PROJ, 0o700)
    cc = write_child(f"{TAG}_carol700/{TAG}_c.txt", PRIV_C.decode() + "\n",
                     UID_CAROL, GID_PROJ, 0o600)
    dd = mkdir_chown(f"{TAG}_dave700", UID_DAVE, GID_RESEARCH, 0o700)
    cd = write_child(f"{TAG}_dave700/{TAG}_d.txt", PRIV_D.decode() + "\n",
                     UID_DAVE, GID_RESEARCH, 0o600)
    u, g = uid_gid(dc)
    ok(u == UID_CAROL, f"fixture 0700 carol dir owned carol (uid={u})")
    u2, _ = uid_gid(dd)
    ok(u2 == UID_DAVE, f"fixture 0700 dave dir owned dave (uid={u2})")

    # (19) carol (owner) lists + reads her own 0700 dir.
    st, b = propfind(f"/{TAG}_carol700/", "carol")
    ok(st in (200, 207) and (TAG + "_c.txt").encode() in (b or b""),
       f"owner carol lists her 0700 private dir (HTTP {st})")
    st, b = http("GET", f"/{TAG}_carol700/{TAG}_c.txt", port, mint(key, "carol"))
    ok(st == 200 and PRIV_C in (b or b""),
       f"owner carol reads child of her 0700 dir (HTTP {st})")
    # (20) dave (not owner, even though carol shares 'proj' with dave the DIR group
    #      is proj but mode 0700 grants NOTHING to group) -> denied listing.
    st, b = propfind(f"/{TAG}_carol700/", "dave")
    ok(not (st in (200, 207) and (TAG + "_c.txt").encode() in (b or b"")),
       f"dave (proj groupmate, but 0700 -> no group bits) cannot list carol's dir (HTTP {st})")
    # (21) dave cannot read the child + cannot metadata-stat it.
    st, b = http("GET", f"/{TAG}_carol700/{TAG}_c.txt", port, mint(key, "dave"))
    ok(PRIV_C not in (b or b""),
       f"dave denied child of carol's 0700 dir, no leak (HTTP {st})")
    st, b = http("PROPFIND", f"/{TAG}_carol700/{TAG}_c.txt", port, mint(key, "dave"),
                 data=PF, hdrs={"Depth": "0", "Content-Type": "application/xml"})
    ok(not (st in (200, 207) and (TAG + "_c.txt").encode() in (b or b"")),
       f"dave cannot PROPFIND-stat a child of carol's 0700 dir (HTTP {st})")
    # (22) alice (unrelated) denied too.
    st, b = http("GET", f"/{TAG}_carol700/{TAG}_c.txt", port, mint(key, "alice"))
    ok(PRIV_C not in (b or b""),
       f"alice denied child of carol's 0700 dir, no leak (HTTP {st})")
    # (23) symmetric: dave OWNS his 0700 dir -> dave reads, carol denied.
    st, b = http("GET", f"/{TAG}_dave700/{TAG}_d.txt", port, mint(key, "dave"))
    ok(st == 200 and PRIV_D in (b or b""),
       f"owner dave reads child of his 0700 dir (HTTP {st})")
    st, b = http("GET", f"/{TAG}_dave700/{TAG}_d.txt", port, mint(key, "carol"))
    ok(PRIV_D not in (b or b""),
       f"carol denied child of dave's 0700 dir, no leak (HTTP {st})")
    st, b = propfind(f"/{TAG}_dave700/", "carol")
    ok(not (st in (200, 207) and (TAG + "_d.txt").encode() in (b or b"")),
       f"carol cannot list dave's 0700 dir (HTTP {st})")

    # 0700 cross-owner deny over root:// (independent protocol confirmation).
    if xrd_avail():
        rc, out, _e = xrd_fs(["cat", f"/{TAG}_carol700/{TAG}_c.txt"], "carol")
        ok(rc == 0 and PRIV_C.decode() in (out or ""),
           f"owner carol reads her 0700 child via root:// (rc={rc})")
        rc, out, _e = xrd_fs(["ls", f"/{TAG}_carol700/"], "dave")
        ok(rc != 0 or (TAG + "_c.txt") not in (out or ""),
           f"dave root:// ls of carol's 0700 dir denied/empty (rc={rc})")
        rc, out, _e = xrd_fs(["cat", f"/{TAG}_carol700/{TAG}_c.txt"], "dave")
        ok(rc != 0 and PRIV_C.decode() not in (out or ""),
           f"dave root:// cat of carol's 0700 child denied (rc={rc})")

    # ===================================================== S3 (alice leg) LISTING
    # S3 only has alice's access key.  alice is NOT in proj and NOT the owner of the
    # carol-private/proj dirs, so a ListObjects MUST NOT enumerate their children;
    # it MUST still list a dir alice owns (control).  alice IS in staff, but the
    # listing leak we guard is the per-entry dir-read gate, so the 0750 proj dir and
    # carol's 0700 dir are the deny targets.  This is the S3 analogue of the
    # PROPFIND/ls listing-confidentiality checks above.
    if s3port:
        # control: a public, alice-owned subtree key set lists fine.
        amk = write_child(f"{TAG}_alice_pub.txt", "GDD-ALICE-PUBLIC\n",
                          UID_ALICE, GID_STAFF, 0o644)
        st, body = s3("GET", "", s3port, params={"list-type": "2"})
        ok(st == 200 and _has(body, (TAG + "_alice_pub.txt").encode()),
           f"S3 ListObjects lists alice's own public key (HTTP {st})")
        # deny: the listing must not enumerate carol's 0700-private child or the
        # 0750 proj child (alice has no UNIX dir-read on either) + no marker bytes.
        leaked = (_has(body, (TAG + "_c.txt").encode())
                  or _has(body, PRIV_C)
                  or _has(body, LIST750))
        ok(not leaked,
           f"S3 ListObjects (alice) leaks no carol-0700 / proj-0750 child or marker "
           f"(HTTP {st}, leaked={leaked})")
        # a prefixed listing scoped at carol's private dir must also stay empty of
        # the protected child for alice.
        st, body = s3("GET", "", s3port,
                      params={"list-type": "2", "prefix": f"{TAG}_carol700/"})
        ok(not _has(body, (TAG + "_c.txt").encode()) and not _has(body, PRIV_C),
           f"S3 prefixed ListObjects (alice) does not reveal carol's 0700 child "
           f"(HTTP {st})")

    # ============================================================ SETGID DIR (2770)
    # sgiddir is 2770 alice:staff (SETGID): a NEW file a staff member creates inside
    # inherits group=staff (not the creator's primary group).  Then a DIFFERENT
    # staff member can group-access it -> a clean multi-party group-inheritance flow
    # that depends on BOTH setgid semantics AND the broker's setgroups for the
    # second user.  bob (non-staff) cannot create in the dir at all.
    st, _ = http("PUT", f"/sgiddir/{TAG}_carol_new.txt", port, mint(key, "carol"),
                 b"carol-in-setgid\n")
    sfp = os.path.join(data, "sgiddir", f"{TAG}_carol_new.txt")
    created = os.path.exists(sfp)
    ok(created, f"carol (staff) creates a file in 2770 setgid staffdir (HTTP {st})")
    if created:
        u, g = uid_gid(sfp)
        ok(u == UID_CAROL and g == GID_STAFF,
           f"setgid: carol's new file owned carol but GROUP-INHERITED staff "
           f"(uid={u}, gid={g})")
        # alice (also staff) can group-read the inherited-group file -> setgroups
        # for the SECOND identity over the inherited group.
        st, b = http("GET", f"/sgiddir/{TAG}_carol_new.txt", port, mint(key, "alice"))
        ok(st == 200 and b"carol-in-setgid" in (b or b""),
           f"alice (staff) group-reads carol's setgid-inherited file (HTTP {st})")
        # bob (non-staff) cannot read it (other bits clear on a 0664/0660 create).
        st, b = http("GET", f"/sgiddir/{TAG}_carol_new.txt", port, mint(key, "bob"))
        ok(b"carol-in-setgid" not in (b or b""),
           f"bob (non-staff) denied carol's setgid file, no leak (HTTP {st})")
    # bob cannot create in the 2770 dir (not staff, no group w/x).
    st, _ = http("PUT", f"/sgiddir/{TAG}_bob_evil.txt", port, mint(key, "bob"), b"x\n")
    ok(not os.path.exists(os.path.join(data, "sgiddir", f"{TAG}_bob_evil.txt")),
       f"bob (non-staff) cannot create in 2770 setgid staffdir (HTTP {st})")

    # ============================================================ WORKER SURVIVAL
    # After all the per-request identity churn + denials, a fresh legit op as the
    # OWNER must still succeed and land with correct ownership -> the worker did not
    # wedge and the broker did not leak/stick a prior principal.
    st, _ = http("PUT", f"/staffdir/{TAG}_survive.txt", port, mint(key, "alice"),
                 b"survive\n")
    svp = os.path.join(data, "staffdir", f"{TAG}_survive.txt")
    su, _ = uid_gid(svp)
    ok(os.path.exists(svp) and su == UID_ALICE,
       f"WORKER SURVIVES: alice PUT after the churn lands owned by alice "
       f"(HTTP {st}, uid={su})")


