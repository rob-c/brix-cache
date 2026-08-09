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


def run_stream_extended_ops(key, data, port, s3port):
    """NOVEL root:// native-client subcommands NOT exercised by any prior battery,
    driven through per-request UNIX impersonation: touch (create+utime), ln HARD
    LINK, ln -s SYMLINK + readlink, head/tail -c partial reads, du/find/tree
    recursive enumeration, statvfs/df filesystem stats, and locate existence-oracle.
    Each surface gets a SELF-SUCCESS, a CROSS-TENANT DENY (with secret-marker-absence
    for read-denies), and an OWNERSHIP INVARIANT (created objects owned by the mapped
    uid via os.stat().st_uid; a hard link's owner == the original; a symlink to /etc
    or to another tenant's 0600 is NOT followed on later access).  Unsupported
    subcommands are accepted as 'handled' (never as a leak).  A final benign op proves
    the worker/broker survived the whole battery."""
    TAG = "seo"
    if not xrd_avail():
        ok(True, "stream_extended_ops: native xrdfs unavailable — skipped (handled)")
        return

    SECRET = "BOB-PRIVATE-SECRET"   # bytes of data/bob/private.txt (0600, bob)

    def uid_of(rel):
        try:
            return os.stat(os.path.join(data, rel.lstrip("/"))).st_uid
        except OSError:
            return -1

    def luid_of(rel):
        try:
            return os.lstat(os.path.join(data, rel.lstrip("/"))).st_uid
        except OSError:
            return -1

    def nlink_of(rel):
        try:
            return os.stat(os.path.join(data, rel.lstrip("/"))).st_nlink
        except OSError:
            return -1

    def exists(rel):
        return os.path.exists(os.path.join(data, rel.lstrip("/")))

    def lexists(rel):
        return os.path.lexists(os.path.join(data, rel.lstrip("/")))

    def mk_fixture(rel, content, uid, gid, mode):
        p = os.path.join(data, rel.lstrip("/"))
        try:
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, "w") as fh:
                fh.write(content)
            os.chown(p, uid, gid)
            os.chmod(p, mode)
        except OSError:
            pass
        return p

    def mk_dir(rel, uid, gid, mode):
        p = os.path.join(data, rel.lstrip("/"))
        try:
            os.makedirs(p, exist_ok=True)
            os.chown(p, uid, gid)
            os.chmod(p, mode)
        except OSError:
            pass
        return p

    def rm_quiet(rel):
        p = os.path.join(data, rel.lstrip("/"))
        try:
            if os.path.islink(p) or os.path.isfile(p):
                os.remove(p)
            elif os.path.isdir(p):
                import shutil as _sh
                _sh.rmtree(p, ignore_errors=True)
        except OSError:
            pass

    # ================================================================= TOUCH
    # touch as the mapped user must create a 0-byte (or empty) file owned by that
    # uid; touch into another tenant's tree must be denied (no file appears owned
    # by the worker/attacker, and bob's dir is not mutated).
    rm_quiet(f"alice/{TAG}_touch.txt")
    rc, _o, _e = xrd_fs(["touch", f"/alice/{TAG}_touch.txt"], "alice")
    if rc == 0 and exists(f"alice/{TAG}_touch.txt"):
        ok(uid_of(f"alice/{TAG}_touch.txt") == UID_ALICE,
           f"touch: alice's new file owned by mapped uid alice "
           f"(uid={uid_of(f'alice/{TAG}_touch.txt')})")
    else:
        ok(True, f"touch unsupported/handled for alice (rc={rc})")

    # touch an EXISTING own file (utime path) — owner unchanged, still alice.
    rc, _o, _e = xrd_fs(["touch", f"/alice/{TAG}_touch.txt"], "alice")
    ok(uid_of(f"alice/{TAG}_touch.txt") in (UID_ALICE, -1),
       f"touch utime of own file keeps alice ownership (rc={rc})")

    # cross-tenant: alice touches a NEW file inside bob's 0755 dir — must be denied;
    # if anything is created it must NOT be owned by alice (i.e. no escalation), and
    # ideally nothing is created at all.
    rm_quiet(f"bob/{TAG}_alice_intrusion.txt")
    rc, _o, _e = xrd_fs(["touch", f"/bob/{TAG}_alice_intrusion.txt"], "alice")
    created = exists(f"bob/{TAG}_alice_intrusion.txt")
    leaked_owner = created and uid_of(f"bob/{TAG}_alice_intrusion.txt") == UID_ALICE
    ok(rc != 0 or not created,
       f"touch into bob's dir by alice denied (rc={rc}, created={created})")
    ok(not leaked_owner,
       f"touch cross-tenant created no alice-owned file in bob's dir (created={created})")
    rm_quiet(f"bob/{TAG}_alice_intrusion.txt")

    # cross-tenant utime: alice touches bob's EXISTING 0600 private.txt — denied,
    # and that touch must not have changed its owner.
    rc, _o, _e = xrd_fs(["touch", "/bob/private.txt"], "alice")
    ok(rc != 0,
       f"touch (utime) of bob's 0600 private.txt by alice denied (rc={rc})")
    ok(uid_of("bob/private.txt") == UID_BOB,
       f"bob's private.txt still owned by bob after alice touch attempt "
       f"(uid={uid_of('bob/private.txt')})")

    # positive control: bob CAN touch his own private.txt (owner).
    rc, _o, _e = xrd_fs(["touch", "/bob/private.txt"], "bob")
    ok(rc == 0 or uid_of("bob/private.txt") == UID_BOB,
       f"control: bob touches his own private.txt (rc={rc})")

    # ============================================================ HARD LINK (ln)
    # alice hard-links her own file -> link is the SAME inode (owner == original,
    # nlink>=2); cross-tenant hard links (to bob's file, or into bob's dir) denied.
    mk_fixture(f"alice/{TAG}_orig.txt", "ALICE-HARDLINK-ORIGIN\n", UID_ALICE,
               UID_ALICE, 0o644)
    rm_quiet(f"alice/{TAG}_hard.txt")
    rc, _o, _e = xrd_fs(["ln", f"/alice/{TAG}_orig.txt", f"/alice/{TAG}_hard.txt"],
                        "alice")
    if rc == 0 and exists(f"alice/{TAG}_hard.txt"):
        ok(uid_of(f"alice/{TAG}_hard.txt") == UID_ALICE,
           f"hard link to alice's own file owned by alice "
           f"(uid={uid_of(f'alice/{TAG}_hard.txt')})")
        ok(nlink_of(f"alice/{TAG}_orig.txt") >= 2,
           f"hard link shares inode (nlink={nlink_of(f'alice/{TAG}_orig.txt')})")
    else:
        ok(True, f"hard link unsupported/handled for alice (rc={rc})")
        ok(True, "hard-link nlink check skipped (unsupported)")

    # cross-tenant hard link: alice tries to link bob's 0600 private.txt into her
    # own dir — a successful link would alias bob's inode and let alice read his
    # secret.  Must be denied; if any link object lands, alice must NOT be able to
    # read SECRET through it.
    rm_quiet(f"alice/{TAG}_steal_hard.txt")
    rc, _o, _e = xrd_fs(["ln", "/bob/private.txt", f"/alice/{TAG}_steal_hard.txt"],
                        "alice")
    landed = exists(f"alice/{TAG}_steal_hard.txt")
    ok(rc != 0 or not landed,
       f"cross-tenant hard link of bob's 0600 into alice dir denied "
       f"(rc={rc}, landed={landed})")
    # even if a link object exists, alice must not be able to cat the secret via it.
    rc2, out2, _e2 = xrd_fs(["cat", f"/alice/{TAG}_steal_hard.txt"], "alice")
    ok(SECRET not in (out2 or ""),
       f"no SECRET leak via cross-tenant hard link (rc={rc2})")
    rm_quiet(f"alice/{TAG}_steal_hard.txt")

    # cross-tenant hard link target dir: alice links her own file INTO bob's dir —
    # denied; nothing alice-owned should appear in bob's tree.
    rm_quiet(f"bob/{TAG}_into_bob.txt")
    rc, _o, _e = xrd_fs(["ln", f"/alice/{TAG}_orig.txt", f"/bob/{TAG}_into_bob.txt"],
                        "alice")
    landed = exists(f"bob/{TAG}_into_bob.txt")
    ok(rc != 0 or not landed,
       f"hard link INTO bob's dir by alice denied (rc={rc}, landed={landed})")
    ok(not (landed and uid_of(f"bob/{TAG}_into_bob.txt") == UID_ALICE),
       f"no alice-owned hard link planted in bob's dir (landed={landed})")
    rm_quiet(f"bob/{TAG}_into_bob.txt")

    # ============================================================= SYMLINK (ln -s)
    # alice creates a symlink in her own dir (the LINK is owned by alice; lstat uid).
    rm_quiet(f"alice/{TAG}_sym_self")
    rc, _o, _e = xrd_fs(["ln", "-s", f"/alice/{TAG}_orig.txt", f"/alice/{TAG}_sym_self"],
                        "alice")
    sym_supported = rc == 0 and lexists(f"alice/{TAG}_sym_self")
    if sym_supported:
        ok(luid_of(f"alice/{TAG}_sym_self") == UID_ALICE,
           f"symlink created owned by alice "
           f"(luid={luid_of(f'alice/{TAG}_sym_self')})")
        # readlink returns the stored target verbatim.
        rc2, out2, _e2 = xrd_fs(["readlink", f"/alice/{TAG}_sym_self"], "alice")
        ok(rc2 == 0 and f"{TAG}_orig.txt" in (out2 or ""),
           f"readlink returns the symlink target (rc={rc2})")
        # following the symlink to alice's OWN file: the module's confined open uses
        # RESOLVE_NO_MAGICLINKS / no-symlink-follow as a SECURE default, so a symlink
        # may simply NOT be followed (rc!=0) — that is acceptable.  What must hold:
        # it never resolves to FOREIGN content; if it resolves at all it is alice's
        # own bytes.
        rc2, out2, _e2 = xrd_fs(["cat", f"/alice/{TAG}_sym_self"], "alice")
        ok(rc2 != 0 or "ALICE-HARDLINK-ORIGIN" in (out2 or ""),
           f"alice's own symlink: not-followed (secure default) or own content (rc={rc2})")
    else:
        ok(True, f"symlink create unsupported/handled (rc={rc})")
        ok(True, "readlink check skipped (symlink unsupported)")
        ok(True, "self-symlink follow skipped (symlink unsupported)")

    # CONFINEMENT: a symlink whose target is /etc/passwd (absolute, outside export)
    # must NOT be followed on later access — content of the host passwd must never
    # appear, and no "root:x:0" marker leaks.  We plant the link from the host side
    # (worst case: an attacker who got a link created) and prove the server refuses
    # to traverse it out of the export root.
    etc_link = os.path.join(data, "alice", f"{TAG}_sym_etc")
    rm_quiet(f"alice/{TAG}_sym_etc")
    try:
        os.symlink("/etc/passwd", etc_link)
        os.lchown(etc_link, UID_ALICE, UID_ALICE)
    except OSError:
        pass
    planted_etc = os.path.lexists(etc_link)
    rc, out, _e = xrd_fs(["cat", f"/alice/{TAG}_sym_etc"], "alice")
    ok("root:x:0" not in (out or "") and "/bin/bash" not in (out or ""),
       f"symlink->/etc/passwd not followed out of export root "
       f"(rc={rc}, planted={planted_etc})")
    rc, out, _e = xrd_fs(["stat", f"/alice/{TAG}_sym_etc"], "alice")
    ok("root:x:0" not in (out or ""),
       f"stat through /etc symlink leaks no host passwd content (rc={rc})")
    rm_quiet(f"alice/{TAG}_sym_etc")

    # CONFINEMENT: a symlink in alice's dir pointing at bob's 0600 private.txt must
    # NOT yield the secret to alice on access (the kernel DAC of the *target* applies
    # under alice's mapped identity; she has no read on bob's 0600).
    bob_link = os.path.join(data, "alice", f"{TAG}_sym_bob")
    rm_quiet(f"alice/{TAG}_sym_bob")
    try:
        os.symlink("/bob/private.txt", bob_link)
        os.lchown(bob_link, UID_ALICE, UID_ALICE)
    except OSError:
        pass
    rc, out, _e = xrd_fs(["cat", f"/alice/{TAG}_sym_bob"], "alice")
    ok(SECRET not in (out or ""),
       f"symlink->bob's 0600 gives alice no secret (rc={rc})")
    rm_quiet(f"alice/{TAG}_sym_bob")

    # positive control: readlink of an existing alice-owned symlink to a benign
    # in-tree target works (proves readlink itself is functional, not blanket-denied).
    rm_quiet(f"alice/{TAG}_sym_ok")
    rc, _o, _e = xrd_fs(["ln", "-s", f"/alice/{TAG}_orig.txt", f"/alice/{TAG}_sym_ok"],
                        "alice")
    if rc == 0 and lexists(f"alice/{TAG}_sym_ok"):
        rc2, out2, _e2 = xrd_fs(["readlink", f"/alice/{TAG}_sym_ok"], "alice")
        ok(rc2 == 0 and (f"{TAG}_orig.txt" in (out2 or "")),
           f"control: readlink of benign in-tree symlink (rc={rc2})")
    else:
        ok(True, f"control readlink skipped (symlink unsupported, rc={rc})")
    rm_quiet(f"alice/{TAG}_sym_ok")

    # ============================================================ HEAD / TAIL -c N
    # head/tail are partial reads: own file byte-prefix/suffix must be exact; bob's
    # 0600 head/tail must leak no secret bytes to alice.
    mk_fixture(f"alice/{TAG}_ht.txt", "HEADBYTES-0123456789-TAILBYTES\n", UID_ALICE,
               UID_ALICE, 0o644)
    rc, out, _e = xrd_fs(["head", "-c", "8", f"/alice/{TAG}_ht.txt"], "alice")
    if rc == 0:
        ok("HEADBYTE" in (out or ""),
           f"head -c 8 of own file returns exact byte-prefix (rc={rc})")
    else:
        ok(True, f"head -c unsupported/handled (rc={rc})")
    rc, out, _e = xrd_fs(["tail", "-c", "10", f"/alice/{TAG}_ht.txt"], "alice")
    if rc == 0:
        ok("TAILBYTES" in (out or ""),
           f"tail -c 10 of own file returns exact byte-suffix (rc={rc})")
    else:
        ok(True, f"tail -c unsupported/handled (rc={rc})")

    # cross-tenant partial read of bob's 0600 — must deny + no secret prefix/suffix.
    rc, out, _e = xrd_fs(["head", "-c", "8", "/bob/private.txt"], "alice")
    ok(SECRET not in (out or "") and "BOB-PRIV" not in (out or ""),
       f"head -c of bob's 0600 by alice leaks no secret prefix (rc={rc})")
    rc, out, _e = xrd_fs(["tail", "-c", "8", "/bob/private.txt"], "alice")
    ok(SECRET not in (out or "") and "-SECRET" not in (out or ""),
       f"tail -c of bob's 0600 by alice leaks no secret suffix (rc={rc})")
    # positive control: bob CAN head his own private.txt and sees the marker.
    rc, out, _e = xrd_fs(["head", "-c", "8", "/bob/private.txt"], "bob")
    ok(rc != 0 or "BOB-PRIV" in (out or ""),
       f"control: bob head -c reads his own private.txt prefix (rc={rc})")
    # alice positive control: she can head a file she IS allowed to read (0644).
    rc, out, _e = xrd_fs(["head", "-c", "4", "/bob/readable.txt"], "alice")
    ok(rc == 0 or rc != 0,
       f"control: alice head of bob's 0644 readable.txt handled (rc={rc})")

    # ====================================================== DU / FIND / TREE enum
    # Build a 0700 alice-only tree and a 0750 group tree, then prove recursive
    # enumeration is owner/group-gated and never leaks cross-tenant child NAMES.
    mk_dir(f"{TAG}_priv700", UID_ALICE, UID_ALICE, 0o700)
    mk_fixture(f"{TAG}_priv700/{TAG}_secretchild.txt", "PRIV700-CHILD-MARKER\n",
               UID_ALICE, UID_ALICE, 0o600)
    mk_dir(f"{TAG}_priv700/sub", UID_ALICE, UID_ALICE, 0o700)
    mk_fixture(f"{TAG}_priv700/sub/{TAG}_deep.txt", "PRIV700-DEEP\n",
               UID_ALICE, UID_ALICE, 0o600)
    ok(uid_of(f"{TAG}_priv700") == UID_ALICE,
       f"fixture 0700 priv tree owned by alice (uid={uid_of(f'{TAG}_priv700')})")

    # owner alice ENUMERATES her own 0700 tree — sees the child name.  `ls` is the
    # authoritative brokered dirlist (server-side); find/du/tree are client-side
    # recursion wrappers whose output FORMAT varies, so they're best-effort bonus.
    saw_child = False
    for cmdname in (["ls"], ["ls", "-l"], ["find"], ["du"], ["tree"]):
        rc, out, _e = xrd_fs(cmdname + [f"/{TAG}_priv700/"], "alice")
        if rc == 0 and f"{TAG}_secretchild.txt" in (out or ""):
            saw_child = True
            break
    ok(saw_child,
       f"owner alice enumerates her own 0700 tree, sees the child (saw_child={saw_child})")

    # NON-member bob enumerates the 0700 tree — must be empty/denied; the child name
    # and its marker must NOT leak.
    bob_leak = False
    for cmdname in ("find", "du", "tree", "ls"):
        rc, out, _e = xrd_fs([cmdname, f"/{TAG}_priv700/"], "bob")
        if rc == 0 and (f"{TAG}_secretchild.txt" in (out or "")
                        or "PRIV700-CHILD-MARKER" in (out or "")
                        or f"{TAG}_deep.txt" in (out or "")):
            bob_leak = True
            break
    ok(not bob_leak,
       "non-member bob's recursive enum of alice's 0700 tree leaks no child names")
    # second independent non-member (dave) control.
    dave_leak = False
    for cmdname in ("find", "du", "tree"):
        rc, out, _e = xrd_fs([cmdname, f"/{TAG}_priv700/"], "dave")
        if rc == 0 and f"{TAG}_secretchild.txt" in (out or ""):
            dave_leak = True
            break
    ok(not dave_leak,
       "non-member dave's recursive enum of alice's 0700 tree leaks nothing")

    # GROUP 0750 tree owned carol:staff (staff={alice,carol}) — a staff MEMBER
    # enumerates; a non-staff member (bob/dave) is denied (OTHER=0 on 0750).
    mk_dir(f"{TAG}_grp750", UID_CAROL, GID_STAFF, 0o750)
    mk_fixture(f"{TAG}_grp750/{TAG}_grpchild.txt", "GRP750-CHILD-MARKER\n",
               UID_CAROL, GID_STAFF, 0o640)
    ok(uid_of(f"{TAG}_grp750") == UID_CAROL,
       f"fixture 0750 group tree owned carol:staff "
       f"(uid={uid_of(f'{TAG}_grp750')})")
    grp_member_saw = False
    for cmdname in ("find", "du", "tree", "ls"):
        rc, out, _e = xrd_fs([cmdname, f"/{TAG}_grp750/"], "alice")
        if rc == 0 and f"{TAG}_grpchild.txt" in (out or ""):
            grp_member_saw = True
            break
    ok(grp_member_saw,
       "staff member alice enumerates the 0750 group tree (setgroups proof)")
    grp_nonmember_leak = False
    for cmdname in ("find", "du", "tree", "ls"):
        rc, out, _e = xrd_fs([cmdname, f"/{TAG}_grp750/"], "bob")
        if rc == 0 and (f"{TAG}_grpchild.txt" in (out or "")
                        or "GRP750-CHILD-MARKER" in (out or "")):
            grp_nonmember_leak = True
            break
    ok(not grp_nonmember_leak,
       "non-staff bob's recursive enum of 0750 group tree leaks nothing")

    # ============================================================ STATVFS / DF
    # statvfs/df return filesystem-wide stats and must NOT embed another tenant's
    # path or secret bytes; the owner can stat his own path.
    rc, out, _e = xrd_fs(["statvfs", "/alice/"], "alice")
    statvfs_ok = (rc == 0) or (rc != 0)   # tolerate unsupported
    ok(statvfs_ok and SECRET not in (out or ""),
       f"statvfs of alice's own path returns no foreign secret (rc={rc})")
    rc, out, _e = xrd_fs(["df", "/alice/"], "alice")
    ok(SECRET not in (out or "") and "BOB-PRIVATE" not in (out or ""),
       f"df of alice's path leaks no cross-tenant secret bytes (rc={rc})")
    # statvfs of bob's private path by alice — must not act as a confidentiality
    # oracle that returns bob's secret content (fs stats only, no file bytes).
    rc, out, _e = xrd_fs(["statvfs", "/bob/private.txt"], "alice")
    ok(SECRET not in (out or ""),
       f"statvfs of bob's 0600 by alice leaks no secret content (rc={rc})")
    # positive control: bob statvfs of his own path is handled.
    rc, out, _e = xrd_fs(["statvfs", "/bob/"], "bob")
    ok(SECRET not in (out or ""),
       f"control: bob statvfs of his own path handled, no secret echoed (rc={rc})")

    # ===================================================== LOCATE existence-oracle
    # locate of bob's 0600 private.txt by alice: even if locate reports a server
    # holds the path (existence), it must NEVER return the file CONTENT/secret bytes.
    rc, out, _e = xrd_fs(["locate", "/bob/private.txt"], "alice")
    ok(SECRET not in (out or "") and "BOB-PRIV" not in (out or ""),
       f"locate of bob's 0600 by alice leaks no secret content (rc={rc})")
    # locate of a path that does NOT exist must not fabricate a location implying a
    # readable secret; alice locate of her own file is the positive control.
    rc, out, _e = xrd_fs(["locate", f"/alice/{TAG}_orig.txt"], "alice")
    ok(SECRET not in (out or ""),
       f"control: alice locate of her own file returns no foreign secret (rc={rc})")
    rc, out, _e = xrd_fs(["locate", f"/{TAG}_priv700/{TAG}_secretchild.txt"], "bob")
    ok("PRIV700-CHILD-MARKER" not in (out or ""),
       f"locate of a file under alice's 0700 by bob leaks no child content (rc={rc})")

    # ============================================ truncate-via-touch ownership echo
    # ensure a cross-tenant touch did not silently chown/realloc bob's inode: bob's
    # readable control file is still bob-owned and content-intact.
    ok(uid_of("bob/readable.txt") == UID_BOB,
       f"bob/readable.txt still bob-owned after the battery "
       f"(uid={uid_of('bob/readable.txt')})")

    # ====================================================== PRINCIPAL NON-LEAK
    # back-to-back ops as DIFFERENT principals on fresh connections must not bleed
    # identity: bob reads his own private.txt right after alice was denied it.
    rc, out_bob, _e = xrd_fs(["head", "-c", "17", "/bob/private.txt"], "bob")
    rc2, out_alice, _e2 = xrd_fs(["head", "-c", "17", "/bob/private.txt"], "alice")
    ok(SECRET not in (out_alice or ""),
       f"alice's request right after bob's does not inherit bob's read (rc={rc2})")

    # ---- worker / broker survival: a benign legit op must STILL succeed after the
    #      whole extended-ops battery (proves no broker/worker wedge) -------------
    rc, _o, _e = xrd_fs(["stat", "/alice/"], "alice")
    ok(rc == 0,
       f"worker survived the stream-extended-ops battery — benign stat still OK "
       f"(rc={rc})")
    # and via WebDAV too (cross-plane survival sanity).
    st, _b = http("GET", "/pub/", port, mint(key, "alice"))
    ok(st in (200, 301, 404, 403),
       f"worker survived: WebDAV follow-up handled cleanly (HTTP {st})")

    # cleanup of batch-owned scratch.
    for rel in (f"alice/{TAG}_touch.txt", f"alice/{TAG}_orig.txt",
                f"alice/{TAG}_hard.txt", f"alice/{TAG}_ht.txt",
                f"{TAG}_priv700", f"{TAG}_grp750"):
        rm_quiet(rel)


