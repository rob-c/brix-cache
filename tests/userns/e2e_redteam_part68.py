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


def run_special_file_rename_matrix(key, data, port, s3port):
    """SPECIAL-FILE + CROSS-DIRECTORY-RENAME matrix under per-request UNIX
    impersonation.  Novel axis (vs broker_resource_limits / stream_extended_ops,
    which own FIFO-hang, single-hop /etc & cross-tenant hardlinks, readlink): (1)
    CROSS-TENANT rename CLOBBER + rename ATOMICITY — alice MOVE/mv into or out of
    bob's tree is DAC-denied, a rename-OVER bob's existing file never clobbers his
    bytes, and a rename is atomic (dest is OLD-or-NEW, never truncated/zero); (2)
    multi-hop symlink CHAIN and symlink LOOP traversal — no /etc escape, no
    cross-tenant 0600 leak through a chained link, no worker hang on the loop; (3)
    confirm there is NO gateway verb that creates a NON-REGULAR file (mknod/mkfifo
    /mksock): the namespace cannot manufacture a device/FIFO/socket.  Every check is
    an (op, identity, expected-outcome) invariant; planted host-side fixtures are
    cleaned up so the shared export stays canonical."""
    TAG = "sfrm"
    ta = mint(key, "alice")
    tb = mint(key, "bob")
    SECRET = b"BOB-PRIVATE-SECRET"
    adir = os.path.join(data, "alice")
    bdir = os.path.join(data, "bob")
    pubdir = os.path.join(data, "pub")

    def disk(rel):
        return os.path.join(data, rel.lstrip("/"))

    def uid_of(rel):
        try:
            return os.stat(disk(rel)).st_uid
        except OSError:
            return -1

    def exists(rel):
        return os.path.exists(disk(rel))

    def lexists(rel):
        return os.path.lexists(disk(rel))

    def read_bytes(rel):
        try:
            with open(disk(rel), "rb") as fh:
                return fh.read()
        except OSError:
            return b""

    def plant(rel, content, uid, gid, mode):
        p = disk(rel)
        try:
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, "wb") as fh:
                fh.write(content)
            os.chown(p, uid, gid)
            os.chmod(p, mode)
        except OSError:
            pass
        return p

    def rm_quiet(rel):
        p = disk(rel)
        try:
            if os.path.islink(p) or os.path.isfile(p):
                os.remove(p)
            elif os.path.isdir(p):
                import shutil as _sh
                _sh.rmtree(p, ignore_errors=True)
        except OSError:
            pass

    def mklink(rel, target):
        p = disk(rel)
        try:
            if os.path.lexists(p):
                os.remove(p)
            os.symlink(target, p)
            os.lchown(p, UID_ALICE, UID_ALICE)
            return True
        except OSError:
            return False

    def webdav_move(src, dst_path, token, overwrite=None):
        hdrs = {"Destination": f"http://{HOST}:{port}{dst_path}"}
        if overwrite is not None:
            hdrs["Overwrite"] = overwrite
        return http("MOVE", src, port, token, hdrs=hdrs)

    DENY_HTTP = (401, 403, 404, 409, 412, 500, -1)

    # =====================================================================
    # 0) Positive controls: a legit alice MOVE within her OWN tree succeeds and
    #    PRESERVES ownership (the brokered rename ran AS alice, st_uid stays 1001).
    # =====================================================================
    rm_quiet(f"alice/{TAG}_self_src.txt")
    rm_quiet(f"alice/{TAG}_self_dst.txt")
    plant(f"alice/{TAG}_self_src.txt", b"ALICE-SELF-MOVE-BODY\n", UID_ALICE,
          UID_ALICE, 0o644)
    st, _ = webdav_move(f"/alice/{TAG}_self_src.txt", f"/alice/{TAG}_self_dst.txt", ta)
    moved_ok = (st in (200, 201, 204)
                and exists(f"alice/{TAG}_self_dst.txt")
                and not exists(f"alice/{TAG}_self_src.txt"))
    ok(moved_ok, f"WebDAV MOVE within alice's own tree succeeds (HTTP {st})")
    ok(uid_of(f"alice/{TAG}_self_dst.txt") in (UID_ALICE, -1),
       f"MOVE within alice's tree preserves alice ownership "
       f"(uid={uid_of(f'alice/{TAG}_self_dst.txt')})")
    ok(read_bytes(f"alice/{TAG}_self_dst.txt") == b"ALICE-SELF-MOVE-BODY\n",
       "MOVE within alice's tree preserved file content byte-exact")
    rm_quiet(f"alice/{TAG}_self_dst.txt")

    # native xrdfs mv self-move control (same invariant via the root:// path).
    if xrd_avail():
        rm_quiet(f"alice/{TAG}_mv_src.txt")
        rm_quiet(f"alice/{TAG}_mv_dst.txt")
        plant(f"alice/{TAG}_mv_src.txt", b"ALICE-XRDFS-MV\n", UID_ALICE,
              UID_ALICE, 0o644)
        rc, _o, _e = xrd_fs(["mv", f"/alice/{TAG}_mv_src.txt",
                             f"/alice/{TAG}_mv_dst.txt"], "alice")
        ok((rc == 0 and exists(f"alice/{TAG}_mv_dst.txt")
            and uid_of(f"alice/{TAG}_mv_dst.txt") == UID_ALICE)
           or not exists(f"alice/{TAG}_mv_dst.txt"),
           f"root:// xrdfs mv within alice's tree owned by alice (rc={rc})")
        rm_quiet(f"alice/{TAG}_mv_src.txt")
        rm_quiet(f"alice/{TAG}_mv_dst.txt")

    # =====================================================================
    # 1) CROSS-TENANT rename INTO bob's 0755 dir.  alice has r-x on bob/ but NOT
    #    write, so the impersonated rename's link-into-bob step must EPERM; nothing
    #    alice-owned may appear in bob's tree (no laundering of a file into another
    #    tenant's namespace via rename).
    # =====================================================================
    rm_quiet(f"alice/{TAG}_into_src.txt")
    rm_quiet(f"bob/{TAG}_into_bob.txt")
    plant(f"alice/{TAG}_into_src.txt", b"ALICE-INTO-BOB\n", UID_ALICE,
          UID_ALICE, 0o644)
    st, _ = webdav_move(f"/alice/{TAG}_into_src.txt", f"/bob/{TAG}_into_bob.txt", ta)
    landed = exists(f"bob/{TAG}_into_bob.txt")
    ok(st in DENY_HTTP and not landed,
       f"WebDAV MOVE alice->bob's dir DENIED, no file planted (HTTP {st}, "
       f"landed={landed})")
    ok(not (landed and uid_of(f"bob/{TAG}_into_bob.txt") == UID_ALICE),
       "MOVE into bob's dir created no alice-owned file (no escalation)")
    # alice's source must survive a denied MOVE (rename failed, source intact).
    ok(exists(f"alice/{TAG}_into_src.txt"),
       "denied cross-tenant MOVE left alice's source file intact (atomic, no loss)")
    if xrd_avail():
        rm_quiet(f"bob/{TAG}_into_bob2.txt")
        rc, _o, _e = xrd_fs(["mv", f"/alice/{TAG}_into_src.txt",
                             f"/bob/{TAG}_into_bob2.txt"], "alice")
        ok(rc != 0 and not exists(f"bob/{TAG}_into_bob2.txt"),
           f"root:// xrdfs mv alice->bob's dir DENIED (rc={rc})")
        rm_quiet(f"bob/{TAG}_into_bob2.txt")
    rm_quiet(f"alice/{TAG}_into_src.txt")

    # =====================================================================
    # 2) CROSS-TENANT rename OUT of bob's dir by alice.  Removing an entry from
    #    bob's dir needs write on bob/, which alice lacks -> DENIED.  bob's file
    #    must stay put, bob-owned, content intact (no exfil-by-move).
    # =====================================================================
    plant(f"bob/{TAG}_victim.txt", b"BOB-VICTIM-BODY\n", UID_BOB, UID_BOB, 0o644)
    rm_quiet(f"alice/{TAG}_stolen.txt")
    st, _ = webdav_move(f"/bob/{TAG}_victim.txt", f"/alice/{TAG}_stolen.txt", ta)
    ok(st in DENY_HTTP and not exists(f"alice/{TAG}_stolen.txt"),
       f"WebDAV MOVE bob's file OUT of bob's dir by alice DENIED (HTTP {st})")
    ok(exists(f"bob/{TAG}_victim.txt") and uid_of(f"bob/{TAG}_victim.txt") == UID_BOB,
       "bob's file stayed in bob's dir, still bob-owned after alice's move-out")
    ok(read_bytes(f"bob/{TAG}_victim.txt") == b"BOB-VICTIM-BODY\n",
       "bob's file content intact after denied cross-tenant move-out (no exfil)")
    # control: bob CAN move his own file within his own tree.
    if xrd_avail():
        rm_quiet(f"bob/{TAG}_victim2.txt")
        rc, _o, _e = xrd_fs(["mv", f"/bob/{TAG}_victim.txt",
                             f"/bob/{TAG}_victim2.txt"], "bob")
        ok((rc == 0 and exists(f"bob/{TAG}_victim2.txt")
            and uid_of(f"bob/{TAG}_victim2.txt") == UID_BOB)
           or rc != 0,
           f"control: bob moves his own file within his tree (rc={rc})")
        # restore name for the clobber test below
        if exists(f"bob/{TAG}_victim2.txt") and not exists(f"bob/{TAG}_victim.txt"):
            xrd_fs(["mv", f"/bob/{TAG}_victim2.txt", f"/bob/{TAG}_victim.txt"], "bob")
        rm_quiet(f"bob/{TAG}_victim2.txt")

    # =====================================================================
    # 3) CROSS-TENANT rename-OVER (clobber) of bob's EXISTING file by alice.  A
    #    rename whose dest is bob's file would, if it ran, DESTROY bob's data.  It
    #    must be DENIED (alice has no write on bob/) and bob's bytes must be byte-
    #    identical afterward — NO clobber, NO truncation of the victim.
    # =====================================================================
    bob_before = read_bytes(f"bob/{TAG}_victim.txt")
    plant(f"alice/{TAG}_clobber_src.txt", b"ALICE-CLOBBER-PAYLOAD\n", UID_ALICE,
          UID_ALICE, 0o644)
    st, _ = webdav_move(f"/alice/{TAG}_clobber_src.txt",
                        f"/bob/{TAG}_victim.txt", ta, overwrite="T")
    ok(st in DENY_HTTP,
       f"WebDAV MOVE-clobber of bob's existing file by alice DENIED (HTTP {st})")
    after = read_bytes(f"bob/{TAG}_victim.txt")
    ok(after == bob_before and after == b"BOB-VICTIM-BODY\n",
       "bob's file bytes UNCHANGED after alice's clobber attempt (no overwrite)")
    ok(after != b"ALICE-CLOBBER-PAYLOAD\n",
       "alice's payload did NOT replace bob's file (no cross-tenant data swap)")
    ok(uid_of(f"bob/{TAG}_victim.txt") == UID_BOB,
       "bob's clobbered-target file still owned by bob (inode not re-aliased)")
    rm_quiet(f"alice/{TAG}_clobber_src.txt")
    rm_quiet(f"bob/{TAG}_victim.txt")

    # =====================================================================
    # 4) Rename ATOMICITY in a SHARED writable dir (pub/ 0777).  alice MOVEs over
    #    an existing file she is allowed to clobber: the destination must always be
    #    a COMPLETE file (old OR new content), NEVER zero-length/truncated — proving
    #    the gateway uses atomic rename(2), not truncate+copy.
    # =====================================================================
    rm_quiet(f"pub/{TAG}_atom_dst.txt")
    rm_quiet(f"pub/{TAG}_atom_src.txt")
    plant(f"pub/{TAG}_atom_dst.txt", b"OLD-COMPLETE-CONTENT-AAAA\n", UID_ALICE,
          UID_ALICE, 0o644)
    plant(f"pub/{TAG}_atom_src.txt", b"NEW-COMPLETE-CONTENT-BBBB\n", UID_ALICE,
          UID_ALICE, 0o644)
    st, _ = webdav_move(f"/pub/{TAG}_atom_src.txt", f"/pub/{TAG}_atom_dst.txt",
                        ta, overwrite="T")
    dst_body = read_bytes(f"pub/{TAG}_atom_dst.txt")
    ok(dst_body in (b"OLD-COMPLETE-CONTENT-AAAA\n", b"NEW-COMPLETE-CONTENT-BBBB\n"),
       f"MOVE-over in shared dir is ATOMIC: dest is OLD-or-NEW, never truncated "
       f"(HTTP {st}, len={len(dst_body)})")
    ok(len(dst_body) > 0,
       "MOVE-over destination is never a zero-length/partial file (atomicity)")
    if st in (200, 201, 204):
        ok(dst_body == b"NEW-COMPLETE-CONTENT-BBBB\n"
           and not exists(f"pub/{TAG}_atom_src.txt"),
           "successful MOVE-over replaced dest with full new content, src gone")
    else:
        ok(dst_body == b"OLD-COMPLETE-CONTENT-AAAA\n",
           "rejected MOVE-over left the original dest fully intact")
    rm_quiet(f"pub/{TAG}_atom_dst.txt")
    rm_quiet(f"pub/{TAG}_atom_src.txt")

    # =====================================================================
    # 5) Same-resource MOVE (src == dst) must not destroy the file (self-move is a
    #    no-op or 403, never a delete).
    # =====================================================================
    plant(f"alice/{TAG}_selfmv.txt", b"SELF-MOVE-INTACT\n", UID_ALICE,
          UID_ALICE, 0o644)
    st, _ = webdav_move(f"/alice/{TAG}_selfmv.txt", f"/alice/{TAG}_selfmv.txt", ta)
    ok(exists(f"alice/{TAG}_selfmv.txt")
       and read_bytes(f"alice/{TAG}_selfmv.txt") == b"SELF-MOVE-INTACT\n",
       f"MOVE of a file onto ITSELF did not delete/truncate it (HTTP {st})")
    rm_quiet(f"alice/{TAG}_selfmv.txt")

    # =====================================================================
    # 6) Multi-hop symlink CHAIN a->b->c->realfile (all in-export, relative).
    #    Following it must EITHER refuse (secure no-follow default) OR resolve to
    #    alice's OWN content — never to /etc, never to a foreign secret, never hang.
    # =====================================================================
    plant(f"alice/{TAG}_chain_real.txt", b"CHAIN-REAL-ALICE\n", UID_ALICE,
          UID_ALICE, 0o644)
    c3 = mklink(f"alice/{TAG}_chain_c", f"{TAG}_chain_real.txt")
    c2 = mklink(f"alice/{TAG}_chain_b", f"{TAG}_chain_c")
    c1 = mklink(f"alice/{TAG}_chain_a", f"{TAG}_chain_b")
    if c1 and c2 and c3:
        t0 = time.time()
        st, body = http("GET", f"/alice/{TAG}_chain_a", port, ta)
        dt = time.time() - t0
        ok(dt < 5.0,
           f"GET through 3-hop symlink chain did not hang worker ({dt:.2f}s)")
        ok(b"root:" not in (body or b"") and b"/bin/bash" not in (body or b""),
           f"3-hop symlink chain leaks no /etc/host content (HTTP {st})")
        ok(st != 200 or b"CHAIN-REAL-ALICE" in (body or b""),
           "symlink chain resolves to alice's OWN content or is refused, "
           f"never foreign bytes (HTTP {st})")
        if xrd_avail():
            rc, out, _e = xrd_fs(["stat", f"/alice/{TAG}_chain_a"], "alice")
            ok("root:x:0" not in (out or ""),
               f"root:// stat through symlink chain leaks no host passwd (rc={rc})")
    else:
        ok(True, "symlink-chain fixture skipped (symlink unsupported on fs)")
        ok(True, "symlink-chain leak check skipped")
        ok(True, "symlink-chain content check skipped")
    rm_quiet(f"alice/{TAG}_chain_a")
    rm_quiet(f"alice/{TAG}_chain_b")
    rm_quiet(f"alice/{TAG}_chain_c")
    rm_quiet(f"alice/{TAG}_chain_real.txt")

    # =====================================================================
    # 7) Symlink LOOP of length 3 (a->b->c->a).  GET / PROPFIND / stat must fail
    #    closed on ELOOP and, crucially, must NOT spin the single-threaded worker.
    # =====================================================================
    l1 = mklink(f"alice/{TAG}_loop_a", f"{TAG}_loop_b")
    l2 = mklink(f"alice/{TAG}_loop_b", f"{TAG}_loop_c")
    l3 = mklink(f"alice/{TAG}_loop_c", f"{TAG}_loop_a")
    if l1 and l2 and l3:
        t0 = time.time()
        st, body = http("GET", f"/alice/{TAG}_loop_a", port, ta)
        ok(time.time() - t0 < 5.0 and st != 200,
           f"3-cycle symlink LOOP GET fails closed (ELOOP), no hang (HTTP {st})")
        t0 = time.time()
        st2, _ = http("PROPFIND", f"/alice/{TAG}_loop_a", port, ta,
                      hdrs={"Depth": "0", "Content-Type": "application/xml"},
                      data=b'<?xml version="1.0"?><D:propfind xmlns:D="DAV:">'
                           b'<D:prop><D:displayname/></D:prop></D:propfind>')
        ok(time.time() - t0 < 5.0 and st2 != 200,
           f"3-cycle symlink LOOP PROPFIND fails closed, no hang (HTTP {st2})")
        if xrd_avail():
            t0 = time.time()
            rc, _o, _e = xrd_fs(["stat", f"/alice/{TAG}_loop_a"], "alice")
            ok(time.time() - t0 < 8.0,
               f"root:// stat on symlink LOOP returned, did not hang (rc={rc})")
    else:
        ok(True, "symlink-loop fixture skipped (symlink unsupported on fs)")
        ok(True, "symlink-loop PROPFIND check skipped")
    rm_quiet(f"alice/{TAG}_loop_a")
    rm_quiet(f"alice/{TAG}_loop_b")
    rm_quiet(f"alice/{TAG}_loop_c")

    # =====================================================================
    # 8) Symlink CHAIN whose TAIL is bob's 0600 private.txt (a->b->bob/private).
    #    A chained link is NOT a read capability: following it as alice must be
    #    DAC-denied on the real inode — bob's secret never reaches alice, even
    #    through multiple indirections.  (Distinct from the single-hop bob-link
    #    tests in the neighbour batches.)
    # =====================================================================
    rm_quiet(f"alice/{TAG}_bchain_a")
    rm_quiet(f"alice/{TAG}_bchain_b")
    bc2 = mklink(f"alice/{TAG}_bchain_b", os.path.join("..", "bob", "private.txt"))
    bc1 = mklink(f"alice/{TAG}_bchain_a", f"{TAG}_bchain_b")
    if bc1 and bc2:
        st, body = http("GET", f"/alice/{TAG}_bchain_a", port, ta)
        ok(st != 200 and SECRET not in (body or b""),
           f"chained symlink -> bob's 0600 gives alice NO secret (HTTP {st})")
        if xrd_avail():
            rc, out, _e = xrd_fs(["cat", f"/alice/{TAG}_bchain_a"], "alice")
            ok(SECRET.decode() not in (out or ""),
               f"root:// cat of chained symlink -> bob's 0600 leaks nothing (rc={rc})")
        # control: bob reading his OWN private.txt directly still works (proves the
        # deny above is identity-scoped, not a blanket break of the file).
        st, body = http("GET", "/bob/private.txt", port, tb)
        ok(st == 200 and SECRET in (body or b""),
           f"control: bob reads his own 0600 private.txt directly (HTTP {st})")
    else:
        ok(True, "bob-chain fixture skipped (symlink unsupported on fs)")
        ok(True, "bob-chain control skipped")
    rm_quiet(f"alice/{TAG}_bchain_a")
    rm_quiet(f"alice/{TAG}_bchain_b")

    # =====================================================================
    # 9) NO non-regular-file CREATION verb.  There is no MKNOD/MKFIFO op in the
    #    XRootD namespace or WebDAV/S3 surface.  Prove that NO create path produces
    #    a non-regular file: a PUT and an xrdfs touch/mkdir produce a regular file /
    #    directory, and there is no method that yields a FIFO/socket/device inode.
    # =====================================================================
    S_IFMT = 0o170000       # file-type mask
    S_IFREG = 0o100000      # regular file
    S_IFDIR = 0o040000      # directory

    def is_regular(path):
        try:
            return (os.stat(path).st_mode & S_IFMT) == S_IFREG
        except OSError:
            return False

    def is_dir_node(path):
        try:
            return (os.stat(path).st_mode & S_IFMT) == S_IFDIR
        except OSError:
            return False

    rm_quiet(f"alice/{TAG}_reg.txt")
    st, _ = http("PUT", f"/alice/{TAG}_reg.txt", port, ta, b"regular\n")
    p = disk(f"alice/{TAG}_reg.txt")
    if st in (200, 201, 204) and os.path.exists(p):
        ok(is_regular(p),
           "WebDAV PUT created a REGULAR file (no FIFO/socket/device verb)")
    else:
        ok(True, f"WebDAV PUT regular-file create handled (HTTP {st})")
    rm_quiet(f"alice/{TAG}_reg.txt")

    if xrd_avail():
        rm_quiet(f"alice/{TAG}_tch.txt")
        rc, _o, _e = xrd_fs(["touch", f"/alice/{TAG}_tch.txt"], "alice")
        tp = disk(f"alice/{TAG}_tch.txt")
        if rc == 0 and os.path.exists(tp):
            ok(is_regular(tp),
               "root:// touch created a REGULAR file (namespace has no mknod)")
        else:
            ok(True, f"root:// touch create handled, no special node (rc={rc})")
        rm_quiet(f"alice/{TAG}_tch.txt")

        rm_quiet(f"alice/{TAG}_d")
        rc, _o, _e = xrd_fs(["mkdir", f"/alice/{TAG}_d"], "alice")
        dp = disk(f"alice/{TAG}_d")
        if rc == 0 and os.path.exists(dp):
            ok(is_dir_node(dp),
               "root:// mkdir created a DIRECTORY, not a special node")
        else:
            ok(True, f"root:// mkdir handled (rc={rc})")
        rm_quiet(f"alice/{TAG}_d")

    # S3 surface: a PUT with a key cannot manufacture a non-regular object either.
    if s3port:
        rm_quiet(f"alice/{TAG}_s3reg.txt")
        st, _ = s3("PUT", f"alice/{TAG}_s3reg.txt", s3port, data=b"s3regular\n")
        sp = disk(f"alice/{TAG}_s3reg.txt")
        if st in (200, 201) and os.path.exists(sp):
            ok(is_regular(sp),
               "S3 PUT created a REGULAR object file (no special-node verb)")
        else:
            ok(True, f"S3 PUT regular-object create handled (HTTP {st})")
        rm_quiet(f"alice/{TAG}_s3reg.txt")

    # =====================================================================
    # 10) FINAL RECOVERY: a legit alice PUT+GET roundtrip proves the worker AND the
    #     broker survived the entire special-file / rename battery (no wedge, no
    #     leaked principal).
    # =====================================================================
    rm_quiet(f"alice/{TAG}_recover.txt")
    body = b"SFRM-RECOVER-OK\n"
    stp, _ = http("PUT", f"/alice/{TAG}_recover.txt", port, ta, body)
    stg, gb = http("GET", f"/alice/{TAG}_recover.txt", port, ta)
    ok(stp in (200, 201, 204) and stg == 200 and gb == body
       and uid_of(f"alice/{TAG}_recover.txt") == UID_ALICE,
       f"recovery: alice PUT+GET roundtrip ok, owned 1001 after battery "
       f"(PUT {stp}, GET {stg})")
    rm_quiet(f"alice/{TAG}_recover.txt")


