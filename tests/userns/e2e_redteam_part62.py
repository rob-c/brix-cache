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


def run_multistep_lifecycle_invariants(key, data, port, s3port):
    """MULTI-STEP LIFECYCLE END-STATE INVARIANTS under per-request UNIX impersonation.

    Every other combo batch asserts properties PER STEP (run_combo_setgid_via_copymove
    checks the group on each copied/moved file; run_combo_multipart_lock_identity checks
    each interrupted-multipart/lock transition; run_combo_error_rollback checks each
    FAILED op leaves no residue).  This batch instead drives chains that SUCCEED all the
    way through and asserts a single invariant at the END of the whole chain — the
    property that only holds once every step has run.  Each sequence ends in a DISTINCT
    end-state observation: ownership stability across a verb chain, child ownership after
    a whole-collection MOVE, clean recursive-DELETE end-state, byte-exact ordered
    multipart assembly, setgid inheritance for a freshly CREATED (not copied) file,
    a non-empty rmdir that must FAIL and leave the subtree wholly intact, overwrite
    idempotency (replace not append, single inode), and a rename-chain leaving exactly
    one inode.  All fixtures prefixed `msli_` to avoid collisions with the battery."""
    TAG = "msli"
    base = f"http://{HOST}:{port}"
    ta = mint(key, "alice")
    tb = mint(key, "bob")
    tc = mint(key, "carol")

    # ---- on-disk introspection (runs as in-ns root, sees true uid/gid/mode) ----
    def realp(rel):
        return os.path.join(data, rel.lstrip("/"))

    def st_of(rel):
        try:
            p = realp(rel)
            return os.stat(p) if os.path.exists(p) else None
        except OSError:
            return None

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

    def has(body, needle):
        if body is None:
            return False
        if isinstance(body, str):
            body = body.encode("utf-8", "replace")
        return needle in body

    # =====================================================================
    # SEQ 1 — alice CREATE -> alice tighten to 0600 -> bob GET.
    # END-STATE INVARIANT: after the successful create+chmod chain the file is
    # still alice-owned at 0600 AND a cross-tenant reader (bob) gets zero bytes.
    # (Distinct from rollback: every step here SUCCEEDS; the invariant is the
    # post-tighten ownership+confidentiality end-state, not a failed-op cleanup.)
    # =====================================================================
    S1_REL = f"alice/{TAG}_s1_tighten.txt"
    S1_MARK = b"MSLI-S1-ALICE-CONFIDENTIAL-7Q"
    http("DELETE", "/" + S1_REL, port, ta)
    c1, _ = http("PUT", "/" + S1_REL, port, ta, S1_MARK)
    ok(c1 in (200, 201, 204), f"{TAG}/s1: alice PUT creates her file (HTTP {c1})")
    pp1, _ = http("PROPPATCH", "/" + S1_REL, port, ta,
                  data=b'<?xml version="1.0"?><D:propertyupdate xmlns:D="DAV:"'
                       b' xmlns:Z="urn:x"><D:set><D:prop><Z:tag>t1</Z:tag>'
                       b'</D:prop></D:set></D:propertyupdate>',
                  hdrs={"Content-Type": "application/xml"})
    try:
        os.chmod(realp(S1_REL), 0o600)
        chm1 = True
    except OSError:
        chm1 = False
    ok(chm1, f"{TAG}/s1: 0600 tighten applied (os.chmod)")
    sb1, bb1 = http("GET", "/" + S1_REL, port, tb)   # bob: cross-tenant reader
    s1 = st_of(S1_REL)
    # The terminal invariant: alice-owned 0600 AND bob denied AND no marker leak.
    ok(s1 is not None and s1.st_uid == UID_ALICE
       and (s1.st_mode & 0o777) == 0o600
       and s1.st_uid not in (UID_SVC, 0)
       and sb1 in (401, 403, 404, 500) and not has(bb1, S1_MARK),
       f"{TAG}/s1 INVARIANT: after create+proppatch+tighten the file is "
       f"alice:0600 and bob's read is denied+empty "
       f"(uid={getattr(s1,'st_uid',None)} HTTP_bob={sb1})")

    # =====================================================================
    # SEQ 2 — alice MKCOL coll -> PUT 3 distinct files into it -> MOVE the WHOLE
    # collection to a new path.
    # END-STATE INVARIANT: at the NEW path every child is still alice-owned with
    # byte-exact content, and NOTHING remains at the OLD path.  (setgid batch
    # COPYs single files into a setgid dir; this is a plain whole-collection MOVE
    # whose invariant is child-ownership + content survival across the rename.)
    # =====================================================================
    C_OLD = f"alice/{TAG}_s2_coll"
    C_NEW = f"alice/{TAG}_s2_moved"
    http("DELETE", "/" + C_OLD, port, ta)
    http("DELETE", "/" + C_NEW, port, ta)
    mk2, _ = http("MKCOL", "/" + C_OLD, port, ta)
    ok(mk2 in (200, 201), f"{TAG}/s2: alice MKCOL collection (HTTP {mk2})")
    kids = {"a.txt": b"MSLI-S2-CHILD-A", "b.txt": b"MSLI-S2-CHILD-BB",
            "c.txt": b"MSLI-S2-CHILD-CCC"}
    put_all = True
    for nm, bd in kids.items():
        pc, _ = http("PUT", f"/{C_OLD}/{nm}", port, ta, bd)
        put_all = put_all and pc in (200, 201, 204)
    ok(put_all, f"{TAG}/s2: alice PUT 3 children into the collection")
    mv2, _ = http("MOVE", "/" + C_OLD, port, ta,
                  hdrs={"Destination": base + "/" + C_NEW, "Depth": "infinity"})
    ok(mv2 in (200, 201, 204),
       f"{TAG}/s2: alice MOVE whole collection to new path (HTTP {mv2})")
    # Terminal invariant over ALL children at the destination.
    all_ok = True
    for nm, bd in kids.items():
        cs = st_of(f"{C_NEW}/{nm}")
        if cs is None or cs.st_uid != UID_ALICE or cs.st_uid in (UID_SVC, 0):
            all_ok = False
        if body_of(f"{C_NEW}/{nm}") != bd:
            all_ok = False
    ok(all_ok,
       f"{TAG}/s2 INVARIANT: every moved child is alice-owned with byte-exact "
       f"content at the new path (not svc/root)")
    ok(not exists(C_OLD),
       f"{TAG}/s2 INVARIANT: old collection path fully gone after MOVE (rename, "
       f"no stray copy left behind)")

    # =====================================================================
    # SEQ 3 — alice MKCOL -> PUT a file -> recursive DELETE the collection.
    # END-STATE INVARIANT: the whole subtree is gone AND the parent dir contains
    # no svc/root-owned residue from the delete (a successful recursive delete
    # leaves a clean namespace — distinct from rollback's *failed*-op residue).
    # =====================================================================
    D_COLL = f"alice/{TAG}_s3_del"
    http("DELETE", "/" + D_COLL, port, ta)
    mk3, _ = http("MKCOL", "/" + D_COLL, port, ta)
    ok(mk3 in (200, 201), f"{TAG}/s3: alice MKCOL deletable collection (HTTP {mk3})")
    http("PUT", f"/{D_COLL}/inner.txt", port, ta, b"MSLI-S3-INNER")
    http("MKCOL", f"/{D_COLL}/sub", port, ta)
    http("PUT", f"/{D_COLL}/sub/deep.txt", port, ta, b"MSLI-S3-DEEP")
    seeded3 = exists(f"{D_COLL}/inner.txt") and exists(f"{D_COLL}/sub/deep.txt")
    ok(seeded3, f"{TAG}/s3: collection populated with nested children")
    # The WebDAV module implements NON-recursive collection DELETE
    # (src/protocols/webdav/namespace.c sets opts.require_empty_dir = 1): a DELETE of a
    # non-empty collection is refused with 409 Conflict and leaves the subtree
    # wholly intact (no partial wipe) — same policy as S3 BucketNotEmpty.  This
    # is the documented/tested contract (test_webdav_delete_lock_security.py:
    # test_delete_nonempty_collection_returns_409).  Assert that refusal, then
    # walk the documented happy path (empty depth-first, then drop the now-empty
    # collection) to reach the SAME clean end-state this invariant checks.
    dl3_busy, _ = http("DELETE", "/" + D_COLL, port, ta)
    ok(dl3_busy == 409,
       f"{TAG}/s3: alice DELETE of NON-empty collection refused 409 Conflict "
       f"(non-recursive WebDAV policy; HTTP {dl3_busy})")
    http("DELETE", f"/{D_COLL}/sub/deep.txt", port, ta)
    http("DELETE", f"/{D_COLL}/sub", port, ta)
    http("DELETE", f"/{D_COLL}/inner.txt", port, ta)
    dl3, _ = http("DELETE", "/" + D_COLL, port, ta)
    ok(dl3 in (200, 204), f"{TAG}/s3: alice DELETE now-empty collection (HTTP {dl3})")
    # scan alice/ for any new svc/root-owned entry matching this seq's prefix.
    leftover = []
    try:
        for n in os.listdir(realp("alice")):
            if not n.startswith(f"{TAG}_s3"):
                continue
            try:
                u = os.stat(os.path.join(realp("alice"), n)).st_uid
            except OSError:
                continue
            if u in (UID_SVC, 0):
                leftover.append((n, u))
    except OSError:
        pass
    ok(not exists(D_COLL) and not leftover,
       f"{TAG}/s3 INVARIANT: recursive DELETE removed the whole subtree and "
       f"left no svc/root residue (leftover={leftover})")

    # =====================================================================
    # SEQ 4 — S3 multipart: alice initiate -> upload part 1 -> part 2 -> complete.
    # END-STATE INVARIANT: the final object is alice-owned, its bytes are the
    # ORDERED concatenation part1||part2 (assembly correctness), and a
    # cross-tenant (bob) GET is denied with no marker leak.  (multipart_lock
    # batch covers abort/RST/cross-tenant-complete; this is a CLEAN 2-part
    # complete whose invariant is ordered byte-exact assembly as the end-state.)
    # =====================================================================
    if not s3port:
        ok(True, f"{TAG}/s4: S3 port down — multipart-assembly invariant skipped")
    else:
        # confirm S3 plane is answering before driving the lifecycle.
        s4live, _ = s3("GET", "", s3port, params={"list-type": "2"})
        if s4live == -1:
            ok(True, f"{TAG}/s4: S3 not answering — assembly invariant skipped")
        else:
            S4_KEY = f"alice/{TAG}_s4_mpu.bin"
            P1 = b"MSLI-S4-PART-ONE-".ljust(64, b"1") * 80    # ~5 KiB, distinct
            P2 = b"MSLI-S4-PART-TWO-".ljust(64, b"2") * 80    # ~5 KiB, distinct
            s3("DELETE", S4_KEY, s3port)
            ini, ib = s3("POST", S4_KEY, s3port, params={"uploads": ""})
            m = re.search(rb"<UploadId>([^<]+)</UploadId>", ib or b"")
            if ini in (200, 201) and m:
                up = m.group(1).decode()
                pe = []
                pok = True
                for n, pb in ((1, P1), (2, P2)):
                    ps, pbody = s3("PUT", S4_KEY, s3port,
                                   params={"uploadId": up, "partNumber": str(n)},
                                   data=pb)
                    et = re.search(rb'ETag>\\?"?([^"<\\]+)', pbody or b"")
                    pe.append((n, et.group(1).decode() if et else "etag"))
                    pok = pok and ps in (200, 201)
                ok(pok, f"{TAG}/s4: alice uploaded 2 distinct multipart parts")
                cx = b"<CompleteMultipartUpload>"
                for n, et in pe:
                    cx += (f"<Part><PartNumber>{n}</PartNumber>"
                           f"<ETag>{et}</ETag></Part>").encode()
                cx += b"</CompleteMultipartUpload>"
                cs, _ = s3("POST", S4_KEY, s3port, params={"uploadId": up}, data=cx)
                fst = st_of(S4_KEY)
                disk = body_of(S4_KEY)
                # ordered-assembly invariant: exact P1||P2, alice-owned.
                ok(cs in (200, 201) and fst is not None
                   and fst.st_uid == UID_ALICE and fst.st_uid not in (UID_SVC, 0)
                   and disk == (P1 + P2),
                   f"{TAG}/s4 INVARIANT: completed object is alice-owned and bytes "
                   f"== ordered part1||part2 ({len(disk)}=={len(P1)+len(P2)}? "
                   f"complete={cs})")
                # cross-tenant denial of the assembled object (bob as accessor).
                bs, bb = s3("GET", S4_KEY, s3port, access_key="bob")
                ok(bs in (401, 403, 404) and not has(bb, b"MSLI-S4-PART"),
                   f"{TAG}/s4 INVARIANT: bob cross-tenant GET of alice's assembled "
                   f"object is denied with no part-marker leak (HTTP {bs})")
                s3("DELETE", S4_KEY, s3port)
            else:
                ok(False, f"{TAG}/s4: multipart initiate failed (HTTP {ini})")

    # =====================================================================
    # SEQ 5 — alice CREATE a fresh file (PUT) directly INSIDE a 02770 alice:staff
    # setgid dir, then tighten to 0640.
    # END-STATE INVARIANT: the freshly-CREATED (not copied/moved) file inherits
    # group=staff and owner=alice; a SECOND staff member (carol) can then read it
    # via the inherited group while a NON-staff tenant (bob) is denied.  (setgid
    # batch only inherits through COPY/MOVE/TPC; this proves inheritance on the
    # plain create path as a lifecycle end-state with a positive+negative probe.)
    # =====================================================================
    SG = f"{TAG}_s5_sgid"
    sg_dir = realp(SG)
    try:
        os.makedirs(sg_dir, exist_ok=True)
        os.chown(sg_dir, UID_ALICE, GID_STAFF)
        os.chmod(sg_dir, 0o2770)
        ensure_traversable(sg_dir)
        sgmade = True
    except OSError:
        sgmade = False
    sgst = st_of(SG)
    ok(sgmade and sgst is not None and (sgst.st_mode & 0o2000)
       and sgst.st_gid == GID_STAFF,
       f"{TAG}/s5: 02770 alice:staff setgid dir present on disk")
    S5_REL = f"{SG}/{TAG}_s5_created.txt"
    S5_MARK = b"MSLI-S5-STAFF-GROUP-CREATED-3K"
    c5, _ = http("PUT", "/" + S5_REL, port, ta, S5_MARK)
    ok(c5 in (200, 201, 204),
       f"{TAG}/s5: alice CREATEs a fresh file inside the setgid dir (HTTP {c5})")
    s5 = st_of(S5_REL)
    ok(s5 is not None and s5.st_gid == GID_STAFF and s5.st_uid == UID_ALICE
       and s5.st_uid not in (UID_SVC, 0),
       f"{TAG}/s5 INVARIANT: freshly-created file INHERITS group=staff and is "
       f"owned by alice (uid={getattr(s5,'st_uid',None)} "
       f"gid={getattr(s5,'st_gid',None)})")
    try:
        os.chmod(realp(S5_REL), 0o640)
    except OSError:
        pass
    rc5, rb5 = http("GET", "/" + S5_REL, port, tc)   # carol = staff member
    bc5, bb5 = http("GET", "/" + S5_REL, port, tb)   # bob = NOT staff
    ok(rc5 == 200 and has(rb5, S5_MARK)
       and bc5 in (401, 403, 404, 500) and not has(bb5, S5_MARK),
       f"{TAG}/s5 INVARIANT: created-file's inherited staff group grants carol "
       f"(member) but denies bob (non-member) — group is real, not cosmetic "
       f"(carol={rc5} bob={bc5})")

    # =====================================================================
    # SEQ 6 — alice mkdir chain top/mid/leaf -> PUT a file in leaf -> attempt to
    # rmdir the NON-EMPTY mid directory.
    # END-STATE INVARIANT: the rmdir is REFUSED (ENOTEMPTY) and the ENTIRE subtree
    # (top, mid, leaf, the file) survives unchanged + alice-owned.  (Distinct from
    # rollback's staging-residue: here the failure is a directory-removal refusal
    # whose invariant is tree-INTACTNESS, not absence of temp files.)
    # =====================================================================
    A = "alice"
    TOP = f"/{A}/{TAG}_s6_top"
    MID = TOP + "/mid"
    LEAF = MID + "/leaf"
    xrd_fs(["rm", LEAF + "/f.bin"], "alice")
    xrd_fs(["rmdir", LEAF], "alice")
    xrd_fs(["rmdir", MID], "alice")
    xrd_fs(["rmdir", TOP], "alice")
    r_top, _, _ = xrd_fs(["mkdir", TOP], "alice")
    r_mid, _, _ = xrd_fs(["mkdir", MID], "alice")
    r_leaf, _, _ = xrd_fs(["mkdir", LEAF], "alice")
    ok(r_top == 0 and r_mid == 0 and r_leaf == 0,
       f"{TAG}/s6: alice built 3-level mkdir chain (rc={r_top},{r_mid},{r_leaf})")
    pl6, _ = http("PUT", LEAF + "/f.bin", port, ta, b"MSLI-S6-LEAF-FILE")
    ok(pl6 in (200, 201, 204) and exists(f"{A}/{TAG}_s6_top/mid/leaf/f.bin"),
       f"{TAG}/s6: file planted in the leaf directory (HTTP {pl6})")
    rrc, _, rerr = xrd_fs(["rmdir", MID], "alice")     # mid is NON-empty
    # Terminal invariant: rmdir refused AND every level + the file still present
    # and alice-owned (nothing partially removed, nothing reparented to svc/root).
    lvl = [st_of(f"{A}/{TAG}_s6_top"), st_of(f"{A}/{TAG}_s6_top/mid"),
           st_of(f"{A}/{TAG}_s6_top/mid/leaf"),
           st_of(f"{A}/{TAG}_s6_top/mid/leaf/f.bin")]
    tree_intact = all(s is not None and s.st_uid == UID_ALICE
                      and s.st_uid not in (UID_SVC, 0) for s in lvl)
    ok(rrc != 0 and tree_intact,
       f"{TAG}/s6 INVARIANT: rmdir of non-empty dir REFUSED (rc={rrc}) and the "
       f"full subtree (top/mid/leaf/f.bin) survives intact + alice-owned")

    # =====================================================================
    # SEQ 7 — alice PUT v1 -> PUT v2 OVER the same path (overwrite) -> PUT v3.
    # END-STATE INVARIANT: exactly ONE file at the path holding the LATEST body
    # (replace, not append), still alice-owned, with size == len(v3) and no stray
    # .xrd-tmp / .part residue beside it.  (Idempotent-overwrite end-state; no
    # other combo batch asserts replace-not-append + single-inode terminal state.)
    # =====================================================================
    S7_REL = f"alice/{TAG}_s7_overwrite.txt"
    http("DELETE", "/" + S7_REL, port, ta)
    v1 = b"MSLI-S7-VERSION-ONE"
    v2 = b"MSLI-S7-VERSION-TWO-LONGER-BODY"
    v3 = b"MSLI-S7-V3"
    o1, _ = http("PUT", "/" + S7_REL, port, ta, v1)
    o2, _ = http("PUT", "/" + S7_REL, port, ta, v2)
    o3, _ = http("PUT", "/" + S7_REL, port, ta, v3)
    ok(o1 in (200, 201, 204) and o2 in (200, 201, 204) and o3 in (200, 201, 204),
       f"{TAG}/s7: alice PUT same path three times ({o1},{o2},{o3})")
    s7 = st_of(S7_REL)
    disk7 = body_of(S7_REL)
    # residue scan in alice/ for this seq (overwrite must not strand temps).
    res7 = []
    try:
        for n in os.listdir(realp("alice")):
            low = n.lower()
            if n.startswith(f"{TAG}_s7") and (".xrd-tmp." in low
                                              or low.endswith(".part")
                                              or ".part." in low):
                res7.append(n)
    except OSError:
        pass
    ok(s7 is not None and disk7 == v3 and len(disk7) == len(v3)
       and s7.st_uid == UID_ALICE and s7.st_uid not in (UID_SVC, 0)
       and not res7,
       f"{TAG}/s7 INVARIANT: overwrite REPLACED content (==v3, size {len(disk7)}) "
       f"as a single alice-owned inode with no temp residue (res={res7})")

    # =====================================================================
    # SEQ 8 — alice PUT -> MOVE to path2 -> MOVE to path3 (rename chain within
    # alice's own tree).
    # END-STATE INVARIANT: exactly ONE inode exists, at the FINAL path, alice-owned
    # with intact content; NEITHER intermediate path retains a copy (no inode
    # leakage across a chain of renames).  (Distinct from setgid's single MOVE: the
    # invariant here is no-stray-copy across MULTIPLE chained renames.)
    # =====================================================================
    P1R = f"alice/{TAG}_s8_p1.txt"
    P2R = f"alice/{TAG}_s8_p2.txt"
    P3R = f"alice/{TAG}_s8_p3.txt"
    for p in (P1R, P2R, P3R):
        http("DELETE", "/" + p, port, ta)
    S8_BODY = b"MSLI-S8-RENAME-CHAIN-BODY"
    p8, _ = http("PUT", "/" + P1R, port, ta, S8_BODY)
    ok(p8 in (200, 201, 204), f"{TAG}/s8: alice PUT initial file (HTTP {p8})")
    mv8a, _ = http("MOVE", "/" + P1R, port, ta,
                   hdrs={"Destination": base + "/" + P2R})
    mv8b, _ = http("MOVE", "/" + P2R, port, ta,
                   hdrs={"Destination": base + "/" + P3R})
    ok(mv8a in (200, 201, 204) and mv8b in (200, 201, 204),
       f"{TAG}/s8: alice chained two MOVEs ({mv8a},{mv8b})")
    s8 = st_of(P3R)
    ok(s8 is not None and s8.st_uid == UID_ALICE and s8.st_uid not in (UID_SVC, 0)
       and body_of(P3R) == S8_BODY
       and not exists(P1R) and not exists(P2R),
       f"{TAG}/s8 INVARIANT: after a 2-hop rename chain exactly ONE alice-owned "
       f"inode with intact content exists at the final path and neither "
       f"intermediate path retains a copy")

    # =====================================================================
    # SEQ 9 — final liveness: prove the worker/broker never wedged through all of
    # the above by serving a fresh legit alice create+read.  (END-STATE health
    # invariant for the whole batch — a single decisive observation.)
    # =====================================================================
    LIVE = f"alice/{TAG}_s9_live.txt"
    LMARK = b"MSLI-S9-LIVENESS"
    http("DELETE", "/" + LIVE, port, ta)
    lp, _ = http("PUT", "/" + LIVE, port, ta, LMARK)
    lg, lgb = http("GET", "/" + LIVE, port, ta)
    ls = st_of(LIVE)
    ok(lp in (200, 201, 204) and lg == 200 and has(lgb, LMARK)
       and ls is not None and ls.st_uid == UID_ALICE,
       f"{TAG}/s9 INVARIANT: after every lifecycle chain a fresh alice "
       f"create+read still works owned alice — worker never wedged "
       f"(PUT {lp} GET {lg})")
    http("DELETE", "/" + LIVE, port, ta)



# ===== Round-8 novel-surface batches (workflow-authored) =====
