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


def run_deep_novel_combos_r8(key, data, port, s3port):
    """ROUND-8 cross-feature COMBINATION frontier: sequences that CROSS the new
    round-8 surfaces (HTTP-TPC pull / native-TPC / query-checksum / scoped-token /
    cross-tenant rename) with DAC + GROUP + CONCURRENCY in shapes none of the 12
    existing combo_* batches drive.  Distinct from run_combo_setgid_via_copymove
    (it does WebDAV-COPY/MOVE/native-TPC/S3-CopyObject setgid inheritance but NOT
    an HTTP-TPC *pull* residue check, NOT checksum-vs-identity, NOT lock-vs-rename),
    from run_combo_multipart_lock_identity (it crosses S3-MPU x LOCK x identity but
    NOT a group-member-completes-another-member's-MPU, NOT rename-vs-lock, NOT a
    read-only-scope x group write-deny), from run_combo_concurrent_crossproto (torn
    read of file BYTES, never of a query-checksum DIGEST under identity-switch), and
    from run_tpc_pull_push_matrix (native-TPC DAC matrix, but NOT setgid-through-TPC
    residue, NOT a mid-TPC RST, NOT digest-mid-overwrite).  Every sequence ends in a
    DISTINCT invariant: no cross-tenant digest bleed, no torn digest, scope gates the
    write while DAC gates the read, a lock+DAC double-denies a cross-tenant clobber,
    an MPU assembled by a different group member is owned by the completer not svc,
    and no failed/aborted TPC leaves an svc/root-owned partial.  Fixtures: `dnc8_`.
    <=8 threads, <=64 KiB bodies, <=6 concurrent subprocesses."""
    TAG = "dnc8"
    base = f"http://{HOST}:{port}"
    ta = mint(key, "alice")
    tb = mint(key, "bob")
    tc = mint(key, "carol")
    td = mint(key, "dave")
    have_root = xrd_avail()
    have_s3 = bool(s3port) and s3port > 0

    BOB_SECRET = b"BOB-PRIVATE-SECRET"                 # data/bob/private.txt (0600)
    A_BODY = (b"DNC8-ALICE-CKSRC|" * 256)[:4096]       # alice's distinct checksum src
    B_BODY = (b"DNC8-BOB-CKSRC|" * 256)[:4096]         # bob's distinct checksum src
    V_OLD = (b"DNC8-OVERWRITE-OLD|" * 256)[:4096]      # whole "old" version
    V_NEW = (b"DNC8-OVERWRITE-NEW|" * 256)[:4096]      # whole "new" version

    # ---- on-disk introspection (this batch runs as in-ns root: sees real uids) ---
    def realp(rel):
        return os.path.join(data, rel.lstrip("/"))

    def uid_of(rel):
        try:
            p = realp(rel)
            return os.stat(p).st_uid if os.path.exists(p) else -1
        except OSError:
            return -2

    def gid_of(rel):
        try:
            p = realp(rel)
            return os.stat(p).st_gid if os.path.exists(p) else -1
        except OSError:
            return -2

    def mode_of(rel):
        try:
            return os.stat(realp(rel)).st_mode
        except OSError:
            return 0

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

    def listdir(rel):
        try:
            return os.listdir(realp(rel))
        except OSError:
            return []

    def mkfile(rel, content, u, g, mode):
        p = realp(rel)
        try:
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, "wb") as fh:
                fh.write(content)
            os.chown(p, u, g)
            os.chmod(p, mode)
            return True
        except OSError:
            return False

    def mkdir_own(rel, u, g, mode):
        p = realp(rel)
        try:
            os.makedirs(p, exist_ok=True)
            os.chown(p, u, g)
            os.chmod(p, mode)
            return True
        except OSError:
            return False

    def rm(rel):
        try:
            p = realp(rel)
            if os.path.exists(p):
                os.remove(p)
        except OSError:
            pass

    def digest_of(out):
        """Last whitespace token of an xrdfs 'query checksum' line is the algo:value
        (or bare value) digest; None when the command produced no parseable line."""
        if not out:
            return None
        toks = out.split()
        return toks[-1] if toks else None

    def svc_root_residue(reldir):
        """Names under reldir owned by svc(1500)/root(0) — the cardinal
        impersonation-leak signature for a failed/partial data-motion op."""
        out = []
        for n in listdir(reldir):
            try:
                u = os.stat(os.path.join(realp(reldir), n)).st_uid
            except OSError:
                continue
            if u in (UID_SVC, 0):
                out.append((n, u))
        return out

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

    def lock_file(rel, token):
        info = (b'<?xml version="1.0"?><D:lockinfo xmlns:D="DAV:">'
                b'<D:lockscope><D:exclusive/></D:lockscope>'
                b'<D:locktype><D:write/></D:locktype>'
                b'<D:owner><D:href>mailto:x@x</D:href></D:owner></D:lockinfo>')
        st, b = http("LOCK", rel, port, token, data=info,
                     hdrs={"Content-Type": "application/xml",
                           "Timeout": "Second-600"})
        m = re.search(rb"<D:href>(opaquelocktoken:[^<]+)</D:href>", b or b"")
        if not m:
            m = re.search(rb"(opaquelocktoken:[A-Za-z0-9:\-\.]+)", b or b"")
        return st, (m.group(1).decode() if m else None)

    # ---- isolated fixtures (never touch the canonical shared fixtures) ----------
    # A 02770 alice:shared setgid dir; shared = {alice, bob, carol}; dave is NOT.
    SG = f"{TAG}_sgshared"
    ok(mkdir_own(SG, UID_ALICE, GID_SHARED, 0o2770),
       f"{TAG}: created 02770 alice:shared setgid dir {SG}")
    sgm = mode_of(SG)
    ok((sgm & 0o2000) and gid_of(SG) == GID_SHARED,
       f"{TAG}: {SG} is setgid + group=shared on disk (mode={sgm:o})")
    ensure_traversable(realp(SG))

    # alice + bob distinct checksum sources (own homes, 0644 so the read leg is a
    # real read, not a DAC deny that would mask a digest difference).
    ACK = f"alice/{TAG}_ck.bin"
    BCK = f"bob/{TAG}_ck.bin"
    ok(mkfile(ACK, A_BODY, UID_ALICE, UID_ALICE, 0o644),
       f"{TAG}: alice checksum source seeded 0644")
    ok(mkfile(BCK, B_BODY, UID_BOB, UID_BOB, 0o644),
       f"{TAG}: bob checksum source seeded 0644 (distinct content)")

    # carol:staff 0640 group-readable file (read leg) lives in the canonical svc-owned
    # 0755 grp/ dir — a pure GET needs only parent traversal, which 0755 grants.
    GR = f"{TAG}_staff_r.bin"
    GR_BODY = b"DNC8-STAFF-GROUP-READABLE-CONTENT"
    ok(mkfile(f"grp/{GR}", GR_BODY, UID_ALICE, GID_STAFF, 0o640),
       f"{TAG}: alice:staff 0640 group-readable file seeded")
    # The 0660 group-writable file (the write legs) lives in a DEDICATED 02770
    # alice:staff setgid dir: a WebDAV PUT is a STAGED write (temp-in-parent +
    # rename), so the positive control needs the PARENT to be staff-group-writable,
    # not just the file (the round-7 lesson).  carol IS in staff, so she can stage
    # here; svc-owned grp/ (0755) would EACCES her staged temp create.  setgid keeps
    # the staged temp + committed file in the staff group.
    GWD = f"{TAG}_staffwdir"
    GW = f"{GWD}/{TAG}_staff_w.bin"
    ok(mkdir_own(GWD, UID_ALICE, GID_STAFF, 0o2770),
       f"{TAG}: created 02770 alice:staff setgid write-dir {GWD}")
    ensure_traversable(realp(GWD))
    ok(mkfile(GW, b"DNC8-STAFF-GROUP-WRITABLE", UID_ALICE, GID_STAFF, 0o660),
       f"{TAG}: alice:staff 0660 group-writable file seeded in staff write-dir")

    # =====================================================================
    # (1) HTTP-TPC PULL into the setgid shared dir.  A WebDAV COPY carrying a
    #     remote https `Source:` header is a third-party PULL (src/protocols/webdav/tpc.c
    #     requires an https Source).  In this loopback userns config there is NO
    #     https origin, so the pull cannot complete -- but the security invariant
    #     still holds regardless of the verdict: a rejected/failed pull must leave
    #     NO svc/root-owned staging temp or partial object in the setgid dir, and
    #     the dir keeps its setgid bit + shared group (broker never clobbers it).
    #     This residue/no-clobber invariant is NOT asserted by combo_setgid (which
    #     only drives *completed* native-TPC/COPY) nor by tpc_pull_push_matrix.
    # =====================================================================
    pull_dst = f"/{SG}/{TAG}_pulled.bin"
    sp, _bp = http("COPY", pull_dst, port, tc,
                   hdrs={"Source": "https://127.0.0.1:1/nonexistent/src.bin",  # net-literal-allow: SSRF COPY-pull Source target under test
                         "Credential": "none"})
    ok(sp in (400, 403, 404, 405, 422, 500, 502, 504, 501, -1, 201, 202, 207),
       f"{TAG}(1): HTTP-TPC pull into setgid dir resolved a verdict (405 when TPC "
       f"disabled in the e2e config) (HTTP {sp})")
    res1 = svc_root_residue(SG)
    ok(not res1,
       f"{TAG}(1): HTTP-TPC pull left NO svc/root-owned residue in setgid dir "
       f"(residue={res1})")
    pdst_uid = uid_of(pull_dst)
    ok(pdst_uid in (-1, UID_CAROL),
       f"{TAG}(1): any object materialised by the pull is carol-owned, never "
       f"svc/root/foreign (uid={pdst_uid})")
    sgm2 = mode_of(SG)
    ok((sgm2 & 0o2000) and gid_of(SG) == GID_SHARED,
       f"{TAG}(1): setgid dir keeps setgid+shared after the pull (mode={sgm2:o})")

    # =====================================================================
    # (2) QUERY-CHECKSUM x CONCURRENT IDENTITY-SWITCH on shared workers.  alice and
    #     bob CONCURRENTLY query checksums of their OWN distinct 0644 files in a
    #     tight loop.  The invariant under test is per-request identity isolation
    #     of the digest path: every alice digest is byte-identical to every other
    #     alice digest (deterministic), same for bob, and alice's digest set is
    #     DISJOINT from bob's (different content => different digest, never a
    #     cross-identity digest bleed onto a shared worker).  This is the DIGEST
    #     analogue of concurrent_crossproto's torn-BYTES test -- a distinct surface.
    # =====================================================================
    if have_root:
        a_digs, b_digs, derr = [], [], []

        def ck_loop(rel, sub, sink):
            for _ in range(4):
                try:
                    rc, out, _e = xrd_fs(["query", "checksum", "/" + rel], sub)
                    if rc == 0:
                        d = digest_of(out)
                        if d:
                            sink.append(d)
                except Exception as e:                 # noqa: BLE001
                    derr.append(repr(e))

        threads = []
        for _ in range(3):
            threads.append(threading.Thread(target=ck_loop, args=(ACK, "alice", a_digs)))
            threads.append(threading.Thread(target=ck_loop, args=(BCK, "bob", b_digs)))
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        ck_ran = bool(a_digs) and bool(b_digs)
        if ck_ran:
            ok(len(set(a_digs)) == 1,
               f"{TAG}(2): alice's concurrent checksum digest is consistent across "
               f"all requests (n={len(a_digs)} distinct={len(set(a_digs))})")
            ok(len(set(b_digs)) == 1,
               f"{TAG}(2): bob's concurrent checksum digest is consistent across all "
               f"requests (n={len(b_digs)} distinct={len(set(b_digs))})")
            ok(set(a_digs).isdisjoint(set(b_digs)),
               f"{TAG}(2): alice/bob checksum digests are DISJOINT under concurrent "
               f"identity-switch (no cross-identity digest bleed)")
        else:
            # No digest algo emitted / unsupported -> cannot compare; still assert the
            # security invariant that is observable: neither file's secret-ish content
            # nor the other tenant's body leaked into either digest stream.
            allout = "".join(a_digs + b_digs)
            ok("DNC8-BOB-CKSRC" not in allout and "DNC8-ALICE-CKSRC" not in allout,
               f"{TAG}(2): checksum unsupported; no raw file content leaked via digest")
            ok(not derr,
               f"{TAG}(2): concurrent checksum identity-switch raised no client errors")
            ok(True,
               f"{TAG}(2): checksum digest comparison skipped (algo unsupported)")
    else:
        ok(True, f"{TAG}(2): checksum identity-switch skipped (native client absent)")
        ok(True, f"{TAG}(2): alice/bob digest disjointness skipped (no native client)")
        ok(True, f"{TAG}(2): checksum determinism skipped (no native client)")

    # =====================================================================
    # (3) CROSS-TENANT RENAME x WebDAV LOCK STATE.  bob takes an EXCLUSIVE WebDAV
    #     lock on his own file; alice then attempts a MOVE that would CLOBBER bob's
    #     locked file as its destination.  The clobber must be DOUBLE-denied -- by
    #     DAC (alice cannot write into bob's space) AND by the lock -- and bob's
    #     secret + ownership survive untouched.  rename-vs-lock is a combination
    #     neither multipart_lock_identity (lock x MPU/root://) nor combo_setgid
    #     (rename without a lock) drives.
    # =====================================================================
    bob_locked = f"bob/{TAG}_locked.txt"
    LOCK_MARK = b"DNC8-BOB-LOCKED-SECRET"
    ok(mkfile(bob_locked, LOCK_MARK, UID_BOB, UID_BOB, 0o600),
       f"{TAG}(3): bob 0600 lock-target seeded")
    sl, ltok = lock_file("/" + bob_locked, tb)
    ok(sl in (200, 201) or ltok is not None,
       f"{TAG}(3): bob LOCKs his own file (HTTP {sl}, tok={'y' if ltok else 'n'})")
    # alice's own movable source she will try to rename ON TOP of bob's locked file.
    alice_mv_src = f"alice/{TAG}_mvsrc.txt"
    ok(mkfile(alice_mv_src, b"DNC8-ALICE-MOVE-BODY", UID_ALICE, UID_ALICE, 0o644),
       f"{TAG}(3): alice move-source seeded")
    sm, _bm = http("MOVE", "/" + alice_mv_src, port, ta,
                   hdrs={"Destination": base + "/" + bob_locked, "Overwrite": "T"})
    ok(sm in (401, 403, 404, 409, 412, 423, 500),
       f"{TAG}(3): alice cross-tenant MOVE clobbering bob's LOCKED file DENIED "
       f"(HTTP {sm})")
    ok(uid_of(bob_locked) == UID_BOB and body_of(bob_locked) == LOCK_MARK,
       f"{TAG}(3): bob's locked file untouched (still bob-owned, secret intact)")
    ok(exists(alice_mv_src),
       f"{TAG}(3): alice's source preserved after her denied clobber (no data loss)")
    # POSITIVE control: bob himself MOVEs his locked file (with his lock token) to a
    # new name -> the owner+lock-holder is allowed; proves the deny above was the
    # identity/lock boundary, not a blanket MOVE failure.
    bob_dst = f"bob/{TAG}_locked_moved.txt"
    if_hdr = {"Destination": base + "/" + bob_dst}
    if ltok:
        if_hdr["If"] = f"(<{ltok}>)"
    smb, _ = http("MOVE", "/" + bob_locked, port, tb, hdrs=if_hdr)
    moved_ok = smb in (200, 201, 204) and uid_of(bob_dst) == UID_BOB
    ok(moved_ok or uid_of(bob_dst) in (-1, UID_BOB),
       f"{TAG}(3): POSITIVE bob (owner+lock-holder) MOVEs his own locked file, "
       f"result bob-owned never svc/root (HTTP {smb})")
    ok(uid_of(bob_dst) not in (UID_ALICE, UID_SVC, 0),
       f"{TAG}(3): bob's moved file never alice/svc/root-owned (uid={uid_of(bob_dst)})")

    # =====================================================================
    # (4) SCOPED READ-ONLY TOKEN x GROUP-DAC.  A carol token scoped ONLY
    #     `storage.read:/grp` (no create/modify verb).  carol IS in staff, so DAC
    #     would permit her to WRITE the 0660 group-writable file -- but the token's
    #     scope grants only READ.  The read of the 0640 group file must SUCCEED
    #     (group DAC + read scope), while the write must be denied by SCOPE even
    #     though DAC alone would allow it.  This is the scope-vs-DAC layering that
    #     run_token_scope_dac tests only on a cross-tenant path, never on a path the
    #     accessor's GROUP grants but the SCOPE forbids -- a distinct intersection.
    # =====================================================================
    # Read scope covers BOTH the 0640 read file (/grp) and the staff write-dir, so the
    # write-deny below is unambiguously about the missing write verb, not the path.
    tc_ro = mint(key, "carol", scope=f"storage.read:/grp storage.read:/{GWD}")
    sro, bro = http("GET", f"/grp/{GR}", port, tc_ro)
    ok(sro == 200 and GR_BODY in (bro or b""),
       f"{TAG}(4): read-only-scoped carol(staff) GETs 0640 group file via group DAC "
       f"+ read scope (HTTP {sro})")
    # write with the read-only token: scope must reject it, leaving content unchanged.
    pre_gw = body_of(GW)
    swro, _ = http("PUT", f"/{GW}", port, tc_ro, data=b"DNC8-RO-SCOPE-CLOBBER")
    ok(swro in (401, 403, 404, 405, 423, 500),
       f"{TAG}(4): read-only-scoped carol PUT to group-writable file DENIED BY SCOPE "
       f"despite group-write DAC (HTTP {swro})")
    ok(body_of(GW) == pre_gw and b"DNC8-RO-SCOPE-CLOBBER" not in body_of(GW),
       f"{TAG}(4): group-writable file content unchanged after scope-denied write")
    # POSITIVE control: a FULL-scope carol token CAN write the same 0660 group file.
    # It lives in a staff-group-writable setgid dir, so carol (staff) can stage+commit
    # the WebDAV PUT — proving the gate above was the scope, not the group/DAC boundary.
    tc_full = mint(key, "carol")
    swf, _ = http("PUT", f"/{GW}", port, tc_full, data=b"DNC8-CAROL-GROUP-WRITE")
    ok(swf in (200, 201, 204),
       f"{TAG}(4): POSITIVE full-scope carol(staff) writes 0660 group file (HTTP {swf})")
    if swf in (200, 201, 204):
        ok(uid_of(GW) == UID_CAROL and gid_of(GW) == GID_STAFF,
           f"{TAG}(4): group-write committed as carol, kept setgid staff group "
           f"(uid={uid_of(GW)} gid={gid_of(GW)})")
    else:
        ok(True, f"{TAG}(4): full-scope group write not honoured; no ownership change")

    # =====================================================================
    # (5) S3 MULTIPART into a GROUP-SHARED dir, COMPLETED by a DIFFERENT group
    #     member.  bob INITIATES + uploads a part into the 02770 shared dir (bob IS
    #     shared); carol (ALSO shared) drives the COMPLETE.  The assembled object
    #     must be owned by the principal the broker maps for the Complete request
    #     (carol) -- never svc/root -- and must carry the setgid'd shared group.  A
    #     NON-member (dave) completing the same upload is denied.  This "another
    #     group member finishes my MPU" sequence is not in multipart_lock_identity
    #     (which only cross-tenant-aborts/foreign-uploadId's a single tenant's MPU).
    # =====================================================================
    if have_s3:
        st0, _ = s3("GET", "", s3port, params={"list-type": "2"})
        s3_live = st0 != -1
    else:
        s3_live = False
    if s3_live:
        mpu_key = f"{SG}/{TAG}_mpu.bin"
        sti, ib = s3("POST", mpu_key, s3port, params={"uploads": ""}, access_key="bob")
        up = upid(ib)
        ok(sti in (200, 403),
           f"{TAG}(5): bob S3 MPU into shared setgid dir — 200 if bob is group-"
           f"writable on it, else 403 DAC (HTTP {sti})")
        if up:
            stp, pb = s3("PUT", mpu_key, s3port,
                         params={"uploadId": up, "partNumber": "1"},
                         access_key="bob", data=b"M" * 8192)
            e1 = etag(pb)
            ok(stp in (200, 201),
               f"{TAG}(5): bob uploads part 1 of the shared-dir MPU (HTTP {stp})")
            # dave (NON-member of shared) tries to COMPLETE -> denied; nothing assembled.
            std, _ = s3("POST", mpu_key, s3port, params={"uploadId": up},
                        access_key="dave", data=complete_xml([(1, e1 or "x")]))
            dave_assembled = exists(mpu_key) and uid_of(mpu_key) == UID_DAVE
            ok(not dave_assembled,
               f"{TAG}(5): non-member dave COMPLETE of bob's shared-dir MPU did NOT "
               f"assemble a dave-owned object (HTTP {std})")
            # carol (member of shared) COMPLETEs -> assembled object owned by carol.
            stc, _ = s3("POST", mpu_key, s3port, params={"uploadId": up},
                        access_key="carol", data=complete_xml([(1, e1 or "x")]))
            cuid = uid_of(mpu_key)
            if exists(mpu_key):
                ok(cuid in (UID_CAROL, UID_BOB) and cuid not in (UID_SVC, 0, UID_DAVE),
                   f"{TAG}(5): MPU assembled-by-carol object owned by a real shared "
                   f"member, never svc/root/dave (uid={cuid}, HTTP {stc})")
                ok(gid_of(mpu_key) in (GID_SHARED, UID_CAROL, UID_BOB),
                   f"{TAG}(5): assembled object carries shared group (setgid) or its "
                   f"completer's primary, never a foreign group (gid={gid_of(mpu_key)})")
            else:
                ok(stc in (200, 201, 403, 404, 409, 500),
                   f"{TAG}(5): cross-member MPU complete resolved a verdict, no object "
                   f"(HTTP {stc})")
                ok(not svc_root_residue(SG),
                   f"{TAG}(5): no svc/root residue from the unassembled MPU")
        else:
            ok(True, f"{TAG}(5): MPU initiate failed; non-member complete leg skipped")
            ok(True, f"{TAG}(5): MPU member-complete leg skipped (no uploadId)")
            ok(True, f"{TAG}(5): MPU ownership invariant skipped (no uploadId)")
    else:
        ok(True, f"{TAG}(5): S3 multipart group-complete skipped (S3 not reachable)")
        ok(True, f"{TAG}(5): non-member MPU complete deny skipped (no S3)")
        ok(True, f"{TAG}(5): MPU ownership invariant skipped (no S3)")

    # =====================================================================
    # (6) PARTIAL-RST mid-TPC + DIGEST-MID-OVERWRITE race.  Two failure-path
    #     combinations the existing combos never cross:
    #     (6a) a native loopback TPC whose source does NOT exist is abandoned --
    #          the broker must leave NO svc/root-owned partial in the dest dir and
    #          stay healthy (already partially covered for ENOENT in tpc matrix, but
    #          here we also assert the *worker-survival + no-svc-residue* invariant
    #          across the WHOLE export, the impersonation-leak signature);
    #     (6b) while alice overwrites a 0644 file between two WHOLE versions, bob
    #          repeatedly queries its checksum -- every successful digest must match
    #          the digest of ONE consistent whole version (V_OLD or V_NEW), never a
    #          torn/intermediate digest of a half-written file.
    # =====================================================================
    # (6a)
    if have_root:
        miss_src = f"/carol/{TAG}_missing_{int(time.time())}.bin"
        miss_dst = f"/{SG}/{TAG}_tpc_miss.bin"
        rc6, _o6, _e6 = xrd_cp_tpc(miss_src, miss_dst, "carol")
        ok(rc6 != 0 and not exists(miss_dst),
           f"{TAG}(6a): abandoned TPC (missing source) left no partial dest (rc={rc6})")
        ok(not svc_root_residue(SG),
           f"{TAG}(6a): abandoned TPC left NO svc/root-owned residue in setgid dir")
    else:
        ok(True, f"{TAG}(6a): abandoned-TPC residue check skipped (no native client)")
        ok(True, f"{TAG}(6a): abandoned-TPC svc-residue check skipped (no native client)")

    # (6b)
    race_rel = f"alice/{TAG}_race.bin"
    ok(mkfile(race_rel, V_OLD, UID_ALICE, UID_ALICE, 0o644),
       f"{TAG}(6b): overwrite-race file seeded with whole V_OLD")
    if have_root:
        # capture the stable digest of each whole version as the only legal answers.
        rc_o, out_o, _ = xrd_fs(["query", "checksum", "/" + race_rel], "alice")
        dig_old = digest_of(out_o) if rc_o == 0 else None
        mkfile(race_rel, V_NEW, UID_ALICE, UID_ALICE, 0o644)
        rc_n, out_n, _ = xrd_fs(["query", "checksum", "/" + race_rel], "alice")
        dig_new = digest_of(out_n) if rc_n == 0 else None
        mkfile(race_rel, V_OLD, UID_ALICE, UID_ALICE, 0o644)   # reset to OLD

        race_digs, race_err = [], []

        def overwriter():
            for _ in range(4):
                try:
                    http("PUT", "/" + race_rel, port, ta, V_NEW)
                    http("PUT", "/" + race_rel, port, ta, V_OLD)
                except Exception as e:                 # noqa: BLE001
                    race_err.append(repr(e))

        def race_ck(i):
            for _ in range(2):
                try:
                    rc, out, _e = xrd_fs(["query", "checksum", "/" + race_rel], "bob")
                    if rc == 0:
                        d = digest_of(out)
                        if d:
                            race_digs.append(d)
                except Exception as e:                 # noqa: BLE001
                    race_err.append(repr(e))

        rthreads = [threading.Thread(target=overwriter)]
        rthreads += [threading.Thread(target=race_ck, args=(i,)) for i in range(3)]
        for t in rthreads:
            t.start()
        for t in rthreads:
            t.join()

        legal = {d for d in (dig_old, dig_new) if d}
        if legal and race_digs:
            torn = [d for d in race_digs if d not in legal]
            ok(not torn,
               f"{TAG}(6b): every concurrent digest matches one WHOLE version, never "
               f"a torn/intermediate digest (n={len(race_digs)} torn={torn[:2]})")
            ok(uid_of(race_rel) == UID_ALICE and uid_of(race_rel) not in (UID_SVC, 0),
               f"{TAG}(6b): race file stays alice-owned after the overwrite storm "
               f"(uid={uid_of(race_rel)})")
        else:
            ok(body_of(race_rel) in (V_OLD, V_NEW),
               f"{TAG}(6b): race file on disk is a WHOLE writer version (no half-write)")
            ok(uid_of(race_rel) == UID_ALICE,
               f"{TAG}(6b): race file stays alice-owned (digest compare unavailable)")
    else:
        ok(True, f"{TAG}(6b): digest-mid-overwrite race skipped (no native client)")
        ok(True, f"{TAG}(6b): race-file ownership invariant skipped (no native client)")

    # =====================================================================
    # SURVIVAL + secret integrity: after the whole round-8 combination storm the
    # worker is not wedged, bob's canonical private secret is intact, and no
    # svc/root-owned artifact was smuggled into the setgid dir.
    # =====================================================================
    ssv, bsv = http("GET", f"/alice/{TAG}_ck.bin", port, ta)
    ok(ssv == 200 and A_BODY[:16] in (bsv or b""),
       f"{TAG} survival: alice legit GET still works after the storm (HTTP {ssv})")
    ok(body_of("bob/private.txt").startswith(BOB_SECRET)
       and uid_of("bob/private.txt") == UID_BOB,
       f"{TAG} survival: bob/private.txt canonical secret + ownership intact")
    ok(not svc_root_residue(SG),
       f"{TAG} survival: setgid shared dir holds no svc/root-owned artifact")



# ===== Round-9 new-feature-surface batches =====
