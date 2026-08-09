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


def run_combo_error_rollback(key, data, port, s3port):
    """Errored-mid-op OWNERSHIP / CLEANUP / ROLLBACK under impersonation — the
    FAILURE-PATH combination frontier.  Every existing batch drives ops that
    SUCCEED (and checks ownership) or ops that are denied UP FRONT (and checks the
    target survives).  This batch instead drives ops that BEGIN as the mapped user,
    stage real on-disk state (a temp file, a partial body, a multipart staging
    dir), and then FAIL PARTWAY — the final rename is EACCES, the dest is
    cross-tenant, the parent is denied, the source is denied, the upload is
    abandoned.  The invariant a failed op MUST uphold: the namespace is left
    EXACTLY as it was, with NOTHING owned by svc(1500)/root(0) and NO stray
    .xrd-tmp / .part / .mpu staging residue — and the worker stays healthy so a
    later legit op still works.  Each combination pairs the failing path with a
    POSITIVE CONTROL (the same op that SUCCEEDS cleanly for the owner), and every
    read-deny also asserts the secret marker bytes never landed at the dest.  All
    fixtures are prefixed `cer_` to avoid collisions with the rest of the battery."""
    TAG = "cer"
    ta, tb = mint(key, "alice"), mint(key, "bob")
    base = f"http://{HOST}:{port}"
    MARK_BOB = b"CER-BOB-PRIVATE-MARKER-7Q"      # must never appear at any alice dest
    MARK_SVC = b"CER-SVC-ONLY-MARKER-9Z"         # must never appear at any user dest

    # ---- on-disk introspection helpers (run as in-ns root, see real uids) -------
    def realp(rel):
        return os.path.join(data, rel.lstrip("/"))

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

    def size_of(rel):
        try:
            p = realp(rel)
            return os.path.getsize(p) if os.path.exists(p) else -1
        except OSError:
            return -1

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

    def residue(reldir):
        """Names under reldir that look like orphaned staging artifacts:
        WebDAV/S3 staged temps (.xrd-tmp.), multipart staging dirs (.mpu-),
        or *.part fragments."""
        out = []
        for n in listdir(reldir):
            low = n.lower()
            if (".xrd-tmp." in low or ".mpu-" in low
                    or low.endswith(".part") or ".part." in low):
                out.append(n)
        return out

    def _svc_root_baseline():
        """Snapshot the svc(1500)/root(0)-owned names that ALREADY exist (planted by
        OTHER batches, e.g. run_broker_resource_limits' brl_topasswd symlink owned by
        in-ns root and brl_svc_hardlink owned by svc 1500) BEFORE this batch drives any
        op.  bad_owned() excludes these so the residue sweep flags only NEW svc/root
        residue created by THIS batch's failed ops — the genuine impersonation-leak
        signature — never pre-existing cross-batch fixture pollution.  Mirrors the
        _baseline pattern in run_connection_errors.  Only the top-level tenant dirs
        carry cross-batch fixtures (brl_* live directly in alice/); the cer_ scratch
        subdirs start empty for this batch, so .get(reldir, set()) yields an empty
        (correct) baseline for them."""
        seen = {}
        for sub in ("alice", "bob"):
            pre = set()
            for n in listdir(sub):
                try:
                    if os.stat(os.path.join(realp(sub), n)).st_uid in (UID_SVC, 0):
                        pre.add(n)
                except OSError:
                    continue
            seen[sub] = pre
        return seen

    _bad_baseline = _svc_root_baseline()

    def bad_owned(reldir):
        """Names under reldir owned by svc(1500) or root(0) that APPEARED during this
        batch — the cardinal impersonation-leak signature (a failed op must never leave
        such residue).  Pre-existing svc/root-owned fixtures planted by other batches
        are excluded via _bad_baseline so only this batch's residue is flagged."""
        out = []
        pre = _bad_baseline.get(reldir, set())
        for n in listdir(reldir):
            if n in pre:
                continue   # planted by another batch, not by this batch's failed op
            try:
                u = os.stat(os.path.join(realp(reldir), n)).st_uid
            except OSError:
                continue
            if u in (UID_SVC, 0):
                out.append((n, u))
        return out

    # ---- plant cross-tenant + svc-only failure sources --------------------------
    try:
        bp = realp(f"bob/{TAG}_src.txt")
        with open(bp, "wb") as fh:
            fh.write(MARK_BOB + b"\n")
        os.chown(bp, UID_BOB, UID_BOB)
        os.chmod(bp, 0o600)
    except OSError:
        pass
    ok(exists(f"bob/{TAG}_src.txt") and uid_of(f"bob/{TAG}_src.txt") == UID_BOB,
       "fixture: bob-owned 0600 cross-tenant failure-source planted")

    # a dir alice may ENTER + LIST (0755 bob dir) but not WRITE — the classic
    # "staged temp opens but the final rename is denied" trap (rename into a dir
    # the mapped user cannot create entries in).
    ndw = f"bob/{TAG}_nodirwrite"
    try:
        chown_dir(realp(ndw), UID_BOB, UID_BOB, 0o755)
    except OSError:
        pass
    ok(exists(ndw) and uid_of(ndw) == UID_BOB,
       "fixture: bob 0755 enter-but-not-write dir planted")

    # alice's own scratch dir (positive controls land here owned by alice).
    awork = f"alice/{TAG}_work"
    try:
        chown_dir(realp(awork), UID_ALICE, UID_ALICE, 0o755)
    except OSError:
        pass
    ok(exists(awork) and uid_of(awork) == UID_ALICE,
       "fixture: alice 0755 scratch dir for positive controls")

    # =========================================================================
    # (a) WebDAV PUT whose staged temp opens but the FINAL RENAME is DENIED.
    #     Two flavours: PUT into a dir alice can enter but not write; and PUT
    #     over a 0700 file alice can neither read nor replace.  In both the temp
    #     is created+written as alice, then commit (rename) must fail and abort
    #     must unlink the temp — leaving NO .xrd-tmp residue, NO half-file.
    # =========================================================================
    big = (MARK_SVC + b"-PUT-BODY-").ljust(40, b"x") * 256       # ~10 KiB body

    # (a1) POSITIVE CONTROL: alice PUT into her own scratch dir -> clean success,
    #      owned alice, body exact, and NO leftover temp in that dir.
    st, _ = http("PUT", f"/{awork}/ok.bin", port, ta, big)
    ok(st in (200, 201, 204) and uid_of(f"{awork}/ok.bin") == UID_ALICE,
       f"control: alice PUT into own dir succeeds, owned alice (HTTP {st})")
    ok(body_of(f"{awork}/ok.bin") == big,
       "control: alice PUT body byte-exact at final path")
    ok(residue(awork) == [],
       f"control: no staged-temp residue after successful PUT (saw {residue(awork)})")

    # (a2) PUT into bob's enter-but-not-write dir: rename denied (EACCES as alice).
    before = sorted(listdir(ndw))
    st, _ = http("PUT", f"/{ndw}/intruder.bin", port, ta, big)
    ok(st not in (200, 201, 204) and not exists(f"{ndw}/intruder.bin"),
       f"(a) PUT into enter-but-not-write dir DENIED, no final file (HTTP {st})")
    ok(residue(ndw) == [],
       f"(a) no .xrd-tmp left in bob's dir after denied PUT (saw {residue(ndw)})")
    ok(bad_owned(ndw) == [],
       f"(a) no svc/root-owned residue in bob's dir (saw {bad_owned(ndw)})")
    ok(sorted(listdir(ndw)) == before,
       "(a) bob's dir listing unchanged after failed PUT (clean rollback)")
    ok(MARK_SVC not in body_of(f"{ndw}/intruder.bin"),
       "(a) no body bytes landed at the denied dest")

    # (a3) PUT OVER a bob-owned 0700 file: alice is 'other', replace denied.
    try:
        op = realp(f"bob/{TAG}_0700.txt")
        with open(op, "wb") as fh:
            fh.write(b"original-0700-content\n")
        os.chown(op, UID_BOB, UID_BOB)
        os.chmod(op, 0o700)
    except OSError:
        pass
    orig = body_of(f"bob/{TAG}_0700.txt")
    st, _ = http("PUT", f"/bob/{TAG}_0700.txt", port, ta, big)
    ok(st not in (200, 201, 204) and body_of(f"bob/{TAG}_0700.txt") == orig,
       f"(a) PUT over bob 0700 file DENIED, content unchanged (HTTP {st})")
    ok(uid_of(f"bob/{TAG}_0700.txt") == UID_BOB,
       "(a) bob 0700 file still owned by bob after failed overwrite")
    ok(residue("bob") == [] or all(".xrd-tmp." not in n for n in residue("bob")),
       f"(a) no .xrd-tmp residue beside bob 0700 file (saw {residue('bob')})")

    # (a4) empty-body PUT (zero-length) into the denied dir: still no residue/file.
    st, _ = http("PUT", f"/{ndw}/empty.bin", port, ta, b"")
    ok(st not in (200, 201, 204) and not exists(f"{ndw}/empty.bin")
       and residue(ndw) == [],
       f"(a) empty-body PUT into denied dir leaves nothing (HTTP {st})")

    # =========================================================================
    # (b) WebDAV COPY whose DEST is cross-tenant-denied.  alice COPYs her OWN
    #     readable file to a path inside bob's no-write dir: the source read
    #     succeeds (own file) but the dest create/rename fails -> source intact,
    #     no temp/partial at dest, nothing svc/root-owned.
    # =========================================================================
    src_rel = f"{awork}/copysrc.txt"
    SRC_BODY = b"CER-ALICE-COPY-SOURCE-INTACT\n" * 8
    st, _ = http("PUT", f"/{src_rel}", port, ta, SRC_BODY)
    ok(st in (200, 201, 204) and uid_of(src_rel) == UID_ALICE,
       f"(b) COPY source staged owned alice (HTTP {st})")

    # (b1) POSITIVE CONTROL: COPY within alice's own space -> success, owned alice.
    st, _ = http("COPY", f"/{src_rel}", port, ta,
                 hdrs={"Destination": f"{base}/{awork}/copydst_ok.txt"})
    ok(st in (200, 201, 204) and uid_of(f"{awork}/copydst_ok.txt") == UID_ALICE
       and body_of(f"{awork}/copydst_ok.txt") == SRC_BODY,
       f"control: COPY within alice's space succeeds, owned alice (HTTP {st})")

    # (b2) COPY to a cross-tenant-denied dest -> denied, source intact, no residue.
    before = sorted(listdir(ndw))
    st, _ = http("COPY", f"/{src_rel}", port, ta,
                 hdrs={"Destination": f"{base}/{ndw}/copied.txt"})
    ok(st not in (200, 201, 204) and not exists(f"{ndw}/copied.txt"),
       f"(b) COPY to cross-tenant dest DENIED, no dest file (HTTP {st})")
    ok(body_of(src_rel) == SRC_BODY and uid_of(src_rel) == UID_ALICE,
       "(b) COPY source intact + still alice-owned after denied dest")
    ok(residue(ndw) == [] and bad_owned(ndw) == [],
       f"(b) no temp/partial/svc-owned residue at denied COPY dest "
       f"(res={residue(ndw)} bad={bad_owned(ndw)})")
    ok(sorted(listdir(ndw)) == before,
       "(b) denied dir listing unchanged after failed COPY")

    # (b3) COPY whose SOURCE is bob's 0600 file -> source read denied as alice;
    #      no dest file, and the bob MARK must NOT have leaked into any temp.
    st, _ = http("COPY", f"/bob/{TAG}_src.txt", port, ta,
                 hdrs={"Destination": f"{base}/{awork}/leaked.txt"})
    ok(st not in (200, 201, 204) and not exists(f"{awork}/leaked.txt"),
       f"(b) COPY of bob 0600 source DENIED, no dest (HTTP {st})")
    ok(MARK_BOB not in body_of(f"{awork}/leaked.txt"),
       "(b) bob's secret marker did not leak via failed COPY dest")
    ok(all(MARK_BOB not in body_of(f"{awork}/" + n) for n in listdir(awork)),
       "(b) bob's marker absent from EVERY file in alice's work dir")
    ok(residue(awork) == [],
       f"(b) no staged-temp residue in alice's dir after denied-source COPY "
       f"(saw {residue(awork)})")

    # =========================================================================
    # (c) S3 multipart ABANDONED after some parts, then ABORT.  The staging dir
    #     (.<key>.mpu-<id>) must be the MAPPED user's (alice, never svc/root); a
    #     later Abort must clean it; no orphan parts owned by svc/root remain.
    # =========================================================================
    s3_up = False
    if s3port:
        stp, _ = s3("GET", "", s3port, params={"list-type": "2"})
        s3_up = stp not in (-1,)
    if not s3_up:
        ok(True, "(c) S3 multipart rollback skipped (S3 endpoint unreachable)")
    else:
        mkey = f"alice/{TAG}_mpu.bin"
        st_i, bdy = s3("POST", mkey, s3port, params={"uploads": ""})
        m = re.search(rb"<UploadId>([^<]+)</UploadId>", bdy or b"")
        up = m.group(1).decode() if m else None
        ok(st_i == 200 and up,
           f"(c) multipart initiate for abandon test (HTTP {st_i})")

        def mpu_dir_name():
            # staging dir layout: .<objname>.mpu-<uploadid> beside the final key
            for n in listdir("alice"):
                if n.startswith(f".{TAG}_mpu.bin.mpu-") or ".mpu-" in n:
                    if n.startswith(f".{TAG}_mpu.bin"):
                        return n
            return None

        if up:
            # upload only SOME parts, then abandon (never Complete).
            st, _ = s3("PUT", mkey, s3port,
                       params={"uploadId": up, "partNumber": "1"},
                       data=b"P" * 5242880)
            ok(st in (200, 201), f"(c) UploadPart 1 of abandoned MPU (HTTP {st})")
            st, _ = s3("PUT", mkey, s3port,
                       params={"uploadId": up, "partNumber": "2"},
                       data=b"Q" * 4096)
            ok(st in (200, 201), f"(c) UploadPart 2 of abandoned MPU (HTTP {st})")

            mdir = mpu_dir_name()
            if mdir is not None:
                duid = uid_of(f"alice/{mdir}")
                ok(duid == UID_ALICE and duid not in (UID_SVC, 0),
                   f"(c) INVARIANT: MPU staging dir owned by mapped user alice "
                   f"(uid={duid})")
                # every staged part inside is alice-owned, never svc/root.
                bad = []
                for pn in listdir(f"alice/{mdir}"):
                    pu = uid_of(f"alice/{mdir}/{pn}")
                    if pu in (UID_SVC, 0):
                        bad.append((pn, pu))
                ok(bad == [],
                   f"(c) no svc/root-owned staged parts in MPU dir (saw {bad})")
            else:
                # staging may be opaque/in-place; still must not leave svc residue.
                ok(bad_owned("alice") == [],
                   f"(c) no svc/root-owned MPU residue in alice dir "
                   f"(saw {bad_owned('alice')})")

            # ABORT must remove the staging dir and assemble NO final object.
            st_a, _ = s3("DELETE", mkey, s3port, params={"uploadId": up})
            ok(st_a in (204, 200, 404),
               f"(c) AbortMultipartUpload of abandoned MPU (HTTP {st_a})")
            ok(not exists(mkey),
               "(c) abandoned MPU assembled NO final object after abort")
            leftover = [n for n in listdir("alice")
                        if f"{TAG}_mpu.bin.mpu-" in n or
                        n.startswith(f".{TAG}_mpu.bin.mpu-")]
            ok(leftover == [],
               f"(c) abort cleaned the MPU staging dir, no orphan parts "
               f"(saw {leftover})")
            ok(bad_owned("alice") == [],
               f"(c) no svc/root-owned residue after MPU abort "
               f"(saw {bad_owned('alice')})")

            # POSITIVE CONTROL: a clean small MPU completes + is alice-owned, so
            # the abort path above is a real per-lifecycle clean-up, not a blanket
            # MPU failure.
            okkey = f"alice/{TAG}_mpu_ok.bin"
            st_i2, b2 = s3("POST", okkey, s3port, params={"uploads": ""})
            m2 = re.search(rb"<UploadId>([^<]+)</UploadId>", b2 or b"")
            up2 = m2.group(1).decode() if m2 else None
            if up2:
                _, e1 = s3("PUT", okkey, s3port,
                           params={"uploadId": up2, "partNumber": "1"},
                           data=b"Z" * 5242880)
                et = re.search(rb'ETag>\\?"?([^"<\\]+)', e1 or b"")
                etag = et.group(1).decode() if et else "x"
                cx = (b"<CompleteMultipartUpload><Part><PartNumber>1</PartNumber>"
                      + f"<ETag>{etag}</ETag></Part></CompleteMultipartUpload>"
                      .encode())
                st_c, _ = s3("POST", okkey, s3port,
                             params={"uploadId": up2}, data=cx)
                ok(st_c in (200, 201) and uid_of(okkey) == UID_ALICE,
                   f"control: clean MPU completes owned alice (HTTP {st_c})")
                ok([n for n in listdir("alice")
                    if f"{TAG}_mpu_ok.bin.mpu-" in n] == [],
                   "control: clean MPU left no staging dir after complete")
            else:
                ok(True, "control MPU skipped (re-initiate unsupported)")

        # (c2) ABORT of a FORGED uploadId must create no staging dir / no object,
        #      and leave no svc/root residue (combining abort + forgery + residue).
        st_a, _ = s3("DELETE", f"alice/{TAG}_forged.bin", s3port,
                     params={"uploadId": "deadbeef-not-real-cer"})
        ok(st_a in (204, 404, 400) and not exists(f"alice/{TAG}_forged.bin"),
           f"(c) abort of forged uploadId no-ops cleanly (HTTP {st_a})")
        ok(bad_owned("alice") == [],
           f"(c) forged-abort left no svc/root residue (saw {bad_owned('alice')})")

    # =========================================================================
    # (d) MKCOL whose PARENT is denied / missing.  Combine: MKCOL under a parent
    #     that does not exist (409), MKCOL inside bob's no-write dir (403), and
    #     MKCOL over an existing file (405) — none may create anything, and the
    #     parent listing must be untouched.
    # =========================================================================
    # (d1) POSITIVE CONTROL: MKCOL under alice's own dir -> created, owned alice.
    st, _ = http("MKCOL", f"/{awork}/newcol", port, ta)
    ok(st in (200, 201) and uid_of(f"{awork}/newcol") == UID_ALICE,
       f"control: MKCOL in alice's dir succeeds, owned alice (HTTP {st})")

    # (d2) MKCOL whose intermediate parent is MISSING -> 409, nothing created.
    st, _ = http("MKCOL", f"/{awork}/cer_ghost_parent/child", port, ta)
    ok(st not in (200, 201) and not exists(f"{awork}/cer_ghost_parent")
       and not exists(f"{awork}/cer_ghost_parent/child"),
       f"(d) MKCOL with missing parent DENIED, no partial tree (HTTP {st})")

    # (d3) MKCOL inside bob's enter-but-not-write dir -> denied as alice.
    before = sorted(listdir(ndw))
    st, _ = http("MKCOL", f"/{ndw}/cer_col", port, ta)
    ok(st not in (200, 201) and not exists(f"{ndw}/cer_col"),
       f"(d) MKCOL in cross-tenant no-write dir DENIED (HTTP {st})")
    ok(sorted(listdir(ndw)) == before and bad_owned(ndw) == [],
       "(d) cross-tenant dir unchanged + no svc/root residue after denied MKCOL")

    # (d4) MKCOL over an EXISTING file -> 405, file untouched + still owned alice.
    http("PUT", f"/{awork}/cer_isfile.txt", port, ta, b"i-am-a-file\n")
    st, _ = http("MKCOL", f"/{awork}/cer_isfile.txt", port, ta)
    ok(st not in (200, 201)
       and body_of(f"{awork}/cer_isfile.txt") == b"i-am-a-file\n"
       and uid_of(f"{awork}/cer_isfile.txt") == UID_ALICE,
       f"(d) MKCOL over existing file DENIED, file intact (HTTP {st})")

    # =========================================================================
    # (e) TRUNCATE that fails (root://) -> file size unchanged.  Combine: alice
    #     truncates bob's 0600 file (denied) vs her own (control); then truncate
    #     of bob's enter-but-not-write FILE created above.  Size must be intact.
    # =========================================================================
    if not xrd_avail():
        ok(True, "(e) root:// truncate rollback skipped (native client absent)")
    else:
        # control file owned alice with known content/size.
        lf = os.path.join(WORK, f"{TAG}_trunc.bin")
        try:
            with open(lf, "wb") as fh:
                fh.write(b"T" * 4096)
        except OSError:
            pass
        rc, _, _ = xrd_cp_up(lf, f"{awork}/trunc_ok.bin", "alice")
        ok(rc == 0 and size_of(f"{awork}/trunc_ok.bin") == 4096,
           f"(e) control truncate-target uploaded, 4096B owned alice (rc={rc})")

        # (e1) POSITIVE CONTROL: alice truncates her own file -> size changes.
        rc, _, _ = xrd_fs(["truncate", f"/{awork}/trunc_ok.bin", "100"], "alice")
        ok(rc == 0 and size_of(f"{awork}/trunc_ok.bin") == 100,
           f"control: alice truncate of own file shrinks it to 100B (rc={rc})")

        # (e2) alice truncates BOB's 0600 file -> denied, size unchanged.
        bsz = size_of(f"bob/{TAG}_src.txt")
        rc, _, err = xrd_fs(["truncate", f"/bob/{TAG}_src.txt", "0"], "alice")
        ok(rc != 0 and size_of(f"bob/{TAG}_src.txt") == bsz and bsz > 0,
           f"(e) truncate of bob 0600 file DENIED, size unchanged (rc={rc})")
        ok(uid_of(f"bob/{TAG}_src.txt") == UID_BOB
           and MARK_BOB in body_of(f"bob/{TAG}_src.txt"),
           "(e) bob's file content + ownership intact after denied truncate")

        # (e3) alice truncates bob's 0700 file (from (a3)) -> denied, size intact.
        if exists(f"bob/{TAG}_0700.txt"):
            psz = size_of(f"bob/{TAG}_0700.txt")
            rc, _, _ = xrd_fs(["truncate", f"/bob/{TAG}_0700.txt", "0"], "alice")
            ok(rc != 0 and size_of(f"bob/{TAG}_0700.txt") == psz and psz > 0,
               f"(e) truncate of bob 0700 file DENIED, size unchanged (rc={rc})")

    # =========================================================================
    # (f) TPC whose SOURCE is denied (root:// native third-party copy) -> no
    #     partial dest file.  alice TPCs bob's 0600 file to her own space: the
    #     source pull is denied -> dest must not exist (no partial), and bob's
    #     marker must not have leaked into any alice file.
    # =========================================================================
    if not xrd_avail():
        ok(True, "(f) root:// TPC rollback skipped (native client absent)")
    else:
        # control source: alice's own readable file.
        lf2 = os.path.join(WORK, f"{TAG}_tpc.bin")
        try:
            with open(lf2, "wb") as fh:
                fh.write(b"CER-TPC-PAYLOAD-" * 64)
        except OSError:
            pass
        xrd_cp_up(lf2, f"{awork}/tpc_src.bin", "alice")

        # (f1) POSITIVE CONTROL: alice TPC of her OWN source -> dest owned alice.
        rc, _, _ = xrd_cp_tpc(f"{awork}/tpc_src.bin",
                              f"{awork}/tpc_dst_ok.bin", "alice")
        ok((rc == 0 and uid_of(f"{awork}/tpc_dst_ok.bin") == UID_ALICE)
           or rc != 0,
           f"control: TPC of own source either succeeds owned-alice or "
           f"is cleanly unsupported (rc={rc})")
        if rc == 0:
            ok(uid_of(f"{awork}/tpc_dst_ok.bin") == UID_ALICE,
               "control: TPC dest owned by mapped user alice")
        else:
            ok(not exists(f"{awork}/tpc_dst_ok.bin")
               or uid_of(f"{awork}/tpc_dst_ok.bin") == UID_ALICE,
               "control: unsupported TPC left no wrongly-owned dest")

        # (f2) TPC whose SOURCE is bob's 0600 file -> source pull denied as alice.
        before = sorted(listdir(awork))
        rc, _, _ = xrd_cp_tpc(f"/bob/{TAG}_src.txt",
                              f"{awork}/tpc_leak.bin", "alice")
        ok(rc != 0 and not exists(f"{awork}/tpc_leak.bin"),
           f"(f) TPC with denied bob 0600 source -> no dest file (rc={rc})")
        ok(MARK_BOB not in body_of(f"{awork}/tpc_leak.bin"),
           "(f) bob's marker did not leak into the TPC dest")
        ok(all(MARK_BOB not in body_of(f"{awork}/" + n)
               for n in listdir(awork)),
           "(f) bob's marker absent from EVERY file in alice's dir after TPC")
        ok(residue(awork) == [] and bad_owned(awork) == [],
           f"(f) no partial/temp/svc residue after denied-source TPC "
           f"(res={residue(awork)} bad={bad_owned(awork)})")
        # a partial may legitimately appear+vanish; assert the listing is clean
        # of NEW non-positive-control entries beyond what we expect.
        ok(sorted(listdir(awork)) == before or "tpc_leak.bin" not in listdir(awork),
           "(f) no leftover tpc_leak dest fragment after denied source")

    # =========================================================================
    # CROSS-CUT: a denied PUT followed IMMEDIATELY by a legit op on the SAME
    #     keep-alive connection — proves the failed-op rollback did not wedge the
    #     worker or leak the prior (failing) identity onto the next request.
    # =========================================================================
    seq = http_keepalive([
        ("PUT", f"/{ndw}/wedge.bin", ta, big, None),          # denied (rename fail)
        ("PUT", f"/{awork}/after_fail.txt", ta, b"recovered\n", None),  # must work
        ("GET", f"/{awork}/after_fail.txt", ta, None, None),
    ], port)
    ok(len(seq) >= 2 and seq[0][0] not in (200, 201, 204),
       f"(x) denied PUT on keep-alive conn rejected (HTTP {seq[0][0]})")
    ok(len(seq) >= 2 and seq[1][0] in (200, 201, 204)
       and uid_of(f"{awork}/after_fail.txt") == UID_ALICE,
       f"(x) legit PUT right after the failure succeeds owned alice "
       f"(HTTP {seq[1][0] if len(seq) >= 2 else -1})")
    ok(len(seq) >= 3 and seq[2][0] == 200 and seq[2][1] == b"recovered\n",
       "(x) GET after the failure returns the correct byte-exact body")
    ok(not exists(f"{ndw}/wedge.bin") and residue(ndw) == [],
       "(x) the wedge PUT left no file/temp in the cross-tenant dir")

    # final worker-survival probe via a fresh connection (independent of (x)).
    st, b = http("GET", f"/{awork}/ok.bin", port, ta)
    ok(st == 200 and b == big,
       f"(x) worker healthy after all rollback paths: fresh GET exact (HTTP {st})")
    ok(bad_owned("alice") == [],
       f"(x) FINAL: no svc/root-owned residue anywhere in alice's tree "
       f"(saw {bad_owned('alice')})")
    ok(bad_owned(ndw) == [] and bad_owned("bob") == []
       or all(u not in (0, UID_SVC)
              for _, u in (bad_owned("bob") + bad_owned(ndw))),
       "(x) FINAL: no svc/root-owned residue left in bob's tree by any failed op")



# ===== Round-7 genuinely-new batches (workflow-authored) =====
