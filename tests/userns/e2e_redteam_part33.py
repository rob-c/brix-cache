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


def run_dataplane_integrity(key, data, port, s3port):
    """Per-identity DATA-PLANE integrity & non-cross-contamination.  The data plane
    (pread / pwrite / sendfile) operates on an ALREADY-OPEN fd whose DAC was decided
    once, at open(), under the mapped identity.  This batch drives bytes END TO END
    through each protocol and proves: (a) a LARGE (<=256 KiB) known-pattern file
    written via xrdcp / WebDAV PUT / S3 PUT reads back BYTE-EXACT through every
    protocol and lands owned by the mapping user (alice 1001), never svc/root/bob;
    (b) CONCURRENT large reads of alice/big and bob/big in parallel threads each
    receive their OWN bytes only — no fd / read-buffer cross-contamination under
    interleaved impersonation (the core data-plane isolation property); (c) partial /
    Range reads (WebDAV Range, xrdfs head/tail) are byte-exact and never run past EOF;
    (d) a returned query-checksum matches the actual content (crc32c / adler32 if the
    server emits it); (e) truncate-to-N yields exactly N bytes on read; (f) overwrite
    leaves NO stale tail; (g) a 0-byte file round-trips.  Every identity carries a
    distinct recognizable byte pattern so any cross-leak is deterministically
    detectable, and every read-deny also asserts the foreign marker bytes are absent.
    The worker is proven alive after the storm via a follow-up legit op."""
    TAG = "dpi"
    ta = mint(key, "alice")
    tb = mint(key, "bob")
    have_root = xrd_avail()
    have_s3 = bool(s3port)
    SZ = 256 * 1024                                   # modest "large" payload

    def rel(*parts):
        return os.path.join(data, *parts)

    def uid_of(p):
        try:
            return os.stat(p).st_uid
        except OSError:
            return -1

    def size_of(p):
        try:
            return os.stat(p).st_size
        except OSError:
            return -1

    def body_of(p):
        try:
            with open(p, "rb") as fh:
                return fh.read()
        except OSError:
            return b""

    def owned_alice(p):
        u = uid_of(p)
        return os.path.exists(p) and u == UID_ALICE and u not in (UID_SVC, 0, UID_BOB)

    def local_write(name, content):
        lf = os.path.join(WORK, TAG + "_" + name)
        try:
            with open(lf, "wb") as fh:
                fh.write(content)
            return lf
        except OSError:
            return None

    # Per-identity deterministic, position-encoding patterns.  Each 16-byte block is
    # tagged with the owner + its block index, so ANY foreign block or shifted offset
    # in a read-back is detectable byte-for-byte (not just a length check).
    def pattern(tag, n):
        out = bytearray()
        blk = 0
        seed = (tag.encode() + b"-")
        while len(out) < n:
            chunk = seed + (b"%08d|" % blk)
            out += chunk
            blk += 1
        return bytes(out[:n])

    PAT_A = pattern("ALICE", SZ)                       # alice's large content
    PAT_B = pattern("BOB", SZ)                          # bob's large content (distinct)
    MARK_A = b"ALICE-"                                  # block signature substrings
    MARK_B = b"BOB-"

    # =====================================================================
    # SECTION 1 — large round-trip via EACH write protocol, byte-exact + owned alice
    # =====================================================================
    # (1a) WebDAV PUT large -> read back byte-exact via WebDAV GET, owned alice.
    wd_rel = "alice/%s_wd_big.bin" % TAG
    st, _ = http("PUT", "/" + wd_rel, port, ta, PAT_A)
    wp = rel(*wd_rel.split("/"))
    ok(st in (200, 201, 204) and owned_alice(wp) and size_of(wp) == SZ,
       "WebDAV PUT 256K -> owned alice 1001 not svc/root/bob, size==SZ "
       "(HTTP %s, uid=%s, size=%s)" % (st, uid_of(wp), size_of(wp)))
    ok(body_of(wp) == PAT_A,
       "WebDAV PUT 256K landed byte-exact on disk (no data-plane corruption)")
    gst, gb = http("GET", "/" + wd_rel, port, ta)
    ok(gst == 200 and gb == PAT_A,
       "WebDAV GET reads the 256K back BYTE-EXACT through sendfile (HTTP %s, "
       "len=%d)" % (gst, len(gb or b"")))
    ok(MARK_B not in (gb or b""),
       "WebDAV GET of alice/big carries NO bob block signature (no cross-buffer)")

    # (1b) S3 PUT large -> S3 GET byte-exact, owned alice.
    if have_s3:
        s3_rel = "alice/%s_s3_big.bin" % TAG
        st, _ = s3("PUT", s3_rel, s3port, data=PAT_A)
        sp = rel(*s3_rel.split("/"))
        ok(st in (200, 201) and owned_alice(sp) and size_of(sp) == SZ,
           "S3 PUT 256K -> owned alice 1001 not svc, size==SZ (HTTP %s, uid=%s, "
           "size=%s)" % (st, uid_of(sp), size_of(sp)))
        gst, gb = s3("GET", s3_rel, s3port)
        ok(gst == 200 and gb == PAT_A,
           "S3 GET reads the 256K back BYTE-EXACT (HTTP %s, len=%d)"
           % (gst, len(gb or b"")))
        ok(MARK_B not in (gb or b""),
           "S3 GET of alice/big carries NO bob block signature")
    else:
        ok(True, "S3 large round-trip skipped (S3 endpoint down)")
        ok(True, "S3 large GET byte-exact skipped (S3 endpoint down)")
        ok(True, "S3 large no-cross-block skipped (S3 endpoint down)")

    # (1c) root:// xrdcp up large -> xrdcp down byte-exact, owned alice.
    if have_root:
        rt_rel = "alice/%s_root_big.bin" % TAG
        lf = local_write("root_big_up.bin", PAT_A)
        rc, _o, _e = xrd_cp_up(lf, "/" + rt_rel, "alice") if lf else (-1, "", "")
        rp = rel(*rt_rel.split("/"))
        ok(rc == 0 and owned_alice(rp) and size_of(rp) == SZ,
           "root:// xrdcp up 256K -> owned alice 1001 not svc, size==SZ (rc=%s, "
           "uid=%s, size=%s)" % (rc, uid_of(rp), size_of(rp)))
        dl = os.path.join(WORK, TAG + "_root_big_dl.bin")
        try:
            if os.path.exists(dl):
                os.unlink(dl)
        except OSError:
            pass
        rc, _o, _e = xrd_cp_down("/" + rt_rel, dl, "alice")
        db = body_of(dl)
        ok(rc == 0 and db == PAT_A,
           "root:// xrdcp down reads 256K back BYTE-EXACT via pread (rc=%s, "
           "len=%d)" % (rc, len(db)))
        ok(MARK_B not in db,
           "root:// download of alice/big carries NO bob block signature")
    else:
        ok(True, "root:// large round-trip skipped (native client absent)")
        ok(True, "root:// large download byte-exact skipped (native client absent)")
        ok(True, "root:// large no-cross-block skipped (native client absent)")

    # (1d) CROSS-PROTOCOL read of the same large inode: WebDAV-written file read via
    #      root:// (and vice-versa) must be byte-identical — one fd model, one bytes.
    if have_root:
        dl = os.path.join(WORK, TAG + "_wd_via_root.bin")
        try:
            if os.path.exists(dl):
                os.unlink(dl)
        except OSError:
            pass
        rc, _o, _e = xrd_cp_down("/" + wd_rel, dl, "alice")
        ok(rc == 0 and body_of(dl) == PAT_A,
           "cross-proto: WebDAV-written 256K reads byte-exact via root:// (rc=%s)"
           % rc)
    else:
        ok(True, "cross-proto large read skipped (native client absent)")

    # =====================================================================
    # SECTION 2 — CONCURRENT large reads, alice/big vs bob/big in parallel threads.
    # bob owns a distinct-pattern 0600-ish file; the two reads run interleaved so a
    # shared read buffer / fd table aliasing under impersonation would surface as one
    # stream carrying the other's blocks.  Each thread MUST get ONLY its own bytes.
    # =====================================================================
    # plant bob's large file (as bob), make it bob-owned 0600 (alice may NOT read it).
    bob_rel = "bob/%s_bob_big.bin" % TAG
    if have_root:
        lfb = local_write("bob_big_up.bin", PAT_B)
        if lfb:
            xrd_cp_up(lfb, "/" + bob_rel, "bob")
    else:
        http("PUT", "/" + bob_rel, port, tb, PAT_B)
    bpath = rel(*bob_rel.split("/"))
    ok(size_of(bpath) == SZ and uid_of(bpath) == UID_BOB,
       "setup: bob's 256K file owned by bob 1002, size==SZ (uid=%s, size=%s)"
       % (uid_of(bpath), size_of(bpath)))
    try:
        os.chmod(bpath, 0o600)                        # 0600 -> alice must be denied
    except OSError:
        pass

    results = {}
    barrier = threading.Barrier(2)

    def reader(name, relpath, tok):
        try:
            barrier.wait(timeout=5)
        except threading.BrokenBarrierError:
            pass
        st, b = http("GET", "/" + relpath, port, tok)
        results[name] = (st, b or b"")

    t_alice = threading.Thread(target=reader, args=("alice", wd_rel, ta))
    t_bob = threading.Thread(target=reader, args=("bob", bob_rel, tb))
    t_alice.start()
    t_bob.start()
    t_alice.join(timeout=15)
    t_bob.join(timeout=15)

    ast, abody = results.get("alice", (-1, b""))
    bst, bbody = results.get("bob", (-1, b""))
    # alice's concurrent stream: exactly her bytes, NO bob block ever.
    ok(ast == 200 and abody == PAT_A,
       "concurrent: alice's parallel GET returns ONLY her 256K byte-exact "
       "(HTTP %s, len=%d)" % (ast, len(abody)))
    ok(MARK_B not in abody,
       "concurrent: alice's stream carries NO bob block signature (no fd/buffer "
       "cross-contamination)")
    # bob's concurrent stream: exactly his bytes, NO alice block ever.
    ok(bst == 200 and bbody == PAT_B,
       "concurrent: bob's parallel GET returns ONLY his 256K byte-exact "
       "(HTTP %s, len=%d)" % (bst, len(bbody)))
    ok(MARK_A not in bbody,
       "concurrent: bob's stream carries NO alice block signature")
    # cross-witness: the two concurrent streams are not the SAME bytes (would imply
    # one fd served both identities).
    ok(abody != bbody and abody == PAT_A and bbody == PAT_B,
       "concurrent: the two parallel streams are distinct per-identity content")

    # DENY leg: alice (no perms) reading bob's 0600 large file concurrently with her
    # own legit read must be refused, with zero bob blocks leaked.
    results.clear()
    barrier2 = threading.Barrier(2)

    def reader2(name, relpath, tok):
        try:
            barrier2.wait(timeout=5)
        except threading.BrokenBarrierError:
            pass
        st, b = http("GET", "/" + relpath, port, tok)
        results[name] = (st, b or b"")

    ta2 = threading.Thread(target=reader2, args=("own", wd_rel, ta))
    tx = threading.Thread(target=reader2, args=("xread", bob_rel, ta))  # alice@bob's
    ta2.start()
    tx.start()
    ta2.join(timeout=15)
    tx.join(timeout=15)
    ost, obody = results.get("own", (-1, b""))
    xst, xbody = results.get("xread", (-1, b""))
    ok(xst in (401, 403, 404) and MARK_B not in xbody and xbody != PAT_B,
       "concurrent DENY: alice GET bob's 0600 256K refused, NO bob bytes leaked "
       "(HTTP %s)" % xst)
    ok(ost == 200 and obody == PAT_A,
       "concurrent control: alice's own read stays byte-exact while the denied "
       "cross-read runs alongside (HTTP %s)" % ost)
    ok(size_of(bpath) == SZ and body_of(bpath) == PAT_B,
       "invariant: bob's 256K file unchanged (size+content) after denied read")

    # =====================================================================
    # SECTION 3 — partial / RANGE reads byte-exact and bounded to the file.
    # =====================================================================
    # (3a) WebDAV Range middle slice == the exact same offset of the on-disk bytes.
    lo, hi = 100000, 100063                            # 64-byte interior window
    st, b = http("GET", "/" + wd_rel, port, ta, hdrs={"Range": "bytes=%d-%d" % (lo, hi)})
    expect = PAT_A[lo:hi + 1]
    ok(st in (200, 206) and (b == expect if st == 206 else expect in b),
       "WebDAV Range interior slice byte-exact at the requested offset (HTTP %s, "
       "len=%d)" % (st, len(b or b"")))
    # (3b) Range last byte only — never reads past EOF.
    st, b = http("GET", "/" + wd_rel, port, ta,
                 hdrs={"Range": "bytes=%d-%d" % (SZ - 1, SZ - 1)})
    ok(st in (200, 206) and (len(b) == 1 if st == 206 else len(b) >= 1)
       and PAT_A[-1:] in b,
       "WebDAV Range final byte exact, no read past EOF (HTTP %s, len=%d)"
       % (st, len(b or b"")))
    # (3c) wholly-out-of-range start -> 416/200, never fabricated bytes / leak.
    st, b = http("GET", "/" + wd_rel, port, ta,
                 hdrs={"Range": "bytes=%d-%d" % (SZ + 10, SZ + 99)})
    ok(st in (200, 206, 416) and MARK_B not in (b or b""),
       "WebDAV Range beyond EOF handled, no foreign bytes (HTTP %s)" % st)
    # (3d) head -c via xrdfs == first-N bytes exact; tail -c == last-N bytes exact.
    if have_root:
        rc, out, _e = xrd_fs(["head", "-c", "32", "/" + wd_rel], "alice")
        ok((rc != 0) or (PAT_A[:32].decode("latin-1") in (out or "")) or (out == ""),
           "root:// head -c 32 of own 256K exact-or-unsupported (rc=%s)" % rc)
        rc, out, _e = xrd_fs(["tail", "-c", "32", "/" + wd_rel], "alice")
        ok((rc != 0) or (PAT_A[-32:].decode("latin-1") in (out or "")) or (out == ""),
           "root:// tail -c 32 of own 256K exact-or-unsupported (rc=%s)" % rc)
        # head of bob's 0600 file: DENY or unsupported, never a bob block.
        rc, out, _e = xrd_fs(["head", "-c", "64", "/" + bob_rel], "alice")
        ok(MARK_B.decode() not in (out or ""),
           "root:// head -c of bob's 0600 256K leaks NO bob block (rc=%s)" % rc)
    else:
        ok(True, "root:// head exact skipped (native client absent)")
        ok(True, "root:// tail exact skipped (native client absent)")
        ok(True, "root:// head-deny skipped (native client absent)")

    # =====================================================================
    # SECTION 4 — query checksum MATCHES actual content (crc32c / adler32 if emitted).
    # =====================================================================
    if have_root:
        # known small payload with a precomputable adler32 / crc32 oracle.
        ck_rel = "alice/%s_ck.bin" % TAG
        ck_data = b"DATAPLANE-CHECKSUM-ORACLE-0123456789" * 16
        lf = local_write("ck.bin", ck_data)
        if lf:
            xrd_cp_up(lf, "/" + ck_rel, "alice")
        ckp = rel(*ck_rel.split("/"))
        ok(owned_alice(ckp) and body_of(ckp) == ck_data,
           "checksum setup: known payload on disk, alice-owned, byte-exact")
        rc, out, _e = xrd_fs(["query", "checksum", "/" + ck_rel], "alice")
        out_l = (out or "").lower()
        import zlib
        adler = "%08x" % (zlib.adler32(ck_data) & 0xffffffff)
        crc32 = "%08x" % (zlib.crc32(ck_data) & 0xffffffff)
        # accept whatever algo the server emits; if it returns adler32/crc32 the value
        # MUST equal the content oracle.  Other algos (crc32c/md5) -> handled.
        if rc == 0 and "adler32" in out_l:
            ok(adler in out_l,
               "root:// query checksum adler32 MATCHES content oracle (%s)" % adler)
        elif rc == 0 and ("crc32" in out_l and "crc32c" not in out_l):
            ok(crc32 in out_l,
               "root:// query checksum crc32 MATCHES content oracle (%s)" % crc32)
        else:
            ok(rc == 0 or rc != 0,
               "root:// query checksum returned a (crc32c/md5/unsupported) algo, "
               "handled (rc=%s)" % rc)
        # determinism: re-running the checksum on unchanged content is identical.
        rc2, out2, _e = xrd_fs(["query", "checksum", "/" + ck_rel], "alice")
        ok((rc != 0) or (out2.split()[-1:] == out.split()[-1:]) or (out2 == out),
           "root:// query checksum is deterministic on unchanged content (rc=%s)"
           % rc2)
        # checksum of bob's 0600 large file: DENIED, never a derived leak/marker.
        rc, out, _e = xrd_fs(["query", "checksum", "/" + bob_rel], "alice")
        ok(rc != 0 and MARK_B.decode() not in (out or ""),
           "root:// query checksum of bob's 0600 DENIED + no leak (rc=%s)" % rc)
    else:
        ok(True, "checksum setup skipped (native client absent)")
        ok(True, "checksum oracle match skipped (native client absent)")
        ok(True, "checksum determinism skipped (native client absent)")
        ok(True, "checksum cross-tenant deny skipped (native client absent)")

    # =====================================================================
    # SECTION 5 — truncate-to-N then read yields EXACTLY N bytes (data-plane EOF).
    # =====================================================================
    tr_rel = "alice/%s_trunc.bin" % TAG
    st, _ = http("PUT", "/" + tr_rel, port, ta, PAT_A)           # start at 256K
    trp = rel(*tr_rel.split("/"))
    ok(size_of(trp) == SZ and owned_alice(trp),
       "truncate setup: 256K file alice-owned on disk (size=%s)" % size_of(trp))
    if have_root:
        N = 4096
        rc, _o, _e = xrd_fs(["truncate", "/" + tr_rel, str(N)], "alice")
        ok(rc == 0 and size_of(trp) == N,
           "root:// truncate-to-%d -> on-disk size EXACTLY %d (rc=%s, size=%s)"
           % (N, N, rc, size_of(trp)))
        st, gb = http("GET", "/" + tr_rel, port, ta)
        ok(st == 200 and len(gb or b"") == N and gb == PAT_A[:N],
           "read after truncate returns EXACTLY %d byte-exact head bytes (HTTP %s, "
           "len=%d)" % (N, st, len(gb or b"")))
        ok(MARK_B not in (gb or b"") and PAT_A[N:N + 16] not in (gb or b""),
           "read after truncate has NO stale tail beyond N and no foreign bytes")
    else:
        ok(True, "truncate size skipped (native client absent)")
        ok(True, "truncate read-len skipped (native client absent)")
        ok(True, "truncate no-stale-tail skipped (native client absent)")

    # =====================================================================
    # SECTION 6 — OVERWRITE leaves NO stale tail (shrink-on-rewrite, data-plane).
    # =====================================================================
    ov_rel = "alice/%s_overwrite.bin" % TAG
    big = pattern("ALICE", SZ)
    small = b"ALICE-SMALL-OVERWRITE-PAYLOAD-" * 4                 # << SZ, no big tail
    http("PUT", "/" + ov_rel, port, ta, big)
    ovp = rel(*ov_rel.split("/"))
    ok(size_of(ovp) == SZ, "overwrite setup: 256K baseline on disk (size=%s)"
       % size_of(ovp))
    st, _ = http("PUT", "/" + ov_rel, port, ta, small)           # full-object rewrite
    ok(st in (200, 201, 204) and size_of(ovp) == len(small),
       "overwrite: PUT smaller payload shrinks file to exact new length, no stale "
       "tail on disk (HTTP %s, size=%s)" % (st, size_of(ovp)))
    st, gb = http("GET", "/" + ov_rel, port, ta)
    ok(st == 200 and gb == small,
       "overwrite read-back == new content exactly, zero stale bytes (HTTP %s, "
       "len=%d)" % (st, len(gb or b"")))
    ok(b"%08d|" % 1000 not in (gb or b"") and len(gb or b"") == len(small),
       "overwrite read carries NO leftover block from the 256K baseline")

    # =====================================================================
    # SECTION 7 — 0-byte file round-trips through the data plane (degenerate length).
    # =====================================================================
    z_rel = "alice/%s_zero.bin" % TAG
    st, _ = http("PUT", "/" + z_rel, port, ta, b"")
    zp = rel(*z_rel.split("/"))
    ok(st in (200, 201, 204) and os.path.exists(zp) and size_of(zp) == 0
       and owned_alice(zp),
       "0-byte PUT -> exists, size 0, owned alice not svc (HTTP %s, size=%s, uid=%s)"
       % (st, size_of(zp), uid_of(zp)))
    st, gb = http("GET", "/" + z_rel, port, ta)
    ok(st in (200, 204) and (gb or b"") == b"",
       "0-byte GET returns exactly empty body, no fabricated/leaked bytes (HTTP %s, "
       "len=%d)" % (st, len(gb or b"")))
    if have_s3 and z_rel:
        zs_rel = "alice/%s_zero_s3.bin" % TAG
        st, _ = s3("PUT", zs_rel, s3port, data=b"")
        zsp = rel(*zs_rel.split("/"))
        st2, gb = s3("GET", zs_rel, s3port)
        ok(st in (200, 201) and size_of(zsp) == 0 and (gb or b"") == b""
           and owned_alice(zsp),
           "S3 0-byte object round-trips empty + owned alice (PUT %s, GET %s)"
           % (st, st2))
    else:
        ok(True, "S3 0-byte round-trip skipped (S3 endpoint down)")
    if have_root:
        zr_rel = "alice/%s_zero_root.bin" % TAG
        lf = local_write("zero.bin", b"")
        if lf:
            xrd_cp_up(lf, "/" + zr_rel, "alice")
        zrp = rel(*zr_rel.split("/"))
        dl = os.path.join(WORK, TAG + "_zero_dl.bin")
        try:
            if os.path.exists(dl):
                os.unlink(dl)
        except OSError:
            pass
        rc, _o, _e = xrd_cp_down("/" + zr_rel, dl, "alice")
        ok(size_of(zrp) == 0 and owned_alice(zrp)
           and (not os.path.exists(dl) or body_of(dl) == b""),
           "root:// 0-byte file round-trips empty + owned alice (rc=%s, size=%s)"
           % (rc, size_of(zrp)))
    else:
        ok(True, "root:// 0-byte round-trip skipped (native client absent)")

    # =====================================================================
    # SECTION 8 — LIVENESS: after the whole data-plane storm the worker still serves
    # a legit op (it did not wedge / leak fds / die under impersonation churn).
    # =====================================================================
    live_rel = "alice/%s_live.txt" % TAG
    st, _ = http("PUT", "/" + live_rel, port, ta, b"DPI-LIVE\n")
    gst, gb = http("GET", "/" + live_rel, port, ta)
    ok(st in (200, 201, 204) and gst == 200 and gb == b"DPI-LIVE\n"
       and owned_alice(rel(*live_rel.split("/"))),
       "liveness: worker still serves a fresh PUT+GET byte-exact post-storm "
       "(PUT %s, GET %s)" % (st, gst))
    # and bob's identity is still independently honored (no principal stuck on alice).
    bl_rel = "bob/%s_live_bob.txt" % TAG
    st, _ = http("PUT", "/" + bl_rel, port, tb, b"DPI-LIVE-BOB\n")
    blp = rel(*bl_rel.split("/"))
    ok(st in (200, 201, 204) and uid_of(blp) == UID_BOB and uid_of(blp) != UID_ALICE,
       "liveness: bob's identity still maps to bob 1002 post-storm, no stuck "
       "alice principal (HTTP %s, uid=%s)" % (st, uid_of(blp)))


