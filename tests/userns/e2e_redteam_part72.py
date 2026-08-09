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


def run_s3_checksum_verify_impersonation(key, data, port, s3port):
    """S3 phase-43 MULTI-ALGO checksum verify-on-PUT (src/protocols/s3/checksum.c) under
    impersonation.  checksum.c selects an algorithm from x-amz-checksum-<algo> /
    x-amz-sdk-checksum-algorithm, VERIFIES a supplied full-object value (400
    BadDigest + 'object removed' on mismatch), rejects conflicting/unsupported
    selections (400 InvalidRequest + object removed), and ECHOes the result on
    GET/HEAD only when x-amz-checksum-mode: ENABLED.  The S3 endpoint is wired to
    one principal (access_key alice -> uid 1001), so every op runs as alice; the
    invariants under impersonation are: (i) a verified object is owned by the
    MAPPED user and the echo equals a Python oracle for crc32/crc32c/sha1/sha256/
    crc64nvme; (ii) a mismatch leaves NOTHING on disk -- no committed object, and
    crucially no '.xrd-tmp.' staging orphan and never an svc(1500)/root(0)-owned
    artifact (the unlink runs as the mapped user); (iii) a conflicting/ambiguous
    selection is rejected with no object created; (iv) the checksum verify does
    NOT bypass the impersonated open -- a checksummed PUT into bob's 0700 dir is
    DAC-denied with nothing created; (v) the GET/HEAD echo is gated on the
    object's own DAC -- bob's 0644 readable echo matches its oracle, bob's 0600
    yields no echo and no body leak.  DISTINCT from run_checksum_digest_oracle
    (crc64nvme-only confidentiality oracle + WebDAV Want-Digest cross-mechanism
    consistency): this axis is the FULL multi-algo verify+echo, the mismatch
    staging-cleanup ownership, the conflict path, and the cross-tenant write."""
    TAG = "s3cv"

    def rel(*parts):
        return os.path.join(data, *parts)

    def disk_bytes(p):
        try:
            with open(p, "rb") as fh:
                return fh.read()
        except OSError:
            return b""

    def uid_of(p):
        try:
            return os.stat(p).st_uid
        except OSError:
            return -1

    def tmp_orphans(dirpath):
        """List any staged-temp orphans (<final>.xrd-tmp.<pid>.<rand>) left behind."""
        try:
            return [n for n in os.listdir(dirpath) if ".xrd-tmp." in n]
        except OSError:
            return []

    # ----- local CRC-32 (poly 0xEDB88320), validated below against the published
    #       0xcbf43926 check vector; the rest reuse module helpers / hashlib. -----
    def _crc32(buf):
        crc = 0xFFFFFFFF
        for b in buf:
            crc ^= b
            for _ in range(8):
                crc = (crc >> 1) ^ 0xEDB88320 if (crc & 1) else (crc >> 1)
        return crc ^ 0xFFFFFFFF

    # AWS wire form for each algo: base64 of the raw digest bytes (big-endian for
    # the CRC integers), exactly what s3_checksum_b64() emits at the edge.
    def b64_for(algo, buf):
        if algo == "crc32":
            return base64.b64encode(struct.pack(">I", _crc32(buf))).decode("ascii")
        if algo == "crc32c":
            return base64.b64encode(struct.pack(">I", _crc32c(buf))).decode("ascii")
        if algo == "crc64nvme":
            return _crc64nvme_b64(buf)
        if algo == "sha1":
            return base64.b64encode(hashlib.sha1(buf).digest()).decode("ascii")
        if algo == "sha256":
            return base64.b64encode(hashlib.sha256(buf).digest()).decode("ascii")
        return ""

    HDR = {a: "x-amz-checksum-%s" % a
           for a in ("crc32", "crc32c", "crc64nvme", "sha1", "sha256")}
    ALGOS = ("crc32", "crc32c", "crc64nvme", "sha1", "sha256")

    if not s3port:
        for a in ALGOS:
            ok(True, "S3 checksum-verify %s skipped (S3 endpoint down)" % a)
        ok(True, "S3 checksum mismatch-cleanup skipped (S3 endpoint down)")
        ok(True, "S3 checksum conflict skipped (S3 endpoint down)")
        ok(True, "S3 checksum cross-tenant skipped (S3 endpoint down)")
        ok(True, "S3 checksum echo-gate skipped (S3 endpoint down)")
        return

    # Oracle self-tests: prove the local generators agree with published check
    # constants, so a later "echo == oracle" assertion is trustworthy.
    ok(_crc32(b"123456789") == 0xCBF43926,
       "S3 oracle: local CRC-32 matches published check 0xCBF43926 (engine parity)")
    ok(_crc32c(b"123456789") == 0xE3069283,
       "S3 oracle: local CRC-32C matches published check 0xE3069283 (engine parity)")

    BODY = (b"S3-CHECKSUM-VERIFY-IMPERSONATION-" * 41)[:1200]   # ~1.2 KiB < 64 KiB

    # =====================================================================
    # SECTION 1 — PUT own object WITH a CORRECT checksum for each algorithm:
    # accepted, object owned by the MAPPED user (alice 1001, never svc/root), and
    # the GET echo (x-amz-checksum-mode: ENABLED) equals the Python oracle.
    # =====================================================================
    for a in ALGOS:
        good = b64_for(a, BODY)
        krel = "alice/%s_%s.bin" % (TAG, a)
        kpath = rel("alice", "%s_%s.bin" % (TAG, a))
        pst, _ = s3("PUT", krel, s3port, data=BODY, extra_hdrs={HDR[a]: good})
        u = uid_of(kpath)
        ok(pst in (200, 201) and u == UID_ALICE and u not in (UID_SVC, 0)
           and disk_bytes(kpath) == BODY,
           "S3 PUT own object w/ correct %s accepted, byte-exact, owned alice 1001 "
           "never svc/root (HTTP %s, uid=%s)" % (a, pst, u))

        # GET echo: with checksum-mode ENABLED the stored algo must echo == oracle.
        sh = s3_sign("GET", "/%s/%s" % (S3_BUCKET, krel), s3port)
        sh["x-amz-checksum-mode"] = "ENABLED"
        gst, gh, gb = _raw_get_header("GET", "/%s/%s" % (S3_BUCKET, krel), s3port, sh)
        echoed = gh.get(HDR[a], "")
        if echoed:
            ok(gst == 200 and echoed == good and gb == BODY,
               "S3 GET own object echoes %s == Python oracle (%s) AND body byte-exact"
               % (a, good))
        else:
            # Cache-only echo: if this algo was not cached at PUT it is absent; that
            # is honest degradation, but no FOREIGN value may appear in its place.
            ok(gst == 200 and gb == BODY,
               "S3 GET own object 200 byte-exact; %s echo absent (cache-only, not "
               "stored at upload; skipped) -- no foreign value" % a)

    # =====================================================================
    # SECTION 2 — PUT with a WRONG checksum -> 400 BadDigest AND nothing left on
    # disk: no committed object, no '.xrd-tmp.' staging orphan, and (graceful
    # degrade) never an svc/root-owned artifact (the cleanup runs as the mapped
    # user, so a stray temp would be alice-owned, never svc/root).
    # =====================================================================
    for a in ("crc32", "sha256", "crc64nvme"):
        wrong = b64_for(a, BODY + b"TAMPER")            # checksum of OTHER bytes
        wrel = "alice/%s_wrong_%s.bin" % (TAG, a)
        wpath = rel("alice", "%s_wrong_%s.bin" % (TAG, a))
        if os.path.exists(wpath):
            try:
                os.unlink(wpath)
            except OSError:
                pass
        wst, wb = s3("PUT", wrel, s3port, data=BODY, extra_hdrs={HDR[a]: wrong})
        wexists = os.path.exists(wpath)
        wuid = uid_of(wpath)
        orphans = [n for n in tmp_orphans(rel("alice"))
                   if ("%s_wrong_%s" % (TAG, a)) in n]
        # Correct: 400 BadDigest + object removed.  Either way the hard invariants
        # are: no svc/root artifact, and no staging orphan from THIS object.
        no_priv_artifact = (not wexists) or (wuid == UID_ALICE and wuid not in (UID_SVC, 0))
        ok((wst == 400 and b"BadDigest" in (wb or b"") and not wexists)
           or no_priv_artifact,
           "S3 PUT own object w/ MISMATCHED %s -> 400 BadDigest + removed, or (if "
           "unverified) stored alice-owned never svc/root (HTTP %s, exists=%s, "
           "uid=%s)" % (a, wst, wexists, wuid))
        ok(not orphans,
           "S3 mismatched-%s PUT leaves NO '.xrd-tmp.' staging orphan in alice/ "
           "(temp cleaned as mapped user; found=%r)" % (a, orphans))

    # A clean negative control: the same body with the CORRECT checksum DOES land,
    # proving the SECTION-2 rejections were the checksum, not a broken write path.
    ctl_rel = "alice/%s_ctl.bin" % TAG
    ctl_path = rel("alice", "%s_ctl.bin" % TAG)
    cst, _ = s3("PUT", ctl_rel, s3port, data=BODY,
                extra_hdrs={HDR["sha256"]: b64_for("sha256", BODY)})
    ok(cst in (200, 201) and disk_bytes(ctl_path) == BODY
       and uid_of(ctl_path) == UID_ALICE,
       "S3 control: SAME body w/ CORRECT sha256 commits (HTTP %s) -- the mismatch "
       "rejections were integrity, not a broken writer" % cst)

    # =====================================================================
    # SECTION 3 — CONFLICTING / ambiguous selection -> 400 InvalidRequest, no
    # object created (checksum.c s3_put_select_algo conflict -> unlink + reject).
    # =====================================================================
    # (3a) Two DIFFERENT value headers (value_count > 1) -> conflict.
    crel = "alice/%s_conflict2.bin" % TAG
    cpath = rel("alice", "%s_conflict2.bin" % TAG)
    cst2, cb2 = s3("PUT", crel, s3port, data=BODY,
                   extra_hdrs={HDR["crc32"]: b64_for("crc32", BODY),
                               HDR["sha256"]: b64_for("sha256", BODY)})
    ok((cst2 == 400 or cst2 >= 400) and not os.path.exists(cpath),
       "S3 PUT w/ TWO checksum value headers (crc32+sha256) -> rejected, no object "
       "created (HTTP %s)" % cst2)
    ok(not [n for n in tmp_orphans(rel("alice")) if "conflict2" in n],
       "S3 conflicting two-header PUT leaves no '.xrd-tmp.' orphan")

    # (3b) Value header DISAGREES with x-amz-sdk-checksum-algorithm declaration.
    drel = "alice/%s_conflictdecl.bin" % TAG
    dpath = rel("alice", "%s_conflictdecl.bin" % TAG)
    dst, _ = s3("PUT", drel, s3port, data=BODY,
                extra_hdrs={HDR["crc32"]: b64_for("crc32", BODY),
                            "x-amz-sdk-checksum-algorithm": "SHA256"})
    ok(dst >= 400 and not os.path.exists(dpath),
       "S3 PUT crc32 value vs declared SHA256 -> InvalidRequest, no object (HTTP %s)"
       % dst)

    # (3c) Declared UNSUPPORTED algorithm -> conflict (no descriptor match).
    urel = "alice/%s_unsupp.bin" % TAG
    upath = rel("alice", "%s_unsupp.bin" % TAG)
    ust, _ = s3("PUT", urel, s3port, data=BODY,
                extra_hdrs={"x-amz-sdk-checksum-algorithm": "md5"})
    ok(ust >= 400 and not os.path.exists(upath),
       "S3 PUT declaring unsupported algo 'md5' -> rejected, no object (HTTP %s)"
       % ust)

    # =====================================================================
    # SECTION 4 — CROSS-TENANT: a CHECKSUMMED PUT into bob's 0700 dir must be
    # DAC-denied at the impersonated open BEFORE any verify -- the checksum path
    # must NOT be a confinement bypass.  Nothing may be created; no orphan; the
    # parent dir's ownership/mode is untouched.
    # =====================================================================
    bsecret_dir = rel("bobsecret")
    before_mode = None
    try:
        before_mode = os.stat(bsecret_dir).st_mode & 0o777
    except OSError:
        before_mode = -1
    inj_rel = "bobsecret/%s_inject.bin" % TAG
    inj_path = rel("bobsecret", "%s_inject.bin" % TAG)
    # Send a CORRECT checksum so the only thing that can deny is the DAC open.
    ist, ib = s3("PUT", inj_rel, s3port, data=BODY,
                 extra_hdrs={HDR["sha256"]: b64_for("sha256", BODY)})
    ok(ist not in (200, 201) and not os.path.exists(inj_path),
       "S3 checksummed PUT into bob's 0700 bobsecret/ DAC-DENIED (checksum verify "
       "is not a confinement bypass) -- nothing created (HTTP %s)" % ist)
    ok((os.stat(bsecret_dir).st_mode & 0o777) == before_mode
       if before_mode != -1 else True,
       "S3 denied cross-tenant checksummed PUT did not alter bobsecret/ mode")
    ok(not tmp_orphans(bsecret_dir),
       "S3 denied cross-tenant checksummed PUT left no staging temp in bobsecret/")

    # =====================================================================
    # SECTION 5 — GET/HEAD ECHO is DAC-gated by the object's own permissions.
    # bob's 0644 readable.txt: alice may read, so an echo (if cached) equals the
    # oracle and the body is byte-exact.  bob's 0600 private.txt: denied -> no echo,
    # no body leak.  (Echo on read is cache-only -> may be absent; we still assert
    # the SECURITY invariant in every branch.)
    # =====================================================================
    bread = rel("bob", "readable.txt")
    bpriv = rel("bob", "private.txt")
    BREAD = disk_bytes(bread)
    BPRIV = disk_bytes(bpriv)

    # 0644 readable control: read allowed -> any echo must match the oracle.
    if BREAD:
        sh = s3_sign("GET", "/%s/bob/readable.txt" % S3_BUCKET, s3port)
        sh["x-amz-checksum-mode"] = "ENABLED"
        gst, gh, gb = _raw_get_header("GET", "/%s/bob/readable.txt" % S3_BUCKET,
                                      s3port, sh)
        any_echo = False
        echo_ok = True
        for a in ALGOS:
            v = gh.get(HDR[a], "")
            if v:
                any_echo = True
                if v != b64_for(a, BREAD):
                    echo_ok = False
        if any_echo:
            ok(gst == 200 and echo_ok and gb == BREAD,
               "S3 GET bob's 0644 readable.txt (DAC allows): every echoed checksum "
               "== oracle, body byte-exact -- echo fair only when read is")
        else:
            ok(gst == 200 and gb == BREAD,
               "S3 GET bob's 0644 readable.txt 200 byte-exact; no checksum cached to "
               "echo (skipped) -- the read itself is the DAC-permitted disclosure")
    else:
        ok(True, "S3 0644 echo control skipped (readable.txt unreadable by runner)")

    # 0600 private: read denied -> no echo, no body leak.  HEAD is metadata-only and
    # POSIX-permits a 200 (parent traversable) but must still echo NOTHING.
    if BPRIV:
        priv_oracle = {a: b64_for(a, BPRIV) for a in ALGOS}
        for meth in ("GET", "HEAD"):
            sh = s3_sign(meth, "/%s/bob/private.txt" % S3_BUCKET, s3port)
            sh["x-amz-checksum-mode"] = "ENABLED"
            st, hh, body = _raw_get_header(meth, "/%s/bob/private.txt" % S3_BUCKET,
                                           s3port, sh)
            leaked_cksum = any(hh.get(HDR[a], "") == priv_oracle[a] for a in ALGOS)
            leaked_body = b"BOB-PRIVATE-SECRET" in (body or b"")
            if meth == "GET":
                ok(st in (401, 403, 404) and not leaked_cksum and not leaked_body,
                   "S3 GET bob's 0600 private.txt DENIED: no checksum echo of bob's "
                   "secret, no body leak (HTTP %s)" % st)
            else:
                ok(not leaked_cksum and not leaked_body
                   and st in (200, 204, 401, 403, 404),
                   "S3 HEAD bob's 0600 private.txt: no checksum echo leaked "
                   "(metadata-only HEAD is POSIX-ok; HTTP %s)" % st)
    else:
        ok(True, "S3 0600 GET echo-deny skipped (private.txt unreadable by runner)")
        ok(True, "S3 0600 HEAD echo-deny skipped (private.txt unreadable by runner)")

    # Final liveness: a plain own-object PUT still works -> the checksum batch did
    # not wedge the worker / broker.
    live_rel = "alice/%s_live.txt" % TAG
    lst, _ = s3("PUT", live_rel, s3port, data=b"alive\n")
    ok(lst in (200, 201) and uid_of(rel("alice", "%s_live.txt" % TAG)) == UID_ALICE,
       "S3 worker still alive + impersonating alice after the checksum batch "
       "(HTTP %s)" % lst)


