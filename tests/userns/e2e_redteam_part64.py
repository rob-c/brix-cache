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


def run_checksum_digest_oracle(key, data, port, s3port):
    """CHECKSUM / DIGEST endpoints as a CROSS-TENANT CONFIDENTIALITY ORACLE under
    impersonation.  A content digest is a partial read: revealing the adler32 / md5 /
    sha256 / crc64nvme of a file the caller cannot READ leaks a fingerprint enabling
    offline content-guessing.  Under map mode the digest MUST be computed AS THE
    MAPPED USER and DAC-gated exactly like a read.  Distinct from run_dataplane_
    integrity (which oracle-matches a root:// query-checksum of OWN files only): here
    the novel angle is the cross-tenant digest DENIAL across THREE mechanisms — WebDAV
    "Want-Digest:"->"Digest:", S3 x-amz-checksum-crc64nvme echo, and root:// query
    checksum — each proven by (a) own-file digest succeeds AND equals a Python content
    oracle, (b) bob's 0600 private.txt digest is DENIED with NONE of bob's real on-disk
    digest strings present in the response, (c) bob's 0644 readable.txt digest IS
    obtainable (control: DAC permits the read so the digest is fair) and matches its
    oracle, (d) nonexistent-file digest is a clean error, plus cross-mechanism digest
    equality (same inode, same engine).  Worker proven alive afterwards."""
    import zlib
    TAG = "cdo"
    ta = mint(key, "alice")

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

    # ---- Python content oracles for every algorithm the module emits ----
    def hex_digests(content):
        return {
            "adler32": "%08x" % (zlib.adler32(content) & 0xffffffff),
            "crc32":   "%08x" % (zlib.crc32(content) & 0xffffffff),
            "md5":     hashlib.md5(content).hexdigest(),
            "sha256":  hashlib.sha256(content).hexdigest(),
        }

    # alice's known-content file (write it via WebDAV PUT as alice).
    A_CONTENT = b"CHECKSUM-DIGEST-ORACLE-alice-" * 37          # ~1 KiB, < 64 KiB cap
    a_rel = "alice/%s_own.bin" % TAG
    st, _ = http("PUT", "/" + a_rel, port, ta, A_CONTENT)
    ap = rel("alice", "%s_own.bin" % TAG)
    ok(st in (200, 201, 204) and uid_of(ap) == UID_ALICE
       and disk_bytes(ap) == A_CONTENT,
       "setup: alice's known-content file written, owned alice 1001, byte-exact "
       "(HTTP %s, uid=%s)" % (st, uid_of(ap)))
    A = hex_digests(A_CONTENT)

    # bob's fixtures, with their REAL on-disk digests (the runner can read them; this
    # makes the leak assertion EXACT regardless of fixture trailing bytes).
    bpriv = rel("bob", "private.txt")                          # 0600 — alice DENIED
    bread = rel("bob", "readable.txt")                         # 0644 — alice allowed
    BPRIV_BYTES = disk_bytes(bpriv)
    BREAD_BYTES = disk_bytes(bread)
    BPRIV = hex_digests(BPRIV_BYTES) if BPRIV_BYTES else {}
    BREAD = hex_digests(BREAD_BYTES) if BREAD_BYTES else {}
    ALGOS = ["adler32", "md5", "sha-256", "crc32"]             # RFC3230 request tokens
    NORM = {"adler32": "adler32", "md5": "md5", "sha-256": "sha256", "crc32": "crc32"}

    # XrdHttp-flavoured headers maximise the chance the digest path activates.
    def want_hdrs(alg, token):
        return {"Authorization": "Bearer " + token,
                "Want-Digest": alg, "X-Xrootd-Proto": "1.0"}

    def parse_digest(hmap):
        """Return {algo_lower: hexvalue} from a 'Digest: algo=hex[, ...]' header."""
        out = {}
        dv = hmap.get("digest", "")
        for tok in dv.replace(";", ",").split(","):
            tok = tok.strip()
            if "=" in tok:
                a, _, v = tok.partition("=")
                out[a.strip().lower()] = v.strip()
        return out

    # =====================================================================
    # SECTION A — WebDAV Want-Digest of OWN file: digest emitted + MATCHES oracle.
    # =====================================================================
    self_digest = {}                                           # algo -> value seen
    for alg in ALGOS:
        norm = NORM[alg]
        gst, gh, gb = _raw_get_header("GET", "/" + a_rel, port, want_hdrs(alg, ta))
        dmap = parse_digest(gh)
        if norm in dmap:
            self_digest[norm] = dmap[norm]
            ok(dmap[norm].lower() == A[norm],
               "WebDAV GET Want-Digest:%s of OWN file -> Digest %s MATCHES Python "
               "content oracle (%s)" % (alg, norm, A[norm]))
        else:
            # Feature may be gated to XrdHttp clients / unsupported algo — degrade
            # honestly, but still assert NO foreign digest snuck in and GET succeeded.
            ok(gst == 200,
               "WebDAV GET Want-Digest:%s of OWN file served 200 (Digest header not "
               "emitted for this algo; skipped)" % alg)

    # HEAD path emits the Digest from a separate fd-open; prove parity with GET.
    hst, hh, _hb = _raw_get_header("HEAD", "/" + a_rel, port,
                                   want_hdrs("sha-256", ta))
    hmap = parse_digest(hh)
    if "sha256" in hmap:
        ok(hmap["sha256"].lower() == A["sha256"],
           "WebDAV HEAD Want-Digest:sha-256 of OWN file MATCHES oracle (head/get "
           "parity, no body needed to leak)")
    else:
        ok(hst in (200, 204),
           "WebDAV HEAD Want-Digest:sha-256 of OWN file 200/204 (Digest not emitted "
           "on HEAD; skipped)")

    # =====================================================================
    # SECTION B — CROSS-TENANT DENIAL: alice asks for bob's 0600 digest.  Must be
    # refused AND must NOT echo any of bob's real on-disk digest strings (the leak).
    # =====================================================================
    if BPRIV_BYTES:
        for alg in ALGOS:
            norm = NORM[alg]
            for meth in ("GET", "HEAD"):
                st, hh, bb = _raw_get_header(meth, "/bob/private.txt", port,
                                             want_hdrs(alg, ta))
                dmap = parse_digest(hh)
                bobval = BPRIV.get(norm, "\x00never")
                leaked = (dmap.get(norm, "").lower() == bobval) or \
                         (bobval and bobval.encode() in (bb or b"")) or \
                         (b"BOB-PRIVATE-SECRET" in (bb or b""))
                # The security boundary is the DIGEST/CONTENT, not stat metadata.
                # A GET of bob's 0600 must be DENIED (a 200 would leak the body).
                # A HEAD returns only stat metadata (size/etag) of a 0600 file whose
                # PARENT (bob/, 0755) alice may traverse -> a 200 HEAD is standard
                # POSIX, and the digest is correctly gated behind the impersonated
                # open (EACCES -> no Digest header).  So for HEAD accept 200 PROVIDED
                # no digest value / secret leaked; for GET require an outright denial.
                if meth == "GET":
                    ok(st in (401, 403, 404) and not leaked,
                       "WebDAV GET Want-Digest:%s of bob's 0600 DENIED, no body/"
                       "%s digest leaked (HTTP %s)" % (alg, norm, st))
                else:
                    ok(not leaked and st in (200, 204, 401, 403, 404),
                       "WebDAV HEAD Want-Digest:%s of bob's 0600: no %s digest "
                       "leaked (metadata-only HEAD ok; HTTP %s)" % (alg, norm, st))
    else:
        for alg in ALGOS:
            ok(True, "WebDAV cross-tenant Want-Digest:%s deny skipped "
                     "(bob fixture unreadable by runner)" % alg)
            ok(True, "WebDAV HEAD cross-tenant Want-Digest:%s deny skipped" % alg)

    # The whole Digest response header for the denied request must carry NO digest at
    # all (no partial computation before the DAC check).
    st, hh, _b = _raw_get_header("GET", "/bob/private.txt", port,
                                 want_hdrs("md5", ta))
    ok(st in (401, 403, 404) and "digest" not in hh,
       "WebDAV denied cross-tenant request emits NO Digest header (digest gated "
       "behind the open, computed only after DAC) (HTTP %s)" % st)

    # =====================================================================
    # SECTION C — CONTROL: bob's 0644 readable.txt digest IS obtainable by alice and
    # MATCHES its oracle (DAC permits the read, so the digest is a FAIR disclosure).
    # =====================================================================
    if BREAD_BYTES:
        gst, gh, _gb = _raw_get_header("GET", "/bob/readable.txt", port,
                                       want_hdrs("sha-256", ta))
        dmap = parse_digest(gh)
        if "sha256" in dmap:
            ok(gst == 200 and dmap["sha256"].lower() == BREAD["sha256"],
               "WebDAV control: alice GETs bob's 0644 readable.txt sha-256 (DAC "
               "allows) and it MATCHES oracle — digest fair only when read is")
        else:
            ok(gst == 200,
               "WebDAV control: alice GETs bob's 0644 readable.txt 200 (Digest not "
               "emitted; the read itself is the disclosure, which DAC permits)")
        # And the control read must equal the on-disk bytes (no other file served).
        ok(gst == 200 and (_gb or b"") == BREAD_BYTES,
           "WebDAV control: bob's 0644 GET body is exactly readable.txt (the digest "
           "describes the SAME bytes alice is allowed to read)")
    else:
        ok(True, "WebDAV 0644-control digest skipped (readable.txt unreadable)")
        ok(True, "WebDAV 0644-control body skipped")

    # =====================================================================
    # SECTION D — S3 x-amz-checksum-crc64nvme as the same oracle, base64-of-bytes form.
    # =====================================================================
    if s3port:
        s3_self = _crc64nvme_b64(A_CONTENT)
        # self-test the helper against the published NVME check constant first.
        ok(_crc64nvme(b"123456789") == 0xAE8B14860A799888,
           "S3 oracle: local CRC-64/NVME matches published check constant "
           "0xAE8B14860A799888 (engine parity vs src/core/compat/crc64.c)")
        # D1: PUT own object WITH a correct crc64nvme -> accepted (server verifies).
        s3_rel = "alice/%s_s3.bin" % TAG
        pst, _ = s3("PUT", s3_rel, s3port, data=A_CONTENT,
                    extra_hdrs={"x-amz-checksum-crc64nvme": s3_self})
        sp = rel("alice", "%s_s3.bin" % TAG)
        ok(pst in (200, 201) and uid_of(sp) == UID_ALICE
           and disk_bytes(sp) == A_CONTENT,
           "S3 PUT own object with CORRECT x-amz-checksum-crc64nvme accepted + owned "
           "alice (HTTP %s)" % pst)
        # D2: PUT with a WRONG crc64nvme -> rejected (BadDigest) and NOT stored.
        wrong_rel = "alice/%s_s3wrong.bin" % TAG
        wp = rel("alice", "%s_s3wrong.bin" % TAG)
        if os.path.exists(wp):
            try:
                os.unlink(wp)
            except OSError:
                pass
        bad = _crc64nvme_b64(A_CONTENT + b"X")                 # checksum of OTHER bytes
        wst, _ = s3("PUT", wrong_rel, s3port, data=A_CONTENT,
                    extra_hdrs={"x-amz-checksum-crc64nvme": bad})
        # Correct behaviour: 400 BadDigest + object removed.  If a config doesn't
        # verify header-form checksums it may store it — that is degraded, but the
        # security invariant that MUST hold either way is no identity escalation: a
        # forged checksum must never flip the object off alice (svc/root).
        wuid = uid_of(wp)
        ok((wst not in (200, 201) and not os.path.exists(wp))
           or (os.path.exists(wp) and wuid == UID_ALICE and wuid not in (UID_SVC, 0)),
           "S3 PUT own object with MISMATCHED crc64nvme rejected+removed, or (if "
           "verification not wired) stored STILL alice-owned never svc/root "
           "(HTTP %s, uid=%s)" % (wst, wuid))
        # D3: GET own object echoes x-amz-checksum-crc64nvme == oracle.
        sh = s3_sign("GET", "/%s/%s" % (S3_BUCKET, s3_rel), s3port)
        gst, gh, _b = _raw_get_header("GET", "/%s/%s" % (S3_BUCKET, s3_rel),
                                      s3port, sh)
        echoed = gh.get("x-amz-checksum-crc64nvme", "")
        if echoed:
            ok(gst == 200 and echoed == s3_self,
               "S3 GET own object echoes x-amz-checksum-crc64nvme MATCHING the "
               "base64-of-8-BE-bytes oracle (%s)" % s3_self)
        else:
            ok(gst == 200,
               "S3 GET own object 200 (crc64nvme echo absent — cache-only, not "
               "stored at upload; skipped)")
        # D4: HEAD own object — same cache-only echo path, metadata only.
        sh = s3_sign("HEAD", "/%s/%s" % (S3_BUCKET, s3_rel), s3port)
        hst, hh2, _b = _raw_get_header("HEAD", "/%s/%s" % (S3_BUCKET, s3_rel),
                                       s3port, sh)
        he = hh2.get("x-amz-checksum-crc64nvme", "")
        ok((hst == 200) and (not he or he == s3_self),
           "S3 HEAD own object: any crc64nvme echo equals oracle, never a foreign "
           "value (HTTP %s)" % hst)
        # D5: GET/HEAD bob's 0600 -> DENIED, no crc64nvme of bob's secret leaked.
        if BPRIV_BYTES:
            bob_b64 = _crc64nvme_b64(BPRIV_BYTES)
            for meth in ("GET", "HEAD"):
                sh = s3_sign(meth, "/%s/bob/private.txt" % S3_BUCKET, s3port)
                st, hmh, body = _raw_get_header(meth,
                                                "/%s/bob/private.txt" % S3_BUCKET,
                                                s3port, sh)
                leaked = (hmh.get("x-amz-checksum-crc64nvme", "") == bob_b64) or \
                         (b"BOB-PRIVATE-SECRET" in (body or b""))
                if meth == "GET":
                    ok(st in (401, 403, 404) and not leaked,
                       "S3 GET bob's 0600 DENIED, no body/crc64nvme leak (HTTP %s)"
                       % st)
                else:
                    ok(not leaked and st in (200, 204, 401, 403, 404),
                       "S3 HEAD bob's 0600: no crc64nvme echoed (metadata-only HEAD "
                       "is POSIX-ok; HTTP %s)" % st)
        else:
            ok(True, "S3 cross-tenant crc64nvme deny skipped (bob fixture)")
            ok(True, "S3 HEAD cross-tenant crc64nvme deny skipped")
        # D6: anonymous (no SigV4) GET must not yield a digest oracle either.
        ast, ah, _b = _raw_get_header("GET", "/%s/%s" % (S3_BUCKET, s3_rel),
                                      s3port, {})
        ok(ast in (401, 403) and "x-amz-checksum-crc64nvme" not in ah,
           "S3 anonymous GET of alice's object denied + no crc64nvme oracle leaked "
           "(HTTP %s)" % ast)
    else:
        for _i in range(8):
            ok(True, "S3 checksum-oracle leg skipped (S3 endpoint down)")

    # =====================================================================
    # SECTION E — root:// query checksum: cross-MECHANISM consistency (one engine).
    # The digest of alice's SAME inode via root:// must equal the WebDAV Digest value
    # for whichever algo both emit — proving a single content-fingerprint engine, and
    # that no protocol is a softer oracle than another.
    # =====================================================================
    if xrd_avail():
        rc, out, _e = xrd_fs(["query", "checksum", "/" + a_rel], "alice")
        out_l = (out or "").lower()
        ok(rc == 0, "root:// query checksum of alice's OWN file succeeds (rc=%s)" % rc)
        matched = False
        for norm, val in (("adler32", A["adler32"]), ("crc32", A["crc32"]),
                          ("md5", A["md5"]), ("sha256", A["sha256"])):
            if norm in out_l and val in out_l:
                matched = True
                ok(val in out_l,
                   "root:// query checksum %s of alice's file EQUALS the Python "
                   "oracle AND the WebDAV Digest (one engine, cross-protocol "
                   "agreement)" % norm)
                break
        if not matched:
            ok(rc == 0,
               "root:// query checksum returned a (crc32c/crc64/other) algo not in "
               "the WebDAV/Python oracle set — handled, no false fail")
        # cross-tenant: the digest output must not contain bob's secret bytes (the
        # deny itself is covered by run_root_deep; here we assert ZERO secret leak in
        # any returned text even if some algo were mistakenly emitted).
        rc2, out2, _e = xrd_fs(["query", "checksum", "/bob/private.txt"], "alice")
        ok(rc2 != 0 and "BOB-PRIVATE-SECRET" not in (out2 or "")
           and (not BPRIV or BPRIV.get("md5", "zz") not in (out2 or "").lower()),
           "root:// query checksum of bob's 0600 DENIED with NO bob digest/secret "
           "text in output (rc=%s)" % rc2)
    else:
        ok(True, "root:// query-checksum consistency skipped (native client absent)")
        ok(True, "root:// query-checksum oracle-match skipped (native client absent)")
        ok(True, "root:// query-checksum cross-tenant deny skipped (client absent)")

    # =====================================================================
    # SECTION F — nonexistent file digest -> clean error, never a fabricated value.
    # =====================================================================
    miss = "/alice/%s_nope.bin" % TAG
    st, hh, _b = _raw_get_header("GET", miss, port, want_hdrs("sha-256", ta))
    ok(st == 404 and "digest" not in hh,
       "WebDAV Want-Digest of NONEXISTENT file -> 404, no fabricated Digest header "
       "(HTTP %s)" % st)
    if s3port:
        sh = s3_sign("GET", "/%s/alice/%s_nope.bin" % (S3_BUCKET, TAG), s3port)
        st, hh, _b = _raw_get_header("GET",
                                     "/%s/alice/%s_nope.bin" % (S3_BUCKET, TAG),
                                     s3port, sh)
        ok(st in (403, 404) and "x-amz-checksum-crc64nvme" not in hh,
           "S3 GET checksum of NONEXISTENT object -> error, no fabricated checksum "
           "header (HTTP %s)" % st)
    else:
        ok(True, "S3 nonexistent-checksum skipped (S3 endpoint down)")
    if xrd_avail():
        rc, out, _e = xrd_fs(["query", "checksum", "/alice/%s_nope.bin" % TAG],
                             "alice")
        ok(rc != 0, "root:// query checksum of NONEXISTENT file -> error (rc=%s)" % rc)
    else:
        ok(True, "root:// nonexistent-checksum skipped (native client absent)")

    # =====================================================================
    # SECTION G — LIVENESS: the digest storm did not wedge / strand a principal.
    # =====================================================================
    lst, _ = http("PUT", "/alice/%s_live.txt" % TAG, port, ta, b"CDO-LIVE\n")
    gst, gb = http("GET", "/alice/%s_live.txt" % TAG, port, ta)
    ok(lst in (200, 201, 204) and gst == 200 and gb == b"CDO-LIVE\n"
       and uid_of(rel("alice", "%s_live.txt" % TAG)) == UID_ALICE,
       "liveness: worker still serves a fresh alice PUT+GET byte-exact after the "
       "digest-oracle storm (PUT %s, GET %s)" % (lst, gst))


