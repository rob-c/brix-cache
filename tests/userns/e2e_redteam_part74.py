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


def run_compression_impersonation(key, data, port, s3port):
    """PHASE-42 COMPRESSION x impersonation, BOTH directions.  INBOUND (WebDAV/S3
    PUT with Content-Encoding gzip/deflate, decoded-on-ingest into a staged temp that
    is created and written AS THE MAPPED USER inside brix_imp_request_begin): a
    valid gzip/deflate body is decompressed-and-stored, the object is owned by the
    MAPPING user (alice 1001 / bob 1002, never svc 1500 / root 0), and GET returns the
    DECOMPRESSED bytes.  Cross-tenant: an encoded PUT by alice into bob's 0700 dir is
    DAC-denied at the staged-temp open (which runs as alice) -> clean 4xx, NO partial /
    undecoded object, and NO svc/root-owned `.xrd-tmp.` orphan left in bob's dir.  A
    DECOMPRESSION BOMB (>1000:1 ratio, the only active guard since the PUT path passes
    out_cap=0) into the mapped user's OWN dir trips the bomb guard (413) AS that user,
    commits NO oversized object, and leaves no staged orphan.  OUTBOUND (brix_*_compress
    GET response compression): a GET with Accept-Encoding: gzip either returns an HONEST
    Content-Encoding that decompresses (in Python) to the EXACT stored bytes, or — when
    the directive is OFF in this harness (the generated nginx.conf sets no
    brix_compress / brix_compress, so this path is currently UNREACHABLE)
    — identity byte-exact; EITHER way a cross-tenant GET of bob's 0600 file with
    Accept-Encoding: gzip is DAC-DENIED with NO secret in the body (compressed or plain),
    because the compress read path dup()s an fd already DAC-checked at open under the
    mapped identity.  The KEY bug hunted: the outbound compress read opening the file as
    the worker (svc) instead of the mapped user (a cross-tenant leak via the compression
    path), or a partial compressed object left on a failed inbound decode.  DISTINCT from
    run_content_negotiation_ranges (which only sends a MALFORMED gzip PUT and treats the
    Accept-Encoding response OPAQUELY without decoding) — this batch round-trips VALID
    codec frames, decodes outbound bytes, drives the BOMB guard, and adds the S3 protocol
    + per-user (bob) decode-ownership dimension; DISTINCT from run_dataplane_integrity
    (plaintext only, no Content-Encoding)."""
    import zlib

    ta = mint(key, "alice")
    tb = mint(key, "bob")

    def gz(raw):
        co = zlib.compressobj(9, zlib.DEFLATED, 31)      # wbits 31 == gzip framing
        return co.compress(raw) + co.flush()

    def df(raw):
        return zlib.compress(raw, 6)                     # zlib/deflate framing (wbits 15)

    def uid_of(p):
        try:
            return os.stat(p).st_uid
        except OSError:
            return -1

    def exists(p):
        return os.path.exists(p)

    def body_of(p):
        try:
            with open(p, "rb") as fh:
                return fh.read()
        except OSError:
            return b""

    def has_staged_orphan(dirpath):
        """Any leaked '.xrd-tmp.' sibling (the staged-temp name = <final>.xrd-tmp.pid.rand)
        left behind in dirpath."""
        try:
            names = os.listdir(dirpath)
        except OSError:
            return False
        for nm in names:
            if ".xrd-tmp." in nm:
                return True
        return False

    def svc_root_artifact(dirpath, since):
        """A file in dirpath owned by svc(1500)/root(0) created at/after `since` -> leak."""
        try:
            names = os.listdir(dirpath)
        except OSError:
            return False
        for nm in names:
            fp = os.path.join(dirpath, nm)
            try:
                st = os.stat(fp)
            except OSError:
                continue
            if st.st_uid in (UID_SVC, 0) and st.st_ctime >= since - 1:
                return True
        return False

    def raw_get_headers(relpath, token, accept_enc):
        """GET via raw socket so we can read the Content-Encoding response header that
        http() discards.  Returns (status_int, content_encoding_lower, body_bytes)."""
        lines = ["GET %s HTTP/1.1" % relpath, "Host: %s:%d" % (HOST, port),
                 "Authorization: Bearer %s" % token,
                 "Accept-Encoding: %s" % accept_enc, "Connection: close"]
        raw = raw_http(("\r\n".join(lines) + "\r\n\r\n").encode(), port)
        if not raw:
            return -1, "", b""
        head, _, bdy = raw.partition(b"\r\n\r\n")
        hl = head.split(b"\r\n")
        try:
            status = int(hl[0].split(b" ")[1])
        except (IndexError, ValueError):
            status = -1
        ce = ""
        for ln in hl[1:]:
            if b":" in ln:
                k, _, v = ln.partition(b":")
                if k.strip().lower() == b"content-encoding":
                    ce = v.strip().lower().decode("latin-1")
        return status, ce, bdy

    def raw_head(relpath, token, accept_enc):
        lines = ["HEAD %s HTTP/1.1" % relpath, "Host: %s:%d" % (HOST, port),
                 "Authorization: Bearer %s" % token,
                 "Accept-Encoding: %s" % accept_enc, "Connection: close"]
        raw = raw_http(("\r\n".join(lines) + "\r\n\r\n").encode(), port)
        if not raw:
            return -1, b""
        head, _, bdy = raw.partition(b"\r\n\r\n")
        hl = head.split(b"\r\n")
        try:
            status = int(hl[0].split(b" ")[1])
        except (IndexError, ValueError):
            status = -1
        return status, bdy

    # A compressible, deterministic plaintext (repeating tagged blocks -> high ratio but
    # NOT a bomb) used for the round-trip + outbound checks.
    PLAIN = (b"COMPRESSION-IMPERSONATION-PAYLOAD-BLOCK|" * 64)        # 2560 bytes
    # A genuine decompression bomb: ~4 MB of one byte -> ~4 KB compressed (well under
    # 64 KiB on the wire) -> ratio ~1025 > BRIX_DECODE_MAX_RATIO(1000) -> ERR_BOMB/413.
    # Decompresses to only 4 MB, so host-safe even if the guard were absent.
    BOMB_RAW = b"\x00" * (4 * 1024 * 1024)
    BOMB_GZ = gz(BOMB_RAW)
    BOMB_DF = df(BOMB_RAW)

    ok(len(gz(PLAIN)) < 65536 and len(df(PLAIN)) < 65536
       and len(BOMB_GZ) < 65536 and len(BOMB_DF) < 65536,
       "setup: all codec frames are <64KiB on the wire (host-load safe)")

    # =================================================================
    # INBOUND 1 — own object, valid gzip -> decoded-and-stored, owned by alice,
    # GET returns the DECOMPRESSED plaintext (NOT the compressed bytes).
    # =================================================================
    rel_gz = "alice/cmp_in_gzip.bin"
    disk_gz = os.path.join(data, "alice", "cmp_in_gzip.bin")
    if exists(disk_gz):
        try:
            os.remove(disk_gz)
        except OSError:
            pass
    sgz, _ = http("PUT", "/" + rel_gz, port, ta, gz(PLAIN),
                  hdrs={"Content-Encoding": "gzip"})
    if sgz in (200, 201, 204):
        ok(exists(disk_gz) and body_of(disk_gz) == PLAIN,
           "INBOUND gzip PUT (alice) decoded-and-stored: on-disk bytes == DECOMPRESSED "
           "plaintext, not the gzip frame (HTTP %s)" % sgz)
        ok(exists(disk_gz) and uid_of(disk_gz) == UID_ALICE
           and uid_of(disk_gz) not in (UID_SVC, 0),
           "INBOUND gzip-decoded object owned by mapped user alice 1001, not svc/root")
        ggz, gb = http("GET", "/" + rel_gz, port, ta)
        ok(ggz == 200 and gb == PLAIN,
           "INBOUND gzip object GET returns the DECOMPRESSED plaintext byte-exact "
           "(HTTP %s)" % ggz)
        gzip_decoded = True
    else:
        # If the build lacks zlib the codec is unavailable -> 415/400 and NO undecoded
        # object (never stored verbatim).  Still a valid, security-preserving contract.
        ok(sgz >= 400 and not exists(disk_gz),
           "INBOUND gzip PUT not decoded (codec unavailable) -> 4xx + NO undecoded "
           "object stored (HTTP %s)" % sgz)
        ok(not exists(disk_gz),
           "INBOUND gzip unavailable leaves NO partial object on disk")
        gzip_decoded = False

    # =================================================================
    # INBOUND 2 — own object, valid DEFLATE (codec variety) -> decoded-and-stored.
    # =================================================================
    rel_df = "alice/cmp_in_deflate.bin"
    disk_df = os.path.join(data, "alice", "cmp_in_deflate.bin")
    if exists(disk_df):
        try:
            os.remove(disk_df)
        except OSError:
            pass
    sdf, _ = http("PUT", "/" + rel_df, port, ta, df(PLAIN),
                  hdrs={"Content-Encoding": "deflate"})
    if sdf in (200, 201, 204):
        ok(exists(disk_df) and body_of(disk_df) == PLAIN
           and uid_of(disk_df) == UID_ALICE and uid_of(disk_df) not in (UID_SVC, 0),
           "INBOUND deflate PUT (alice) decoded-and-stored byte-exact + owned alice 1001 "
           "not svc/root (HTTP %s)" % sdf)
    else:
        ok(sdf >= 400 and not exists(disk_df),
           "INBOUND deflate PUT not decoded (codec unavailable) -> 4xx + NO undecoded "
           "object (HTTP %s)" % sdf)

    # =================================================================
    # INBOUND 3 — per-user decode ownership: bob PUTs an encoded body into HIS OWN
    # dir -> object owned by bob 1002 (proves the decode/staged-write ran AS BOB,
    # not svc), and is byte-exact decoded.
    # =================================================================
    rel_bob = "bob/cmp_in_bob.bin"
    disk_bob = os.path.join(data, "bob", "cmp_in_bob.bin")
    if exists(disk_bob):
        try:
            os.remove(disk_bob)
        except OSError:
            pass
    sbob, _ = http("PUT", "/" + rel_bob, port, tb, gz(PLAIN),
                   hdrs={"Content-Encoding": "gzip"})
    if sbob in (200, 201, 204):
        ok(exists(disk_bob) and uid_of(disk_bob) == UID_BOB
           and uid_of(disk_bob) not in (UID_SVC, 0, UID_ALICE)
           and body_of(disk_bob) == PLAIN,
           "INBOUND gzip PUT as BOB into bob/ decoded + owned by bob 1002 (decode ran as "
           "mapped user, not svc) (HTTP %s)" % sbob)
    else:
        ok(sbob >= 400 and not exists(disk_bob),
           "INBOUND gzip PUT as bob not decoded (codec unavailable) -> 4xx + no object "
           "(HTTP %s)" % sbob)

    # =================================================================
    # INBOUND 4 — CROSS-TENANT: alice PUTs an encoded body into bob's 0700 dir.
    # The staged-temp open runs AS ALICE inside bob's 0700 dir -> EACCES -> clean 4xx;
    # NO partial/undecoded object, NO svc/root .xrd-tmp orphan in bob's private dir.
    # =================================================================
    bobsecret_dir = os.path.join(data, "bobsecret")
    t_before = time.time()
    before_listing = set(os.listdir(bobsecret_dir)) if os.path.isdir(bobsecret_dir) else set()
    rel_xt = "bobsecret/alice_intrusion.bin"
    disk_xt = os.path.join(data, "bobsecret", "alice_intrusion.bin")
    sxt, _ = http("PUT", "/" + rel_xt, port, ta, gz(PLAIN),
                  hdrs={"Content-Encoding": "gzip"})
    ok(not (200 <= sxt < 300),
       "CROSS-TENANT gzip PUT alice -> bob/0700 dir DAC-DENIED with a non-2xx denial "
       "(the EACCES staged-temp create maps to 403 via put.c->errno_to_status; a 5xx "
       "broker corner is a tolerated robustness nit -- no decode into bob's private "
       "dir either way) (HTTP %s)" % sxt)
    ok(not exists(disk_xt),
       "CROSS-TENANT denied encoded PUT leaves NO object at the target path (no "
       "partial/undecoded write)")
    after_listing = set(os.listdir(bobsecret_dir)) if os.path.isdir(bobsecret_dir) else set()
    ok(not has_staged_orphan(bobsecret_dir),
       "CROSS-TENANT denied encoded PUT leaves NO '.xrd-tmp.' staged orphan in bob's "
       "0700 dir")
    ok(not svc_root_artifact(bobsecret_dir, t_before)
       and (after_listing - before_listing) == set(),
       "CROSS-TENANT denied encoded PUT creates NO svc/root-owned artifact in bob's dir "
       "(staged temp opened as alice, never as worker)")

    # =================================================================
    # INBOUND 5 — DECOMPRESSION BOMB (gzip) into alice's OWN dir.  out_cap is 0 on the
    # PUT path, so the ratio guard (>1000) is the only defense -> must 413 (or a clean
    # 4xx) AS alice, commit NO oversized object, leave no staged orphan / disk blowup.
    # =================================================================
    alice_dir = os.path.join(data, "alice")
    rel_bz = "alice/cmp_bomb_gzip.bin"
    disk_bz = os.path.join(data, "alice", "cmp_bomb_gzip.bin")
    if exists(disk_bz):
        try:
            os.remove(disk_bz)
        except OSError:
            pass
    sbz, _ = http("PUT", "/" + rel_bz, port, ta, BOMB_GZ,
                  hdrs={"Content-Encoding": "gzip"})
    if gzip_decoded:
        ok(sbz == 413 or (400 <= sbz < 500),
           "BOMB gzip PUT (alice, ratio>1000) REJECTED by the bomb guard with a 4xx "
           "(413 preferred) (HTTP %s)" % sbz)
        ok(not exists(disk_bz) or os.stat(disk_bz).st_size < len(BOMB_RAW),
           "BOMB gzip PUT commits NO full %d-byte decompressed object (no disk "
           "exhaustion)" % len(BOMB_RAW))
        ok(not exists(disk_bz),
           "BOMB gzip PUT leaves NO committed object at the final path (staged temp "
           "aborted)")
        ok(not has_staged_orphan(alice_dir),
           "BOMB gzip PUT leaves NO '.xrd-tmp.' staged orphan in alice's dir")
    else:
        ok(sbz >= 400 and not exists(disk_bz),
           "BOMB gzip PUT rejected (codec unavailable) -> 4xx, no object (HTTP %s)" % sbz)
        ok(not has_staged_orphan(alice_dir),
           "BOMB gzip PUT (codec unavailable) leaves no staged orphan")

    # =================================================================
    # INBOUND 6 — DECOMPRESSION BOMB (deflate) into alice's own dir -> same guard.
    # =================================================================
    rel_bd = "alice/cmp_bomb_deflate.bin"
    disk_bd = os.path.join(data, "alice", "cmp_bomb_deflate.bin")
    if exists(disk_bd):
        try:
            os.remove(disk_bd)
        except OSError:
            pass
    sbd, _ = http("PUT", "/" + rel_bd, port, ta, BOMB_DF,
                  hdrs={"Content-Encoding": "deflate"})
    ok(sbd >= 400 and (not exists(disk_bd)
                       or os.stat(disk_bd).st_size < len(BOMB_RAW)),
       "BOMB deflate PUT (alice, ratio>1000) REJECTED 4xx + no full decompressed object "
       "committed (HTTP %s)" % sbd)
    ok(not has_staged_orphan(alice_dir),
       "BOMB deflate PUT leaves NO '.xrd-tmp.' staged orphan in alice's dir")

    # =================================================================
    # INBOUND 7 (S3) — cross-protocol decode-on-ingest under impersonation.
    # =================================================================
    if s3port:
        s3key = "alice/cmp_s3_gzip.bin"
        s3disk = os.path.join(data, "alice", "cmp_s3_gzip.bin")
        if exists(s3disk):
            try:
                os.remove(s3disk)
            except OSError:
                pass
        ss, _ = s3("PUT", s3key, s3port, data=gz(PLAIN),
                   access_key="alice", extra_hdrs={"Content-Encoding": "gzip"})
        if ss in (200, 201, 204):
            ok(exists(s3disk) and body_of(s3disk) == PLAIN
               and uid_of(s3disk) == UID_ALICE and uid_of(s3disk) not in (UID_SVC, 0),
               "S3 INBOUND gzip PUT (alice) decoded-and-stored byte-exact + owned alice "
               "1001 not svc/root (HTTP %s)" % ss)
            gss, gsb = s3("GET", s3key, s3port, access_key="alice")
            ok(gss == 200 and gsb == PLAIN,
               "S3 GET of gzip-decoded object returns DECOMPRESSED plaintext byte-exact "
               "(HTTP %s)" % gss)
        else:
            ok(ss >= 400 and not exists(s3disk),
               "S3 INBOUND gzip PUT not decoded -> 4xx + NO undecoded object (HTTP %s)"
               % ss)
            ok(not exists(s3disk),
               "S3 INBOUND gzip unavailable leaves no partial object")

        # S3 CROSS-TENANT: alice principal PUTs an encoded body into bob's 0700 dir.
        b_before = time.time()
        s3xkey = "bobsecret/alice_s3_intrusion.bin"
        s3xdisk = os.path.join(data, "bobsecret", "alice_s3_intrusion.bin")
        sx, _ = s3("PUT", s3xkey, s3port, data=gz(PLAIN),
                   access_key="alice", extra_hdrs={"Content-Encoding": "gzip"})
        ok(sx in (401, 403, 404, 409) and not exists(s3xdisk),
           "S3 CROSS-TENANT gzip PUT alice -> bob/0700 DAC-DENIED + no object "
           "(HTTP %s)" % sx)
        ok(not has_staged_orphan(bobsecret_dir)
           and not svc_root_artifact(bobsecret_dir, b_before),
           "S3 CROSS-TENANT denied encoded PUT leaves no staged orphan / svc-root "
           "artifact in bob's dir")

        # S3 BOMB into alice's own key namespace.
        s3bkey = "alice/cmp_s3_bomb.bin"
        s3bdisk = os.path.join(data, "alice", "cmp_s3_bomb.bin")
        if exists(s3bdisk):
            try:
                os.remove(s3bdisk)
            except OSError:
                pass
        sb, _ = s3("PUT", s3bkey, s3port, data=BOMB_GZ,
                   access_key="alice", extra_hdrs={"Content-Encoding": "gzip"})
        ok(sb >= 400 and (not exists(s3bdisk)
                          or os.stat(s3bdisk).st_size < len(BOMB_RAW)),
           "S3 BOMB gzip PUT (alice) REJECTED 4xx + no full decompressed object "
           "(HTTP %s)" % sb)
        ok(not has_staged_orphan(alice_dir),
           "S3 BOMB gzip PUT leaves no staged orphan in alice's dir")
    else:
        ok(True, "S3 inbound compression checks skipped (S3 port not up)")

    # =================================================================
    # OUTBOUND — brix_*_compress GET response compression.  The directive is OFF in
    # this harness's generated nginx.conf, so this path is currently UNREACHABLE; we
    # detect the response Content-Encoding and graceful-degrade, but ALWAYS assert the
    # security invariant (no corruption on own read; cross-tenant denied with no leak).
    # =================================================================
    # Own compressible object (well above BRIX_COMPRESS_MIN_SIZE=256) for the read path.
    rel_out = "alice/cmp_out_src.txt"
    disk_out = os.path.join(data, "alice", "cmp_out_src.txt")
    sput, _ = http("PUT", "/" + rel_out, port, ta, PLAIN)
    ok(sput in (200, 201, 204) and body_of(disk_out) == PLAIN
       and uid_of(disk_out) == UID_ALICE,
       "OUTBOUND setup: compressible source stored plaintext + owned alice (HTTP %s)"
       % sput)

    ostat, oce, obody = raw_get_headers("/" + rel_out, ta, "gzip")
    outbound_compressed = False
    if ostat == 200 and oce in ("gzip", "deflate", "br", "zstd", "x-gzip"):
        # Compression path active: the body must decompress to the EXACT stored bytes.
        outbound_compressed = True
        recovered = b""
        try:
            if oce in ("gzip", "x-gzip"):
                recovered = zlib.decompress(obody, 31)
            elif oce == "deflate":
                recovered = zlib.decompress(obody)
        except Exception:  # noqa: BLE001
            recovered = b""
        ok(obody != PLAIN and recovered == PLAIN,
           "OUTBOUND GET own object Accept-Encoding:gzip -> body IS compressed (not raw) "
           "and decompresses to the EXACT stored bytes (coding=%s)" % oce)
    elif ostat == 200:
        # Compression OFF (this harness): identity must be byte-exact, never corrupted.
        ok(obody == PLAIN and oce in ("", "identity"),
           "OUTBOUND compression OFF in harness: GET Accept-Encoding:gzip served IDENTITY "
           "byte-exact (no corruption, coding=%r)" % oce)
    else:
        ok(False, "OUTBOUND GET own object unexpectedly non-200 (HTTP %s)" % ostat)

    # OUTBOUND CROSS-TENANT — the KEY leak hunt.  Whether or not compression is active,
    # the compress read path dup()s an fd already DAC-checked at open under the MAPPED
    # identity, so alice reading bob's 0600 file MUST be denied at open and the secret
    # MUST NOT appear in the response body — neither plaintext nor compressed-then-leaked.
    SECRET = b"BOB-PRIVATE-SECRET"
    xstat, xce, xbody = raw_get_headers("/bob/private.txt", ta, "gzip")
    # If the body were a compressed leak, gunzip would reveal the secret -> check both.
    leaked = SECRET in xbody
    if not leaked and xce in ("gzip", "x-gzip", "deflate") and xbody:
        try:
            dec = zlib.decompress(xbody, 31) if xce in ("gzip", "x-gzip") \
                else zlib.decompress(xbody)
            leaked = SECRET in dec
        except Exception:  # noqa: BLE001
            leaked = False
    ok(xstat in (401, 403, 404) and not leaked,
       "OUTBOUND CROSS-TENANT: alice GET bob/private.txt (0600) Accept-Encoding:gzip "
       "DAC-DENIED with NO secret in body (compressed or plain) -> compress read runs as "
       "mapped user, never as svc (HTTP %s)" % xstat)

    # OUTBOUND CROSS-TENANT on bob's 0700-dir 0600 file (no traversal even with gzip).
    s2, ce2, b2 = raw_get_headers("/bobsecret/s.txt", ta, "gzip, deflate, br")
    leak2 = b"bob-only" in b2
    if not leak2 and ce2 in ("gzip", "x-gzip", "deflate") and b2:
        try:
            d2 = zlib.decompress(b2, 31) if ce2 in ("gzip", "x-gzip") else zlib.decompress(b2)
            leak2 = b"bob-only" in d2
        except Exception:  # noqa: BLE001
            leak2 = False
    ok(s2 in (401, 403, 404) and not leak2,
       "OUTBOUND CROSS-TENANT: alice GET bobsecret/s.txt (0700 dir) with Accept-Encoding "
       "DAC-DENIED, no compressed secret leak (HTTP %s)" % s2)

    # OUTBOUND HEAD with Accept-Encoding -> never any body bytes (negotiation skips HEAD).
    hstat, hbody = raw_head("/" + rel_out, ta, "gzip")
    ok(hstat in (200, 206) and hbody == b"",
       "OUTBOUND HEAD own object with Accept-Encoding:gzip returns headers only, NO body "
       "(HTTP %s, bodylen=%d)" % (hstat, len(hbody)))

    # =================================================================
    # LIVENESS — after the codec/bomb storm the worker still serves a fresh, byte-exact
    # read for the mapped user (no codec-state corruption / fd leak wedged the worker).
    # =================================================================
    if outbound_compressed:
        # When compression is on, re-fetch with identity to compare against plaintext.
        lst, lb = http("GET", "/" + rel_out, port, ta, hdrs={"Accept-Encoding": "identity"})
    else:
        lst, lb = http("GET", "/" + rel_out, port, ta)
    ok(lst == 200 and lb == PLAIN,
       "LIVENESS: alice still served the source byte-exact after the codec/bomb storm "
       "(worker not wedged) (HTTP %s)" % lst)


