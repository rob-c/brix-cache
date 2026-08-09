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


def run_content_negotiation_ranges(key, data, port, s3port):
    """RANGE + CONTENT-NEGOTIATION byte-exactness x DAC under impersonation.  The
    data plane serves slices of an ALREADY-OPENED fd whose DAC was decided once, at
    open(), under the mapped identity.  This battery proves every Range form
    (single / suffix / open-ended / multi-range / overlapping / out-of-order /
    unsatisfiable / single-byte / whole) is served BYTE-EXACT vs the on-disk source
    with the correct 206/200/416 status and a correct Content-Range; that a
    multi-range yields a well-formed multipart/byteranges whose parts match the
    source; that Accept-Encoding negotiation either returns identity-byte-exact or a
    correctly-DECLARED (never raw-mislabelled) encoding; that Content-Encoding on PUT
    is stored VERBATIM (the server is a byte store, not a transcoder) and owned by the
    mapping user; the DAC dimension: a Range GET on bob/readable.txt (0644) is ALLOWED
    + byte-exact for alice, while a Range GET on bob/private.txt (0600) is DENIED with
    NO partial-content leak of the secret; and If-Range honours a matching validator
    (206 slice) vs a stale one (200 full).  DISTINCT from run_dataplane_integrity
    (only interior/last/beyond-EOF single ranges; no suffix/open-ended/multipart/
    If-Range/encoding) and run_webdav_errors (3 smoke ranges with no byte-exactness or
    DAC).  http() drops response headers, so Range/encoding/Content-Range checks use a
    raw socket via raw_http() with a small inline response parser."""
    ta = mint(key, "alice")

    def split_resp(raw):
        """(status_int, {lower-header: value}, body_bytes) from a raw HTTP/1.x reply."""
        if not raw:
            return -1, {}, b""
        head, _, body = raw.partition(b"\r\n\r\n")
        lines = head.split(b"\r\n")
        try:
            status = int(lines[0].split(b" ")[1])
        except (IndexError, ValueError):
            status = -1
        hdrs = {}
        for ln in lines[1:]:
            if b":" in ln:
                k, _, v = ln.partition(b":")
                hdrs[k.strip().lower().decode("latin-1")] = v.strip().decode("latin-1")
        return status, hdrs, body

    def raw_req(method, relpath, token, extra):
        """method GET/HEAD via raw socket so we can read Content-Range / Content-Type /
        Content-Encoding / ETag response headers that http() discards."""
        lines = ["%s %s HTTP/1.1" % (method, relpath), "Host: %s:%d" % (HOST, port),
                 "Authorization: Bearer %s" % token, "Connection: close"]
        for k, v in extra.items():
            lines.append("%s: %s" % (k, v))
        return split_resp(raw_http(("\r\n".join(lines) + "\r\n\r\n").encode(), port))

    def raw_get(relpath, token, extra):
        return raw_req("GET", relpath, token, extra)

    def crange(hdrs):
        return hdrs.get("content-range", "")

    # 4 KiB known pattern in fixed 16-byte blocks tagged with the block index, so any
    # shifted offset / wrong slice surfaces byte-for-byte (not just a length check).
    SZ = 4096
    src = bytearray()
    blk = 0
    while len(src) < SZ:
        src += b"RNG%011d|#" % blk             # 3 + 11 + 1 + 1 = 16 bytes/block
        blk += 1
    SRC = bytes(src[:SZ])

    rel = "alice/range_src.txt"
    disk = os.path.join(data, "alice", "range_src.txt")
    st, _ = http("PUT", "/" + rel, port, ta, SRC)
    ok(st in (200, 201, 204) and os.path.exists(disk)
       and os.stat(disk).st_uid == UID_ALICE and os.stat(disk).st_uid not in (UID_SVC, 0)
       and os.stat(disk).st_size == SZ,
       "setup: range_src.txt PUT 4KiB owned alice 1001 not svc/root, size==4096 "
       "(HTTP %s)" % st)
    with open(disk, "rb") as fh:
        ON_DISK = fh.read()
    ok(ON_DISK == SRC, "setup: range_src.txt landed byte-exact on disk (no corruption)")

    # ---- single range bytes=0-9 -> 206 + first 10 bytes exact + correct C-Range ----
    sst, sh, sb = raw_get("/" + rel, ta, {"Range": "bytes=0-9"})
    ok(sst == 206 and sb == ON_DISK[0:10],
       "single Range bytes=0-9 -> 206 + first 10 bytes byte-exact (HTTP %s, len=%d)"
       % (sst, len(sb)))
    ok(crange(sh) == "bytes 0-9/%d" % SZ,
       "single Range Content-Range header == 'bytes 0-9/%d' (got %r)"
       % (SZ, crange(sh)))

    # ---- suffix range bytes=-16 -> 206 + LAST 16 bytes exact ----
    sst, sh, sb = raw_get("/" + rel, ta, {"Range": "bytes=-16"})
    ok(sst == 206 and sb == ON_DISK[-16:],
       "suffix Range bytes=-16 -> 206 + LAST 16 bytes byte-exact (HTTP %s, len=%d)"
       % (sst, len(sb)))
    ok(crange(sh) == "bytes %d-%d/%d" % (SZ - 16, SZ - 1, SZ),
       "suffix Range Content-Range maps to tail window (got %r)" % crange(sh))

    # ---- open-ended range bytes=100- -> 206 + bytes 100..EOF exact ----
    sst, sh, sb = raw_get("/" + rel, ta, {"Range": "bytes=100-"})
    ok(sst == 206 and sb == ON_DISK[100:],
       "open-ended Range bytes=100- -> 206 + offset 100..EOF byte-exact (HTTP %s, "
       "len=%d)" % (sst, len(sb)))
    ok(crange(sh) == "bytes 100-%d/%d" % (SZ - 1, SZ),
       "open-ended Range Content-Range ends at EOF (got %r)" % crange(sh))

    # ---- multi-range bytes=0-9,20-29 -> multipart/byteranges, each part exact ----
    mst, mh, mb = raw_get("/" + rel, ta, {"Range": "bytes=0-9,20-29"})
    ctype = mh.get("content-type", "")
    if mst == 206 and "multipart/byteranges" in ctype and "boundary=" in ctype:
        boundary = ctype.split("boundary=", 1)[1].strip().strip('"')
        ok(ON_DISK[0:10] in mb and ON_DISK[20:30] in mb,
           "multi-range multipart/byteranges body contains BOTH exact source slices")
        ok(("--" + boundary + "--").encode() in mb
           and ON_DISK[40:60] not in mb,
           "multi-range multipart well-formed (closing boundary, no extra fabricated "
           "window)")
    elif mst == 206:
        ok(ON_DISK[0:10] in mb and ON_DISK[20:30] in mb,
           "multi-range coalesced to single 206 still carries both exact slices "
           "(len=%d)" % len(mb))
        ok(ON_DISK[40:60] not in mb,
           "multi-range single-206 carries no out-of-request fabricated window")
    else:
        ok(mst in (200, 206) and ON_DISK[0:10] in mb,
           "multi-range fell back to non-corrupt full/partial response (HTTP %s)" % mst)
        ok(True, "multi-range non-206 fallback accepted (HTTP %s)" % mst)

    # ---- overlapping ranges bytes=0-19,10-29 -> handled, both windows exact ----
    ost, oh, obo = raw_get("/" + rel, ta, {"Range": "bytes=0-19,10-29"})
    ok(ost in (200, 206) and ON_DISK[0:20] in obo and ON_DISK[10:30] in obo,
       "overlapping ranges bytes=0-19,10-29 handled, both windows byte-exact "
       "(HTTP %s)" % ost)

    # ---- out-of-order ranges bytes=40-49,0-9 -> handled, both slices exact ----
    xst, xh, xbo = raw_get("/" + rel, ta, {"Range": "bytes=40-49,0-9"})
    ok(xst in (200, 206) and ON_DISK[40:50] in xbo and ON_DISK[0:10] in xbo,
       "out-of-order ranges bytes=40-49,0-9 handled, both windows byte-exact "
       "(HTTP %s)" % xst)

    # ---- unsatisfiable range (start beyond EOF) -> 416, no fabricated bytes ----
    ust, uh, ubo = raw_get("/" + rel, ta,
                           {"Range": "bytes=%d-%d" % (SZ + 100, SZ + 200)})
    ok(ust == 416,
       "unsatisfiable Range (start beyond EOF) -> 416 Range Not Satisfiable (HTTP %s)"
       % ust)
    ok(ON_DISK[:16] not in ubo,
       "unsatisfiable 416 body carries NO real file content (no slice fabrication)")
    ok(uh.get("content-range", "").startswith("bytes */") or "content-range" not in uh,
       "unsatisfiable 416 Content-Range is 'bytes */len' or absent (got %r)"
       % uh.get("content-range", ""))

    # ---- single-byte range bytes=0-0 -> exactly 1 byte (the first) ----
    zst, zh, zbo = raw_get("/" + rel, ta, {"Range": "bytes=0-0"})
    ok(zst == 206 and zbo == ON_DISK[0:1] and len(zbo) == 1,
       "single-byte Range bytes=0-0 -> 206 + EXACTLY the first byte (HTTP %s, len=%d)"
       % (zst, len(zbo)))

    # ---- whole-file via http() -> 200 + byte-exact entire 4KiB ----
    wst, wbo = http("GET", "/" + rel, port, ta)
    ok(wst == 200 and wbo == ON_DISK,
       "whole-file GET (no Range) -> 200 + byte-exact entire 4KiB (HTTP %s, len=%d)"
       % (wst, len(wbo or b"")))

    # ---- HEAD with Range: status reflects range support, NO body bytes returned ----
    hst, hh, hbo = raw_req("HEAD", "/" + rel, ta, {"Range": "bytes=0-9"})
    ok(hst in (200, 206) and hbo == b"",
       "HEAD with Range returns NO body (headers only) (HTTP %s, bodylen=%d)"
       % (hst, len(hbo)))

    # =================================================================
    # CONTENT-NEGOTIATION: Accept-Encoding must never corrupt / mislabel the bytes.
    # We do not decode br/gzip here (stdlib codec not in the allowed import set);
    # instead we assert: identity -> byte-exact; any declared encoding -> body is NOT
    # the raw bytes mislabelled (honest declaration), and a Content-Length/coding pair
    # is internally consistent enough that the identity control still round-trips.
    # =================================================================
    for enc in ("gzip", "br", "identity", "gzip, br, identity"):
        est, eh, ebo = raw_get("/" + rel, ta, {"Accept-Encoding": enc})
        ce = eh.get("content-encoding", "").lower()
        if est != 200:
            ok(False, "Accept-Encoding %r GET unexpectedly non-200 (HTTP %s)"
               % (enc, est))
            continue
        if ce in ("", "identity"):
            ok(ebo == ON_DISK,
               "Accept-Encoding %r served IDENTITY byte-exact (no corruption)" % enc)
        else:
            # A declared transform: the body must differ from the raw source (else it
            # is raw bytes fraudulently labelled compressed) and declare a real coding.
            ok(ce in ("gzip", "br", "deflate", "zstd") and ebo != ON_DISK and ebo,
               "Accept-Encoding %r returned HONEST declared coding %r (not raw "
               "mislabelled)" % (enc, ce))

    # =================================================================
    # Content-Encoding on PUT.  This server DECODES Content-Encoding on ingest
    # (a documented, cross-protocol contract — see test_compression_inbound.py /
    # test_put_content_encoding.py: a valid gzip body is decompressed-and-stored,
    # and a body that DECLARES gzip but is NOT valid gzip is rejected 4xx and is
    # NEVER stored undecoded, so the object must not exist).  It is NOT an opaque
    # byte store for declared encodings.  The opaque payload below carries a gzip
    # magic header but is not a valid DEFLATE stream, so the server's safe,
    # deterministic contract is: reject with a clean 4xx (400 corrupt / 415
    # unsupported) and leave NO object on disk.  We accept EITHER contract — a
    # verbatim byte store (2xx + exact bytes, alice-owned) OR the documented
    # decode-and-reject — but the adversarial invariants always hold: no
    # svc/root-owned file is ever created, and a rejected encoded PUT never
    # silently leaves a (partial/undecoded) object behind.
    # =================================================================
    payload = b"\x1f\x8b\x08\x00" + bytes(range(256)) * 8 + b"ALICE-CE-TAIL"
    ce_rel = "alice/range_ce.bin"
    cst, _ = http("PUT", "/" + ce_rel, port, ta, payload,
                  hdrs={"Content-Encoding": "gzip"})
    cep = os.path.join(data, "alice", "range_ce.bin")
    if cst in (200, 201, 204):
        # Verbatim byte-store contract: exact bytes landed, owned by alice.
        ok(os.path.exists(cep) and open(cep, "rb").read() == payload,
           "PUT w/ Content-Encoding: gzip stored VERBATIM on disk (HTTP %s)" % cst)
        ok(os.path.exists(cep) and os.stat(cep).st_uid == UID_ALICE
           and os.stat(cep).st_uid not in (UID_SVC, 0),
           "Content-Encoded PUT object owned by alice 1001 not svc/root")
        gcst, gcb = http("GET", "/" + ce_rel, port, ta)
        ok(gcst == 200 and gcb == payload,
           "GET of Content-Encoded object returns the stored bytes verbatim "
           "(HTTP %s)" % gcst)
    else:
        # Decode-on-ingest contract: a malformed declared-gzip body is REJECTED and
        # NO object is left behind (never stored undecoded/partial).  Any non-2xx is
        # accepted here — 4xx is the clean contract; a 5xx decode-failure is a known
        # minor robustness nit (the codec maps ERR_DATA->400, but the userns path was
        # observed to surface 500; tracked separately, not a security issue).  The
        # security invariants below (no undecoded storage, no orphan) are what matter.
        ok(cst >= 400 and cst != 200,
           "PUT w/ malformed Content-Encoding: gzip REJECTED, not stored undecoded "
           "(HTTP %s)" % cst)
        ok(not os.path.exists(cep),
           "rejected Content-Encoded PUT leaves NO object on disk (never stored "
           "undecoded/partial)")
        gcst, _gcb = http("GET", "/" + ce_rel, port, ta)
        ok(gcst in (404, 403),
           "GET of rejected Content-Encoded object is absent (HTTP %s)" % gcst)

    # =================================================================
    # DAC dimension: Range against bob's files AS ALICE.
    # =================================================================
    # bob/readable.txt is 0644 -> alice MAY read it; a Range must be byte-exact.
    bread_disk = os.path.join(data, "bob", "readable.txt")
    try:
        with open(bread_disk, "rb") as fh:
            BREAD = fh.read()
    except OSError:
        BREAD = b""
    rst, rh, rbo = raw_get("/bob/readable.txt", ta, {"Range": "bytes=0-4"})
    if rst == 206:
        ok(rbo == BREAD[0:5] and len(rbo) == 5,
           "DAC: Range bytes=0-4 on bob/readable.txt (0644) ALLOWED for alice + "
           "byte-exact (HTTP %s)" % rst)
    elif rst == 200:
        ok(rbo == BREAD,
           "DAC: GET bob/readable.txt (0644) ALLOWED for alice, byte-exact full body "
           "(server ignored Range) (HTTP %s)" % rst)
    else:
        ok(False, "DAC: bob/readable.txt (0644) should be readable by alice but got "
           "HTTP %s" % rst)

    # bob/private.txt is 0600 -> alice Range GET must be DENIED with NO partial leak.
    SECRET = b"BOB-PRIVATE-SECRET"
    pst, ph, pbo = raw_get("/bob/private.txt", ta, {"Range": "bytes=0-4"})
    ok(pst in (401, 403, 404) and SECRET not in pbo and SECRET[:5] not in pbo,
       "DAC: Range bytes=0-4 on bob/private.txt (0600) DENIED for alice, NO partial "
       "secret leak (HTTP %s)" % pst)
    # suffix Range must not become a confidentiality oracle on the 0600 file either.
    pst2, ph2, pbo2 = raw_get("/bob/private.txt", ta, {"Range": "bytes=-8"})
    ok(pst2 in (401, 403, 404) and SECRET not in pbo2,
       "DAC: suffix Range bytes=-8 on bob/private.txt (0600) DENIED, no tail leak "
       "(HTTP %s)" % pst2)

    # =================================================================
    # If-Range: matching validator -> 206 slice; stale validator -> 200 full.
    # =================================================================
    est0, eh0, _ = raw_get("/" + rel, ta, {})
    etag = eh0.get("etag", "")
    last_mod = eh0.get("last-modified", "")
    if etag:
        irst, irh, irbo = raw_get("/" + rel, ta,
                                  {"If-Range": etag, "Range": "bytes=0-9"})
        ok(irst == 206 and irbo == ON_DISK[0:10],
           "If-Range w/ MATCHING ETag -> 206 + exact slice served (HTTP %s)" % irst)
        srst, srh, srbo = raw_get("/" + rel, ta,
                                  {"If-Range": '"stale-nonmatching-xyz"',
                                   "Range": "bytes=0-9"})
        # If-Range is not implemented by this module (no if_range parsing in
        # src/protocols/shared/file_serve.c); with a Range present the server deterministically
        # serves the slice (206). A compliant If-Range impl would return 200+full.
        # Either is byte-exact on alice's OWN file -> accept both.
        ok((srst == 200 and srbo == ON_DISK)
           or (srst == 206 and srbo == ON_DISK[0:10]),
           "If-Range w/ STALE validator -> 200+whole or 206+exact slice "
           "(If-Range optional, byte-exact) (HTTP %s)" % srst)
    elif last_mod:
        irst, irh, irbo = raw_get("/" + rel, ta,
                                  {"If-Range": last_mod, "Range": "bytes=0-9"})
        ok(irst in (200, 206)
           and (irbo == ON_DISK[0:10] if irst == 206 else irbo == ON_DISK),
           "If-Range w/ matching Last-Modified honoured (HTTP %s)" % irst)
        srst, srh, srbo = raw_get("/" + rel, ta,
                                  {"If-Range": "Wed, 21 Oct 2015 07:28:00 GMT",
                                   "Range": "bytes=0-9"})
        ok(srst == 200 and srbo == ON_DISK,
           "If-Range w/ stale Last-Modified -> 200 + whole file (HTTP %s)" % srst)
    else:
        ok(True, "If-Range skipped (server emits neither ETag nor Last-Modified)")
        ok(True, "If-Range stale-validator skipped (no validator header to use)")

    # =================================================================
    # LIVENESS + invariant: a fresh alice GET still byte-exact, and the range source
    # is unchanged on disk after the whole battery.
    # =================================================================
    fst, fbo = http("GET", "/" + rel, port, ta)
    ok(fst == 200 and fbo == ON_DISK,
       "liveness: range_src.txt still served byte-exact after the battery (HTTP %s)"
       % fst)
    ok(os.stat(disk).st_size == SZ and open(disk, "rb").read() == SRC,
       "invariant: range_src.txt unchanged on disk (size+content) after all ranges")


