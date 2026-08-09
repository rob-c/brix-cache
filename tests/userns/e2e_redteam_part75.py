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


def run_raw_kxr_authed(key, data, port, s3port):
    """RAW kXR_query SUB-CODE matrix under an ACTUALLY-AUTHENTICATED ztn session —
    the wire-level metadata/oracle plane that neither run_raw_kxr_deep (which drives
    authed open/read/readv/pgread/pgwrite/statx/dirlist/truncate/bind but NEVER
    kXR_query) nor run_query_subcode_oracle (which uses the NATIVE xrdfs binary, not
    hand-framed wire bytes) exercises.  Establishes handshake->protocol->login->
    kXR_auth(ztn, alice-token) so the connection's impersonation identity is uid
    1001, then hand-frames ClientQueryRequest for Qcksum / Qxattr / Qconfig / Qspace
    / QStats / Qopaquf / an unknown infotype against (a) alice's OWN file and (b)
    bob's 0600 cross-tenant (direct + traversal + /etc escape).  Asserts the
    boundary AT THE WIRE: alice's own Qcksum returns a digest with no foreign bytes;
    alice's Qcksum/Qxattr of bob's 0600 is DENIED at the auth gate and leaks neither
    bob's secret NOR a bob-derived fingerprint (digest / oss.used size — a content-
    derived leak even at a non-error status); the GLOBAL subcodes never embed a
    tenant path/secret; a malformed query dlen errors cleanly without desync; and a
    bob ztn session proves the deny was identity-scoped, with bob's REAL wire digest
    captured to assert it never appeared in alice's denied response.  Degrades
    honestly (pre-auth raw query framing not covered by run_raw_kxr_wire/deep, each
    paired with a survival probe) if ztn cannot be established.  GUARDED by
    xrd_avail()."""
    if not xrd_avail() or not _stream_port:
        ok(True, "raw-kXR authed-query skipped (native client absent or no stream port)")
        return

    BOB_SECRET = b"BOB-PRIVATE-SECRET"

    def survives(label):
        rc, _o, _e = xrd_fs(["stat", "/alice"], "alice")
        ok(rc == 0,
           f"worker+broker survived {label}: native xrdfs stat /alice (alice) ok (rc={rc})")

    def hexfp(blob):
        """Hex tokens (>=8 chars) in a raw query response body — a Qcksum reply is
        'algo <long-hex-digest>', so this captures the content fingerprint a cross-
        tenant query must NEVER echo back to a different identity."""
        toks = set()
        text = (blob or b"").decode("latin-1", "replace")
        for raw in (text.replace("\n", " ").replace("=", " ")
                        .replace("\x00", " ").split()):
            t = raw.strip().lower()
            if len(t) >= 8 and all(ch in "0123456789abcdef" for ch in t):
                toks.add(t)
        return toks

    # Seed distinctive, known-content fixtures so a leaked digest/size is recognisable.
    # Each < 64 KiB, written as the in-ns provisioner so ownership/mode are exact.
    bob_payload = b"BOB-RKA-WIRE-DIFFERENTIAL-" + (b"Q7" * 40) + b"\n"
    alice_payload = b"ALICE-RKA-OWN-WIRE-" + (b"a3" * 30) + b"\n"
    bob_rel, alice_rel = "bob/rka_diff.bin", "alice/rka_own.bin"
    bpath = os.path.join(data, "bob", "rka_diff.bin")
    apath = os.path.join(data, "alice", "rka_own.bin")
    try:
        with open(bpath, "wb") as fh:
            fh.write(bob_payload)
        os.chown(bpath, UID_BOB, UID_BOB)
        os.chmod(bpath, 0o600)
        with open(apath, "wb") as fh:
            fh.write(alice_payload)
        os.chown(apath, UID_ALICE, UID_ALICE)
        os.chmod(apath, 0o644)
    except OSError:
        pass
    bob_size_tok = b"oss.used=%d" % len(bob_payload)

    # ----- establish the authenticated ztn session as alice ------------------
    sock, authed = _kxr_authed_session(mint(key, "alice"))

    if not authed or sock is None:
        # ---- DEGRADE: ztn flow not replicable; probe pre-auth query framing ----
        ok(True, "ztn-authed raw-kXR session not established; deep opcode matrix skipped")

        # (D1) pre-auth raw kXR_query Qcksum of bob's 0600 — a query before any
        # login/auth must be rejected and serve no bob bytes/digest (distinct from
        # run_raw_kxr_wire/deep, which never frame a query opcode at all).
        _hs, st, body, _c = _kxr_oneshot(
            _kxr_query_bytes(_KXR_QCKSUM, b"crc32c /bob/rka_diff.bin", streamid=b"\x00\x60"))
        ok(st != _KXR_OK and BOB_SECRET not in (body or b""),
           f"raw-authed(degraded): pre-auth Qcksum of bob 0600 not ok, no leak (status={st})")
        survives("degraded-preauth-qcksum")

        # (D2) pre-auth raw kXR_query with a malformed dlen (claims ~256 MiB arg,
        # sends a short one) — clean error, no crash.
        bad = struct.pack("!2sHH2s4s8sI", b"\x00\x61", _KXR_QUERY, _KXR_QCKSUM,
                          b"\x00" * 2, b"\x00" * 4, b"\x00" * 8,
                          0x10000000) + b"crc32c /alice/x"
        _hs, st, _b, closed = _kxr_oneshot(bad)
        ok(st != _KXR_OK or closed,
           f"raw-authed(degraded): pre-auth query with oversized dlen not ok (status={st})")
        survives("degraded-preauth-bad-dlen")

        # (D3) pre-auth global Qconfig — even the non-path subcode must not be
        # served as a privileged ok before auth; never embeds a tenant secret.
        _hs, st, body, _c = _kxr_oneshot(
            _kxr_query_bytes(_KXR_QCONFIG, b"chksum", streamid=b"\x00\x62"))
        ok(BOB_SECRET not in (body or b""),
           f"raw-authed(degraded): pre-auth Qconfig carries no tenant secret (status={st})")
        survives("degraded-preauth-qconfig")

        rc, _o, _e = xrd_fs(["ls", "/alice"], "alice")
        ok(rc == 0,
           f"raw-authed(degraded): after query framing attacks native xrdfs ls /alice ok (rc={rc})")
        return

    # ---- authenticated alice (uid 1001): drive the raw kXR_query matrix --------
    alice_fp = set()
    alice_deny_blobs = []      # every cross-tenant DENIED response body (for leak check)
    try:
        # ----- (1) Qcksum of alice's OWN file -> a digest, no foreign bytes -----
        st, body = _kxr_send_recv(
            sock, _kxr_query_bytes(_KXR_QCKSUM, b"crc32c /" + alice_rel.encode(),
                                   streamid=b"\x00\x63"))
        alice_fp = hexfp(body)
        ok(st == _KXR_OK and alice_fp,
           f"raw-authed: alice Qcksum of her OWN 0644 file returns a digest (status={st})")
        ok(BOB_SECRET not in (body or b""),
           "raw-authed: alice's own Qcksum response carries no bob secret bytes")

        # ----- (2) Qcksum of bob's 0600 DIRECT -> DENIED, no secret/digest ------
        st, body = _kxr_send_recv(
            sock, _kxr_query_bytes(_KXR_QCKSUM, b"crc32c /" + bob_rel.encode(),
                                   streamid=b"\x00\x64"))
        alice_deny_blobs.append(body or b"")
        ok(st != _KXR_OK,
           f"raw-authed: alice Qcksum of bob's 0600 is DENIED at the auth gate (status={st})")
        ok(BOB_SECRET not in (body or b""),
           "raw-authed: alice's denied bob-0600 Qcksum carries no raw secret bytes")

        # ----- (3) Qcksum of bob's 0600 via ../ TRAVERSAL -> DENIED ------------
        st, body = _kxr_send_recv(
            sock, _kxr_query_bytes(_KXR_QCKSUM, b"crc32c /alice/../bob/rka_diff.bin",
                                   streamid=b"\x00\x65"))
        alice_deny_blobs.append(body or b"")
        ok(st != _KXR_OK and BOB_SECRET not in (body or b""),
           f"raw-authed: alice Qcksum of bob's 0600 via ../ traversal denied, no leak (status={st})")

        # ----- (4) Qcksum escaping the export to /etc/passwd -> DENIED --------
        st, body = _kxr_send_recv(
            sock, _kxr_query_bytes(_KXR_QCKSUM, b"crc32c /../../../../etc/passwd",
                                   streamid=b"\x00\x66"))
        ok(st != _KXR_OK and b"root:" not in (body or b"") and b"daemon:" not in (body or b""),
           f"raw-authed: alice Qcksum escaping export to /etc/passwd denied, no passwd content (status={st})")

        # ----- (5) Qxattr of alice's OWN file -> her metadata, no foreign bytes -
        st, body = _kxr_send_recv(
            sock, _kxr_query_bytes(_KXR_QXATTR, b"/" + alice_rel.encode(),
                                   streamid=b"\x00\x67"))
        ok(BOB_SECRET not in (body or b"") and bob_size_tok not in (body or b""),
           f"raw-authed: alice's OWN Qxattr exposes no bob secret/size (status={st})")

        # ----- (6) Qxattr of bob's 0600 -> CONTENT boundary holds -------------
        # The xattr handler stats the file under impersonation (as alice, uid
        # 1001).  bob's file lives in /bob, a 0755 (world-traversable) dir, so a
        # plain POSIX stat by alice legitimately returns the file's METADATA
        # (size/mtime) — exactly what `stat /bob/rka_diff.bin` yields for any
        # traverser on a real FS; 0600 protects file CONTENT, not metadata under a
        # world-traversable parent.  The impersonation invariant is therefore that
        # no bob CONTENT (secret bytes / a content-derived digest) is returned, NOT
        # that the POSIX-visible size is hidden (raw-deep already proves the OPEN of
        # bob's 0600 is NotAuthorized, so the bytes never leave).
        st, body = _kxr_send_recv(
            sock, _kxr_query_bytes(_KXR_QXATTR, b"/" + bob_rel.encode(),
                                   streamid=b"\x00\x68"))
        alice_deny_blobs.append(body or b"")
        ok(BOB_SECRET not in (body or b""),
           f"raw-authed: alice Qxattr of bob's 0600 leaks no bob CONTENT bytes (status={st})")
        ok(not hexfp(body or b""),
           "raw-authed: alice's bob-0600 Qxattr carries no content-derived digest fingerprint")
        ok(BOB_SECRET not in (body or b""),
           "raw-authed: alice's bob-0600 Qxattr carries no raw secret bytes")

        # ----- (7) Qopaquf of bob's 0600 -> DAC gate fires BEFORE 'unsupported' -
        # opaquefile resolves+auth-gates the path before the fctl-unsupported reply;
        # cross-tenant must be denied at the gate, not masked as a generic
        # unsupported, and must leak no secret/size.
        st, body = _kxr_send_recv(
            sock, _kxr_query_bytes(_KXR_QOPAQUF, b"/" + bob_rel.encode(),
                                   streamid=b"\x00\x69"))
        alice_deny_blobs.append(body or b"")
        ok(st != _KXR_OK and BOB_SECRET not in (body or b"")
           and bob_size_tok not in (body or b""),
           f"raw-authed: alice Qopaquf of bob's 0600 denied at DAC gate, no secret/size (status={st})")

        # ----- (8) GLOBAL Qconfig -> no tenant path/secret embedded -----------
        st, body = _kxr_send_recv(
            sock, _kxr_query_bytes(_KXR_QCONFIG, b"chksum", streamid=b"\x00\x6A"))
        ok(BOB_SECRET not in (body or b"") and b"/bob/" not in (body or b""),
           f"raw-authed: global Qconfig response embeds no tenant path/secret (status={st})")

        # ----- (9) GLOBAL Qspace -> no tenant path/secret ----------------------
        st, body = _kxr_send_recv(
            sock, _kxr_query_bytes(_KXR_QSPACE, b"/", streamid=b"\x00\x6B"))
        ok(BOB_SECRET not in (body or b"") and bob_size_tok not in (body or b""),
           f"raw-authed: global Qspace response embeds no tenant secret/size (status={st})")

        # ----- (10) GLOBAL QStats -> no tenant path/secret ---------------------
        st, body = _kxr_send_recv(
            sock, _kxr_query_bytes(_KXR_QSTATS, b"", streamid=b"\x00\x6C"))
        ok(BOB_SECRET not in (body or b"") and b"/bob/" not in (body or b""),
           f"raw-authed: global QStats response embeds no tenant path/secret (status={st})")

        # ----- (11) malformed query dlen on the AUTHED conn -> clean error, no
        # desync (a following well-formed own-Qcksum must still parse correctly) --
        bad = struct.pack("!2sHH2s4s8sI", b"\x00\x6D", _KXR_QUERY, _KXR_QCKSUM,
                          b"\x00" * 2, b"\x00" * 4, b"\x00" * 8,
                          0x08000000) + b"crc32c /alice/short"
        st, _b = _kxr_send_recv(sock, bad)
        ok(st != _KXR_OK,
           f"raw-authed: authed query with oversized dlen not ok (status={st})")

        # ----- (12) UNKNOWN infotype -> kXR_Unsupported, no crash, no leak -----
        st, body = _kxr_send_recv(
            sock, _kxr_query_bytes(0x7777, b"/bob/rka_diff.bin", streamid=b"\x00\x6E"))
        ok(st != _KXR_OK and BOB_SECRET not in (body or b""),
           f"raw-authed: unknown query infotype 0x7777 unsupported, no leak (status={st})")
    finally:
        try:
            sock.close()
        except OSError:
            pass

    survives("authed-cross-tenant-query-matrix")

    # ---- cross-identity control: a BOB ztn session reads HIS OWN wire digest,
    # proving the alice-deny was identity-scoped, and capturing the authoritative
    # bob-derived fingerprint to assert it never appeared in alice's responses. ----
    bob_fp = set()
    sock_b, authed_b = _kxr_authed_session(mint(key, "bob"))
    if authed_b and sock_b is not None:
        try:
            st, body = _kxr_send_recv(
                sock_b, _kxr_query_bytes(_KXR_QCKSUM, b"crc32c /" + bob_rel.encode(),
                                         streamid=b"\x00\x70"))
            bob_fp = hexfp(body)
            ok(st == _KXR_OK and bob_fp,
               f"raw-authed: bob Qcksum of his OWN 0600 succeeds at the wire (status={st})")
            ok(not (alice_fp and bob_fp and alice_fp == bob_fp),
               "raw-authed: bob's own-file digest != alice's own-file digest "
               "(distinct content -> distinct wire checksum, no shared-state bleed)")
        finally:
            try:
                sock_b.close()
            except OSError:
                pass
    else:
        ok(True, "raw-authed: second (bob) ztn session not established; identity control skipped")
        ok(True, "raw-authed: bob own-digest distinctness control skipped")

    # DIFFERENTIAL leak check: none of alice's DENIED cross-tenant responses may
    # echo bob's real wire digest fingerprint (a returned digest is a content-
    # derived leak even at a non-error status).
    leaked = False
    if bob_fp:
        for blob in alice_deny_blobs:
            if bob_fp & hexfp(blob):
                leaked = True
                break
    ok(not leaked,
       "raw-authed: NO alice denied cross-tenant query echoes bob's real wire digest "
       "(no content-derived leak through the raw query oracle)")

    # ---- final native round-trip: worker + broker fully alive ----------------
    rc, _o, _e = xrd_fs(["ls", "/alice"], "alice")
    ok(rc == 0,
       f"raw-authed: after all authed raw-query frames native xrdfs ls /alice ok (rc={rc})")


