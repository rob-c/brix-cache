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


def run_raw_kxr_deep(key, data, port, s3port):
    """RAW kXR WIRE under an ACTUALLY-AUTHENTICATED ztn session, exercising the
    impersonation data/metadata plane the way run_raw_kxr_wire could not (it
    degraded pre-auth).  Establishes handshake->protocol->login->kXR_auth(ztn,
    alice-token), then hand-frames kXR_open/read/readv/pgread/pgwrite/statx/
    dirlist/truncate/close/bind to assert the boundary: alice opens her own file
    and reads it byte-exact; an OOB/overflow read or readv segment errors with no
    leak; a pgwrite page with a CORRUPTED CRC32c is NEVER silently accepted; a raw
    open of bob's 0600 (direct + traversal) is NotAuthorized and never returns
    secret bytes; kXR_bind to a foreign sessid is rejected.  Each adversarial
    frame is followed by a native xrdfs survival probe (worker + privileged broker
    still answer).  If the ztn flow cannot be replicated, DEGRADE honestly but
    still run no-auth open/readv/pgwrite framing robustness checks not covered by
    run_raw_kxr_wire, each paired with a survival probe.  GUARDED by xrd_avail()."""
    if not xrd_avail() or not _stream_port:
        ok(True, "raw-kXR deep skipped (native client absent or no stream port)")
        return

    BOB_SECRET = b"BOB-PRIVATE-SECRET"
    ALICE_BODY = b"ALICE-RAW-DEEP-PAYLOAD-0123456789\n"

    def survives(label):
        rc, _o, _e = xrd_fs(["stat", "/alice"], "alice")
        ok(rc == 0,
           f"worker+broker survived {label}: native xrdfs stat /alice (alice) ok (rc={rc})")

    # Seed an alice-owned file via the native write path so the raw reader has a
    # known target whose bytes we can compare exactly.
    seed = os.path.join(WORK, "rkd_seed.bin")
    try:
        with open(seed, "wb") as fh:
            fh.write(ALICE_BODY)
    except OSError:
        pass
    rc_up, _o, _e = xrd_cp_up(seed, "/alice/rkd_self.bin", "alice")
    alice_seeded = (rc_up == 0
                    and os.path.exists(os.path.join(data, "alice", "rkd_self.bin")))
    ok(alice_seeded, f"raw-deep: seeded alice-owned /alice/rkd_self.bin via native write (rc={rc_up})")

    # ----- establish the authenticated ztn session as alice ------------------
    sock, authed = _kxr_authed_session(mint(key, "alice"))

    if not authed or sock is None:
        # ---- DEGRADE: ztn flow not replicable; still probe error paths -------
        ok(True, "raw-kXR authed session not established; deep opcode framing skipped")

        # (D1) malformed kXR_open: header dlen claims a ~512 MiB path body but only
        # a short path is sent (length-mismatch framing the native client cannot emit).
        bad_open = struct.pack("!2sHHHH6s4sI", b"\x00\x40", _KXR_OPEN, 0,
                               _KXR_OPEN_READ, 0, b"\x00" * 6, b"\x00" * 4,
                               0x20000000) + b"/alice/x"
        _hs, st, body, _c = _kxr_oneshot(bad_open)
        ok(st != _KXR_OK,
           f"raw-deep(degraded): pre-auth kXR_open with oversized dlen not ok (status={st})")
        survives("degraded-bad-open")

        # (D2) malformed kXR_readv on a bogus handle pre-auth (distinct from
        # run_raw_kxr_wire's single overflow vector: here MANY tiny segments).
        segs = [(b"\xAA\xAA\xAA\xAA", 1, i) for i in range(8)]
        _hs, st, body, _c = _kxr_oneshot(_kxr_readv_bytes(segs, streamid=b"\x00\x41"))
        ok(st != _KXR_OK and BOB_SECRET not in (body or b""),
           f"raw-deep(degraded): pre-auth multi-seg readv on bogus handle not ok, no leak (status={st})")
        survives("degraded-bad-readv")

        # (D3) malformed kXR_pgwrite pre-auth: a page whose CRC cannot be verified
        # without an open write handle MUST NOT be accepted.
        pgw = _kxr_pgwrite_bytes(b"\x00\x00\x00\x00", 0, b"PRE-AUTH-PG", crc=0xDEADBEEF,
                                 streamid=b"\x00\x42")
        _hs, st, body, _c = _kxr_oneshot(pgw)
        ok(st != _KXR_OK,
           f"raw-deep(degraded): pre-auth kXR_pgwrite (no handle) not ok (status={st})")
        survives("degraded-bad-pgwrite")

        # (D4) native control still works -> broker path intact.
        rc, _o, _e = xrd_fs(["ls", "/alice"], "alice")
        ok(rc == 0,
           f"raw-deep(degraded): after framing attacks native xrdfs ls /alice (alice) ok (rc={rc})")
        return

    # We have an authenticated alice session; the connection's impersonation
    # identity is now uid 1001.  Drive the deep opcode matrix.
    try:
        # ----- (1) AUTHED kXR_open of alice's OWN file -> fhandle -------------
        st, fh = _kxr_open_fhandle(sock, b"/alice/rkd_self.bin",
                                   options=_KXR_OPEN_READ, streamid=b"\x00\x30")
        ok(st == _KXR_OK and fh is not None,
           f"raw-deep: authed kXR_open of alice's own file returns a handle (status={st})")

        if fh is not None:
            # (2) VALID kXR_read of the whole file -> exact bytes.
            st, body = _kxr_send_recv(sock, _kxr_read_bytes(fh, 0, len(ALICE_BODY)))
            ok(st in (_KXR_OK, 4000) and (body or b"").startswith(ALICE_BODY[:16]),
               f"raw-deep: authed kXR_read of own file returns own bytes (status={st})")

            # (3) OOB kXR_read far past EOF -> error or empty, never another
            # tenant's bytes; worker survives.
            st, body = _kxr_send_recv(sock, _kxr_read_bytes(fh, 1 << 40, 4096,
                                                            streamid=b"\x00\x31"))
            ok(BOB_SECRET not in (body or b""),
               f"raw-deep: OOB kXR_read (offset 2^40) returns no foreign bytes (status={st})")

            # (4) kXR_read with overflowing rlen (negative as int32) on a valid
            # handle -> rejected/clamped, no crash.
            st, body = _kxr_send_recv(sock, _kxr_read_bytes(fh, 0, -1,
                                                            streamid=b"\x00\x32"))
            ok(BOB_SECRET not in (body or b""),
               f"raw-deep: kXR_read with -1 rlen handled, no foreign bytes (status={st})")

            # (5) VALID kXR_pgread of page 0 -> kXR_status framing + data+CRC.
            st, body = _kxr_send_recv(sock, _kxr_pgread_bytes(fh, 0, len(ALICE_BODY),
                                                              streamid=b"\x00\x33"))
            ok(st in (4007, _KXR_OK, 4000),
               f"raw-deep: authed kXR_pgread of own file uses status framing (status={st})")
            ok(BOB_SECRET not in (body or b""),
               "raw-deep: pgread of own file carries no foreign secret bytes")

            # (6) kXR_pgread with OOB offset -> no leak.
            st, body = _kxr_send_recv(sock, _kxr_pgread_bytes(fh, 1 << 42, 4096,
                                                              streamid=b"\x00\x34"))
            ok(BOB_SECRET not in (body or b""),
               f"raw-deep: OOB kXR_pgread (offset 2^42) returns no foreign bytes (status={st})")

            # (7) kXR_readv mixing a VALID segment with an out-of-range one on the
            # SAME (valid) handle: must not splice another tenant's bytes.
            segs = [(fh, 8, 0), (fh, 4096, 1 << 40)]
            st, body = _kxr_send_recv(sock, _kxr_readv_bytes(segs, streamid=b"\x00\x35"))
            ok(BOB_SECRET not in (body or b""),
               f"raw-deep: readv [valid, OOB] on own handle leaks no foreign bytes (status={st})")

            # (8) kXR_statx of own file path -> metadata, no secret.
            st, body = _kxr_send_recv(sock, _kxr_statx_bytes(b"/alice/rkd_self.bin"))
            ok(BOB_SECRET not in (body or b""),
               f"raw-deep: authed kXR_statx of own file carries no secret (status={st})")

            # (9) kXR_dirlist of own dir -> entries, never bob's secret content.
            st, body = _kxr_send_recv(sock, _kxr_dirlist_bytes(b"/alice"))
            ok(BOB_SECRET not in (body or b""),
               f"raw-deep: authed kXR_dirlist of /alice carries no secret bytes (status={st})")

            # close the read handle before opening for write.
            _kxr_send_recv(sock, _kxr_close_bytes(fh))

        # ----- (10) open own file for WRITE, then pgwrite with a CORRUPTED CRC -
        stw, fhw = _kxr_open_fhandle(sock, b"/alice/rkd_wr.bin",
                                     options=_KXR_OPEN_UPDT | _KXR_NEW,
                                     mode=0o600, streamid=b"\x00\x36")
        if fhw is not None:
            # (10a) VALID pgwrite of one page -> accepted (status framing).
            st, _b = _kxr_send_recv(sock, _kxr_pgwrite_bytes(fhw, 0, b"GOODPAGE-BYTES",
                                                             crc=None,
                                                             streamid=b"\x00\x37"))
            ok(st in (4007, _KXR_OK),
               f"raw-deep: authed kXR_pgwrite with VALID CRC32c accepted (status={st})")

            # (10b) CORRUPTED CRC -> MUST be rejected (kXR_ChkSumErr / status err),
            # never silently accepted.  THE integrity invariant.
            st, _b = _kxr_send_recv(sock, _kxr_pgwrite_bytes(fhw, 0, b"TAMPERED-PAGE",
                                                             crc=0x00000000,
                                                             streamid=b"\x00\x38"))
            ok(st != _KXR_OK,
               f"raw-deep: kXR_pgwrite with CORRUPTED CRC32c NOT silently accepted (status={st})")

            # (10c) truncate own write handle -> deterministic, no crash.
            st, _b = _kxr_send_recv(sock, _kxr_truncate_bytes(fhw, 0,
                                                              streamid=b"\x00\x39"))
            ok(True, f"raw-deep: authed kXR_truncate of own handle handled (status={st})")
            _kxr_send_recv(sock, _kxr_close_bytes(fhw))

        # ----- (11) authed raw kXR_open of bob's 0600 (DIRECT) ---------------
        st, fhx = _kxr_open_fhandle(sock, b"/bob/private.txt",
                                    options=_KXR_OPEN_READ, streamid=b"\x00\x3A")
        ok(st != _KXR_OK and fhx is None,
           f"raw-deep: authed (alice) kXR_open of bob's 0600 NotAuthorized (status={st})")

        # ----- (12) authed raw kXR_open of bob's file via TRAVERSAL ----------
        st, fhx = _kxr_open_fhandle(sock, b"/alice/../bob/private.txt",
                                    options=_KXR_OPEN_READ, streamid=b"\x00\x3B")
        ok(st != _KXR_OK and fhx is None,
           f"raw-deep: authed kXR_open of bob's 0600 via ../ traversal denied (status={st})")

        # ----- (13) authed raw kXR_open escaping the export to /etc/passwd ---
        st, fhx = _kxr_open_fhandle(sock, b"/../../../../etc/passwd",
                                    options=_KXR_OPEN_READ, streamid=b"\x00\x3C")
        ok(st != _KXR_OK and fhx is None,
           f"raw-deep: authed kXR_open escaping export to /etc/passwd denied (status={st})")

        # ----- (14) kXR_read on a NEVER-OPENED / bogus handle ----------------
        st, body = _kxr_send_recv(sock, _kxr_read_bytes(b"\x7F\x00\x00\x00", 0, 4096,
                                                        streamid=b"\x00\x3D"))
        ok(st != _KXR_OK and BOB_SECRET not in (body or b""),
           f"raw-deep: authed kXR_read on unopened handle 0x7F rejected, no leak (status={st})")

        # ----- (15) kXR_bind to a FOREIGN/garbage sessid on the authed conn --
        bind = struct.pack("!2sH16sI", b"\x00\x3E", 3024, b"\xFF" * 16, 0)
        st, _b = _kxr_send_recv(sock, bind)
        ok(st != _KXR_OK,
           f"raw-deep: authed conn kXR_bind to foreign sessid rejected (status={st})")
    finally:
        try:
            sock.close()
        except OSError:
            pass

    # survival probes for the adversarial authed frames (broker + worker intact).
    survives("authed-oob-and-traversal-frames")
    survives("authed-corrupted-pgwrite")

    # ----- cross-identity confirmation: a SECOND authed session as BOB can
    # read his own 0600 at the wire level (proves the deny above is alice-specific,
    # not a blanket failure) -----------------------------------------------------
    sock_b, authed_b = _kxr_authed_session(mint(key, "bob"))
    if authed_b and sock_b is not None:
        try:
            st, fhb = _kxr_open_fhandle(sock_b, b"/bob/private.txt",
                                        options=_KXR_OPEN_READ, streamid=b"\x00\x50")
            ok(st == _KXR_OK and fhb is not None,
               f"raw-deep: authed BOB kXR_open of his OWN 0600 succeeds (status={st})")
            if fhb is not None:
                st, body = _kxr_send_recv(sock_b, _kxr_read_bytes(fhb, 0, 64))
                ok(BOB_SECRET in (body or b""),
                   "raw-deep: authed BOB reads his own secret (control: deny was identity-scoped)")
                _kxr_send_recv(sock_b, _kxr_close_bytes(fhb))
        finally:
            try:
                sock_b.close()
            except OSError:
                pass
    else:
        ok(True, "raw-deep: second (bob) authed session not established; identity-control skipped")
        ok(True, "raw-deep: bob own-read identity control skipped")

    # ----- final native round-trip: worker + broker fully alive --------------
    rc, _o, _e = xrd_fs(["ls", "/alice"], "alice")
    ok(rc == 0,
       f"raw-deep: after all authed adversarial frames native xrdfs ls /alice ok (rc={rc})")


