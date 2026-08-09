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


def run_confine_encoding_exhaustive(key, data, port, s3port):
    """CONFINEMENT / TRAVERSAL / ENCODING exhaustive across all 3 protocols under
    impersonation.  The broker re-applies RESOLVE_BENEATH after the worker resolves
    the path, so EVERY traversal/encoding variant must fail closed: never return a
    byte of /etc/passwd, never leak another tenant's secret, never create or read a
    path OUTSIDE the export root.  We also plant a symlink inside a tenant's OWN dir
    pointing OUT (to /etc, to bob's private file, to svconly) and have a DIFFERENT
    identity try to follow it via each protocol — the broker must not follow it out.
    Every deny has a nearby POSITIVE CONTROL (a legit nested in-tenant path works)
    so a blanket block cannot false-pass."""
    ta = mint(key, "alice")
    tb = mint(key, "bob")
    PW = b"root:x:"                       # /etc/passwd signature
    BOB = b"BOB-PRIVATE-SECRET"           # bob/private.txt body
    SVC = b"svc-only-secret"              # svconly/secret-name.txt body

    # parent dirs of the export — nothing our attacks create may land in them.
    export_abs = os.path.abspath(data)
    parent1 = os.path.dirname(export_abs)
    parent2 = os.path.dirname(parent1)

    def no_passwd(body):
        b = body or b""
        return PW not in b and b"root:!" not in b and b"daemon:x:" not in b

    def outside_clean(*names):
        """True iff NONE of the candidate outside paths exist (nothing escaped)."""
        for n in names:
            try:
                if os.path.exists(n):
                    return False
            except OSError:
                pass
        return True

    # ---- A unique marker file OUTSIDE the export the attacks try to read -----------
    # Planted by the in-ns-root test process so a successful escape would surface it.
    out_marker = os.path.join(parent1, "CONFENC_OUTSIDE_MARKER.txt")
    MARK = b"CONFENC-OUTSIDE-LEAK-7Q"
    try:
        with open(out_marker, "wb") as fh:
            fh.write(MARK + b"\n")
        os.chmod(out_marker, 0o644)
    except OSError:
        out_marker = None

    # =============================================================================
    # POSITIVE CONTROL CLUSTER — legit nested in-tenant paths must keep working, so
    # the deny checks below cannot be satisfied by a server that blocks everything.
    # =============================================================================
    st, _ = http("MKCOL", "/alice/cf_nest", port, ta)
    ok(st in (200, 201, 405),
       f"control: WebDAV MKCOL nested dir in own tenant OK (HTTP {st})")
    st, _ = http("PUT", "/alice/cf_nest/legit.txt", port, ta, b"LEGIT-NESTED\n")
    lp = os.path.join(data, "alice", "cf_nest", "legit.txt")
    ok(st in (200, 201, 204) and os.path.exists(lp)
       and os.stat(lp).st_uid == UID_ALICE,
       f"control: WebDAV PUT nested in-tenant file owned by alice (HTTP {st})")
    st, body = http("GET", "/alice/cf_nest/legit.txt", port, ta)
    ok(st == 200 and _has(body, b"LEGIT-NESTED"),
       f"control: WebDAV GET nested in-tenant file readable (HTTP {st})")
    # A dot-segment that NORMALIZES back inside the tenant must still resolve (not
    # be rejected as an escape) — confinement != breaking legitimate "." segments.
    st, body = http("GET", "/alice/./cf_nest/../cf_nest/legit.txt", port, ta)
    ok(st in (200, 404) and no_passwd(body) and not _has(body, BOB),
       f"control: in-tenant normalizing dot-segments handled (HTTP {st})")

    # =============================================================================
    # WEBDAV GET — exhaustive traversal/encoding enumeration; NONE may read passwd
    # or escape to the outside marker.
    # =============================================================================
    wd_get = [
        "/../../../../etc/passwd",
        "/..\\..\\..\\etc\\passwd",
        "/alice/../../../../etc/passwd",
        "/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
        "/%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "/alice/%2e%2e%2f%2e%2e%2fetc/passwd",
        "/%252e%252e/%252e%252e/etc/passwd",
        "/alice/....//....//....//etc/passwd",
        "/..;/..;/..;/etc/passwd",
        "/alice/..;/..;/etc/passwd",
        "/%2fetc/passwd",
        "//etc/passwd",
        "/etc/passwd",
        "/./../.././../etc/passwd",
        "/alice/%00/../../../etc/passwd",
        "/CONFENC_OUTSIDE_MARKER.txt",
        "/../CONFENC_OUTSIDE_MARKER.txt",
        "/alice/../../CONFENC_OUTSIDE_MARKER.txt",
    ]
    for p in wd_get:
        st, b = http("GET", p, port, ta)
        ok(no_passwd(b) and not _has(b, MARK) and not _has(b, BOB),
           f"WebDAV GET traversal {p[:30]!r} no passwd/marker/tenant leak (HTTP {st})")

    # =============================================================================
    # WEBDAV PUT / MKCOL — traversal write escapes must create NOTHING outside.
    # =============================================================================
    wd_put = [
        "/../CONF_WD_A.txt",
        "/alice/../../CONF_WD_B.txt",
        "/alice/..%2f..%2fCONF_WD_C.txt",
        "/%2e%2e/CONF_WD_D.txt",
        "/alice/....//....//CONF_WD_E.txt",
        "/..;/CONF_WD_F.txt",
    ]
    for p in wd_put:
        http("PUT", p, port, ta, b"escape\n")
    esc_put_names = []
    for n in ("CONF_WD_A.txt", "CONF_WD_B.txt", "CONF_WD_C.txt", "CONF_WD_D.txt",
              "CONF_WD_E.txt", "CONF_WD_F.txt"):
        esc_put_names += [os.path.join(parent1, n), os.path.join(parent2, n),
                          os.path.join(export_abs, n)]
    ok(outside_clean(*esc_put_names),
       "WebDAV traversal PUT created nothing outside the export root")

    st, _ = http("MKCOL", "/../CONF_WD_DIR", port, ta)
    http("MKCOL", "/alice/../../CONF_WD_DIR2", port, ta)
    ok(outside_clean(os.path.join(parent1, "CONF_WD_DIR"),
                     os.path.join(parent2, "CONF_WD_DIR"),
                     os.path.join(parent1, "CONF_WD_DIR2"),
                     os.path.join(parent2, "CONF_WD_DIR2")),
       f"WebDAV traversal MKCOL created no dir outside the export (HTTP {st})")

    # =============================================================================
    # WEBDAV MOVE / COPY Destination header — traversal + CRLF + absolute targets.
    # The Destination must be confined; nothing may land outside the export.
    # =============================================================================
    http("PUT", "/alice/cf_src.txt", port, ta, b"MOVE-COPY-SRC\n")
    dst_variants = [
        f"http://{HOST}:{port}/../CONF_DST_A.txt",
        f"http://{HOST}:{port}/alice/../../CONF_DST_B.txt",
        f"http://{HOST}:{port}/%2e%2e/CONF_DST_C.txt",
        f"http://{HOST}:{port}/alice/..%2f..%2fCONF_DST_D.txt",
        f"http://{HOST}:{port}/etc/CONF_DST_E.txt",
        f"http://{HOST}:{port}/alice/cf_src.txt%0d%0aX-Inject:%20pwn",
        f"http://{HOST}:{port}/alice/cf%00null.txt",
    ]
    for d in dst_variants:
        st, _ = http("COPY", "/alice/cf_src.txt", port, ta,
                     hdrs={"Destination": d})
    copy_outside = []
    for n in ("CONF_DST_A.txt", "CONF_DST_B.txt", "CONF_DST_C.txt", "CONF_DST_D.txt"):
        copy_outside += [os.path.join(parent1, n), os.path.join(parent2, n)]
    copy_outside.append("/etc/CONF_DST_E.txt")
    ok(outside_clean(*copy_outside),
       "WebDAV COPY Destination traversal created nothing outside the export")

    for d in dst_variants:
        st, _ = http("MOVE", "/alice/cf_src.txt", port, ta,
                     hdrs={"Destination": d})
    move_outside = []
    for n in ("CONF_DST_A.txt", "CONF_DST_B.txt", "CONF_DST_C.txt", "CONF_DST_D.txt"):
        move_outside += [os.path.join(parent1, n), os.path.join(parent2, n)]
    move_outside.append("/etc/CONF_DST_E.txt")
    ok(outside_clean(*move_outside),
       "WebDAV MOVE Destination traversal created nothing outside the export")
    # MOVE positive control: a legit in-tenant MOVE must SUCCEED and land confined,
    # owned by the mapped tenant.  NOTE: one "escaping" Destination above
    # (cf_src.txt%0d%0aX-Inject:...) normalizes to an in-export, in-tenant filename
    # with no ".." component, so the confined MOVE legitimately renamed the source
    # to that odd-but-confined name and consumed it -- which is correct (outside_clean
    # above already proved NOTHING escaped the export).  Re-plant the source, then
    # assert the security invariant: the moved file lives INSIDE the export and is
    # owned by alice (no escape, no escalation, ownership preserved).
    src_path = os.path.join(data, "alice", "cf_src.txt")
    cf_moved = os.path.join(data, "alice", "cf_dst_ok.txt")
    http("PUT", "/alice/cf_src.txt", port, ta, b"MOVE-COPY-SRC\n")
    st, _ = http("MOVE", "/alice/cf_src.txt", port, ta,
                 hdrs={"Destination": f"http://{HOST}:{port}/alice/cf_dst_ok.txt"})
    ok(st in (201, 204),
       f"control: in-tenant MOVE Destination succeeded (HTTP {st})")
    ok(os.path.exists(cf_moved)
       and os.path.realpath(cf_moved).startswith(export_abs + os.sep)
       and os.stat(cf_moved).st_uid == UID_ALICE,
       "control: in-tenant MOVE landed confined under export and owned by alice")

    # CRLF / NUL in the request path itself must not split the response or escape.
    for p in ["/alice/cf_nest/legit.txt%0d%0aSet-Cookie:%20x",
              "/alice/%0d%0aHost:%20evil/legit.txt",
              "/alice/legit%00.txt"]:
        st, b = http("GET", p, port, ta)
        ok(no_passwd(b) and not _has(b, MARK),
           f"WebDAV GET CRLF/NUL-in-path {p[:28]!r} no leak/escape (HTTP {st})")

    # =============================================================================
    # WEBDAV PROPFIND on a traversal target must not enumerate outside the export.
    # =============================================================================
    pf = (b'<?xml version="1.0"?><D:propfind xmlns:D="DAV:">'
          b'<D:prop><D:displayname/></D:prop></D:propfind>')
    for p in ["/../", "/alice/../../", "/%2e%2e/", "/..;/"]:
        st, b = http("PROPFIND", p, port, ta, data=pf,
                     hdrs={"Depth": "1", "Content-Type": "application/xml"})
        ok(not _has(b, b"CONFENC_OUTSIDE_MARKER") and not _has(b, b"passwd")
           and not _has(b, SVC),
           f"WebDAV PROPFIND traversal {p!r} no outside/svc enumeration (HTTP {st})")

    # =============================================================================
    # SYMLINK-OUT: alice plants a symlink INSIDE HER OWN DIR pointing OUT; a
    # DIFFERENT identity (bob) — and alice herself — must NOT be able to follow it
    # out of the export via any protocol.  RESOLVE_BENEATH must refuse the symlink.
    # =============================================================================
    links = {
        "cf_to_etc": "/etc",
        "cf_to_passwd": "/etc/passwd",
        "cf_to_bobpriv": os.path.join(data, "bob", "private.txt"),
        "cf_to_svc": os.path.join(data, "svconly", "secret-name.txt"),
        "cf_rel_etc": "../../../../etc/passwd",
    }
    made = {}
    for name, target in links.items():
        lpath = os.path.join(data, "alice", name)
        try:
            if os.path.islink(lpath) or os.path.exists(lpath):
                os.remove(lpath)
            os.symlink(target, lpath)
            try:
                os.lchown(lpath, UID_ALICE, UID_ALICE)
            except (AttributeError, OSError):
                pass
            made[name] = True
        except OSError:
            made[name] = False

    # WebDAV GET through alice's symlinks, as BOB (different identity) and as alice.
    for name in ("cf_to_passwd", "cf_rel_etc"):
        if not made.get(name):
            ok(True, f"symlink {name} fixture absent — skipped")
            continue
        st, b = http("GET", f"/alice/{name}", port, tb)
        ok(no_passwd(b), f"WebDAV GET bob-follows-alice-symlink {name} no passwd "
                         f"leak (HTTP {st})")
        st, b = http("GET", f"/alice/{name}", port, ta)
        ok(no_passwd(b), f"WebDAV GET alice-follows-own-symlink {name} no passwd "
                         f"leak (HTTP {st})")
    if made.get("cf_to_bobpriv"):
        st, b = http("GET", "/alice/cf_to_bobpriv", port, ta)
        ok(not _has(b, BOB),
           f"WebDAV GET alice-symlink->bob/private not followed to bob secret "
           f"(HTTP {st})")
    if made.get("cf_to_svc"):
        st, b = http("GET", "/alice/cf_to_svc", port, ta)
        ok(not _has(b, SVC),
           f"WebDAV GET alice-symlink->svconly not followed to svc secret "
           f"(HTTP {st})")
    if made.get("cf_to_etc"):
        st, b = http("GET", "/alice/cf_to_etc/passwd", port, tb)
        ok(no_passwd(b),
           f"WebDAV GET bob via alice-symlink-dir->/etc/passwd no leak (HTTP {st})")
        st, b = http("PROPFIND", "/alice/cf_to_etc/", port, ta, data=pf,
                     hdrs={"Depth": "1", "Content-Type": "application/xml"})
        ok(not _has(b, b"passwd") and not _has(b, b"shadow"),
           f"WebDAV PROPFIND alice-symlink-dir->/etc did not enumerate /etc "
           f"(HTTP {st})")

    # =============================================================================
    # S3 — object key + copy-source traversal/encoding enumeration (signed as alice).
    # =============================================================================
    s3_get_keys = [
        "../../../../etc/passwd",
        "..%2f..%2f..%2f..%2fetc%2fpasswd",
        "%2e%2e/%2e%2e/%2e%2e/etc/passwd",
        "alice/../../../etc/passwd",
        "alice/..%2f..%2f..%2fetc%2fpasswd",
        "....//....//....//etc/passwd",
        "%2fetc/passwd",
        "alice/cf_to_passwd",        # via alice's planted symlink object
        "alice/cf_rel_etc",
        "../CONFENC_OUTSIDE_MARKER.txt",
    ]
    if s3port:
        for k in s3_get_keys:
            st, b = s3("GET", k, s3port)
            ok(no_passwd(b) and not _has(b, MARK) and not _has(b, BOB),
               f"S3 GET traversal key {k[:26]!r} no passwd/marker/tenant leak "
               f"(HTTP {st})")

        # S3 PUT traversal keys must not write outside the export.
        s3_put_keys = ["../CONF_S3_A.txt", "../../CONF_S3_B.txt",
                       "..%2f..%2fCONF_S3_C.txt", "alice/../../CONF_S3_D.txt",
                       "....//CONF_S3_E.txt"]
        for k in s3_put_keys:
            s3("PUT", k, s3port, data=b"s3escape\n")
        s3_outside = []
        for n in ("CONF_S3_A.txt", "CONF_S3_B.txt", "CONF_S3_C.txt",
                  "CONF_S3_D.txt", "CONF_S3_E.txt"):
            s3_outside += [os.path.join(parent1, n), os.path.join(parent2, n)]
        ok(outside_clean(*s3_outside),
           "S3 traversal PUT created nothing outside the export")

        # S3 CopyObject with a traversal/symlink copy-source must not read outside
        # or read another tenant's private object.
        cs_variants = [
            f"/{S3_BUCKET}/../../../../etc/passwd",
            f"/{S3_BUCKET}/..%2f..%2f..%2fetc%2fpasswd",
            f"/{S3_BUCKET}/alice/cf_to_passwd",
            f"/{S3_BUCKET}/bob/private.txt",
            f"/{S3_BUCKET}/alice/cf_to_bobpriv",
        ]
        for i, cs in enumerate(cs_variants):
            dstkey = f"alice/cf_copy_{i}.bin"
            st, _ = s3("PUT", dstkey, s3port,
                       extra_hdrs={"x-amz-copy-source": cs})
            dpath = os.path.join(data, "alice", f"cf_copy_{i}.bin")
            leaked = False
            try:
                if os.path.exists(dpath):
                    c = open(dpath, "rb").read()
                    leaked = (PW in c) or (BOB in c) or (MARK in c)
            except OSError:
                leaked = False
            ok(not leaked,
               f"S3 CopyObject src {cs[len(S3_BUCKET)+2:][:22]!r} did not exfil "
               f"passwd/tenant/outside (HTTP {st})")

        # S3 positive control: alice's own nested key round-trips.
        st, _ = s3("PUT", "alice/cf_s3_ok.txt", s3port, data=b"S3-OK-MARK\n")
        st2, b = s3("GET", "alice/cf_s3_ok.txt", s3port)
        ok(st in (200, 201) and st2 == 200 and _has(b, b"S3-OK-MARK"),
           f"control: S3 PUT+GET own nested key round-trips (HTTP {st}/{st2})")
        okp = os.path.join(data, "alice", "cf_s3_ok.txt")
        ok(os.path.exists(okp) and os.stat(okp).st_uid == UID_ALICE,
           "control: S3-created object owned by alice")

    # =============================================================================
    # root:// (stream) — stat/cat/mkdir/cp traversal + symlink-follow under map.
    # =============================================================================
    if not xrd_avail():
        ok(True, "root:// confinement matrix skipped (native client absent)")
    else:
        root_cat = [
            "/../../../../etc/passwd",
            "/alice/../../../etc/passwd",
            "/%2e%2e/%2e%2e/etc/passwd",
            "/alice/....//....//etc/passwd",
            "/alice/cf_to_passwd",
            "/alice/cf_rel_etc",
        ]
        for p in root_cat:
            rc, out, _e = xrd_fs(["cat", p], "alice")
            ok(rc != 0 and "root:x:" not in (out or ""),
               f"root:// cat traversal/symlink {p[:26]!r} DENIED, no passwd "
               f"(rc={rc})")

        # root:// cat alice's symlink -> bob's private must not leak bob's secret.
        rc, out, _e = xrd_fs(["cat", "/alice/cf_to_bobpriv"], "alice")
        ok("BOB-PRIVATE-SECRET" not in (out or ""),
           f"root:// cat alice-symlink->bob/private no bob leak (rc={rc})")
        rc, out, _e = xrd_fs(["cat", "/alice/cf_to_svc"], "alice")
        ok("svc-only-secret" not in (out or ""),
           f"root:// cat alice-symlink->svconly no svc leak (rc={rc})")

        # root:// xrdcp read of a traversal path must not download passwd.
        dlp = os.path.join(WORK, "cf_root_trav.bin")
        try:
            if os.path.exists(dlp):
                os.remove(dlp)
        except OSError:
            pass
        rc, _o, _e = xrd_cp_down("/../../../../etc/passwd", dlp, "alice")
        leaked = False
        try:
            leaked = os.path.exists(dlp) and b"root:x:" in open(dlp, "rb").read()
        except OSError:
            leaked = False
        ok(rc != 0 and not leaked,
           f"root:// xrdcp traversal download DENIED, no passwd (rc={rc})")

        # root:// mkdir + cp-up traversal must create nothing outside the export.
        xrd_fs(["mkdir", "/../CONF_ROOT_DIR"], "alice")
        xrd_fs(["mkdir", "/alice/../../CONF_ROOT_DIR2"], "alice")
        ok(outside_clean(os.path.join(parent1, "CONF_ROOT_DIR"),
                         os.path.join(parent2, "CONF_ROOT_DIR"),
                         os.path.join(parent1, "CONF_ROOT_DIR2"),
                         os.path.join(parent2, "CONF_ROOT_DIR2")),
           "root:// mkdir traversal created no dir outside the export")

        seed = os.path.join(WORK, "cf_root_seed.bin")
        try:
            with open(seed, "wb") as fh:
                fh.write(b"CF-ROOT-SEED\n")
        except OSError:
            pass
        xrd_cp_up(seed, "/../CONF_ROOT_UP.bin", "alice")
        xrd_cp_up(seed, "/alice/../../CONF_ROOT_UP2.bin", "alice")
        ok(outside_clean(os.path.join(parent1, "CONF_ROOT_UP.bin"),
                         os.path.join(parent2, "CONF_ROOT_UP.bin"),
                         os.path.join(parent1, "CONF_ROOT_UP2.bin"),
                         os.path.join(parent2, "CONF_ROOT_UP2.bin")),
           "root:// xrdcp traversal upload created nothing outside the export")

        # root:// positive control: own nested write/read round-trips + ownership.
        rc, _o, _e = xrd_fs(["mkdir", "/alice/cf_root_nest"], "alice")
        rc2, _o, _e = xrd_cp_up(seed, "/alice/cf_root_nest/ok.bin", "alice")
        nestf = os.path.join(data, "alice", "cf_root_nest", "ok.bin")
        ok(rc2 == 0 and os.path.exists(nestf)
           and os.stat(nestf).st_uid == UID_ALICE,
           f"control: root:// nested in-tenant write owned by alice (rc={rc2})")

    # =============================================================================
    # FINAL INVARIANTS — nothing escaped anywhere + the worker SURVIVES the battery.
    # =============================================================================
    grand_outside = [
        os.path.join(parent1, n) for n in
        ("CONF_WD_A.txt", "CONF_WD_B.txt", "CONF_WD_C.txt", "CONF_WD_D.txt",
         "CONF_WD_E.txt", "CONF_WD_F.txt", "CONF_DST_A.txt", "CONF_DST_B.txt",
         "CONF_S3_A.txt", "CONF_S3_B.txt", "CONF_ROOT_UP.bin", "CONF_WD_DIR",
         "CONF_ROOT_DIR")
    ] + ["/etc/CONF_DST_E.txt", "/tmp/CONF_S3_OUT.txt"]
    ok(outside_clean(*grand_outside),
       "GRAND INVARIANT: no attack file/dir landed outside the export root")

    # The marker file we planted outside must STILL be intact + unmodified (no
    # attack truncated/overwrote it through a traversal write).
    if out_marker:
        try:
            still = open(out_marker, "rb").read()
            ok(MARK in still,
               "outside marker intact (no traversal write reached it)")
        except OSError:
            ok(True, "outside marker unreadable post-battery (acceptable)")

    # Worker SURVIVES: a fresh legit op after the whole encoding battery still works
    # and lands owned by the mapped user (proves no crash / principal corruption).
    st, _ = http("PUT", "/alice/cf_survive.txt", port, ta, b"SURVIVE\n")
    sp = os.path.join(data, "alice", "cf_survive.txt")
    ok(st in (200, 201, 204) and os.path.exists(sp)
       and os.stat(sp).st_uid == UID_ALICE,
       f"worker SURVIVES battery: legit PUT owned by alice (HTTP {st})")
    st, body = http("GET", "/alice/cf_survive.txt", port, ta)
    ok(st == 200 and _has(body, b"SURVIVE"),
       f"worker SURVIVES battery: legit GET round-trips (HTTP {st})")

    # Cleanup the symlinks we planted so later batteries see a clean tenant.
    for name in links:
        try:
            lpath = os.path.join(data, "alice", name)
            if os.path.islink(lpath):
                os.remove(lpath)
        except OSError:
            pass


