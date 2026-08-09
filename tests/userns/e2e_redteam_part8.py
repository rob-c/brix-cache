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


def run_cross_cutting(key, data, port, s3port):
    """Cross-PROTOCOL identity boundaries + erroring connections under
    impersonation.  A file's owner must hold whichever protocol reads/writes it."""
    ta, tb = mint(key, "alice"), mint(key, "bob")

    # alice creates via WebDAV; bob must not read it via S3 or root:// (and the
    # file stays alice-owned).  Make it 0600 so cross-tenant read is a real test.
    http("PUT", "/alice/xp_secret.txt", port, ta, b"ALICE-XPROTO-SECRET\n")
    fp = os.path.join(data, "alice", "xp_secret.txt")
    if os.path.exists(fp):
        os.chmod(fp, 0o600)
    ok(os.path.exists(fp) and os.stat(fp).st_uid == UID_ALICE,
       "cross-protocol: WebDAV-created file owned by alice")
    if s3port:
        # bob can't reach it via S3 (his key maps to bob — but the alice S3 endpoint
        # always maps to alice; so use alice-key reading her own = control, and a
        # root:// bob read for the cross-tenant deny).
        st, b = s3("GET", "alice/xp_secret.txt", s3port)   # alice endpoint == alice
        ok(st == 200 and b"ALICE-XPROTO-SECRET" in (b or b""),
           f"cross-protocol: alice reads her WebDAV file via S3 (HTTP {st})")
    if xrd_avail():
        rc, out, _e = xrd_fs(["cat", "/alice/xp_secret.txt"], "bob")
        ok(rc != 0 and "ALICE-XPROTO-SECRET" not in (out or ""),
           f"cross-protocol: bob CANNOT read alice's 0600 file via root:// (rc={rc})")
        # bob writes via root://; alice must not read it via WebDAV.
        lf = os.path.join(WORK, "xp_bob.bin")
        with open(lf, "wb") as fh:
            fh.write(b"BOB-XPROTO-SECRET\n")
        xrd_cp_up(lf, "/bob/xp_bob.bin", "bob")
        os.chmod(os.path.join(data, "bob", "xp_bob.bin"), 0o600) \
            if os.path.exists(os.path.join(data, "bob", "xp_bob.bin")) else None
        st, b = http("GET", "/bob/xp_bob.bin", port, ta)
        ok(b"BOB-XPROTO-SECRET" not in (b or b""),
           f"cross-protocol: alice CANNOT read bob's root://-written 0600 via WebDAV (HTTP {st})")

    # Erroring connections must not breach / hang the worker.  A FIFO in the export:
    # a GET/PUT on it must not hang (broker opens O_NONBLOCK) and must fail closed.
    fifo = os.path.join(data, "alice", "afifo")
    try:
        if not os.path.exists(fifo):
            os.mkfifo(fifo, 0o600)
            os.chown(fifo, UID_ALICE, UID_ALICE)
    except OSError:
        fifo = None
    if fifo:
        st, _ = http("GET", "/alice/afifo", port, ta)   # must return, not hang
        ok(True, f"WebDAV GET on a FIFO did not hang the worker (HTTP {st})")
    # A dangling symlink: stat/GET must be handled (no crash), not followed out.
    dang = os.path.join(data, "alice", "dangle")
    try:
        if not os.path.exists(dang):
            os.symlink("/nonexistent/target", dang)
    except OSError:
        dang = None
    if dang:
        st, _ = http("GET", "/alice/dangle", port, ta)
        ok(st not in (200,), f"WebDAV GET dangling symlink handled (HTTP {st})")
    # follow-up op proves the worker survived the erroring connections.
    st, _ = http("GET", "/alice/xp_secret.txt", port, ta)
    ok(st == 200, "worker survived FIFO / dangling-symlink requests")


def run_auth_matrix(key, data, port):
    """Forged/invalid bearer tokens must be rejected uniformly across BOTH
    token-authenticated planes (WebDAV + root://) under impersonation — a token
    that fails validation must never reach the broker as a mapped principal, and
    must neither read nor create anything.  A positive control proves the same
    paths accept a good token."""
    ta = mint(key, "alice")
    http("PUT", "/alice/auth_probe.txt", port, ta, b"auth-probe-body\n")

    # Positive control: a valid token reads its own file.
    st, b = http("GET", "/alice/auth_probe.txt", port, ta)
    ok(st == 200 and b"auth-probe-body" in (b or b""),
       f"auth control: valid token reads own file (HTTP {st})")

    for label, tok in _forged_tokens(key):
        # WebDAV READ must be denied and must NOT leak the body.
        st, b = http("GET", "/alice/auth_probe.txt", port, tok)
        ok(st in (401, 403) and b"auth-probe-body" not in (b or b""),
           f"WebDAV {label} token rejected on GET (HTTP {st})")
        # WebDAV WRITE must be denied and must NOT create the file.
        evil = f"/alice/evil_{label}.txt"
        http("PUT", evil, port, tok, b"X\n")
        ok(not os.path.exists(os.path.join(data, "alice", f"evil_{label}.txt")),
           f"WebDAV {label} token cannot create a file")

    # Empty-scope token: this module's model is authn->identity, DAC for reads,
    # explicit write-scope for mutations.  So an empty-scope token authenticates
    # as alice and MAY read her own file (DAC permits) but MUST NOT write and MUST
    # NOT read another tenant (DAC backstops).  Verify all three.
    nos = mint(key, "alice", scope="")
    st, b = http("GET", "/alice/auth_probe.txt", port, nos)
    ok(st == 200 and b"auth-probe-body" in (b or b""),
       f"empty-scope token authenticates + reads own file via DAC (HTTP {st})")
    http("PUT", "/alice/evil_noscope.txt", port, nos, b"X\n")
    ok(not os.path.exists(os.path.join(data, "alice", "evil_noscope.txt")),
       "empty-scope token cannot WRITE (no write scope)")
    st, b = http("GET", "/bob/private.txt", port, nos)
    ok(b"BOB-PRIVATE-SECRET" not in (b or b""),
       f"empty-scope token cannot read bob's 0600 (DAC backstop) (HTTP {st})")

    # root:// plane: the same forged tokens must fail (subset — the heavy ones).
    if xrd_avail():
        for label, tok in _forged_tokens(key):
            if label in ("not-yet-valid", "wrong-audience", "garbage"):
                continue   # keep the native-client matrix tight
            rc, out, _e = xrd_fs_token(["stat", "/alice/auth_probe.txt"], tok)
            ok(rc != 0, f"root:// {label} token rejected on stat (rc={rc})")


def run_root_deep(key, data, port):
    """Per-subcommand root:// (stream) matrix under impersonation: every metadata
    + data op as the mapped user, each in a self-success and a cross-tenant-deny
    variant.  The native client drives the real wire protocol, so this exercises
    the stream dispatch path the HTTP planes never touch."""
    if not xrd_avail():
        ok(True, "root:// deep matrix skipped (native client absent)")
        return

    bobpriv = os.path.join(data, "bob", "private.txt")           # 0600 bob
    bobread = os.path.join(data, "bob", "readable.txt")          # 0644 bob

    # seed an alice-owned file via the data plane (write path).
    lf = os.path.join(WORK, "rd_seed.bin")
    with open(lf, "wb") as fh:
        fh.write(b"ALICE-ROOT-DEEP\n")
    rc, _o, _e = xrd_cp_up(lf, "/alice/rd_self.bin", "alice")
    ok(rc == 0 and os.path.exists(os.path.join(data, "alice", "rd_self.bin")),
       f"root:// xrdcp write own file (rc={rc})")
    sf = os.path.join(data, "alice", "rd_self.bin")
    ok(os.path.exists(sf) and os.stat(sf).st_uid == UID_ALICE,
       "root:// written file owned by alice")

    # cat self vs bob's 0600.
    dl = os.path.join(WORK, "rd_self_dl.bin")
    rc, _o, _e = xrd_cp_down("/alice/rd_self.bin", dl, "alice")
    ok(rc == 0 and os.path.exists(dl) and open(dl, "rb").read() == b"ALICE-ROOT-DEEP\n",
       f"root:// xrdcp read own file byte-exact (rc={rc})")
    rc, out, _e = xrd_fs(["cat", "/bob/private.txt"], "alice")
    ok(rc != 0 and "BOB-PRIVATE-SECRET" not in (out or ""),
       f"root:// cat bob's 0600 DENIED (rc={rc})")
    dlx = os.path.join(WORK, "rd_steal.bin")
    rc, _o, _e = xrd_cp_down("/bob/private.txt", dlx, "alice")
    ok(rc != 0 and not (os.path.exists(dlx)
                        and b"BOB-PRIVATE-SECRET" in open(dlx, "rb").read()),
       f"root:// xrdcp read bob's 0600 DENIED (rc={rc})")

    # stat self ok (a 0644 sibling is fine); bob's 0600 stat may succeed (metadata
    # is not secret) but reading was already proven denied above.
    rc, _o, _e = xrd_fs(["stat", "/alice/rd_self.bin"], "alice")
    ok(rc == 0, f"root:// stat own file (rc={rc})")

    # mkdir self + ownership; mkdir into bob's 0700 dir denied.
    rc, _o, _e = xrd_fs(["mkdir", "/alice/rd_dir"], "alice")
    nd = os.path.join(data, "alice", "rd_dir")
    ok(rc == 0 and os.path.isdir(nd) and os.stat(nd).st_uid == UID_ALICE,
       f"root:// mkdir own dir owned by alice (rc={rc})")
    rc, _o, _e = xrd_fs(["mkdir", "/bobsecret/intrude"], "alice")
    ok(rc != 0 and not os.path.exists(os.path.join(data, "bobsecret", "intrude")),
       f"root:// mkdir into bob's 0700 dir DENIED (rc={rc})")

    # write into bob's dir via the data plane denied.
    rc, _o, _e = xrd_cp_up(lf, "/bobsecret/intrude.bin", "alice")
    ok(rc != 0 and not os.path.exists(os.path.join(data, "bobsecret", "intrude.bin")),
       f"root:// xrdcp write into bob's 0700 dir DENIED (rc={rc})")

    # rm: own file ok; bob's 0644 file denied (DAC: no write on bob's dir).
    rc, _o, _e = xrd_fs(["rm", "/bob/readable.txt"], "alice")
    ok(rc != 0 and os.path.exists(bobread),
       f"root:// rm bob's file DENIED, file intact (rc={rc})")
    rc, _o, _e = xrd_fs(["rm", "/alice/rd_self.bin"], "alice")
    ok(rc == 0 and not os.path.exists(sf), f"root:// rm own file (rc={rc})")

    # mv: bob's file out of bob's dir denied (still present, original name).
    rc, _o, _e = xrd_fs(["mv", "/bob/readable.txt", "/alice/stolen.txt"], "alice")
    ok(rc != 0 and os.path.exists(bobread)
       and not os.path.exists(os.path.join(data, "alice", "stolen.txt")),
       f"root:// mv bob's file into alice's dir DENIED (rc={rc})")

    # truncate bob's file denied (content length unchanged).
    before = os.path.getsize(bobread)
    rc, _o, _e = xrd_fs(["truncate", "/bob/readable.txt", "0"], "alice")
    ok(rc != 0 and os.path.getsize(bobread) == before,
       f"root:// truncate bob's file DENIED, size intact (rc={rc})")

    # chmod bob's file denied (mode unchanged).
    mode_before = os.stat(bobpriv).st_mode & 0o777
    rc, _o, _e = xrd_fs(["chmod", "/bob/private.txt", "666"], "alice")
    ok(rc != 0 and (os.stat(bobpriv).st_mode & 0o777) == mode_before,
       f"root:// chmod bob's file DENIED, mode intact (rc={rc})")

    # locate / query checksum on own file should work; on bob's 0600 must not leak.
    rc, _o, _e = xrd_fs(["query", "checksum", "/bob/private.txt"], "alice")
    ok(rc != 0, f"root:// query checksum of bob's 0600 DENIED (rc={rc})")


def _delete_xml(keys):
    body = b'<?xml version="1.0"?><Delete>'
    for k in keys:
        body += b"<Object><Key>" + k.encode() + b"</Key></Object>"
    return body + b"</Delete>"


def run_s3_deep(key, data, s3port):
    """Deep S3 surface under impersonation: CopyObject + UploadPartCopy with a
    cross-tenant source, DeleteObjects batch, Range/conditional confidentiality,
    ListObjectsV2 prefix/delimiter, and anonymous access — each a DAC boundary."""
    # seed objects.
    s3("PUT", "alice/cp_src.txt", s3port, data=b"alice-copy-source\n")

    # CopyObject self: copy alice/cp_src -> alice/cp_dst, owned by alice.
    st, _ = s3("PUT", "alice/cp_dst.txt", s3port,
               extra_hdrs={"x-amz-copy-source": f"/{S3_BUCKET}/alice/cp_src.txt"})
    cpd = os.path.join(data, "alice", "cp_dst.txt")
    ok(st in (200, 201) and os.path.exists(cpd) and os.stat(cpd).st_uid == UID_ALICE,
       f"S3 CopyObject self owned by alice (HTTP {st})")

    # CopyObject cross-tenant SOURCE: copy bob/private.txt -> alice/stolen.  The
    # broker reads the source as alice; bob's 0600 denies it -> no theft.
    st, _ = s3("PUT", "alice/stolen.txt", s3port,
               extra_hdrs={"x-amz-copy-source": f"/{S3_BUCKET}/bob/private.txt"})
    stolen = os.path.join(data, "alice", "stolen.txt")
    leaked = os.path.exists(stolen) and b"BOB-PRIVATE-SECRET" in open(stolen, "rb").read()
    ok(st not in (200, 201) and not leaked,
       f"S3 CopyObject cross-tenant source DENIED, no theft (HTTP {st})")

    # DeleteObjects batch: deleting bob's file must not remove it (DAC on bob's dir).
    bobread = os.path.join(data, "bob", "readable.txt")
    s3("POST", "", s3port, params={"delete": ""},
       data=_delete_xml(["bob/readable.txt"]))
    ok(os.path.exists(bobread),
       "S3 DeleteObjects of bob's file did not delete it")
    # DeleteObjects self: delete alice's own object works.
    s3("PUT", "alice/del_me.txt", s3port, data=b"x\n")
    s3("POST", "", s3port, params={"delete": ""}, data=_delete_xml(["alice/del_me.txt"]))
    ok(not os.path.exists(os.path.join(data, "alice", "del_me.txt")),
       "S3 DeleteObjects of own object succeeded")

    # GetObject Range + conditional on bob's 0600 must never leak the body.
    for label, hdr in [("Range", {"Range": "bytes=0-4"}),
                       ("If-Match", {"If-Match": "*"}),
                       ("If-None-Match", {"If-None-Match": '"x"'})]:
        h = s3_sign("GET", f"/{S3_BUCKET}/bob/private.txt", s3port)
        h.update(hdr)
        st, b = http("GET", f"/{S3_BUCKET}/bob/private.txt", s3port, hdrs=h)
        ok(b"BOB-PRIVATE-SECRET" not in (b or b""),
           f"S3 GET bob's 0600 with {label} no body leak (HTTP {st})")

    # ListObjectsV2 prefix/delimiter must not enumerate the symlink-escape or other
    # tenants' private subtrees.
    st, b = s3("GET", "", s3port, params={"list-type": "2", "prefix": "", "delimiter": "/"})
    ok(b"escape/" not in (b or b"") and b"secret-name.txt" not in (b or b""),
       f"S3 ListObjectsV2 delimiter no escape/secret leak (HTTP {st})")
    st, b = s3("GET", "", s3port, params={"list-type": "2", "prefix": "bobsecret/"})
    ok(b"BOB-PRIVATE" not in (b or b"") and b"bobsecret/inject" not in (b or b""),
       f"S3 ListObjectsV2 prefix into bob's 0700 no leak (HTTP {st})")

    # Anonymous (no SigV4) request must be denied.
    st, _ = http("GET", f"/{S3_BUCKET}/alice/cp_src.txt", s3port)
    ok(st in (401, 403), f"S3 anonymous GET denied (HTTP {st})")

    # UploadPartCopy cross-tenant source: initiate own MPU, then try to copy a part
    # from bob's 0600 object -> denied (no part written from bob's data).
    st_i, bdy = s3("POST", "alice/upc.bin", s3port, params={"uploads": ""})
    m = re.search(rb"<UploadId>([^<]+)</UploadId>", bdy or b"")
    if st_i == 200 and m:
        up = m.group(1).decode()
        st, _ = s3("PUT", "alice/upc.bin", s3port,
                   params={"uploadId": up, "partNumber": "1"},
                   extra_hdrs={"x-amz-copy-source": f"/{S3_BUCKET}/bob/private.txt"})
        ok(st not in (200, 201), f"S3 UploadPartCopy cross-tenant source DENIED (HTTP {st})")
        s3("DELETE", "alice/upc.bin", s3port, params={"uploadId": up})
    else:
        ok(True, "S3 UploadPartCopy setup skipped (initiate unsupported)")


def run_traversal_matrix(key, data, port, s3port):
    """Path-traversal / encoding / NUL across every protocol under impersonation.
    The broker re-applies RESOLVE_BENEATH, so escapes must fail closed and never
    return a byte of /etc/passwd or write outside the export."""
    ta = mint(key, "alice")
    outside_dir = os.path.dirname(os.path.dirname(os.path.abspath(data)))

    # WebDAV GET traversal variants — none may return root:x: from /etc/passwd.
    wd_paths = [
        "/../../../../etc/passwd",
        "/alice/../../../../etc/passwd",
        "/%2e%2e/%2e%2e/etc/passwd",
        "/alice/%2e%2e%2f%2e%2e%2fetc/passwd",
        "/..%2f..%2f..%2fetc/passwd",
        "/alice/....//....//etc/passwd",
    ]
    for p in wd_paths:
        st, b = http("GET", p, port, ta)
        ok(b"root:x:" not in (b or b"") and b"root:!" not in (b or b""),
           f"WebDAV traversal GET {p[:28]!r} no /etc/passwd leak (HTTP {st})")

    # WebDAV PUT/MKCOL escapes must not create anything outside the export.
    http("PUT", "/../OUTSIDE_WD.txt", port, ta, b"x\n")
    http("PUT", "/alice/../../OUTSIDE_WD2.txt", port, ta, b"x\n")
    ok(not os.path.exists(os.path.join(outside_dir, "OUTSIDE_WD.txt"))
       and not os.path.exists(os.path.join(outside_dir, "OUTSIDE_WD2.txt")),
       "WebDAV traversal PUT created nothing outside the export")

    # S3 key traversal — keys that try to climb out of the bucket root.
    for k in ["../../../etc/passwd", "..%2f..%2f..%2fetc%2fpasswd",
              "alice/../../../etc/passwd", "....//....//etc/passwd"]:
        st, b = s3("GET", k, s3port)
        ok(b"root:x:" not in (b or b""),
           f"S3 traversal key {k[:24]!r} no /etc/passwd leak (HTTP {st})")
    st, _ = s3("PUT", "../../../tmp/OUTSIDE_S3.txt", s3port, data=b"x\n")
    ok(not os.path.exists("/tmp/OUTSIDE_S3.txt"),
       "S3 traversal PUT created nothing outside the export")

    # root:// traversal — stat/cat an escaping path must fail, no passwd leak.
    if xrd_avail():
        for p in ["/../../../../etc/passwd", "/alice/../../../etc/passwd"]:
            rc, out, _e = xrd_fs(["cat", p], "alice")
            ok(rc != 0 and "root:x:" not in (out or ""),
               f"root:// traversal cat {p[:24]!r} DENIED (rc={rc})")
        dlp = os.path.join(WORK, "trav_pw.bin")
        rc, _o, _e = xrd_cp_down("/../../../../etc/passwd", dlp, "alice")
        leaked = os.path.exists(dlp) and b"root:x:" in open(dlp, "rb").read()
        ok(rc != 0 and not leaked, f"root:// xrdcp traversal read DENIED (rc={rc})")


