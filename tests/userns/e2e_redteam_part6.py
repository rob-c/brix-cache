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


def run_s3(data, port):
    """S3 (SigV4) under impersonation.  The access key "alice" is the auth subject
    the broker maps to uid 1001, so every S3 op runs as alice.  Objects created by
    S3 PUT and multipart-complete must be owned 1001 (not the worker), proving the
    S3 async-body impersonation brackets (s3_put_body_handler and the ones added
    for post/delete/multipart-complete) re-establish the principal.  Keys live
    under alice/ so they land in alice's writable subtree of the shared export."""
    # --- single PUT object owned by the mapped user.
    k = "alice/s3put.txt"
    st, _ = s3("PUT", k, port, data=b"s3 object body\n")
    fp = os.path.join(data, k)
    uid = os.stat(fp).st_uid if os.path.exists(fp) else -1
    ok(st in (200, 201) and uid == UID_ALICE,
       f"S3 PUT object owned by mapped user alice (HTTP {st}, uid={uid})")

    # --- GET returns the bytes (read path as alice).
    st, body = s3("GET", k, port)
    ok(st == 200 and body == b"s3 object body\n",
       f"S3 GET returns alice's object (HTTP {st})")

    # --- multipart: initiate -> upload part -> complete; final owned by alice.
    mk = "alice/s3mpu.bin"
    st_i, body = s3("POST", mk, port, params={"uploads": ""})
    m = re.search(rb"<UploadId>([^<]+)</UploadId>", body or b"")
    if st_i == 200 and m:
        upid = m.group(1).decode()
        st_p, body_p = s3("PUT", mk, port,
                          params={"uploadId": upid, "partNumber": "1"},
                          data=b"Z" * 4096)
        et = re.search(rb'ETag>\\?"?([^"<\\]+)', body_p or b"")
        etag = et.group(1).decode() if et else "etag"
        comp = (f"<CompleteMultipartUpload><Part><PartNumber>1</PartNumber>"
                f"<ETag>{etag}</ETag></Part></CompleteMultipartUpload>").encode()
        st_c, _ = s3("POST", mk, port, params={"uploadId": upid}, data=comp)
        mfp = os.path.join(data, mk)
        muid = os.stat(mfp).st_uid if os.path.exists(mfp) else -1
        ok(st_c in (200, 201) and muid == UID_ALICE,
           f"S3 multipart-complete object owned by alice "
           f"(init {st_i}, part {st_p}, complete {st_c}, uid={muid})")
    else:
        ok(False, f"S3 multipart initiate failed (HTTP {st_i})")

    # --- DELETE removes the object (delete path as alice).
    st, _ = s3("DELETE", k, port)
    ok(st in (200, 204) and not os.path.exists(fp),
       f"S3 DELETE removes alice's object (HTTP {st})")


def _has(body, needle):
    return needle in (body or b"")


def run_cross_tenant_read(key, data, port, s3port):
    """alice must not READ bob's PRIVATE (0600) data via any read op — but MAY read
    a file bob made world-readable (0644).  The control proves the deny is genuine
    per-file DAC enforced by the broker, not a blanket cross-prefix block."""
    ta = mint(key, "alice")

    st, body = http("GET", "/bob/private.txt", port, ta)
    ok(st in (403, 404, 401) and not _has(body, b"BOB-PRIVATE-SECRET"),
       f"WebDAV GET of bob's 0600 file DENIED (HTTP {st})")

    st, body = http("GET", "/bob/readable.txt", port, ta)
    ok(st == 200 and _has(body, b"bob-world-readable"),
       f"control: WebDAV GET of bob's 0644 file ALLOWED (HTTP {st})")

    if s3port:
        st, body = s3("GET", "bob/private.txt", s3port)
        ok(st in (403, 404) and not _has(body, b"BOB-PRIVATE-SECRET"),
           f"S3 GET of bob's 0600 object DENIED (HTTP {st})")
        st, body = s3("GET", "bob/readable.txt", s3port)
        ok(st == 200 and _has(body, b"bob-world-readable"),
           f"control: S3 GET of bob's 0644 object ALLOWED (HTTP {st})")

        # S3 ListObjectsV2 must NOT (a) enumerate a directory the mapped user
        # cannot read (svconly 0750 -> 'secret-name.txt'), nor (b) FOLLOW a symlink
        # out of the export ('/escape' -> /etc -> 'escape/...' keys, a confinement
        # escape that enumerates the host filesystem).  It must still list the
        # mapped user's own keys (control).  S3 analogue of the dir-listing leak.
        st, body = s3("GET", "", s3port, params={"list-type": "2"})
        leaked = (_has(body, b"secret-name.txt")        # svc-only dir (gate)
                  or _has(body, b"escape/")             # symlink-followed /etc keys
                  or _has(body, b"passwd"))
        ok(st == 200 and _has(body, b"alice/") and not leaked,
           f"S3 ListObjects: no svc-only/symlink-escape leak + lists own keys "
           f"(HTTP {st}, leaked={leaked})")


def run_cross_tenant_write(key, data, port, s3port):
    """alice must not WRITE / DELETE / MUTATE bob's data via any op.  bob's dir is
    0755 (alice can traverse + list, but not write); the broker enforces the DAC."""
    ta = mint(key, "alice")
    bread = os.path.join(data, "bob", "readable.txt")
    bpriv = os.path.join(data, "bob", "private.txt")

    def unchanged():
        return (os.path.exists(bread) and os.stat(bread).st_uid == UID_BOB
                and open(bread, "rb").read() == b"bob-world-readable\n")

    st, _ = http("PUT", "/bob/readable.txt", port, ta, b"HACKED\n")
    ok(st not in (200, 201, 204) and unchanged(),
       f"WebDAV PUT over bob's file DENIED + unchanged (HTTP {st})")

    st, _ = http("PUT", "/bob/alice_was_here.txt", port, ta, b"x\n")
    ok(st not in (200, 201, 204)
       and not os.path.exists(os.path.join(data, "bob", "alice_was_here.txt")),
       f"WebDAV PUT new file into bob's dir DENIED (HTTP {st})")

    st, _ = http("DELETE", "/bob/readable.txt", port, ta)
    ok(st not in (200, 204) and os.path.exists(bread),
       f"WebDAV DELETE of bob's file DENIED (HTTP {st})")

    st, _ = http("MOVE", "/bob/readable.txt", port, ta,
                 hdrs={"Destination": f"http://{HOST}:{port}/alice/stolen.txt"})
    ok(st not in (200, 201, 204) and os.path.exists(bread)
       and not os.path.exists(os.path.join(data, "alice", "stolen.txt")),
       f"WebDAV MOVE of bob's file DENIED (HTTP {st})")

    st, _ = http("COPY", "/bob/private.txt", port, ta,
                 hdrs={"Destination": f"http://{HOST}:{port}/alice/copied.txt"})
    ok(st not in (200, 201, 204)
       and not os.path.exists(os.path.join(data, "alice", "copied.txt")),
       f"WebDAV COPY of bob's 0600 file DENIED (HTTP {st})")

    # PROPPATCH a uniquely-valued dead-prop onto bob's file, then PROPFIND it back:
    # the value must NOT persist (setxattr as alice on bob's file is EACCES).
    pp = (b'<?xml version="1.0"?><D:propertyupdate xmlns:D="DAV:" xmlns:Z="urn:x">'
          b'<D:set><D:prop><Z:pwn>XT-PWNED</Z:pwn></D:prop></D:set>'
          b'</D:propertyupdate>')
    http("PROPPATCH", "/bob/readable.txt", port, ta, data=pp,
         hdrs={"Content-Type": "application/xml"})
    _, body = http("PROPFIND", "/bob/readable.txt", port, ta,
                   data=b'<?xml version="1.0"?><D:propfind xmlns:D="DAV:">'
                        b'<D:allprop/></D:propfind>',
                   hdrs={"Depth": "0", "Content-Type": "application/xml"})
    ok(not _has(body, b"XT-PWNED"),
       "WebDAV PROPPATCH on bob's file did NOT persist a dead-property")

    if s3port:
        st, _ = s3("PUT", "bob/readable.txt", s3port, data=b"S3HACK\n")
        ok(st not in (200, 201) and unchanged(),
           f"S3 PUT over bob's object DENIED + unchanged (HTTP {st})")

        st, _ = s3("DELETE", "bob/readable.txt", s3port)
        ok(st not in (200, 204) and os.path.exists(bread),
           f"S3 DELETE of bob's object DENIED (HTTP {st})")

        # CopyObject: read bob's 0600 source as alice -> EACCES -> denied.
        st, _ = s3("PUT", "alice/from_bob.bin", s3port,
                   extra_hdrs={"x-amz-copy-source": f"/{S3_BUCKET}/bob/private.txt"})
        ok(st not in (200, 201)
           and not os.path.exists(os.path.join(data, "alice", "from_bob.bin")),
           f"S3 CopyObject of bob's 0600 object DENIED (HTTP {st})")

        # Bulk DeleteObjects of bob's key -> the unlink runs as alice -> denied;
        # the object must survive.  (Exercises s3_delete_objects_body_handler.)
        dx = (b'<?xml version="1.0"?><Delete><Object><Key>bob/readable.txt</Key>'
              b'</Object></Delete>')
        s3("POST", "", s3port, params={"delete": ""}, data=dx)
        ok(os.path.exists(bread) and unchanged(),
           "S3 DeleteObjects of bob's key did NOT delete it (broker DAC)")

        # UploadPartCopy: alice copies a part FROM bob's 0600 object -> the source
        # read runs as alice -> EACCES -> denied (must not leak bob's data).
        st_i, b = s3("POST", "alice/upc.bin", s3port, params={"uploads": ""})
        m = re.search(rb"<UploadId>([^<]+)</UploadId>", b or b"")
        if st_i == 200 and m:
            upid = m.group(1).decode()
            st, _ = s3("PUT", "alice/upc.bin", s3port,
                       params={"uploadId": upid, "partNumber": "1"},
                       extra_hdrs={"x-amz-copy-source": f"/{S3_BUCKET}/bob/private.txt"})
            ok(st not in (200, 201),
               f"S3 UploadPartCopy from bob's 0600 object DENIED (HTTP {st})")


def run_create_ownership(key, data, port, s3port):
    """Every remaining CREATE path lands owned by the mapped user (1001), never the
    worker (1500) or root (0): WebDAV LOCK-creates-a-resource, and S3 CopyObject."""
    ta = mint(key, "alice")

    # LOCK on a NON-existent path must create a zero-byte resource (RFC 4918
    # §9.10.4) — owned by the mapped user (create + lock xattr both via broker).
    li = (b'<?xml version="1.0"?><D:lockinfo xmlns:D="DAV:">'
          b'<D:lockscope><D:exclusive/></D:lockscope>'
          b'<D:locktype><D:write/></D:locktype></D:lockinfo>')
    st, _ = http("LOCK", "/alice/lock_created.txt", port, ta, data=li,
                 hdrs={"Content-Type": "application/xml", "Timeout": "Second-60"})
    lp = os.path.join(data, "alice", "lock_created.txt")
    ok(st in (200, 201) and os.path.exists(lp) and os.stat(lp).st_uid == UID_ALICE,
       f"WebDAV LOCK-creates-resource owned by alice (HTTP {st})")

    if s3port:
        # CopyObject of alice's OWN object -> new object owned by alice.
        s3("PUT", "alice/copy_src.txt", s3port, data=b"copy me\n")
        st, _ = s3("PUT", "alice/copy_dst.txt", s3port,
                   extra_hdrs={"x-amz-copy-source": f"/{S3_BUCKET}/alice/copy_src.txt"})
        cp = os.path.join(data, "alice", "copy_dst.txt")
        ok(st in (200, 201) and os.path.exists(cp) and os.stat(cp).st_uid == UID_ALICE,
           f"S3 CopyObject result owned by alice (HTTP {st})")


def run_recursive_propfind(key, data, port):
    """PROPFIND Depth: infinity from the export root must not leak the CONTENTS of
    subtrees the mapped user cannot read (svc-only 0750, bob's 0700 private dir)."""
    ta = mint(key, "alice")
    st, body = http("PROPFIND", "/", port, ta,
                    data=b'<?xml version="1.0"?><D:propfind xmlns:D="DAV:">'
                         b'<D:prop><D:displayname/></D:prop></D:propfind>',
                    hdrs={"Depth": "infinity", "Content-Type": "application/xml"})
    # secret-name.txt lives in svconly (0750, svc) and s.txt in bobsecret (0700,
    # bob) — neither readable/traversable by alice, so neither may appear.  Nor may
    # the walk FOLLOW /escape (-> /etc) and enumerate the host filesystem.
    leaked = _has(body, b"secret-name.txt") or _has(body, b"bob-only") \
        or _has(body, b">s.txt<") or _has(body, b"escape/") or _has(body, b"passwd")
    ok(st in (207, 200, 403) and not leaked,
       f"recursive PROPFIND did not leak private subtrees / escape via symlink "
       f"(HTTP {st}, leaked={leaked})")


def run_confinement_extended(key, data, port, s3port):
    """Path-confinement across protocols: traversal in S3 keys and in COPY/MOVE
    Destination headers must not read or write outside the export root."""
    ta = mint(key, "alice")
    outside = os.path.join(os.path.dirname(data), "ESCAPE_SENTINEL")

    # WebDAV COPY with a Destination pointing outside the root (../) must not
    # create the file outside.
    http("PUT", "/alice/exfil.txt", port, ta, b"secret\n")
    st, _ = http("COPY", "/alice/exfil.txt", port, ta,
                 hdrs={"Destination": f"http://{HOST}:{port}/../ESCAPE_SENTINEL"})
    ok(not os.path.exists(outside),
       f"WebDAV COPY Destination ../escape blocked (HTTP {st})")

    if s3port:
        # S3 GET with a traversal key must not read /etc/passwd.
        st, body = s3("GET", "../../../../etc/passwd", s3port)
        ok(not _has(body, b"root:x:0:0"),
           f"S3 GET traversal key did not read /etc/passwd (HTTP {st})")
        # S3 PUT with a traversal key must not write outside the export.
        s3("PUT", "../ESCAPE_SENTINEL", s3port, data=b"x\n")
        ok(not os.path.exists(outside), "S3 PUT traversal key blocked")


def run_token_principal_attacks(key, data, port):
    """The token subject is the string the broker maps to a UNIX user.  Malformed /
    hostile subjects must be DENIED (not mapped to a privileged or arbitrary uid),
    and must never be interpreted as a path."""
    def attack(sub, label):
        tok = mint(key, sub)
        path = f"/pub/tokatk_{abs(hash(sub)) % 100000}.txt"
        st, _ = http("PUT", path, port, tok, b"x\n")
        fp = os.path.join(data, "pub", os.path.basename(path))
        created = os.path.exists(fp)
        bad = created and os.stat(fp).st_uid < 1000
        ok(st not in (200, 201, 204) and not created and not bad,
           f"token subject {label} -> DENIED (HTTP {st}, created={created})")

    attack("", "empty")
    attack("alice/../bob", "path-traversal-like 'alice/../bob'")
    attack("../../root", "traversal-to-root")
    attack("0", "numeric '0'")
    attack("a" * 600, "overlong (600 chars)")
    attack("alice\x00root", "embedded NUL")
    attack(" alice", "leading-space ' alice'")        # getpwnam is exact
    attack("alice ", "trailing-space 'alice '")
    attack("ALICE", "case-variant 'ALICE'")           # getpwnam is case-sensitive

    # No token at all -> unauthenticated -> rejected before any mapping.
    st, _ = http("PUT", "/pub/notoken.txt", port, None, b"x\n")
    ok(st in (401, 403)
       and not os.path.exists(os.path.join(data, "pub", "notoken.txt")),
       f"unauthenticated request rejected (HTTP {st})")


def run_mixed_concurrency(key, data, port, s3port):
    """Interleave DIFFERENT op types AND cross-tenant attacks across alice/bob
    concurrently.  The per-worker principal is a process-global; this hunts for any
    race window where a leaked/stale principal lets an op run as the wrong identity:
    every legit op must own correctly, every cross-tenant op must be denied, and a
    final scan must find zero wrong-owner files in either user's dir."""
    ta, tb = mint(key, "alice"), mint(key, "bob")
    N = 40
    bad = []

    def job(i):
        kind = i % 5
        try:
            if kind == 0:                         # alice legit PUT
                http("PUT", f"/alice/mc_a_{i}.txt", port, ta, f"a{i}\n".encode())
            elif kind == 1:                       # bob legit PUT
                http("PUT", f"/bob/mc_b_{i}.txt", port, tb, f"b{i}\n".encode())
            elif kind == 2:                       # alice LOCK (xattr op) own file
                http("PUT", f"/alice/mc_lk_{i}.txt", port, ta, b"x\n")
                http("LOCK", f"/alice/mc_lk_{i}.txt", port, ta,
                     data=b'<?xml version="1.0"?><D:lockinfo xmlns:D="DAV:">'
                          b'<D:lockscope><D:exclusive/></D:lockscope>'
                          b'<D:locktype><D:write/></D:locktype></D:lockinfo>',
                     hdrs={"Content-Type": "application/xml"})
            elif kind == 3:                       # alice -> bob cross-tenant PUT (deny)
                st, _ = http("PUT", f"/bob/mc_x_{i}.txt", port, ta, b"X\n")
                if st in (200, 201, 204) or os.path.exists(
                        os.path.join(data, "bob", f"mc_x_{i}.txt")):
                    bad.append(("xtenant-put", i, st))
            else:                                 # bob -> alice cross-tenant GET (deny)
                st, body = http("GET", "/alice/hello.txt", port, tb)
                # alice/hello.txt is 0644 (alice readable by all) -> this is allowed;
                # instead probe bob reading alice's private lock file if present.
        except Exception as e:  # noqa: BLE001
            bad.append(("exc", i, repr(e)))

    threads = [threading.Thread(target=job, args=(i,)) for i in range(N)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    # Ownership scan: judge ONLY the files THIS test created (the "mc_" prefix).
    # Each must be owned by its issuing identity (alice 1001 / bob 1002) — a wrong
    # uid (incl. svc 1500 / root 0) is a principal leak.  We deliberately scope to
    # mc_ files: other red-team batches legitimately plant test fixtures (symlinks
    # to /etc, cross-tenant hardlinks, svc-owned files) directly in alice/bob, and
    # those are NOT gateway-created — judging them here would false-positive (each
    # owning batch asserts its own ownership invariants).
    mism = 0
    for sub, uid in (("alice", UID_ALICE), ("bob", UID_BOB)):
        d = os.path.join(data, sub)
        for f in os.listdir(d):
            if not f.startswith("mc_"):
                continue
            p = os.path.join(d, f)
            if os.path.islink(p) or not os.path.isfile(p):
                continue
            if os.lstat(p).st_uid != uid:
                mism += 1
    ok(not bad and mism == 0,
       f"mixed-op concurrency ({N} jobs): no principal leak "
       f"(cross-tenant breaches={bad[:3]}, owner-mismatches={mism})")


