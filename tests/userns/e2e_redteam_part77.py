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


def run_broker_failclosed(key, data, port, s3port, sock, tok_alice):
    try:
        with open(sock + ".pid") as fh:
            bpid = int(fh.read().strip())
        os.kill(bpid, 9)
        # wait for it to die
        for _ in range(30):
            if not os.path.exists(f"/proc/{bpid}"):
                break
            time.sleep(0.1)
    except (OSError, ValueError) as e:  # noqa: BLE001
        ok(False, f"could not kill broker for fail-closed test: {e}")
        return

    st, _ = http("PUT", "/alice/after_broker_killed.txt", port, tok_alice, b"x\n")
    fp = os.path.join(data, "alice", "after_broker_killed.txt")
    created = os.path.exists(fp)
    bad_owner = created and os.stat(fp).st_uid != UID_ALICE
    ok(st not in (200, 201, 204) and not (created and bad_owner),
       f"broker killed -> PUT FAILS CLOSED, not silently done as worker "
       f"(HTTP {st}, created={created}, wrong_owner={bad_owner})")

    # An xattr op (LOCK) must ALSO fail closed when the broker is gone — it must
    # NOT silently fall back to a raw setxattr as the worker.
    st, _ = http("LOCK", "/alice/hello.txt", port, tok_alice,
                 data=b'<?xml version="1.0"?><D:lockinfo xmlns:D="DAV:">'
                      b'<D:lockscope><D:exclusive/></D:lockscope>'
                      b'<D:locktype><D:write/></D:locktype></D:lockinfo>',
                 hdrs={"Content-Type": "application/xml"})
    ok(st not in (200, 201),
       f"broker killed -> LOCK (xattr op) FAILS CLOSED (HTTP {st})")

    # An S3 op must ALSO fail closed (no silent worker-uid create).
    if s3port:
        st, _ = s3("PUT", "alice/after_broker_s3.txt", s3port, data=b"x\n")
        sfp = os.path.join(data, "alice", "after_broker_s3.txt")
        s_created = os.path.exists(sfp)
        s_bad = s_created and os.stat(sfp).st_uid != UID_ALICE
        ok(st not in (200, 201) and not (s_created and s_bad),
           f"broker killed -> S3 PUT FAILS CLOSED (HTTP {st}, created={s_created})")


if __name__ == "__main__":
    sys.exit(main())
