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


def wait_port(port, timeout=10.0):
    end = time.time() + timeout
    while time.time() < end:
        try:
            with socket.create_connection((HOST, port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.1)
    return False



# ===== Round-7 batch helpers (workflow-authored) =====

from e2e_redteam_part3 import *  # noqa: F401,F403
from e2e_redteam_part4 import *  # noqa: F401,F403
from e2e_redteam_part5 import *  # noqa: F401,F403
from e2e_redteam_part6 import *  # noqa: F401,F403
from e2e_redteam_part7 import *  # noqa: F401,F403
from e2e_redteam_part8 import *  # noqa: F401,F403
from e2e_redteam_part9 import *  # noqa: F401,F403
from e2e_redteam_part10 import *  # noqa: F401,F403
from e2e_redteam_part11 import *  # noqa: F401,F403
from e2e_redteam_part12 import *  # noqa: F401,F403
from e2e_redteam_part13 import *  # noqa: F401,F403
from e2e_redteam_part14 import *  # noqa: F401,F403
from e2e_redteam_part15 import *  # noqa: F401,F403
from e2e_redteam_part16 import *  # noqa: F401,F403
from e2e_redteam_part17 import *  # noqa: F401,F403
from e2e_redteam_part18 import *  # noqa: F401,F403
from e2e_redteam_part19 import *  # noqa: F401,F403
from e2e_redteam_part20 import *  # noqa: F401,F403
from e2e_redteam_part21 import *  # noqa: F401,F403
from e2e_redteam_part22 import *  # noqa: F401,F403
from e2e_redteam_part23 import *  # noqa: F401,F403
from e2e_redteam_part24 import *  # noqa: F401,F403
from e2e_redteam_part25 import *  # noqa: F401,F403
from e2e_redteam_part26 import *  # noqa: F401,F403
from e2e_redteam_part27 import *  # noqa: F401,F403
from e2e_redteam_part28 import *  # noqa: F401,F403
from e2e_redteam_part29 import *  # noqa: F401,F403
from e2e_redteam_part30 import *  # noqa: F401,F403
from e2e_redteam_part31 import *  # noqa: F401,F403
from e2e_redteam_part32 import *  # noqa: F401,F403
from e2e_redteam_part33 import *  # noqa: F401,F403
from e2e_redteam_part34 import *  # noqa: F401,F403
from e2e_redteam_part35 import *  # noqa: F401,F403
from e2e_redteam_part36 import *  # noqa: F401,F403
from e2e_redteam_part37 import *  # noqa: F401,F403
from e2e_redteam_part38 import *  # noqa: F401,F403
from e2e_redteam_part39 import *  # noqa: F401,F403
from e2e_redteam_part40 import *  # noqa: F401,F403
from e2e_redteam_part41 import *  # noqa: F401,F403
from e2e_redteam_part42 import *  # noqa: F401,F403
from e2e_redteam_part43 import *  # noqa: F401,F403
from e2e_redteam_part44 import *  # noqa: F401,F403
from e2e_redteam_part45 import *  # noqa: F401,F403
from e2e_redteam_part46 import *  # noqa: F401,F403
from e2e_redteam_part47 import *  # noqa: F401,F403
from e2e_redteam_part48 import *  # noqa: F401,F403
from e2e_redteam_part49 import *  # noqa: F401,F403
from e2e_redteam_part50 import *  # noqa: F401,F403
from e2e_redteam_part51 import *  # noqa: F401,F403
from e2e_redteam_part52 import *  # noqa: F401,F403
from e2e_redteam_part53 import *  # noqa: F401,F403
from e2e_redteam_part54 import *  # noqa: F401,F403
from e2e_redteam_part55 import *  # noqa: F401,F403
from e2e_redteam_part56 import *  # noqa: F401,F403
from e2e_redteam_part57 import *  # noqa: F401,F403
from e2e_redteam_part58 import *  # noqa: F401,F403
from e2e_redteam_part59 import *  # noqa: F401,F403
from e2e_redteam_part60 import *  # noqa: F401,F403
from e2e_redteam_part61 import *  # noqa: F401,F403
from e2e_redteam_part62 import *  # noqa: F401,F403
from e2e_redteam_part63 import *  # noqa: F401,F403
from e2e_redteam_part64 import *  # noqa: F401,F403
from e2e_redteam_part65 import *  # noqa: F401,F403
from e2e_redteam_part66 import *  # noqa: F401,F403
from e2e_redteam_part67 import *  # noqa: F401,F403
from e2e_redteam_part68 import *  # noqa: F401,F403
from e2e_redteam_part69 import *  # noqa: F401,F403
from e2e_redteam_part70 import *  # noqa: F401,F403
from e2e_redteam_part71 import *  # noqa: F401,F403
from e2e_redteam_part72 import *  # noqa: F401,F403
from e2e_redteam_part73 import *  # noqa: F401,F403
from e2e_redteam_part74 import *  # noqa: F401,F403
from e2e_redteam_part75 import *  # noqa: F401,F403
from e2e_redteam_part76 import *  # noqa: F401,F403
from e2e_redteam_part77 import *  # noqa: F401,F403
