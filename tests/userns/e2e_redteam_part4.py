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


def main():
    if not os.path.isfile(NGINX):
        print(f"SKIP: nginx binary not at {NGINX}")
        return 0

    data = os.path.join(WORK, "export")
    logs = os.path.join(WORK, "logs")
    tmp = os.path.join(WORK, "tmp")
    run = os.path.join(WORK, "run")
    cadir = os.path.join(WORK, "cadir")
    for d in (logs, tmp, run, cadir):
        os.makedirs(d, exist_ok=True)
        os.chmod(d, 0o777)            # writable by the svc-uid worker

    # Export tree (created as in-ns root so we can chown to mapped users).  The
    # export ROOT is owned by the service (svc) account — as in a real storage
    # deployment, the worker user owns the export and writes housekeeping files
    # (checkpoint/FRM); per-user subdirs are owned by the mapped users.
    chown_dir(data, UID_SVC, UID_SVC, 0o755)
    chown_dir(os.path.join(data, "alice"), UID_ALICE, UID_ALICE, 0o755)
    chown_dir(os.path.join(data, "bob"), UID_BOB, UID_BOB, 0o755)
    chown_dir(os.path.join(data, "bobsecret"), UID_BOB, UID_BOB, 0o700)
    chown_dir(os.path.join(data, "pub"), UID_SVC, UID_SVC, 0o777)
    # A dir the WORKER (svc) can read but the mapped user (alice) cannot (0750,
    # svc-owned, alice is neither owner nor in group svc).  Used to probe whether
    # directory LISTING leaks contents the user has no UNIX permission to read.
    so = os.path.join(data, "svconly")
    chown_dir(so, UID_SVC, UID_SVC, 0o750)
    with open(os.path.join(so, "secret-name.txt"), "w") as fh:
        fh.write("svc-only-secret\n")
    os.chown(os.path.join(so, "secret-name.txt"), UID_SVC, UID_SVC)
    # a file inside bob's secret dir, for the DAC-read test
    sp = os.path.join(data, "bobsecret", "s.txt")
    with open(sp, "w") as fh:
        fh.write("bob-only\n")
    os.chown(sp, UID_BOB, UID_BOB)
    os.chmod(sp, 0o600)

    # Cross-tenant fixtures inside bob's 0755 dir (alice can TRAVERSE + list the
    # dir, so the deny/allow below is decided purely by the FILE's mode):
    #   bob/private.txt  0600  -> alice (other) CANNOT read the contents (deny)
    #   bob/readable.txt 0644  -> alice CAN read it (control: proves the deny is
    #                             real per-file DAC, not a blanket cross-prefix block)
    bpriv = os.path.join(data, "bob", "private.txt")
    with open(bpriv, "w") as fh:
        fh.write("BOB-PRIVATE-SECRET\n")
    os.chown(bpriv, UID_BOB, UID_BOB)
    os.chmod(bpriv, 0o600)
    bread = os.path.join(data, "bob", "readable.txt")
    with open(bread, "w") as fh:
        fh.write("bob-world-readable\n")
    os.chown(bread, UID_BOB, UID_BOB)
    os.chmod(bread, 0o644)
    # the svc-uid worker must be able to traverse to the export root.
    ensure_traversable(data)
    # a symlink escape attempt target
    try:
        os.symlink("/etc", os.path.join(data, "escape"))
    except FileExistsError:
        pass

    # ---- GROUP / POSIX-DAC fixtures (exercise the broker's setfsgid+setgroups) --
    # staff = {alice, carol}; research = {bob, dave}; shared = {alice, bob, carol}.
    # A file's group-permission bits are enforced by the broker applying the mapped
    # user's supplementary groups — the core impersonation mechanism never before
    # exercised end-to-end through the protocols.  Each marker is unique so a
    # must-not-leak assertion can scan for it.
    def mk(rel, content, uid, gid, mode):
        p = os.path.join(data, rel)
        try:
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, "w") as fh:
                fh.write(content)
            os.chown(p, uid, gid)
            os.chmod(p, mode)
        except OSError:
            pass

    def mkdir_g(rel, uid, gid, mode):
        p = os.path.join(data, rel)
        try:
            os.makedirs(p, exist_ok=True)
            os.chown(p, uid, gid)
            os.chmod(p, mode)
        except OSError:
            pass

    # group-readable / group-writable files owned alice:staff (carol is in staff,
    # bob is NOT) — the canonical group-DAC read/write cases.
    mk("grp/staff_r.txt",  "STAFF-GROUP-READABLE\n", UID_ALICE, GID_STAFF, 0o640)
    mk("grp/staff_w.txt",  "STAFF-GROUP-WRITABLE\n", UID_ALICE, GID_STAFF, 0o660)
    mk("grp/staff_none.txt", "STAFF-OWNER-ONLY\n",   UID_ALICE, GID_STAFF, 0o600)
    mk("grp/world_r.txt",  "WORLD-READABLE\n",       UID_ALICE, GID_STAFF, 0o644)
    # research group file owned bob:research (dave in research; alice/carol NOT).
    mk("grp/research_r.txt", "RESEARCH-GROUP-READABLE\n", UID_BOB, GID_RESEARCH, 0o640)
    # shared (alice,bob,carol) group-writable file owned alice:shared.
    mk("grp/shared_w.txt", "SHARED-GROUP-WRITABLE\n", UID_ALICE, GID_SHARED, 0o660)
    # a full permission-matrix subject owned alice:staff (mode set per-test).
    mk("grp/matrix.txt", "MATRIX-SECRET-BODY\n", UID_ALICE, GID_STAFF, 0o600)
    mkdir_g("grp", UID_SVC, UID_SVC, 0o755)
    os.chown(os.path.join(data, "grp"), UID_SVC, UID_SVC)  # parent traversable

    # group-accessible DIRECTORIES: 0770 staff dir (alice,carol enter; bob can't),
    # a setgid 2770 dir (new files inherit the staff group), a 0710 group-exec-only
    # dir (members traverse to a known child but cannot list).
    mkdir_g("staffdir", UID_ALICE, GID_STAFF, 0o770)
    mk("staffdir/inside.txt", "INSIDE-STAFF-DIR\n", UID_ALICE, GID_STAFF, 0o640)
    mkdir_g("sgiddir", UID_ALICE, GID_STAFF, 0o2770)          # setgid
    mkdir_g("execonly", UID_ALICE, GID_STAFF, 0o710)          # group --x, no read
    mk("execonly/known.txt", "EXECONLY-KNOWN\n", UID_ALICE, GID_STAFF, 0o640)
    mkdir_g("shareddir", UID_ALICE, GID_SHARED, 0o770)        # alice,bob,carol
    # a sticky world-writable dir (1777, like /tmp): anyone creates, only the file
    # owner (or dir owner) may delete — the classic sticky-bit protection.
    mkdir_g("stickytmp", UID_SVC, UID_SVC, 0o1777)
    mk("stickytmp/alice_owned.txt", "STICKY-ALICE-FILE\n", UID_ALICE, UID_ALICE, 0o644)

    # ES256 signing key + JWKS.
    key = ec.generate_private_key(ec.SECP256R1())
    nums = key.public_key().public_numbers()
    jwks = {"keys": [{"kty": "EC", "crv": "P-256", "kid": KID, "use": "sig",
                      "alg": "ES256", "x": _b64u(nums.x.to_bytes(32, "big")),
                      "y": _b64u(nums.y.to_bytes(32, "big"))}]}
    jwks_path = os.path.join(WORK, "jwks.json")
    with open(jwks_path, "w") as fh:
        json.dump(jwks, fh)

    sock = os.path.join(run, "impersonate.sock")
    sport, hport, s3port = free_port(), free_port(), free_port()
    global _jwt_key, _stream_port
    _jwt_key, _stream_port = key, sport          # so the root:// helpers can mint tokens

    conf = f"""
user svc;
worker_processes 1;
daemon off;
master_process on;
error_log {logs}/error.log info;
pid {logs}/nginx.pid;
thread_pool default threads=4 max_queue=4096;
events {{ worker_connections 128; }}

stream {{
    brix_impersonation        map;
    brix_impersonation_socket {sock};
    brix_impersonation_export {data};
    brix_idmap_min_uid        1000;
    brix_idmap_forbidden_groups "docker,sudo,wheel";
    server {{
        listen {BIND_HOST}:{sport};
        brix_root on;
        brix_storage_backend posix:{data};
        brix_allow_write on;
        brix_auth token;
        brix_token_jwks     {jwks_path};
        brix_token_issuer   "{ISSUER}";
        brix_token_audience "{AUDIENCE}";
    }}
}}

http {{
    access_log off;
    client_body_temp_path {tmp};
    proxy_temp_path        {tmp};
    fastcgi_temp_path      {tmp};
    uwsgi_temp_path        {tmp};
    scgi_temp_path         {tmp};
    client_max_body_size   64m;
    server {{
        listen {BIND_HOST}:{hport};
        location / {{
            brix_webdav         on;
            brix_storage_backend    posix:{data};
            brix_webdav_auth    required;
            brix_webdav_cadir   {cadir};
            brix_allow_write on;
            brix_webdav_token_jwks     {jwks_path};
            brix_webdav_token_issuer   "{ISSUER}";
            brix_webdav_token_audience "{AUDIENCE}";
        }}
    }}
    server {{
        listen {BIND_HOST}:{s3port};
        location / {{
            brix_s3             on;
            brix_storage_backend        posix:{data};
            brix_s3_bucket      {S3_BUCKET};
            brix_s3_access_key  alice;
            brix_s3_secret_key  {S3_SECRET};
            brix_s3_region      {S3_REGION};
            brix_allow_write on;
        }}
    }}
}}
"""
    confp = os.path.join(WORK, "nginx.conf")
    with open(confp, "w") as fh:
        fh.write(conf)

    proc = subprocess.Popen([NGINX, "-p", WORK, "-c", confp],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if not wait_port(hport, 12):
        time.sleep(0.5)
        proc.terminate()
        err = b""
        try:
            err = proc.stderr.read() if proc.stderr else b""
        except Exception:  # noqa: BLE001
            pass
        elog = ""
        try:
            with open(os.path.join(logs, "error.log")) as fh:
                elog = fh.read()[-2000:]
        except OSError:
            pass
        print("SKIP: nginx (map mode) did not start in the namespace\n"
              + err.decode(errors="replace") + "\n" + elog)
        subprocess.run(["chown", "-R", "0:0", WORK], timeout=30)
        return 0

    # Confirm the real broker spawned (it is double-forked by the master's
    # init_module).  If it is missing, dump the error log to aid triage.
    time.sleep(0.5)
    broker_ok = False
    try:
        with open(sock + ".pid") as fh:
            bpid = int(fh.read().strip())
        broker_ok = os.path.exists(f"/proc/{bpid}")
    except (OSError, ValueError):
        bpid = None
    print(f"broker pid={bpid} alive={broker_ok}", flush=True)
    ok(broker_ok, "real broker spawned by the nginx master (init_module)")
    if not broker_ok:
        try:
            with open(os.path.join(logs, "error.log")) as fh:
                print("error.log tail:\n" + fh.read()[-2000:], flush=True)
        except OSError:
            pass

    try:
        try:
            run_battery(key, data, hport, s3port, sock)
        except Exception as e:  # noqa: BLE001
            import traceback
            traceback.print_exc()
            ok(False, f"battery raised an exception: {e!r}")
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        # kill the double-forked broker (reparented, survives nginx).
        try:
            with open(sock + ".pid") as fh:
                bpid = int(fh.read().strip())
            os.kill(bpid, 9)
        except (OSError, ValueError):
            pass

    # Cleanup: files created inside the ns are owned by mapped subuids (alice/bob
    # /svc -> 101000+ on the host) which the unprivileged invoker cannot remove.
    # As in-ns root, chown the whole work tree back to inside-0 (== the real
    # invoking user) so the pytest tmp_path teardown can delete it.
    try:
        subprocess.run(["chown", "-R", "0:0", WORK], timeout=30)
    except Exception:  # noqa: BLE001
        pass

    print(f"\n{_pass} passed, {_fail} failed", flush=True)
    if _fail == 0:
        print("ALL PASSED")
        return 0
    print("FAILED")
    return 1


def _reset_fixtures(data):
    """Re-establish the canonical mode/owner/content of the SHARED global fixtures.
    Many batches legitimately mutate a shared fixture (e.g. bob re-PUTs his own
    private.txt — a staged write that lands 0644, resetting the 0600 mode a LATER
    batch assumes), so without this a deny-test in batch N+1 sees the changed state
    and false-fails (the DAC itself is correct — it just sees a now-0644 file).
    Called between deep batches so each starts from a known namespace.  Pure os
    (in-ns root); never touched by the server."""
    def fx(rel, content, uid, gid, mode):
        p = os.path.join(data, rel)
        try:
            if content is not None:
                with open(p, "wb") as fh:
                    fh.write(content)
            os.chown(p, uid, gid)
            os.chmod(p, mode)
        except OSError:
            pass

    def fxd(rel, uid, gid, mode):
        p = os.path.join(data, rel)
        try:
            os.makedirs(p, exist_ok=True)
            os.chown(p, uid, gid)
            os.chmod(p, mode)
        except OSError:
            pass

    fx("bob/private.txt", b"BOB-PRIVATE-SECRET\n", UID_BOB, UID_BOB, 0o600)
    fx("bob/readable.txt", b"bob-world-readable\n", UID_BOB, UID_BOB, 0o644)
    fxd("bobsecret", UID_BOB, UID_BOB, 0o700)
    fx("bobsecret/s.txt", b"bob-only\n", UID_BOB, UID_BOB, 0o600)
    fxd("svconly", UID_SVC, UID_SVC, 0o750)
    fx("svconly/secret-name.txt", b"svc-only-secret\n", UID_SVC, UID_SVC, 0o640)
    fx("grp/staff_r.txt", b"STAFF-GROUP-READABLE\n", UID_ALICE, GID_STAFF, 0o640)
    fx("grp/staff_w.txt", b"STAFF-GROUP-WRITABLE\n", UID_ALICE, GID_STAFF, 0o660)
    fx("grp/staff_none.txt", b"STAFF-OWNER-ONLY\n", UID_ALICE, GID_STAFF, 0o600)
    fx("grp/world_r.txt", b"WORLD-READABLE\n", UID_ALICE, GID_STAFF, 0o644)
    fx("grp/research_r.txt", b"RESEARCH-GROUP-READABLE\n", UID_BOB, GID_RESEARCH, 0o640)
    fx("grp/matrix.txt", b"MATRIX-SECRET-BODY\n", UID_ALICE, GID_STAFF, 0o600)
    fxd("staffdir", UID_ALICE, GID_STAFF, 0o770)
    fxd("sgiddir", UID_ALICE, GID_STAFF, 0o2770)
    fxd("execonly", UID_ALICE, GID_STAFF, 0o710)
    fxd("shareddir", UID_ALICE, GID_SHARED, 0o770)
    fxd("stickytmp", UID_SVC, UID_SVC, 0o1777)


