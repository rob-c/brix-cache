#!/usr/bin/env python3
"""e2e_redteam.py — full-stack privilege-escalation red-team for phase-40
impersonation.  RUNS AS IN-NS ROOT (launched by userns_exec_launcher inside an
unprivileged user namespace with a subuid range + bind-mounted fake passwd/group).

This is the pseudo-production permissions test: it boots the REAL nginx binary
with `brix_idmap map` (so the real master spawns the real broker, real
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


def ok(cond, msg):
    global _pass, _fail
    if cond:
        _pass += 1
        print(f"PASS: {msg}", flush=True)
    else:
        _fail += 1
        print(f"FAIL: {msg}", flush=True)


def _b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def mint(key, sub, scope=WRITE_SCOPE, **over):
    now = int(time.time())
    hdr = {"alg": "ES256", "typ": "JWT", "kid": KID}
    pay = {"iss": ISSUER, "sub": sub, "aud": AUDIENCE, "exp": now + 3600,
           "iat": now, "nbf": now, "scope": scope, "wlcg.ver": "1.0"}
    pay.update(over)
    si = (_b64u(json.dumps(hdr, separators=(",", ":")).encode()) + "."
          + _b64u(json.dumps(pay, separators=(",", ":")).encode()))
    der = key.sign(si.encode("ascii"), ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    raw = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    return si + "." + _b64u(raw)


def free_port():
    from ephemeral_port import free_port as assigned_port
    return assigned_port(BIND_HOST)


def chown_dir(path, uid, gid, mode):
    os.makedirs(path, exist_ok=True)
    os.chown(path, uid, gid)
    os.chmod(path, mode)


def ensure_traversable(path):
    """Add +x to every ancestor so the unprivileged svc-uid worker can traverse
    to (and open) the export root — mirrors a correct production export layout
    (the worker user must be able to reach the data tree)."""
    p = os.path.abspath(path)
    while p and p != "/":
        try:
            os.chmod(p, os.stat(p).st_mode | 0o111)
        except OSError:
            pass
        p = os.path.dirname(p)


def http(method, path, port, token=None, data=None, hdrs=None):
    url = f"http://{HOST}:{port}{path}"
    req = urllib.request.Request(url, method=method, data=data)
    _add_request_headers(req, token, hdrs)
    return _open_http(req)


def _add_request_headers(request, token, headers):
    if token:
        request.add_header("Authorization", f"Bearer {token}")
    for key, value in (headers or {}).items():
        request.add_header(key, value)


def _open_http(request):
    try:
        with urllib.request.urlopen(request, timeout=6) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as error:
        return error.code, error.read()
    except Exception as error:  # noqa: BLE001
        return -1, str(error).encode()


def http_keepalive(reqs, port):
    """Send several (method, path, token, data, hdrs) requests over ONE kept-alive
    TCP connection (http.client reuses it).  Used to prove the per-request
    impersonation principal does not LEAK across requests pipelined on the same
    worker connection.  Returns [(status, body), ...]."""
    conn = HTTPConnection(HOST, port, timeout=8)
    out = []
    try:
        for method, path, token, data, extra in reqs:
            hdrs = dict(extra or {})
            if token:
                hdrs["Authorization"] = f"Bearer {token}"
            conn.request(method, path, body=data, headers=hdrs)
            r = conn.getresponse()
            out.append((r.status, r.read()))
    except Exception as e:  # noqa: BLE001
        out.append((-1, str(e).encode()))
    finally:
        conn.close()
    return out


def _raw_get_header(method, path, port, hdrs=None):
    """Issue `method path` and return (status, {resp-header-lower: value}, body).
    `hdrs` carries REQUEST headers (Authorization + any conditional validators /
    Want-Digest).  Used by the checksum-oracle and conditional-header matrices that
    must inspect the response headers, not just the body."""
    url = f"http://{HOST}:{port}{path}"
    req = urllib.request.Request(url, method=method)
    for k, v in (hdrs or {}).items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=6) as r:
            return (r.status,
                    {k.lower(): v for k, v in r.headers.items()},
                    r.read())
    except urllib.error.HTTPError as e:
        return (e.code,
                {k.lower(): v for k, v in (e.headers or {}).items()},
                e.read())
    except Exception as e:  # noqa: BLE001
        return -1, {}, str(e).encode()


def _raw_get_validators(path, port, tok):
    """GET `path` as bearer `tok`; return (status, etag, last_modified, body) — the
    cache/conditional-request validators the If-Match/If-None-Match matrix replays."""
    st, h, b = _raw_get_header("GET", path, port,
                               {"Authorization": f"Bearer {tok}"} if tok else None)
    return st, h.get("etag"), h.get("last-modified"), b


def _dead_xattr_count(fs_path):
    """Count WebDAV dead-property xattrs (user.nginx_xrootd.webdav.*) on the file at
    absolute path `fs_path` — the PROPPATCH store's on-disk carrier (see
    src/protocols/webdav/dead_props_internal.h).  0 when the file is missing or
    carries none, so a PROPPATCH set/remove is observable as a count delta."""
    try:
        names = os.listxattr(fs_path, follow_symlinks=False)
    except OSError:
        return 0
    return sum(1 for n in names
               if n.startswith("user.nginx_xrootd.webdav."))


def _dead_xattr_has_value(fs_path, value):
    """True if ANY WebDAV dead-property xattr on `fs_path` contains the bytes
    `value` — lets a check assert a PROPPATCH set did (PERSIST) or did not (VANISH)
    land on disk, independent of the 207 wire status."""
    try:
        names = os.listxattr(fs_path, follow_symlinks=False)
    except OSError:
        return False
    for n in names:
        if not n.startswith("user.nginx_xrootd.webdav."):
            continue
        try:
            v = os.getxattr(fs_path, n, follow_symlinks=False)
        except OSError:
            continue
        if value in v:
            return True
    return False


_CRC64NVME_TABLE = None


def _crc64nvme(data):
    """The 64-bit CRC-64/NVME of `data` as an int — poly 0xad93d23594c93659
    (reflected 0x9a6c9329ac4bc9b5), refin/refout true, init and xorout all-ones
    (check("123456789") == 0xAE8B14860A799888)."""
    global _CRC64NVME_TABLE
    if _CRC64NVME_TABLE is None:
        poly = 0x9a6c9329ac4bc9b5          # 0xad93d23594c93659, bit-reflected
        tbl = []
        for n in range(256):
            crc = n
            for _ in range(8):
                crc = (crc >> 1) ^ poly if (crc & 1) else (crc >> 1)
            tbl.append(crc)
        _CRC64NVME_TABLE = tbl
    crc = 0xFFFFFFFFFFFFFFFF
    for b in data:
        crc = (crc >> 8) ^ _CRC64NVME_TABLE[(crc ^ b) & 0xFF]
    return crc ^ 0xFFFFFFFFFFFFFFFF


def _crc64nvme_b64(data):
    """base64 of the 8-byte big-endian CRC-64/NVME of `data` — the exact value AWS
    S3 (and brix) emit as x-amz-checksum-crc64nvme."""
    return base64.b64encode(_crc64nvme(data).to_bytes(8, "big")).decode()


def _s3_post_form(sub, key, body, tamper_sig=False, when=None, expires_secs=3600,
                  cred_override=None, expires_min=None, omit_file=False,
                  omit_policy=False, filename="u.bin"):
    """Build a browser-style S3 POST-form upload (multipart/form-data) whose base64
    policy is SigV4-signed as `sub` (the subject the broker maps to a UNIX uid).
    Returns (content_type, body_bytes) for post_form().  `tamper_sig` corrupts the
    signature (must be rejected); `when` overrides the signing/policy time (expiry
    and clock-skew tests); `cred_override` substitutes a forged x-amz-credential
    (e.g. a "root/..." escalation attempt) into BOTH the policy and the form while
    the signature stays keyed to the real secret; the file field is emitted LAST
    per the S3 POST contract."""
    now = when or dt.datetime.now(dt.timezone.utc)
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    date = now.strftime("%Y%m%d")
    scope = f"{date}/{S3_REGION}/s3/aws4_request"
    cred = cred_override if cred_override is not None else f"{sub}/{scope}"
    if expires_min is not None:
        expires_secs = expires_min * 60
    exp = (now + dt.timedelta(seconds=expires_secs)).strftime("%Y-%m-%dT%H:%M:%SZ")
    policy = {
        "expiration": exp,
        "conditions": [
            {"bucket": S3_BUCKET},
            ["starts-with", "$key", ""],
            {"x-amz-algorithm": "AWS4-HMAC-SHA256"},
            {"x-amz-credential": cred},
            {"x-amz-date": amz_date},
        ],
    }
    policy_b64 = base64.b64encode(json.dumps(policy).encode()).decode()
    k = hmac.new(f"AWS4{S3_SECRET}".encode(), date.encode(), hashlib.sha256).digest()
    k = hmac.new(k, S3_REGION.encode(), hashlib.sha256).digest()
    k = hmac.new(k, b"s3", hashlib.sha256).digest()
    k = hmac.new(k, b"aws4_request", hashlib.sha256).digest()
    sig = hmac.new(k, policy_b64.encode(), hashlib.sha256).hexdigest()
    if tamper_sig:
        sig = ("0" if sig[0] != "0" else "1") + sig[1:]

    boundary = "brixRTpostform" + amz_date
    crlf = b"\r\n"
    bb = boundary.encode()
    out = b""
    fields = [("key", key),
              ("x-amz-algorithm", "AWS4-HMAC-SHA256"),
              ("x-amz-credential", cred),
              ("x-amz-date", amz_date),
              ("policy", policy_b64),               # dropped when omit_policy
              ("x-amz-signature", sig)]
    if omit_policy:                                 # forge a form with no policy
        fields = [(n, v) for n, v in fields if n != "policy"]
    for name, val in fields:
        out += (b"--" + bb + crlf
                + f'Content-Disposition: form-data; name="{name}"'.encode()
                + crlf + crlf + val.encode() + crlf)
    if not omit_file:                               # omit_file forges a fileless POST
        # `filename` is emitted raw so a caller can probe the server's ${filename}
        # template with a traversal value (e.g. "../../../PF_FN_ESCAPE").
        out += (b"--" + bb + crlf
                + ('Content-Disposition: form-data; name="file"; filename="%s"'
                   % filename).encode()
                + crlf
                + b"Content-Type: application/octet-stream" + crlf + crlf
                + body + crlf)
    out += b"--" + bb + b"--" + crlf
    return f"multipart/form-data; boundary={boundary}", out


def raw_http(raw, port, read_timeout=4.0):
    """Send RAW bytes on a fresh TCP connection (bypasses http.client so we can
    forge malformed request lines, duplicate headers, bare-LF framing, HTTP/1.0,
    request-smuggling bodies) and return the raw response bytes (b"" on
    timeout/closed).  Used to prove the worker cannot be desynced or tricked into
    running a smuggled request under the wrong identity."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(read_timeout)
    try:
        s.connect((HOST, port))
        s.sendall(raw if isinstance(raw, bytes) else raw.encode())
        return _read_socket(s)
    except (OSError, socket.timeout):
        return b""
    finally:
        _close_socket(s)


def _read_socket(sock):
    buf = b""
    while True:
        chunk = sock.recv(65536)
        if not chunk:
            return buf
        buf += chunk
        if len(buf) > 1 << 20:
            return buf


def _close_socket(sock):
    try:
        sock.close()
    except OSError:
        pass


def s3_presign(method, key, port, expires=300, access_key="alice", when=None,
               tamper=False):
    """Build a PRESIGNED-URL (query-string SigV4) path for /<bucket>/<key>.  Auth
    travels in X-Amz-* query params (no Authorization header), validity bounded by
    X-Amz-Expires.  Returns the path+query string to pass to http() with no token.
    'when' backdates the signing time (expiry tests); 'tamper' corrupts the
    signature (forgery test)."""
    now = when or dt.datetime.now(dt.timezone.utc)
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    date = now.strftime("%Y%m%d")
    host = f"{HOST}:{port}"
    path = f"/{S3_BUCKET}/{key}"
    scope = f"{date}/{S3_REGION}/s3/aws4_request"
    q = {
        "X-Amz-Algorithm": "AWS4-HMAC-SHA256",
        "X-Amz-Credential": f"{access_key}/{scope}",
        "X-Amz-Date": amz_date,
        "X-Amz-Expires": str(expires),
        "X-Amz-SignedHeaders": "host",
    }
    cq = _canon_query(q)
    canonical = (f"{method}\n{quote(path, safe='/-_.~')}\n{cq}\n"
                 f"host:{host}\n\nhost\nUNSIGNED-PAYLOAD")
    sts = (f"AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n"
           f"{hashlib.sha256(canonical.encode()).hexdigest()}")
    k = hmac.new(f"AWS4{S3_SECRET}".encode(), date.encode(), hashlib.sha256).digest()
    k = hmac.new(k, S3_REGION.encode(), hashlib.sha256).digest()
    k = hmac.new(k, b"s3", hashlib.sha256).digest()
    k = hmac.new(k, b"aws4_request", hashlib.sha256).digest()
    sig = hmac.new(k, sts.encode(), hashlib.sha256).hexdigest()
    if tamper:
        sig = ("0" * len(sig)) if sig[0] != "0" else ("f" * len(sig))
    return f"{path}?{cq}&X-Amz-Signature={sig}"


def _canon_query(params):
    """Canonical SigV4 query string: keys sorted, value-encoded, '&'-joined."""
    return "&".join(f"{quote(k, safe='-_.~')}={quote(v, safe='-_.~')}"
                    for k, v in sorted(params.items()))


def s3_sign(method, path, port, params=None, access_key="alice", when=None):
    """Build SigV4 header-auth (UNSIGNED-PAYLOAD, SignedHeaders=host;x-amz-date)
    for a path-style S3 request.  access_key is the subject the broker maps to a
    UNIX uid, so signing as "alice" makes the S3 op run as alice under map mode.
    `when` overrides the timestamp (for clock-skew / expiry attack tests)."""
    now = when or dt.datetime.now(dt.timezone.utc)
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    date = now.strftime("%Y%m%d")
    host = f"{HOST}:{port}"
    cq = _canon_query(params or {})
    canonical = (f"{method}\n{quote(path, safe='/-_.~')}\n{cq}\n"
                 f"host:{host}\nx-amz-date:{amz_date}\n\n"
                 f"host;x-amz-date\nUNSIGNED-PAYLOAD")
    scope = f"{date}/{S3_REGION}/s3/aws4_request"
    sts = (f"AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n"
           f"{hashlib.sha256(canonical.encode()).hexdigest()}")
    k = hmac.new(f"AWS4{S3_SECRET}".encode(), date.encode(), hashlib.sha256).digest()
    k = hmac.new(k, S3_REGION.encode(), hashlib.sha256).digest()
    k = hmac.new(k, b"s3", hashlib.sha256).digest()
    k = hmac.new(k, b"aws4_request", hashlib.sha256).digest()
    sig = hmac.new(k, sts.encode(), hashlib.sha256).hexdigest()
    return {"x-amz-date": amz_date, "x-amz-content-sha256": "UNSIGNED-PAYLOAD",
            "Authorization": (f"AWS4-HMAC-SHA256 Credential={access_key}/{scope}, "
                              f"SignedHeaders=host;x-amz-date, Signature={sig}")}


def _url_query(params):
    """URL query: empty-value params are emitted as BARE flags (e.g. "?uploads"),
    matching the server's bare-flag detection; SigV4 still canonicalizes them as
    "uploads=" (see _canon_query), so the signature matches."""
    parts = []
    for k, v in sorted(params.items()):
        parts.append(quote(k, safe='-_.~') if v == ""
                     else f"{quote(k, safe='-_.~')}={quote(v, safe='-_.~')}")
    return "&".join(parts)


def s3(method, key, port, params=None, data=None, access_key="alice",
       extra_hdrs=None):
    """Issue a signed S3 request for /<bucket>/<key>(+query).  extra_hdrs (e.g.
    x-amz-copy-source) are added unsigned — this server signs only host;x-amz-date."""
    path = f"/{S3_BUCKET}/{key}"
    q = ("?" + _url_query(params)) if params else ""
    h = s3_sign(method, path, port, params, access_key)
    if extra_hdrs:
        h.update(extra_hdrs)
    return http(method, path + q, port, data=data, hdrs=h)


# ----- root:// native-client driver (the stream protocol, token-authenticated) --
def xrd_avail():
    return os.path.isfile(NATIVE_XRDFS) and os.path.isfile(NATIVE_XRDCP)


def _xrd_env(sub):
    env = dict(os.environ)
    env["BEARER_TOKEN"] = mint(_jwt_key, sub)
    env.pop("X509_USER_PROXY", None)      # don't let it pick up a host GSI proxy
    return env


def xrd_fs(args, sub, timeout=15):
    """Run native xrdfs as <sub> (bearer token) vs the impersonation stream server
    root://127.0.0.1:sport.  Returns (rc, stdout, stderr)."""
    cmd = [NATIVE_XRDFS, f"root://{HOST}:{_stream_port}"] + list(args)
    try:
        p = subprocess.run(cmd, env=_xrd_env(sub), capture_output=True,
                           timeout=timeout, text=True)
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "timeout"


def xrd_cp_up(local, remote, sub, timeout=20):
    """xrdcp WRITE: local file -> root://...//remote, as <sub>."""
    url = f"root://{HOST}:{_stream_port}//{remote.lstrip('/')}"
    cmd = [NATIVE_XRDCP, "-f", local, url]
    try:
        p = subprocess.run(cmd, env=_xrd_env(sub), capture_output=True,
                           timeout=timeout, text=True)
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "timeout"


def xrd_cp_down(remote, local, sub, timeout=20):
    """xrdcp READ: root://...//remote -> local file, as <sub>."""
    url = f"root://{HOST}:{_stream_port}//{remote.lstrip('/')}"
    cmd = [NATIVE_XRDCP, "-f", url, local]
    try:
        p = subprocess.run(cmd, env=_xrd_env(sub), capture_output=True,
                           timeout=timeout, text=True)
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "timeout"


def xrd_cp_tpc(src_remote, dst_remote, sub, mode="first", timeout=25):
    """Native THIRD-PARTY COPY (xrdcp --tpc): server-orchestrated copy from
    root://...//src_remote to root://...//dst_remote on the SAME server (loopback
    TPC), driven as <sub>.  Returns (rc, out, err).  Both endpoints are the
    impersonation stream server, so the pulled/pushed file must end up owned by the
    mapped user and a cross-tenant source/dest must be denied."""
    s = f"root://{HOST}:{_stream_port}//{src_remote.lstrip('/')}"
    d = f"root://{HOST}:{_stream_port}//{dst_remote.lstrip('/')}"
    cmd = [NATIVE_XRDCP, "--tpc", mode, "-f", s, d]
    try:
        p = subprocess.run(cmd, env=_xrd_env(sub), capture_output=True,
                           timeout=timeout, text=True)
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "timeout"


def raw_send_steps(steps, port, read_timeout=3.0):
    """Drive a single TCP connection through a SCRIPT of byte-chunks with optional
    pauses, then optionally abrupt-RST or half-close — for connection-state attacks
    (reset mid-request/body, slow/partial sends, abandon-after-auth).  steps is a
    list of (bytes, pause_seconds).  If reset=True is passed as the last element's
    flag the socket is hard-RST (SO_LINGER 0) instead of a graceful close.  Returns
    the bytes received (may be partial/empty)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(read_timeout)
    reset = False
    try:
        s.connect((HOST, port))
        reset = _send_steps(s, steps)
        try:
            return _read_socket(s)
        except (OSError, socket.timeout):
            return b""
    except (OSError, socket.timeout):
        return b""
    finally:
        _close_step_socket(s, reset)


def _send_steps(sock, steps):
    reset = False
    for item in steps:
        chunk, pause = item[0], item[1]
        reset = reset or _step_requests_reset(item)
        _send_chunk(sock, chunk)
        _pause(pause)
    return reset


def _step_requests_reset(item):
    return len(item) > 2 and bool(item[2])


def _send_chunk(sock, chunk):
    if chunk:
        sock.sendall(chunk if isinstance(chunk, bytes) else chunk.encode())


def _pause(seconds):
    if seconds:
        time.sleep(seconds)


def _close_step_socket(sock, reset):
    try:
        if reset:
            import struct as _st
            linger = _st.pack("ii", 1, 0)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, linger)
        sock.close()
    except OSError:
        pass


def xrd_fs_token(args, token_str, timeout=15):
    """Run native xrdfs against the stream server with an ARBITRARY bearer token
    string (for malformed/forged/expired-token attacks).  Returns (rc, out, err)."""
    cmd = [NATIVE_XRDFS, f"root://{HOST}:{_stream_port}"] + list(args)
    env = dict(os.environ)
    env["BEARER_TOKEN"] = token_str
    env.pop("X509_USER_PROXY", None)
    try:
        p = subprocess.run(cmd, env=env, capture_output=True,
                           timeout=timeout, text=True)
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "timeout"


def _forged_tokens(key):
    """A spread of structurally-invalid / forged bearer tokens that MUST all be
    rejected: each is a (label, token_string) pair.  Built once per battery."""
    now = int(time.time())
    good = mint(key, "alice")
    # alg=none with an empty signature (classic JWT downgrade).
    none_hdr = _b64u(json.dumps({"alg": "none", "typ": "JWT", "kid": KID},
                                separators=(",", ":")).encode())
    none_pay = _b64u(json.dumps({"iss": ISSUER, "sub": "alice", "aud": AUDIENCE,
                                 "exp": now + 3600, "iat": now, "nbf": now,
                                 "scope": WRITE_SCOPE},
                                separators=(",", ":")).encode())
    # A token signed by a DIFFERENT EC key (valid structure, wrong issuer key).
    other_key = ec.generate_private_key(ec.SECP256R1())
    return [
        ("expired",        mint(key, "alice", exp=now - 120, iat=now - 240)),
        ("not-yet-valid",  mint(key, "alice", nbf=now + 99999)),
        ("wrong-issuer",   mint(key, "alice", iss="https://evil.example/")),
        ("wrong-audience", mint(key, "alice", aud="https://wrong.aud/")),
        ("tampered-sig",   good[:-3] + ("AAA" if good[-3:] != "AAA" else "BBB")),
        ("alg-none",       f"{none_hdr}.{none_pay}."),
        ("foreign-key",    mint(other_key, "alice")),
        ("garbage",        "not.a.jwt"),
        ("empty",          ""),
    ]

from split_continuation import load_numbered as _load_numbered_continuations


_load_numbered_continuations(
    globals(), __file__, "e2e_redteam_part", 2, 77
)
