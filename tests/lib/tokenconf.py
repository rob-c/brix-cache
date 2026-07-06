"""WLCG token conformance shared wire-test helpers.

WHAT: Module-level helpers for minting hostile tokens and probing the three
      protocol paths (root://, WebDAV, S3) against the managed test fleet.
      Used by every conformance family test module (Tasks 12–16).
WHY:  Centralises raw-socket framing (root://), HTTP Bearer probing (WebDAV/S3),
      manifest loading, and per-case verdict assertion so family test modules
      stay thin and protocol-agnostic.
HOW:  Raw root:// framing is lifted verbatim from tests/test_token_auth.py so
      this library has no test-module dependency.  HTTP paths use requests with
      verify=False (test PKI uses a self-signed CA).
"""

import json
import os
import socket
import struct
from urllib.parse import quote

import requests
import urllib3

import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from settings import (
    DATA_ROOT,
    NGINX_TOKEN_PORT,
    NGINX_TOKEN_STRICT_PORT,
    NGINX_WEBDAV_PORT,
    NGINX_WEBDAV_TOKEN_PORT,
    NGINX_S3_PORT,
    NGINX_S3_TOKEN_PORT,
    SERVER_HOST,
    TOKENS_DIR,
)

# Suppress TLS warnings from the self-signed test PKI.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Protocols the conformance suite covers.
PROTOCOLS = ["root", "webdav", "s3"]

# Data files the "accept" conformance cases stat/GET. A fleet restart
# (start-all) regenerates the export root and would otherwise wipe these, so
# every wire probe re-provisions them idempotently — the suite is robust to a
# fleet restart mid-run. Kept tiny; created only if missing.
_CONFORMANCE_FILES = {
    "test.txt": b"hello from nginx-xrootd\n",
    "atlas/ok.txt": b"atlasfile\n",
    "cms/ok.txt": b"cmsfile\n",
    "database/ok.txt": b"dbfile\n",
}


def ensure_conformance_data():
    """Create the fixture files the accept-cases depend on, if absent."""
    for rel, body in _CONFORMANCE_FILES.items():
        path = os.path.join(DATA_ROOT, rel)
        if os.path.exists(path):
            continue
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as fh:
            fh.write(body)

# ---------------------------------------------------------------------------
# XRootD wire constants
# ---------------------------------------------------------------------------

kXR_auth     = 3000
kXR_login    = 3007
kXR_protocol = 3006
kXR_stat     = 3017

kXR_ok       = 0
kXR_oksofar  = 4000
kXR_error    = 4003
kXR_authmore = 4002


# ---------------------------------------------------------------------------
# Raw XRootD protocol helpers (self-contained — no test-module import)
#
# Lifted verbatim from tests/test_token_auth.py so family modules can import
# from this library without creating a circular test-module dependency.
# ---------------------------------------------------------------------------

def _recv_exact(sock, nbytes):
    """Read exactly nbytes from sock, raising ConnectionError on short read."""
    data = bytearray()
    while len(data) < nbytes:
        chunk = sock.recv(nbytes - len(data))
        if not chunk:
            raise ConnectionError(
                f"socket closed with {nbytes - len(data)} bytes remaining")
        data.extend(chunk)
    return bytes(data)


def _read_response(sock):
    """Read one XRootD response: 8-byte header + body."""
    header = _recv_exact(sock, 8)
    _streamid, status, dlen = struct.unpack("!2sHI", header)
    body = _recv_exact(sock, dlen) if dlen else b""
    return status, body


def _raw_handshake(host, port):
    """Open a raw TCP socket and complete the 20-byte XRootD handshake.

    Returns the connected socket on success; raises ConnectionError on failure.
    """
    sock = socket.create_connection((host, port), timeout=5)
    sock.settimeout(5)
    sock.sendall(struct.pack("!IIIII", 0, 0, 0, 4, 2012))
    status, body = _read_response(sock)
    if status != kXR_ok:
        sock.close()
        raise ConnectionError(f"handshake failed: status={status}")
    if len(body) != 8:
        sock.close()
        raise ConnectionError(f"unexpected handshake body length: {len(body)}")
    return sock


def _send_protocol(sock, streamid=b"\x00\x01"):
    """Send kXR_protocol with kXR_secreqs flag; return (status, body)."""
    req = struct.pack(
        "!2sH I BB 10s I",
        streamid,
        kXR_protocol,
        39,            # clientpv = 0x27 = protocol version 39
        0x01,          # flags: kXR_secreqs
        0x03,          # expect: kXR_ExpLogin
        b"\x00" * 10,  # reserved
        0,             # dlen
    )
    sock.sendall(req)
    return _read_response(sock)


def _send_login(sock, streamid=b"\x00\x02"):
    """Send kXR_login; return (status, body) where body carries auth params."""
    username = b"pytest\x00\x00"
    req = struct.pack(
        "!2sH I 8s B B B B I",
        streamid,
        kXR_login,
        os.getpid() & 0xFFFFFFFF,
        username,
        0,    # ability2
        0,    # ability
        5,    # capver
        0,    # reserved
        0,    # dlen
    )
    sock.sendall(req)
    return _read_response(sock)


def _send_auth_ztn(sock, token, streamid=b"\x00\x03"):
    """Send kXR_auth with credential type 'ztn' and JWT payload.

    Returns (status, body): kXR_ok on accept, kXR_error on reject.
    """
    token_bytes = token.encode("ascii") if isinstance(token, str) else token
    cred_payload = b"ztn\x00" + token_bytes
    credtype  = b"ztn\x00"
    reserved  = b"\x00" * 12
    req  = struct.pack("!2sH", streamid, kXR_auth)
    req += reserved
    req += credtype
    req += struct.pack("!I", len(cred_payload))
    req += cred_payload
    sock.sendall(req)
    return _read_response(sock)


def _send_stat(sock, path, streamid=b"\x00\x04"):
    """Send kXR_stat for path; return (status, body)."""
    path_bytes = path.encode() + b"\x00"
    req  = struct.pack("!2sH", streamid, kXR_stat)
    req += b"\x00" * 16   # reserved body bytes
    req += struct.pack("!I", len(path_bytes))
    req += path_bytes
    sock.sendall(req)
    return _read_response(sock)


# ---------------------------------------------------------------------------
# Manifest helpers
# ---------------------------------------------------------------------------

def load_manifest(family=None):
    """Load token_manifest.json from TOKENS_DIR, building it if absent.

    WHAT: Reads the conformance case manifest, optionally filtering to one
          family.
    WHY:  Provides a single manifest source shared by C and pytest layers.
    HOW:  If the manifest file is missing, calls tokenforge.build_manifest() to
          create a minimal seed so the helper is self-sufficient for smoke runs.
          Family tasks append their rows via their own build_manifest() calls.

    Args:
        family: Optional case-ID prefix (e.g. "SIG").  When given, returns only
                rows whose case_id starts with that prefix.

    Returns:
        list of case dicts with keys: case_id, mint_recipe, protocol, expected,
        expected_reason, spec_ref.
    """
    manifest_path = os.path.join(TOKENS_DIR, "token_manifest.json")
    if not os.path.exists(manifest_path):
        from tokenforge import build_manifest
        build_manifest(TOKENS_DIR)
    with open(manifest_path) as fh:
        data = json.load(fh)
    rows = data.get("cases", [])
    if family is not None:
        rows = [r for r in rows if r["case_id"].startswith(family)]
    return rows


def mint(case_row):
    """Mint the token described by case_row["mint_recipe"].

    WHAT: Instantiates a TokenForge and dispatches to the method named by
          recipe["m"], forwarding recipe["args"] and recipe["kwargs"].
    WHY:  Decouples family tests from token construction — each manifest row
          carries its own recipe so assert_verdict() covers all cases uniformly.
    HOW:  Uses getattr to resolve the method name; recipe format:
            {"m": "alg_none"}
            {"m": "temporal", "args": [-20]}
            {"m": "aud_value", "args": [["a", "b"]]}
            {"m": "generate"}   — plain valid token

    Args:
        case_row: manifest case dict with a "mint_recipe" key.

    Returns:
        JWT token string.
    """
    from tokenforge import TokenForge
    forge = TokenForge(TOKENS_DIR)
    recipe = case_row["mint_recipe"]
    method = getattr(forge, recipe["m"])
    return method(*recipe.get("args", []), **recipe.get("kwargs", {}))


# ---------------------------------------------------------------------------
# Protocol clients
# ---------------------------------------------------------------------------

def root_ztn(token, path="/test.txt", write=False, port=None):
    """Probe NGINX_TOKEN_PORT (11097) via a raw root:// ztn auth sequence.

    WHAT: Runs handshake→protocol→login→auth-ztn→stat and maps the outcome to
          a clean verdict string.
    WHY:  Returns "accept"/"reject" rather than raising so family tests compare
          verdicts without try/except boilerplate.
    HOW:  Any non-kXR_ok status from auth_ztn or the subsequent stat is "reject".
          write=True is accepted for API symmetry but currently maps to a stat
          probe (open-for-write framing is out of scope for this helper; a later
          task will replace the stat with an kXR_open write-mode request).
          Socket/OS errors that indicate a clean auth-rejection (e.g. server
          closes the connection after reject) are caught and returned as "reject".

    Args:
        token: JWT string.
        path:  XRootD path to probe via kXR_stat.
        write: API stub — maps to read-stat for now; write verdict via kXR_open
               will be added in a later task.
        port:  Override the target port (default: NGINX_TOKEN_PORT).

    Returns:
        "accept" or "reject".
    """
    ensure_conformance_data()
    target_port = port if port is not None else NGINX_TOKEN_PORT
    try:
        sock = _raw_handshake(SERVER_HOST, target_port)
        try:
            _send_protocol(sock)
            status, _ = _send_login(sock)
            if status != kXR_ok:
                return "reject"
            status, _ = _send_auth_ztn(sock, token)
            if status != kXR_ok:
                return "reject"
            status, _ = _send_stat(sock, path)
            return "accept" if status == kXR_ok else "reject"
        finally:
            sock.close()
    except (OSError, ConnectionError):
        return "reject"


def webdav_bearer(token, path="/test.txt", write=False, port=None):
    """Probe a WebDAV HTTPS port via Authorization: Bearer.

    WHAT: Issues GET (or PUT for write=True) and maps the HTTP status to a
          verdict string.
    WHY:  HTTP status provides a clean accept/reject/notfound signal.  "notfound"
          is distinct from "reject" so callers can differentiate optional-mode
          fall-through (authenticated but file absent) from auth rejection.
    HOW:  verify=False because the test PKI uses a self-signed CA.  The default
          port is NGINX_WEBDAV_PORT (8443, optional-auth); pass
          NGINX_WEBDAV_TOKEN_PORT (8446) to target the enforcing port.

    Args:
        token: JWT string.
        path:  URL path component (must start with /).
        write: If True, issue PUT instead of GET.
        port:  Target port (default: NGINX_WEBDAV_PORT).

    Returns:
        "accept", "reject", or "notfound".
    """
    ensure_conformance_data()
    target = port if port is not None else NGINX_WEBDAV_PORT
    url = f"https://{SERVER_HOST}:{target}{path}"
    headers = {"Authorization": f"Bearer {token}"}
    try:
        if write:
            resp = requests.put(url, headers=headers, data=b"",
                                verify=False, timeout=5)
        else:
            resp = requests.get(url, headers=headers,
                                verify=False, timeout=5)
        code = resp.status_code
        if code in (200, 206):
            return "accept"
        if code in (401, 403):
            return "reject"
        if code == 404:
            return "notfound"
        # Treat any other 2xx as accept, any other 4xx/5xx as reject.
        return "accept" if 200 <= code < 300 else "reject"
    except requests.RequestException:
        return "reject"


def webdav_query_token(token, path="/test.txt", param="authz",
                       port=NGINX_WEBDAV_TOKEN_PORT, prefix="Bearer "):
    """Probe a WebDAV HTTPS port via query-parameter token transport.

    WHAT: Issues GET with the token embedded in the URL query string rather
          than in the Authorization header.  The server's brix_http_query_token
          directive (default ON) extracts the token from ?authz= or
          ?access_token= and validates it identically to the header path.
    WHY:  WLCG token profile allows both transport modes; this helper lets
          conformance tests verify that query-param delivery is accepted (or
          rejected) as expected without writing bespoke URL construction in
          every test body.
    HOW:  quote(prefix+token) URL-encodes the value so the space in "Bearer "
          becomes %20 and any special characters in the token are safe.
          Verdict mapping mirrors webdav_bearer: 200/206→accept, 401/403→reject,
          404→notfound, other 2xx→accept, other 4xx/5xx→reject.

    Args:
        token:  JWT string.
        path:   URL path component (must start with /).
        param:  Query parameter name ("authz" or "access_token").
        port:   Target port (default: NGINX_WEBDAV_TOKEN_PORT = 8446).
        prefix: String prepended to the token in the query value; use
                "Bearer " for header-like encoding, "" for a raw JWT.

    Returns:
        "accept", "reject", or "notfound".
    """
    ensure_conformance_data()
    url = (
        f"https://{SERVER_HOST}:{port}{path}"
        f"?{param}={quote(prefix + token)}"
    )
    try:
        resp = requests.get(url, verify=False, timeout=5)
        code = resp.status_code
        if code in (200, 206):
            return "accept"
        if code in (401, 403):
            return "reject"
        if code == 404:
            return "notfound"
        return "accept" if 200 <= code < 300 else "reject"
    except requests.RequestException:
        return "reject"


def s3_bearer(token, key="test.txt", write=False, port=None):
    """Probe an S3 port via HTTP with Authorization: Bearer.

    WHAT: Issues GET (or PUT for write=True) and maps the HTTP status to a
          verdict string.
    WHY:  When port is not specified, targets NGINX_S3_PORT (9001, anon/SigV4
          mode — non-enforcing).  To target the enforcing bearer-token port,
          pass NGINX_S3_TOKEN_PORT (9002) as port.  This matches the WebDAV
          helper's port-override API so conformance test bodies are uniform
          across all three protocols.
    HOW:  Plain HTTP (no TLS) because the test S3 endpoint does not use TLS.

    Args:
        token: JWT string.
        key:   S3 object key (no leading slash).
        write: If True, issue PUT instead of GET.
        port:  Target port (default: NGINX_S3_PORT=9001; use
               NGINX_S3_TOKEN_PORT=9002 for the enforcing port).

    Returns:
        "accept", "reject", or "notfound".
    """
    ensure_conformance_data()
    target = port if port is not None else NGINX_S3_PORT
    url = f"http://{SERVER_HOST}:{target}/{key}"
    headers = {"Authorization": f"Bearer {token}"}
    try:
        if write:
            resp = requests.put(url, headers=headers, data=b"",
                                verify=False, timeout=5)
        else:
            resp = requests.get(url, headers=headers,
                                verify=False, timeout=5)
        code = resp.status_code
        if code in (200, 206):
            return "accept"
        if code in (401, 403):
            return "reject"
        if code == 404:
            return "notfound"
        return "accept" if 200 <= code < 300 else "reject"
    except requests.RequestException:
        return "reject"


# ---------------------------------------------------------------------------
# Assertion helper
# ---------------------------------------------------------------------------

def assert_verdict(case_row, protocol):
    """Mint the case token, probe the protocol, and assert the verdict.

    WHAT: Dispatches to the correct protocol client and raises AssertionError
          with a full diagnostic on mismatch.
    WHY:  Centralises verdict checking so family test bodies are one-liners
          (pytest.mark.parametrize + assert_verdict).
    HOW:  Mints via mint(case_row), calls the appropriate client with default
          path/key, and compares observed to case_row["expected"].

    Args:
        case_row: manifest case dict (case_id, mint_recipe, expected,
                  expected_reason, spec_ref).
        protocol: one of "root", "webdav", "s3".

    Raises:
        AssertionError: on verdict mismatch, including case_id, protocol,
                        expected, observed, and expected_reason.
        ValueError:     for an unrecognised protocol name.
    """
    token = mint(case_row)
    path = case_row.get("path", "/test.txt")
    write = case_row.get("write", False)
    if protocol == "root":
        observed = root_ztn(token, path, write)
    elif protocol == "webdav":
        observed = webdav_bearer(token, path, write)
    elif protocol == "s3":
        observed = s3_bearer(token, path.lstrip("/"), write)
    else:
        raise ValueError(f"unknown protocol: {protocol!r}")

    expected = case_row["expected"]
    if observed != expected:
        raise AssertionError(
            f"[{case_row['case_id']}] protocol={protocol} "
            f"expected={expected!r} observed={observed!r} "
            f"reason: {case_row['expected_reason']}"
        )
