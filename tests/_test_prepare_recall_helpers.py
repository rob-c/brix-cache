"""Shared raw-wire + provisioning helpers for the W6 (phase-107 C2) prepare
suite — tests/test_prepare_recall.py (the kXR_stage arm through
brix_vfs_recall) and tests/test_vfs_evict.py (the kXR_evict arm through
brix_vfs_evict + the FRM-1 ownership negatives).

Raw-wire framing follows tests/test_frm_queue.py; provisioning follows
tests/test_frm_scratch.py (cmdscripts.frm_stagecmd).  One home so the two
modules never re-copy the login/prepare/QPrep framing (check_duplication).
"""

import os
import pathlib
import socket
import struct
import types

import pytest

from cmdscripts import frm_stagecmd
from settings import NGINX_BIN, HOST
from server_registry import NginxInstanceSpec
from server_launcher import RegistryCommandFailure

# --- wire constants (XProtocol.hh) ---
kXR_login    = 3007
kXR_query    = 3001
kXR_prepare  = 3021
kXR_QPrep    = 2
kXR_ok       = 0
kXR_error    = 4003

kXR_cancel   = 0x01     # ClientPrepareRequest.options
kXR_noerrs   = 0x04
kXR_stage    = 0x08
kXR_evict    = 0x0001   # ClientPrepareRequest.optionX

kXR_NotAuthorized = 3010
kXR_Unsupported   = 3013
kXR_fsReadOnly    = 3025

TAPE_BYTES = b"W6-TAPE-CONTENT-" + b"t" * 200 + b"\n"


def _recv_exact(sock, n):
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError(f"closed after {len(buf)}/{n}")
        buf.extend(chunk)
    return bytes(buf)


def _read_response(sock):
    sid, status, dlen = struct.unpack("!2sHI", _recv_exact(sock, 8))
    return status, (_recv_exact(sock, dlen) if dlen else b"")


def _session(port):
    """Handshake + anonymous kXR_login.  Each call is a NEW login session, so
    each carries a DISTINCT brix_prepare_owner_key (anon-session:<sessid>) —
    exactly what the FRM-1 ownership negatives need."""
    sock = socket.create_connection((HOST, port), timeout=10)
    sock.settimeout(10)
    sock.sendall(struct.pack("!IIIII", 0, 0, 0, 4, 2012))      # handshake
    status, _ = _read_response(sock)
    assert status == kXR_ok
    sock.sendall(struct.pack("!2sHI8sBBBBI",
                             b"\x00\x01", kXR_login,
                             os.getpid() & 0xFFFFFFFF,
                             b"pytest\x00\x00", 0, 0, 5, 0, 0))
    status, _ = _read_response(sock)
    assert status == kXR_ok
    return sock


def _prepare(sock, paths, options, optionx=0, streamid=b"\x00\x03"):
    """ClientPrepareRequest: 2s H(reqid) B(options) B(prty) H(port) H(optionX)
    10s(reserved) I(dlen)."""
    payload = "".join(p + "\n" for p in paths).encode()
    req = struct.pack("!2sHBBHH10sI", streamid, kXR_prepare,
                      options, 0, 0, optionx, b"\x00" * 10, len(payload))
    sock.sendall(req + payload)
    return _read_response(sock)


def _query(sock, infotype, payload, streamid=b"\x00\x04"):
    req = struct.pack("!2sHHH4s8sI", streamid, kXR_query, infotype, 0,
                      b"\x00" * 4, b"\x00" * 8, len(payload))
    sock.sendall(req + payload)
    return _read_response(sock)


def _qprep_status(sock, reqid, path):
    """Return the single status letter QPrep reports for `path`."""
    payload = (reqid + "\n" + path + "\n").encode()
    status, body = _query(sock, kXR_QPrep, payload)
    assert status == kXR_ok, f"QPrep status {status}"
    return chr(body[0]) if body else "?"


def _err_of(body):
    """kXR_error body = int32 errcode + NUL-terminated message."""
    code = struct.unpack("!i", body[:4])[0]
    return code, body[4:].rstrip(b"\x00").decode(errors="replace")


def _audit_verbs(audit_path, verb=None):
    out = []
    with open(audit_path) as fh:
        for line in fh:
            parts = line.rstrip("\n").split(" ", 2)
            if parts and parts[0] and (verb is None or parts[0] == verb):
                out.append(tuple(parts + [""] * (3 - len(parts))))
    return out


def _provision_mss(tmp_path, failkey):
    """Seed the tape/cache/control dirs + audit log; install the stage command.
    near.dat and cold.dat go on the MSS tape; the exec-adapter online buffer
    is <base>/.online/."""
    for d in ("cache", "base", "tape", "control"):
        (tmp_path / d).mkdir()
    audit = tmp_path / "audit.log"; audit.write_text("")
    tape = tmp_path / "tape"
    (tape / "near.dat").write_bytes(TAPE_BYTES)
    (tape / "cold.dat").write_bytes(TAPE_BYTES)
    cfg = {"tape": str(tape), "audit": str(audit)}
    if failkey is not None:
        (tape / failkey).write_bytes(TAPE_BYTES)   # nearline, but unrecallable
        cfg["failkey"] = failkey
    return frm_stagecmd.install(tmp_path, **cfg)


def _start_frm(lifecycle, tmp_path, *, name, allow_write="on", failkey=None):
    """One self-contained frm://exec + registry instance
    (tests/configs/nginx_lc_prepare_recall.conf)."""
    if not os.path.exists(NGINX_BIN):
        pytest.skip(f"nginx binary not found at {NGINX_BIN}")

    stagecmd = _provision_mss(tmp_path, failkey)
    base = tmp_path / "base"
    cache = tmp_path / "cache"
    control = tmp_path / "control"
    audit = tmp_path / "audit.log"

    try:
        endpoint = lifecycle.start(NginxInstanceSpec(
            name=name,
            template="nginx_lc_prepare_recall.conf",
            protocol="root",
            readiness="tcp",
            template_values={
                "STORAGE_BACKEND": f"frm://exec{base}",
                "CACHE_DIR": str(cache),
                "QUEUE_PATH": str(tmp_path / "frm.queue"),
                "CONTROL_DIR": str(control),
                "ALLOW_WRITE": allow_write,
            },
            env={"BRIX_FRM_STAGECMD": stagecmd},
            reason="W6 prepare stage/evict"))
    except RegistryCommandFailure:
        pytest.skip("nginx build lacks the frm://+registry directive surface")
    return types.SimpleNamespace(port=endpoint.port, prefix=endpoint.prefix,
                                 audit=str(audit), base=str(base),
                                 online=str(base / ".online"))
