"""brix_oss_quota_enforce — §3.3: the advertised quota becomes REAL (parity
audit §3 row 3 slice 1; completes wave-29's advertisement-only brix_oss_quota).

With `brix_oss_quota_enforce on`, a kXR_write/writev/pgwrite whose length would
push the export's usage past `brix_oss_quota` is refused `kXR_overQuota` at the
shared write-admission chokepoint. Usage comes from the SAME probe the Qspace
report advertises: a pblock backend answers from its catalog (exact); plain
POSIX falls back to statvfs of the export's filesystem (conservative on a
shared mount — documented). The probe is TTL-cached 5 s per worker, so
enforcement lags a fresh write by at most that much (stock XrdOssSpace lags
comparably). Default off = advertisement-only, byte-identical.

Coverage:
  * success/exact — pblock export, quota 64 KiB: a 48 KiB write lands; after the
    TTL expires, a second 48 KiB write is refused over-quota; rm + TTL → admits
    again (usage really drives the verdict).
  * conservative — posix export, quota 1 byte: any write refused (statvfs used
    of the export's filesystem exceeds 1 — proves the fallback path gates).
  * off        — same posix config WITHOUT enforce: the write lands (default
    stays advertisement-only).
Self-contained (no shared fleet).
"""

import os
import socket
import struct
import subprocess
import time

import pytest

from settings import BIND_HOST, NGINX_BIN

import _test_session_bind_helpers as H
from ephemeral_port import free_port

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_XRDCP = os.path.join(_REPO, "client", "bin", "xrdcp")
kXR_rm = 3016


def _free_port():
    s = socket.socket()
    s.bind((BIND_HOST, free_port()))  # leased mock-range port (never kernel-assigned)
    port = s.getsockname()[1]
    s.close()
    return port


def _launch(tmp_path, backend_line, quota_lines):
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx not executable: {NGINX_BIN}")
    ns = tmp_path / "ns"
    ns.mkdir(exist_ok=True)
    logs = tmp_path / "logs"
    logs.mkdir(exist_ok=True)
    port = _free_port()
    conf = tmp_path / "nginx.conf"
    conf.write_text(
        "daemon on;\nworker_processes 1;\n"
        f"pid {logs}/nginx.pid;\nerror_log {logs}/error.log info;\n"
        "events { worker_connections 64; }\n"
        "stream {\n  server {\n"
        f"    listen {BIND_HOST}:{port};\n"
        "    brix_root on;\n"
        f"    brix_export {ns};\n"
        "    brix_auth none;\n"
        "    brix_allow_write on;\n"
        f"    {backend_line}\n"
        f"    {quota_lines}\n"
        "  }\n}\n")
    t = subprocess.run([NGINX_BIN, "-p", str(tmp_path), "-c", str(conf), "-t"],
                       capture_output=True, text=True, timeout=30)
    assert t.returncode == 0, f"config rejected: {t.stderr}"
    r = subprocess.run([NGINX_BIN, "-p", str(tmp_path), "-c", str(conf)],
                       capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, f"nginx failed to start: {r.stderr}"
    for _ in range(50):
        try:
            socket.create_connection((BIND_HOST, port), timeout=0.5).close()
            break
        except OSError:
            time.sleep(0.1)
    return port, conf


def _stop(tmp_path, conf):
    subprocess.run([NGINX_BIN, "-p", str(tmp_path), "-c", str(conf),
                    "-s", "quit"], capture_output=True, timeout=30)
    time.sleep(0.2)


def _xrdcp(tmp_path, port, name, nbytes):
    """Upload nbytes to /<name> with the native client; returns the process.
    (Raw kXR_write is unusable here: every create-open routes into the
    in-flight resume-temp machinery which EINVALs raw wire writes — xrdcp
    negotiates it correctly, and the quota gate under test sits upstream of
    the pwrite either way.)"""
    if not os.access(_XRDCP, os.X_OK):
        pytest.skip("native xrdcp not built")
    src = tmp_path / f"src-{name}"
    src.write_bytes(b"Q" * nbytes)
    return subprocess.run(
        ["env", "-u", "LD_LIBRARY_PATH", _XRDCP, "-f", str(src),
         f"root://{BIND_HOST}:{port}//{name}"],
        capture_output=True, text=True, timeout=60)


def _rm(sock, stream, path):
    return H._send_req(sock, stream, kXR_rm, body=b"\x00" * 16,
                       payload=path.encode() + b"\x00")


def test_enforce_on_admits_under_quota(tmp_path):
    """(success) enforce ON with a quota the usage cannot exceed (the export
    filesystem's total size): the gate is ACTIVE but correctly admits — proving
    enforcement doesn't blanket-refuse. (An exact-usage leg on a pblock catalog
    is the documented follow-up: the pblock space slot's arming interacts with
    lazy instance build and needs its own harness.)"""
    fs = os.statvfs(str(tmp_path))
    total = fs.f_frsize * fs.f_blocks
    port, conf = _launch(
        tmp_path, "",
        f"brix_oss_quota {total};\n    brix_oss_quota_enforce on;")
    try:
        r = _xrdcp(tmp_path, port, "ok.bin", 49152)
        assert r.returncode == 0, \
            f"enforce-on refused an under-quota upload: {r.stderr}"
    finally:
        _stop(tmp_path, conf)


def test_pblock_exact_catalog_quota(tmp_path):
    """(exact) the deferred wave-41 leg, unblocked: the correct grammar is
    `pblock://<dir>?tail` (the single-colon `pblock:<dir>` form matches NO parse
    branch and silently runs default posix — that was the wave-41 mystery).
    pblock's own ?quota=1g arms its space slot (catalog usage, exact, huge and
    non-binding); brix_oss_quota 64K + enforce then refuses the second 48K
    upload. DISCRIMINATOR that this is catalog usage, not statvfs: after rm the
    same upload is admitted again — statvfs-used of the big host FS would still
    exceed 64K, only the catalog dropped to ~0."""
    ns = tmp_path / "ns"          # export root == pblock root (the test-config pattern)
    ns.mkdir(exist_ok=True)
    port, conf = _launch(
        tmp_path,
        f"brix_storage_backend pblock://{ns}?quota=1g;",
        "brix_oss_quota 65536;\n    brix_oss_quota_enforce on;")
    primary = None
    try:
        r = _xrdcp(tmp_path, port, "a.bin", 49152)
        assert r.returncode == 0, f"first 48K upload refused: {r.stderr}"

        time.sleep(5.2)   # cross the 5s usage-probe TTL

        r = _xrdcp(tmp_path, port, "b.bin", 49152)
        assert r.returncode != 0, "48K catalog + 48K > 64K quota not refused"
        assert "quota" in (r.stderr + r.stdout).lower(), r.stderr

        xrdfs = os.path.join(_REPO, "client", "bin", "xrdfs")
        rmproc = subprocess.run(
            ["env", "-u", "LD_LIBRARY_PATH", xrdfs,
             f"root://{BIND_HOST}:{port}", "rm", "/a.bin"],
            capture_output=True, text=True, timeout=30)
        assert rmproc.returncode == 0, f"rm failed: {rmproc.stderr}"
        time.sleep(5.2)
        r = _xrdcp(tmp_path, port, "c.bin", 49152)
        assert r.returncode == 0, \
            f"post-rm upload refused (usage is NOT the exact catalog): {r.stderr}"
    finally:
        if primary is not None:
            primary.close()
        _stop(tmp_path, conf)


def test_posix_conservative_quota_gates(tmp_path):
    """(conservative) posix statvfs fallback: quota 1 byte refuses any write."""
    port, conf = _launch(tmp_path, "",
                         "brix_oss_quota 1;\n    brix_oss_quota_enforce on;")
    try:
        r = _xrdcp(tmp_path, port, "x.bin", 4096)
        assert r.returncode != 0, "1-byte enforced quota did not gate"
        assert "quota" in (r.stderr + r.stdout).lower(), r.stderr
    finally:
        _stop(tmp_path, conf)


def test_default_stays_advertisement_only(tmp_path):
    """(off) the same impossible quota WITHOUT enforce: the upload lands."""
    port, conf = _launch(tmp_path, "", "brix_oss_quota 1;")
    try:
        r = _xrdcp(tmp_path, port, "y.bin", 4096)
        assert r.returncode == 0, \
            f"advertisement-only quota gated an upload: {r.stderr}"
    finally:
        _stop(tmp_path, conf)


def test_unknown_backend_scheme_refused(tmp_path):
    """(misconfig guard) an unrecognized brix_storage_backend scheme fails
    nginx -t instead of silently running default posix; the legacy single-colon
    posix:<dir> spelling stays accepted (warned)."""
    ns = tmp_path / "ns"
    ns.mkdir(exist_ok=True)
    logs = tmp_path / "logs"
    logs.mkdir(exist_ok=True)
    conf = tmp_path / "bad.conf"

    def render(backend):
        conf.write_text(
            "daemon on;\nworker_processes 1;\n"
            f"pid {logs}/nginx.pid;\nerror_log {logs}/error.log info;\n"
            "events { worker_connections 16; }\n"
            "stream { server {\n"
            f"  listen {BIND_HOST}:{_free_port()};\n  brix_root on;\n"
            f"  brix_export {ns};\n  brix_auth none;\n"
            f"  brix_storage_backend {backend};\n"
            "} }\n")
        return subprocess.run([NGINX_BIN, "-p", str(tmp_path), "-c", str(conf),
                               "-t"], capture_output=True, text=True, timeout=30)

    r = render("blok:/dev/sda")            # typo'd scheme
    assert r.returncode != 0, "typo'd backend scheme accepted silently"
    assert "unrecognized backend scheme" in r.stderr, r.stderr

    r = render(f"posix:{ns}")              # legacy single-colon: still accepted
    assert r.returncode == 0, f"legacy posix:<dir> now refused: {r.stderr}"
