"""test_acc.py — XrdAcc-compatible authorization engine (brix_authdb_format xrdacc).

Stands up a self-contained dedicated nginx running the `xrdacc` engine over an
anonymous root:// stream tier and drives real `xrdfs`/`xrdcp` requests to verify
the faithful XrdAcc semantics end to end: additive privilege accumulation, the
`r`/`l`/`w` letters (note `r` does NOT imply `l`), default `u *` rules, and
fail-closed denial for unmatched paths and missing privileges.

Self-provisioning (own nginx instance + authdb + data) so it needs no shared
harness tier; skips cleanly when the nginx binary is absent or was built without
the module.  The pure engine algebra is covered separately by the C self-tests;
this is the integration proof on the live wire.
"""

import os
import pathlib
import shutil
import subprocess

import pytest

from settings import BIND_HOST, HOST, NGINX_BIN, url_host
from server_registry import NginxInstanceSpec

pytestmark = [pytest.mark.uses_lifecycle_harness]

# authdb: anonymous (u *) gets read+lookup on /sub only; nothing elsewhere.
AUTHDB = "u * /sub rl\n"
CONTENT = b"hello xrdacc\n"

# Populated by the acc_server fixture so the audit test can find the live log
# directory (function-scoped registry prefix, no more module-level ROOT).
_acc_log_dir: dict[str, pathlib.Path] = {}


def _have_tools():
    return shutil.which("xrdfs") and shutil.which("xrdcp") and os.path.exists(NGINX_BIN)


@pytest.fixture()
def acc_server(lifecycle, tmp_path):
    if not _have_tools():
        pytest.skip("xrdfs/xrdcp or nginx binary unavailable")
    # The binary must be built with the module (acc engine linked).
    try:
        syms = subprocess.run(["nm", NGINX_BIN], capture_output=True, text=True)
        if "brix_acc_access" not in syms.stdout:
            pytest.skip("nginx binary not built with the xrdacc engine")
    except Exception:
        pass

    data = tmp_path / "data"
    (data / "sub").mkdir(parents=True)
    (data / "sub" / "test.txt").write_bytes(CONTENT)
    (data / "other.txt").write_bytes(b"secret\n")
    authdb = tmp_path / "authdb"
    authdb.write_text(AUTHDB)

    ep = lifecycle.start(NginxInstanceSpec(
        name="lc-acc-stream",
        template="nginx_lc_acc_stream.conf",
        protocol="root",
        template_values={"BIND_HOST": BIND_HOST, "DATA_DIR": str(data),
                         "AUTHDB_PATH": str(authdb)},
        reason="stream ACC authdb"))
    _acc_log_dir["path"] = pathlib.Path(ep.prefix) / "logs"
    return f"root://{url_host(HOST)}:{ep.port}"


def _stat(url, path):
    return subprocess.run(["xrdfs", url, "stat", path],
                          capture_output=True, timeout=20)


class TestXrdAccEngine:
    """End-to-end XrdAcc authorization over root:// (anonymous `u *` rules)."""

    def test_granted_stat(self, acc_server):
        """`u * /sub rl` -> anon may stat under /sub (lookup priv)."""
        assert _stat(acc_server, "/sub/test.txt").returncode == 0

    def test_granted_read_content(self, acc_server):
        """`r` privilege -> anon may read the exact bytes."""
        r = subprocess.run(["xrdcp", "-f", f"{acc_server}//sub/test.txt", "-"],
                           capture_output=True, timeout=20)
        assert r.returncode == 0, r.stderr.decode()
        assert r.stdout == CONTENT

    def test_no_rule_denied(self, acc_server):
        """A path with no matching rule is denied (fail-closed default)."""
        assert _stat(acc_server, "/other.txt").returncode != 0

    def test_write_denied_on_readonly(self, acc_server, tmp_path):
        """`rl` grants no write -> open-for-write under /sub is denied."""
        up = tmp_path / "up.txt"
        up.write_bytes(b"data\n")
        r = subprocess.run(["xrdcp", "-f", str(up), f"{acc_server}//sub/new.txt"],
                           capture_output=True, timeout=20)
        assert r.returncode != 0, "write must be denied with only rl privileges"

    def test_audit_log_records_grant_and_deny(self, acc_server):
        """`brix_authdb_audit all` emits structured grant + deny lines."""
        _stat(acc_server, "/sub/test.txt")   # grant
        _stat(acc_server, "/other.txt")      # deny
        with open(_acc_log_dir["path"] / "error.log") as f:
            log = f.read()
        assert "xrootd authz:" in log and "grant" in log and "deny" in log


# ---------------------------------------------------------------------------
# kXR_statx under xrdacc — the batched-stat predicate routes its authdb tier
# through brix_authz_check, so the engine's verdict applies per path exactly
# as it does to a single STAT (phase-18 closure: previously the predicate
# called the bare native check, so `brix_authdb_format xrdacc` never gated
# statx and a rule-less path leaked its metadata via the batch).
# ---------------------------------------------------------------------------

import socket   # noqa: E402
import struct   # noqa: E402


def _statx_raw(host, port, paths):
    """Anonymous login + one kXR_statx; returns (status, body_bytes)."""
    def recvall(sock, n):
        buf = b""
        while len(buf) < n:
            chunk = sock.recv(n - len(buf))
            assert chunk, "connection closed unexpectedly"
            buf += chunk
        return buf

    def recv_response(sock):
        hdr = recvall(sock, 8)
        status = struct.unpack(">H", hdr[2:4])[0]
        dlen = struct.unpack(">I", hdr[4:8])[0]
        return status, (recvall(sock, dlen) if dlen else b"")

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    sock.connect((host, port))
    try:
        sock.sendall(struct.pack(">IIIII", 0, 0, 0, 4, 2012))
        sock.sendall(struct.pack(">BB H I BB 10x I",
                                 0, 1, 3006, 0x00000520, 0, 3, 0))
        recvall(sock, 32)               # handshake + protocol responses
        sock.sendall(struct.pack(">BB H I 8s BB B B I",
                                 0, 1, 3007, 0, b"test\x00\x00\x00\x00",
                                 0, 0, 5, 0, 0))
        recv_response(sock)             # login response
        payload = b"\n".join(p.encode() for p in paths) + b"\n"
        sock.sendall(struct.pack(">BB H B 11x 4x I",
                                 0, 2, 3022, 0, len(payload)) + payload)
        return recv_response(sock)
    finally:
        sock.close()


class TestXrdAccStatx:
    """kXR_statx honours the xrdacc engine (brix_authz_check in the
    per-path predicate — success + error + security-negative)."""

    @staticmethod
    def _hostport(url):
        return HOST, int(url.rsplit(":", 1)[1])

    def test_statx_granted_under_rule(self, acc_server):
        """`u * /sub rl` -> statx of /sub/test.txt returns its flag byte."""
        host, port = self._hostport(acc_server)
        status, body = _statx_raw(host, port, ["/sub/test.txt"])
        assert status == 0, f"granted statx failed: status {status}"
        assert len(body) == 1

    def test_statx_no_rule_denied(self, acc_server):
        """Security-negative: /other.txt EXISTS but matches no rule — statx
        must error, not leak a flag byte (the pre-fix bypass returned one)."""
        host, port = self._hostport(acc_server)
        status, _ = _statx_raw(host, port, ["/other.txt"])
        assert status != 0, "statx leaked metadata for an unruled path"

    def test_statx_batch_aborts_on_denied_path(self, acc_server):
        """A denied path anywhere in the batch errors the whole response,
        matching single-STAT refusal semantics (W4 parity)."""
        host, port = self._hostport(acc_server)
        status, _ = _statx_raw(host, port,
                               ["/sub/test.txt", "/other.txt"])
        assert status != 0, "batch with a denied path must abort"


# ---------------------------------------------------------------------------
# Cross-protocol: the same engine over WebDAV (davs://) and S3
# ---------------------------------------------------------------------------

import urllib.request  # noqa: E402
import urllib.error    # noqa: E402


def _http_code(url, method="GET"):
    req = urllib.request.Request(url, method=method)
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code
    except Exception:
        return 0


def _start_http(lifecycle, tmp_path, make_location):
    """Provision + start an http nginx with the given location block; the data
    tree grants `u * /grant rl` and denies everything else."""
    data = tmp_path / "data"
    (data / "grant").mkdir(parents=True)
    (data / "grant" / "ok.txt").write_bytes(b"ok\n")
    (data / "deny.txt").write_bytes(b"no\n")
    authdb = tmp_path / "authdb"
    authdb.write_text("u * /grant rl\n")
    ep = lifecycle.start(NginxInstanceSpec(
        name="lc-acc-http",
        template="nginx_lc_acc_http_location.conf",
        protocol="http",
        template_values={"BIND_HOST": BIND_HOST, "DATA_DIR": str(data),
                         "AUTHDB_PATH": str(authdb),
                         "LOCATION_BLOCK": make_location(data)},
        reason="http ACC authz location"))
    return ep


@pytest.fixture()
def webdav_server(lifecycle, tmp_path):
    if not os.path.exists(NGINX_BIN):
        pytest.skip("nginx binary unavailable")
    ep = _start_http(lifecycle, tmp_path, lambda data: (
        f"            brix_webdav on;\n"
        f"            brix_storage_backend posix:{data};\n"
        f"            brix_webdav_auth none;\n"
        f"            brix_allow_write on;"))
    return f"http://{url_host(HOST)}:{ep.port}"


@pytest.fixture()
def s3_server(lifecycle, tmp_path):
    if not os.path.exists(NGINX_BIN):
        pytest.skip("nginx binary unavailable")
    ep = _start_http(lifecycle, tmp_path, lambda data: (
        f"            brix_s3 on;\n"
        f"            brix_storage_backend posix:{data};"))
    return f"http://{url_host(HOST)}:{ep.port}"


class TestXrdAccWebDAV:
    """The XrdAcc engine over WebDAV (HTTP method -> AOP)."""

    def test_get_granted(self, webdav_server):
        assert _http_code(f"{webdav_server}/grant/ok.txt") == 200

    def test_get_no_rule_denied(self, webdav_server):
        assert _http_code(f"{webdav_server}/deny.txt") == 403

    def test_put_denied_without_create_priv(self, webdav_server):
        # `rl` grants no create -> PUT (create) is denied.
        assert _http_code(f"{webdav_server}/grant/new.txt", method="PUT") == 403


class TestXrdAccS3:
    """The XrdAcc engine over S3 (S3 op -> AOP)."""

    def test_get_granted(self, s3_server):
        assert _http_code(f"{s3_server}/grant/ok.txt") == 200

    def test_get_no_rule_denied(self, s3_server):
        assert _http_code(f"{s3_server}/deny.txt") == 403
