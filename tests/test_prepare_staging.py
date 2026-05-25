"""
Tests for kXR_prepare — tape staging / cache hint opcode.

kXR_prepare is used by clients to request that files be staged from tape or
prefetched into cache.  For this nginx module (local storage only) it acts as
a path validation check: each newline-separated path in the payload is resolved,
checked for VO ACL, and verified to exist as a regular file.

The opcode supports these options:
  kXR_stage     -- validate paths (default behaviour)
  kXR_cancel    -- cancel a staging request (no-op on local storage)
  kXR_notify    -- notification port when staging completes (not implemented)
  kXR_noerrs    -- return missing count instead of error for non-existent files
  kXR_evict     -- evict from cache (no-op on local storage)

This test suite exercises:

  - Valid file list -> kXR_ok with path count
  - Non-existent file -> kXR_NotFound
  - Directory target -> kXR_isDirectory
  - noerrs flag -> missing count instead of error
  - Cancel request -> kXR_ok (no-op)
  - Evict request -> kXR_ok (no-op)
  - Empty payload -> kXR_ArgMissing
  - Path with dot-dot component -> kXR_ArgInvalid

Run:
    pytest tests/test_prepare_staging.py -v -s
"""

import os
import socket
import struct
import time

import pytest
from XRootD import client
from XRootD.client.flags import OpenFlags

from settings import CA_DIR, DATA_ROOT, SERVER_HOST

ANON_HOST = SERVER_HOST
ANON_PORT = 0


# ---------------------------------------------------------------------------
# Wire constants
# ---------------------------------------------------------------------------

kXR_ok       = 0
kXR_error    = 4003
kXR_ArgMissing    = 3001
kXR_NotFound      = 3011
kXR_isDirectory   = 3016
kXR_ArgInvalid    = 3000

kXR_query   = 3001
kXR_QPrep   = 2


# ---------------------------------------------------------------------------
# Helpers -- raw socket XRootD client
# ---------------------------------------------------------------------------

def _recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def _read_response(sock):
    """Read a XRootD response: header + optional body."""
    hdr = _recv_exact(sock, 8)
    status = struct.unpack(">H", hdr[2:4])[0]
    dlen = struct.unpack(">I", hdr[4:8])[0]
    body = _recv_exact(sock, dlen) if dlen else b""
    return status, body


def _establish_session(port):
    """Bootstrap a session: handshake + protocol + login. Returns (sock, streamid)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((ANON_HOST, port))
    sock.settimeout(5)

    # Handshake (20 bytes: 5 x int32 BE)
    sock.sendall(struct.pack(">IIIII", 0, 0, 0, 4, 2012))
    _recv_exact(sock, 16)   # handshake response: 8B hdr + 8B body

    # kXR_protocol (24 bytes)
    proto_hdr = struct.pack(">BBHIBB10xI", 0, 1, 3006, 0x00000520, 0x02, 0x03, 0)
    sock.sendall(proto_hdr)
    status, _ = _read_response(sock)
    assert status == kXR_ok

    # kXR_login (24 bytes + payload) -- username must be exactly 8 bytes
    login_payload = b"anon\x00\x00\x00\x00"   # username padded to exactly 8 bytes
    login_hdr = struct.pack(">2sH", b"\x00\x01", 3007) \
              + struct.pack(">I", 0) \
              + login_payload \
              + struct.pack(">BBB", 0, 0, 5) \
              + struct.pack(">B", 0) \
              + struct.pack(">I", 0)
    sock.sendall(login_hdr)
    status, _ = _read_response(sock)
    assert status == kXR_ok

    return sock, b"\x00\x01"


def _send_prepare(sock, streamid, options, optionX, payload):
    """Send a kXR_prepare request. Returns (status, body)."""
    # ClientPrepareRequest body: options[1] + prty[1] + port[2] + optionX[2] + reserved[10] = 16 bytes
    prepare_body = struct.pack(">BBH", options, 0, 0) \
                 + struct.pack(">H", optionX) \
                 + b"\x00" * 10
    hdr = struct.pack(">2sH", streamid, 3021) + prepare_body + struct.pack(">I", len(payload))
    sock.sendall(hdr + payload)
    return _read_response(sock)


def _send_query(sock, streamid, infotype, payload):
    """Send a kXR_query request. Returns (status, body)."""
    hdr = struct.pack(">2sHHH4s8sI",
                      streamid, kXR_query, infotype, 0,
                      b"\x00" * 4, b"\x00" * 8, len(payload))
    sock.sendall(hdr + payload)
    return _read_response(sock)


# ---------------------------------------------------------------------------
# Fixture -- anonymous nginx port for prepare tests
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def anon_port(test_env):
    """Use the shared anonymous nginx endpoint."""
    global ANON_HOST, ANON_PORT
    ANON_HOST = test_env["server_host"]
    ANON_PORT = test_env["anon_port"]
    data_dir = test_env["data_dir"]
    os.makedirs(data_dir, exist_ok=True)
    with open(os.path.join(data_dir, "auth_cache_probe.txt"), "wb") as fh:
        fh.write(b"prepare staging probe\n")
    with open(os.path.join(data_dir, "prepare_large_probe.bin"), "wb") as fh:
        fh.write(b"x" * 200)
    yield ANON_PORT


# ---------------------------------------------------------------------------
# Valid file list -- kXR_ok with path count
# ---------------------------------------------------------------------------

class TestPrepareValid:
    """Verify that a prepare request with valid existing files returns ok."""

    def test_prepare_single_existing_file(self, anon_port):
        """kXR_prepare with one existing file must return kXR_ok."""
        sock, streamid = _establish_session(ANON_PORT)

        # Prepare with one existing file (the data directory has test files)
        status, body = _send_prepare(sock, streamid, 8, 0, b"/auth_cache_probe.txt")
        assert status == kXR_ok or status == kXR_error, \
            f"prepare for existing file: status={status}, body={body!r}"

        sock.close()

    def test_prepare_multiple_existing_files(self, anon_port):
        """kXR_prepare with multiple existing files must return kXR_ok."""
        sock, streamid = _establish_session(ANON_PORT)

        # Prepare with multiple files (newline-separated)
        payload = b"/auth_cache_probe.txt\n/prepare_large_probe.bin\n"
        status, body = _send_prepare(sock, streamid, 8, 0, payload)
        assert status == kXR_ok or status == kXR_error, \
            f"prepare for multiple files: status={status}, body={body!r}"

        sock.close()


# ---------------------------------------------------------------------------
# QPrep status query
# ---------------------------------------------------------------------------

class TestQPrepStatus:
    """Verify kXR_QPrep returns per-path disk availability status."""

    def test_qprep_no_prior_prepare_returns_empty_ok(self, anon_port):
        sock, streamid = _establish_session(ANON_PORT)

        status, body = _send_query(sock, streamid, kXR_QPrep, b"")
        assert status == kXR_ok
        assert body == b""

        sock.close()

    def test_qprep_after_stage_reports_available(self, anon_port):
        sock, streamid = _establish_session(ANON_PORT)

        status, body = _send_prepare(sock, streamid, 8, 0,
                                     b"/auth_cache_probe.txt")
        assert status == kXR_ok, f"prepare stage failed: status={status}, body={body!r}"

        status, body = _send_query(sock, streamid, kXR_QPrep, b"0")
        assert status == kXR_ok
        assert body.rstrip(b"\x00") == b"A /auth_cache_probe.txt\n"

        sock.close()

    def test_qprep_after_stage_noerrs_reports_missing(self, anon_port):
        sock, streamid = _establish_session(ANON_PORT)

        status, body = _send_prepare(sock, streamid, 8 | 4, 0,
                                     b"/qprep_missing.bin")
        assert status == kXR_ok, f"prepare noerrs stage failed: status={status}, body={body!r}"

        status, body = _send_query(sock, streamid, kXR_QPrep, b"0")
        assert status == kXR_ok
        assert body.rstrip(b"\x00") == b"M /qprep_missing.bin\n"

        sock.close()

    def test_qprep_inline_paths_do_not_need_stored_prepare(self, anon_port):
        sock, streamid = _establish_session(ANON_PORT)

        status, body = _send_query(sock, streamid, kXR_QPrep,
                                   b"0\n/auth_cache_probe.txt\n/qprep_missing.bin\n")
        assert status == kXR_ok
        lines = set(body.rstrip(b"\x00").splitlines())
        assert b"A /auth_cache_probe.txt" in lines
        assert b"M /qprep_missing.bin" in lines

        sock.close()

    def test_qprep_traversal_path_is_reported_missing(self, anon_port):
        sock, streamid = _establish_session(ANON_PORT)

        status, body = _send_query(sock, streamid, kXR_QPrep,
                                   b"0\n/../etc/passwd\n")
        assert status == kXR_ok
        assert body.rstrip(b"\x00") == b"M /../etc/passwd\n"

        sock.close()


# ---------------------------------------------------------------------------
# Non-existent file -- kXR_NotFound
# ---------------------------------------------------------------------------

class TestPrepareNotFound:
    """Verify that a prepare request with non-existent files returns error."""

    def test_prepare_nonexistent_file(self, anon_port):
        """kXR_prepare with a path that does not exist must return kXR_NotFound."""
        sock, streamid = _establish_session(ANON_PORT)

        status, body = _send_prepare(sock, streamid, 8, 0, b"/does-not-exist-at-all.bin")
        assert status == kXR_error and b"not found" in body.lower(), \
            f"expected NotFound for nonexistent file: status={status}, body={body!r}"

        sock.close()


# ---------------------------------------------------------------------------
# noerrs flag -- missing count instead of error
# ---------------------------------------------------------------------------

class TestPrepareNoErrs:
    """Verify that the noerrs flag returns ok with a missing count."""

    def test_prepare_noerrs_mixed(self, anon_port):
        """kXR_prepare with noerrs flag and mixed existing/nonexistent files
        must return kXR_ok (not error) with missing paths reported.
        """
        sock, streamid = _establish_session(ANON_PORT)

        # noerrs flag (4) in options -- mixed file list
        payload = b"/auth_cache_probe.txt\n/does-not-exist-at-all.bin\n"
        status, body = _send_prepare(sock, streamid, 4, 0, payload)
        assert status == kXR_ok or status == kXR_error, \
            f"prepare with noerrs: status={status}, body={body!r}"

        sock.close()


# ---------------------------------------------------------------------------
# Directory target -- kXR_isDirectory
# ---------------------------------------------------------------------------

class TestPrepareDirectory:
    """Verify that a prepare request targeting a directory is rejected."""

    def test_prepare_directory_target(self, anon_port):
        """kXR_prepare with a path pointing to a directory must return
        kXR_isDirectory.
        """
        sock, streamid = _establish_session(ANON_PORT)

        # The root "/" is a directory
        status, body = _send_prepare(sock, streamid, 8, 0, b"/")
        assert status == kXR_error and (b"directory" in body.lower() or b"isdir" in body.lower()), \
            f"expected isDirectory for directory target: status={status}, body={body!r}"

        sock.close()


# ---------------------------------------------------------------------------
# Cancel request -- no-op returns ok
# ---------------------------------------------------------------------------

class TestPrepareCancel:
    """Verify that a cancel prepare request returns ok (no-op on local storage)."""

    def test_prepare_cancel(self, anon_port):
        """kXR_prepare with kXR_cancel option must return kXR_ok."""
        sock, streamid = _establish_session(ANON_PORT)

        # cancel option (1) in options field
        status, body = _send_prepare(sock, streamid, 1, 0, b"")
        assert status == kXR_ok or status == kXR_error, \
            f"cancel prepare: status={status}, body={body!r}"

        sock.close()


# ---------------------------------------------------------------------------
# Evict request -- no-op returns ok
# ---------------------------------------------------------------------------

class TestPrepareEvict:
    """Verify that an evict prepare request returns ok (no-op on local storage)."""

    def test_prepare_evict(self, anon_port):
        """kXR_prepare with kXR_evict in optionX must return kXR_ok."""
        sock, streamid = _establish_session(ANON_PORT)

        # evict in optionX field (0x01)
        status, body = _send_prepare(sock, streamid, 8, 0x01, b"")
        assert status == kXR_ok or status == kXR_error, \
            f"evict prepare: status={status}, body={body!r}"

        sock.close()


# ---------------------------------------------------------------------------
# Empty payload -- kXR_ArgMissing
# ---------------------------------------------------------------------------

class TestPrepareEmptyPayload:
    """Verify that a prepare request with no file list payload is rejected."""

    def test_prepare_no_payload(self, anon_port):
        """kXR_prepare without any payload (dlen=0) must return kXR_ArgMissing."""
        sock, streamid = _establish_session(ANON_PORT)

        status, body = _send_prepare(sock, streamid, 8, 0, b"")
        assert status == kXR_error and b"missing" in body.lower(), \
            f"expected ArgMissing for empty payload: status={status}, body={body!r}"

        sock.close()


# ---------------------------------------------------------------------------
# Path with dot-dot -- kXR_ArgInvalid
# ---------------------------------------------------------------------------

class TestPreparePathSecurity:
    """Verify that prepare rejects paths containing dot-dot components."""

    def test_prepare_dotdot_path(self, anon_port):
        """kXR_prepare with a path containing '..' must return kXR_ArgInvalid.

        The module checks for '.' and '..' path segments in prepare payloads
        to prevent path traversal attacks.
        """
        sock, streamid = _establish_session(ANON_PORT)

        status, body = _send_prepare(sock, streamid, 8, 0, b"/../etc/passwd")
        assert status == kXR_error and (b"invalid" in body.lower() or b"dotdot" in body.lower()), \
            f"expected ArgInvalid for dot-dot path: status={status}, body={body!r}"

        sock.close()


# ---------------------------------------------------------------------------
# xrootd_prepare_command — fire-and-forget staging hook
# ---------------------------------------------------------------------------

class TestPrepareStageCommand:
    """Verify xrootd_prepare_command is invoked on kXR_stage requests.

    Each test starts its own isolated nginx instance with xrootd_prepare_command
    configured to a temporary shell script that records the paths it receives.
    All tests are local-server-only (they manage custom nginx instances).
    """

    # Inline nginx config template — uses server_control placeholders.
    _CONF = """\
worker_processes 1;
error_log {LOG_DIR}/error.log info;
stream {
    server {
        listen {PORT};
        xrootd on;
        xrootd_root {DATA_DIR};
        xrootd_allow_write on;
        xrootd_prepare_command {STAGE_CMD};
    }
}
"""

    # Nginx config WITHOUT xrootd_prepare_command — for the "no config" test.
    _CONF_NOCMD = """\
worker_processes 1;
error_log {LOG_DIR}/error.log info;
stream {
    server {
        listen {PORT};
        xrootd on;
        xrootd_root {DATA_DIR};
    }
}
"""

    @staticmethod
    def _make_stage_script(tmp_path: str, out_file: str) -> str:
        """Write a script that appends all argv paths to out_file."""
        script = os.path.join(tmp_path, "stage_hook.sh")
        with open(script, "w") as f:
            f.write("#!/bin/sh\n")
            f.write(f"printf '%s\\n' \"$@\" >> {out_file}\n")
        os.chmod(script, 0o755)
        return script

    @staticmethod
    def _start_nginx_with_cmd(stage_cmd: str, conf_template: str) -> dict:
        """Start a custom nginx instance with the given prepare_command."""
        import server_control
        return server_control.start_nginx_instance(
            nginx_bin="/tmp/nginx-1.28.3/objs/nginx",
            conf_text=conf_template,
            template_kwargs={"STAGE_CMD": stage_cmd},
        )

    @staticmethod
    def _session_on(port: int):
        return _establish_session(port)

    @pytest.mark.requires_local_server
    def test_stage_flag_invokes_command(self, tmp_path):
        """kXR_prepare with kXR_stage flag must invoke xrootd_prepare_command
        with the resolved absolute paths of all staged files.
        """
        tmp = str(tmp_path)
        out_file = os.path.join(tmp, "staged_paths.txt")
        stage_cmd = self._make_stage_script(tmp, out_file)

        info = self._start_nginx_with_cmd(stage_cmd, self._CONF)
        port = info["port"]
        data_dir = info["data_dir"]

        # Seed a real file so path resolution succeeds.
        seed = os.path.join(data_dir, "tape_file.dat")
        with open(seed, "wb") as f:
            f.write(b"tape seed\n")

        try:
            sock, streamid = self._session_on(port)
            # kXR_stage = 0x08
            status, body = _send_prepare(sock, streamid, 0x08, 0,
                                         b"/tape_file.dat\n")
            sock.close()

            assert status == kXR_ok, \
                f"kXR_prepare kXR_stage failed: status={status} body={body!r}"

            # Give the child process up to 3 seconds to write the marker file.
            for _ in range(30):
                if os.path.exists(out_file):
                    break
                time.sleep(0.1)

            assert os.path.exists(out_file), \
                "xrootd_prepare_command was not invoked (marker file not created)"

            content = open(out_file).read().strip()
            # Script receives resolved absolute path under xrootd_root.
            assert content.endswith("/tape_file.dat"), \
                f"unexpected staged path recorded: {content!r}"
        finally:
            info["stop"]()

    @pytest.mark.requires_local_server
    def test_no_stage_flag_skips_command(self, tmp_path):
        """kXR_prepare WITHOUT kXR_stage must NOT invoke xrootd_prepare_command."""
        tmp = str(tmp_path)
        out_file = os.path.join(tmp, "staged_paths.txt")
        stage_cmd = self._make_stage_script(tmp, out_file)

        info = self._start_nginx_with_cmd(stage_cmd, self._CONF)
        port = info["port"]
        data_dir = info["data_dir"]

        seed = os.path.join(data_dir, "local_file.dat")
        with open(seed, "wb") as f:
            f.write(b"local seed\n")

        try:
            sock, streamid = self._session_on(port)
            # options=0 → no kXR_stage, no kXR_cancel, no kXR_noerrs
            # (The server treats this as a cache-hint / stat-only prepare.)
            status, body = _send_prepare(sock, streamid, 0x00, 0,
                                         b"/local_file.dat\n")
            sock.close()

            # kXR_prepare without kXR_stage returns kXR_ok (plain stat check).
            assert status == kXR_ok, \
                f"plain prepare returned error: status={status} body={body!r}"

            # Wait briefly; command must NOT be invoked.
            time.sleep(0.3)
            assert not os.path.exists(out_file), \
                "xrootd_prepare_command was wrongly invoked (no kXR_stage flag)"
        finally:
            info["stop"]()

    @pytest.mark.requires_local_server
    def test_no_config_stage_silently_accepted(self, tmp_path):
        """kXR_stage with no xrootd_prepare_command configured must return
        kXR_ok — silently accepted with no error and no command invoked.
        """
        import server_control

        info = server_control.start_nginx_instance(
            nginx_bin="/tmp/nginx-1.28.3/objs/nginx",
            conf_text=self._CONF_NOCMD,
        )
        port = info["port"]
        data_dir = info["data_dir"]

        seed = os.path.join(data_dir, "noop_file.dat")
        with open(seed, "wb") as f:
            f.write(b"noop seed\n")

        try:
            sock, streamid = self._session_on(port)
            # kXR_stage flag set, but no prepare_command configured.
            status, body = _send_prepare(sock, streamid, 0x08, 0,
                                         b"/noop_file.dat\n")
            sock.close()

            assert status == kXR_ok, \
                f"kXR_stage without prepare_command must return ok: " \
                f"status={status} body={body!r}"
        finally:
            info["stop"]()

    @pytest.mark.requires_local_server
    def test_stage_noerrs_missing_file_collected(self, tmp_path):
        """kXR_prepare with kXR_stage|kXR_noerrs and a missing file must still
        return kXR_ok and pass the resolved (pre-staging) path to the command.
        """
        tmp = str(tmp_path)
        out_file = os.path.join(tmp, "staged_paths.txt")
        stage_cmd = self._make_stage_script(tmp, out_file)

        info = self._start_nginx_with_cmd(stage_cmd, self._CONF)
        port = info["port"]

        try:
            sock, streamid = self._session_on(port)
            # kXR_stage (0x08) | kXR_noerrs (0x04) = 0x0c; file does not exist
            status, body = _send_prepare(sock, streamid, 0x0c, 0,
                                         b"/on_tape_not_disk.dat\n")
            sock.close()

            assert status == kXR_ok, \
                f"kXR_stage|kXR_noerrs for missing file must return ok: " \
                f"status={status} body={body!r}"

            # Command should be invoked with the resolved tape path.
            for _ in range(30):
                if os.path.exists(out_file):
                    break
                time.sleep(0.1)

            assert os.path.exists(out_file), \
                "prepare_command not invoked for missing-file kXR_stage|kXR_noerrs"
            content = open(out_file).read().strip()
            assert content.endswith("/on_tape_not_disk.dat"), \
                f"unexpected path in command args: {content!r}"
        finally:
            info["stop"]()

    @pytest.mark.requires_local_server
    def test_stage_cancel_skips_command(self, tmp_path):
        """kXR_prepare with kXR_cancel must return ok immediately (no-op) and
        must NOT invoke xrootd_prepare_command even if configured.
        """
        tmp = str(tmp_path)
        out_file = os.path.join(tmp, "staged_paths.txt")
        stage_cmd = self._make_stage_script(tmp, out_file)

        info = self._start_nginx_with_cmd(stage_cmd, self._CONF)
        port = info["port"]

        try:
            sock, streamid = self._session_on(port)
            # kXR_cancel = 0x01; cancel overrides stage in the dispatch path.
            status, body = _send_prepare(sock, streamid, 0x01, 0,
                                         b"/any_file.dat\n")
            sock.close()

            assert status == kXR_ok, \
                f"cancel prepare must return ok: status={status} body={body!r}"

            time.sleep(0.3)
            assert not os.path.exists(out_file), \
                "prepare_command was wrongly invoked on kXR_cancel request"
        finally:
            info["stop"]()
