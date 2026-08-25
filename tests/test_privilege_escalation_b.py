from split_continuation import reexport as _reexport
_reexport(globals(), "_test_privilege_escalation_helpers")

# Same group as test_privilege_escalation.py — the split halves share the
# readonly export's fixture files and symlinks; see the comment there.
pytestmark = pytest.mark.xdist_group("priv-esc")

class TestReadSideSymlinkEscape:
    """Read-only operations must not follow symlinks outside brix_export."""

    @pytest.fixture(autouse=True)
    def _setup_symlinks(self):
        self.outside = tempfile.TemporaryDirectory(prefix="xrd-priv-outside-")
        self.outside_file = os.path.join(self.outside.name, "secret.txt")
        self.outside_dir = os.path.join(self.outside.name, "secret-dir")
        self.outside_child = os.path.join(self.outside_dir, "leak.txt")
        self.link_file_name = "_priv_symlink_escape_file"
        self.link_dir_name = "_priv_symlink_escape_dir"
        self.link_file = os.path.join(DATA_DIR, self.link_file_name)
        self.link_dir = os.path.join(DATA_DIR, self.link_dir_name)

        os.makedirs(self.outside_dir, exist_ok=True)
        with open(self.outside_file, "wb") as fh:
            fh.write(b"outside file must not be visible\n")
        with open(self.outside_child, "wb") as fh:
            fh.write(b"outside directory must not be listed\n")

        _unlink_if_exists(self.link_file)
        _unlink_if_exists(self.link_dir)
        os.symlink(self.outside_file, self.link_file)
        os.symlink(self.outside_dir, self.link_dir)

        yield

        _unlink_if_exists(self.link_file)
        _unlink_if_exists(self.link_dir)
        self.outside.cleanup()

    def test_stat_rejects_symlink_escape(self):
        with _raw_session() as sock:
            _login_anon(sock)
            status, body = _stat_path_raw(
                sock, f"/{self.link_file_name}".encode(),
            )

        assert status == kXR_ERROR

    def test_open_rejects_symlink_escape(self):
        with _raw_session() as sock:
            _login_anon(sock)
            status, body = _open_file_raw(
                sock, f"/{self.link_file_name}".encode(), kXR_open_read,
            )

        assert status == kXR_ERROR

    def test_dirlist_rejects_symlink_escape(self):
        with _raw_session() as sock:
            _login_anon(sock)
            status, body = _dirlist_raw(
                sock, f"/{self.link_dir_name}".encode(),
            )

        assert status == kXR_ERROR


# ===========================================================================
# Write-side symlink escape checks (partner to TestReadSideSymlinkEscape)
# ===========================================================================

@pytest.mark.skipif(
    CROSS_BACKEND == "xrootd",
    reason="write-side symlink-escape confinement (openat2 RESOLVE_BENEATH) is nginx-xrootd-specific",
)
class TestWriteSideSymlinkEscape:
    """Mutating ops (open-create, mkdir, rm, truncate, mv-destination) must not
    follow a symlink out of brix_export.  This is the write-side partner to
    TestReadSideSymlinkEscape and a direct regression guard for the openat2
    RESOLVE_BENEATH parent-confinement that the *at() syscall family
    (mkdirat/unlinkat/renameat) needs: a symlink in an INTERMEDIATE component
    (/link_dir -> /outside) is otherwise followed straight out of the root.

    The anon endpoint has brix_allow_write on, so a rejection here proves
    CONFINEMENT (not an auth failure).  Each attack targets a genuinely WRITABLE
    directory outside the root and then asserts that directory is left pristine —
    nothing created, the victim file neither overwritten, truncated, nor deleted.
    """

    @pytest.fixture(autouse=True)
    def _setup_symlinks(self):
        self.outside = tempfile.TemporaryDirectory(prefix="xrd-priv-wescape-")
        self.victim = os.path.join(self.outside.name, "victim.txt")
        with open(self.victim, "wb") as fh:
            fh.write(b"ORIGINAL")

        self.link_file_name = "_priv_wsymlink_file"
        self.link_dir_name = "_priv_wsymlink_dir"
        self.link_file = os.path.join(DATA_DIR, self.link_file_name)
        self.link_dir = os.path.join(DATA_DIR, self.link_dir_name)

        _unlink_if_exists(self.link_file)
        _unlink_if_exists(self.link_dir)
        os.symlink(self.victim, self.link_file)        # -> outside file
        os.symlink(self.outside.name, self.link_dir)   # -> outside writable dir

        yield

        _unlink_if_exists(self.link_file)
        _unlink_if_exists(self.link_dir)
        self.outside.cleanup()

    def _assert_outside_pristine(self):
        assert os.path.exists(self.victim), \
            "CONFINEMENT BREACH: victim outside the root was deleted"
        with open(self.victim, "rb") as fh:
            assert fh.read() == b"ORIGINAL", \
                "CONFINEMENT BREACH: victim outside the root was overwritten/truncated"
        leftover = sorted(os.listdir(self.outside.name))
        assert leftover == ["victim.txt"], \
            f"CONFINEMENT BREACH: outside dir gained entries {leftover}"

    def test_open_create_through_dir_symlink_rejected(self):
        with _raw_session() as sock:
            _login_anon(sock)
            status, _ = _open_file_raw(
                sock, f"/{self.link_dir_name}/pwned.txt".encode(),
                kXR_open_wrto | kXR_new,
            )
        assert status == kXR_ERROR
        self._assert_outside_pristine()

    def test_open_write_through_file_symlink_does_not_truncate(self):
        with _raw_session() as sock:
            _login_anon(sock)
            status, _ = _open_file_raw(
                sock, f"/{self.link_file_name}".encode(),
                kXR_open_updt | kXR_new,
            )
        assert status == kXR_ERROR
        self._assert_outside_pristine()

    def test_mkdir_through_dir_symlink_rejected(self):
        payload = f"/{self.link_dir_name}/pwndir".encode()
        req = struct.pack("!2sH1s13sHI", b"\x00\x03", kXR_mkdir,
                          b"\x00", b"\x00" * 13, 0o755, len(payload))
        with _raw_session() as sock:
            _login_anon(sock)
            sock.sendall(req + payload)
            status, _ = _read_response(sock)
        assert status == kXR_ERROR
        self._assert_outside_pristine()

    def test_rm_through_file_symlink_removes_link_not_target(self):
        """kXR_rm of an in-root symlink pointing OUTSIDE the export removes the
        LINK ITSELF, not the victim it targets — unlinkat() never follows the
        final symlink (POSIX/lstat semantics).  This is NOT a confinement escape,
        so it SUCCEEDS (kXR_ok); the security invariant is that the outside victim
        stays untouched.  Matches the documented project policy in test_evil_paths
        ("rm of the in-root symlink-to-victim must SUCCEED — removes the link
        only") and test_xrd_busybox::test_rm_symlink_removes_link_not_target.
        Contrast truncate/mv below, which WRITE *through* the symlink and so DO
        escape and must be rejected."""
        payload = f"/{self.link_file_name}".encode()
        req = struct.pack("!2sH16sI", b"\x00\x03", kXR_rm,
                          b"\x00" * 16, len(payload))
        with _raw_session() as sock:
            _login_anon(sock)
            sock.sendall(req + payload)
            status, _ = _read_response(sock)
        assert status == kXR_OK, \
            f"rm of in-root symlink should remove the link itself (status={status})"
        # The actual confinement guarantee: the victim OUTSIDE the root is
        # untouched (the link was removed, never followed).
        self._assert_outside_pristine()
        assert not os.path.lexists(self.link_file), \
            "rm should have removed the in-root symlink itself"

    def test_truncate_through_file_symlink_rejected(self):
        payload = f"/{self.link_file_name}".encode()
        req = struct.pack("!2sH4sq4sI", b"\x00\x03", kXR_truncate,
                          b"\x00" * 4, 0, b"\x00" * 4, len(payload))
        with _raw_session() as sock:
            _login_anon(sock)
            sock.sendall(req + payload)
            status, _ = _read_response(sock)
        assert status == kXR_ERROR
        self._assert_outside_pristine()

    def test_mv_destination_through_dir_symlink_rejected(self):
        src_disk = os.path.join(DATA_DIR, "_priv_wmv_src.txt")
        with open(src_disk, "wb") as fh:
            fh.write(b"in-root")
        try:
            src = b"/_priv_wmv_src.txt"
            dst = f"/{self.link_dir_name}/moved.txt".encode()
            payload = src + b" " + dst
            req = struct.pack("!2sH14shI", b"\x00\x03", kXR_mv,
                              b"\x00" * 14, len(src), len(payload))
            with _raw_session() as sock:
                _login_anon(sock)
                sock.sendall(req + payload)
                status, _ = _read_response(sock)
            assert status == kXR_ERROR
            self._assert_outside_pristine()
            assert os.path.exists(src_disk), "in-root mv source vanished"
        finally:
            _unlink_if_exists(src_disk)


# ===========================================================================
# Pre-auth rejection of ALL data opcodes
# ===========================================================================

class TestPreAuthRejection:
    """Every data opcode must be rejected before login/auth."""

    def test_preauth_stat_rejected(self):
        """kXR_stat must fail before login."""
        with _raw_session() as sock:
            payload = b"/test.txt"
            req = struct.pack(
                "!2sH1s7sI4sI",
                b"\x00\x01", kXR_stat,
                b"\x00",         # options
                b"\x00" * 7,     # reserved
                0,               # wants
                b"\x00" * 4,     # fhandle
                len(payload),
            )
            sock.sendall(req + payload)
            status, body = _read_response(sock)

        _assert_preauth_rejected(status, body)

    def test_preauth_open_rejected(self):
        """kXR_open must fail before login."""
        with _raw_session() as sock:
            payload = b"/test.txt"
            req = struct.pack(
                "!2sHHH2s6s4sI",
                b"\x00\x01", kXR_open,
                0o644, kXR_open_read,
                b"\x00\x00", b"\x00" * 6, b"\x00" * 4,
                len(payload),
            )
            sock.sendall(req + payload)
            status, body = _read_response(sock)

        _assert_preauth_rejected(status, body)

    def test_preauth_read_rejected(self):
        """kXR_read must fail before login."""
        with _raw_session() as sock:
            req = struct.pack(
                "!2sH4sqiI",
                b"\x00\x01", kXR_read,
                b"\x00" * 4,     # fhandle
                0,               # offset (big-endian int64)
                1024,            # rlen
                0,               # dlen
            )
            sock.sendall(req)
            status, body = _read_response(sock)

        _assert_preauth_rejected(status, body)

    def test_preauth_write_rejected(self):
        """kXR_write must fail before login."""
        with _raw_session() as sock:
            data = b"unauthorized write"
            req = struct.pack(
                "!2sH4sq1s3sI",
                b"\x00\x01", kXR_write,
                b"\x00" * 4,    # fhandle
                0,              # offset
                b"\x00",        # pathid
                b"\x00" * 3,    # reserved
                len(data),
            )
            sock.sendall(req + data)
            status, body = _read_response(sock)

        _assert_preauth_rejected(status, body)

    def test_preauth_dirlist_rejected(self):
        """kXR_dirlist must fail before login."""
        with _raw_session() as sock:
            payload = b"/"
            req = struct.pack(
                "!2sH15sBi",
                b"\x00\x01", kXR_dirlist,
                b"\x00" * 15, 0,  # reserved + options
                len(payload),
            )
            sock.sendall(req + payload)
            status, body = _read_response(sock)

        _assert_preauth_rejected(status, body)

    def test_preauth_truncate_rejected(self):
        """kXR_truncate must fail before login."""
        with _raw_session() as sock:
            payload = b"/test.txt"
            req = struct.pack(
                "!2sH4sq4sI",
                b"\x00\x01", kXR_truncate,
                b"\x00" * 4,   # fhandle
                0,             # target length
                b"\x00" * 4,   # reserved
                len(payload),
            )
            sock.sendall(req + payload)
            status, body = _read_response(sock)

        _assert_preauth_rejected(status, body)

    def test_preauth_query_rejected(self):
        """kXR_query must fail before login."""
        with _raw_session() as sock:
            payload = b"/test.txt"
            # infotype=8 (kXR_Qcksum)
            req = struct.pack(
                "!2sHH2s4s8sI",
                b"\x00\x01", kXR_query,
                8,               # kXR_Qcksum
                b"\x00\x00",
                b"\x00" * 4,
                b"\x00" * 8,
                len(payload),
            )
            sock.sendall(req + payload)
            status, body = _read_response(sock)

        _assert_preauth_rejected(status, body)

    def test_preauth_readv_rejected(self):
        """kXR_readv must fail before login."""
        with _raw_session() as sock:
            # readv payload: [fhandle(4) + rlen(4) + offset(8)] per segment
            segment = struct.pack("!4sIq", b"\x00" * 4, 100, 0)
            req = struct.pack(
                "!2sH16sI",
                b"\x00\x01", kXR_readv,
                b"\x00" * 16,
                len(segment),
            )
            sock.sendall(req + segment)
            status, body = _read_response(sock)

        _assert_preauth_rejected(status, body)

    def test_preauth_mkdir_rejected(self):
        """kXR_mkdir must fail before login."""
        victim = os.path.join(DATA_DIR, "_priv_preauth_mkdir")
        try:
            with _raw_session() as sock:
                payload = b"/_priv_preauth_mkdir"
                req = struct.pack(
                    "!2sH1s13sHI",
                    b"\x00\x01", kXR_mkdir,
                    b"\x00",          # options
                    b"\x00" * 13,     # reserved
                    0o755,            # mode
                    len(payload),
                )
                sock.sendall(req + payload)
                status, body = _read_response(sock)

            _assert_preauth_rejected(status, body)
            assert not os.path.exists(victim), "pre-auth mkdir created directory"
        finally:
            if os.path.isdir(victim):
                os.rmdir(victim)


# ===========================================================================
# Pre-auth ALLOWED opcodes (should succeed before login)
# ===========================================================================
