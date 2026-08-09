from split_continuation import reexport as _reexport
_reexport(globals(), "_test_privilege_escalation_helpers")

class TestReadOnlyServer:
    """A listener without brix_allow_write must permit reads and block mutations."""

    @pytest.fixture(autouse=True)
    def _setup_paths(self):
        self.read_name = "_priv_ro_read.txt"
        self.read_remote = f"/{self.read_name}"
        self.read_disk = os.path.join(READONLY_DATA_ROOT, self.read_name)
        self.read_data = b"read-only listener still serves bytes\n"

        self.list_name = "_priv_ro_list"
        self.list_remote = f"/{self.list_name}"
        self.list_disk = os.path.join(READONLY_DATA_ROOT, self.list_name)
        self.list_child = os.path.join(self.list_disk, "child.txt")

        self.open_write_disk = os.path.join(READONLY_DATA_ROOT, "_priv_ro_open_write.txt")
        self.truncate_disk = os.path.join(READONLY_DATA_ROOT, "_priv_ro_truncate.txt")
        self.mkdir_disk = os.path.join(READONLY_DATA_ROOT, "_priv_ro_mkdir")
        self.rm_disk = os.path.join(READONLY_DATA_ROOT, "_priv_ro_rm.txt")
        self.rmdir_disk = os.path.join(READONLY_DATA_ROOT, "_priv_ro_rmdir")
        self.rmdir_child = os.path.join(self.rmdir_disk, "keep.txt")
        self.mv_src_disk = os.path.join(READONLY_DATA_ROOT, "_priv_ro_mv_src.txt")
        self.mv_dst_disk = os.path.join(READONLY_DATA_ROOT, "_priv_ro_mv_dst.txt")
        self.chmod_disk = os.path.join(READONLY_DATA_ROOT, "_priv_ro_chmod.txt")

        for path in (
            self.open_write_disk,
            self.rm_disk,
            self.mv_src_disk,
            self.mv_dst_disk,
            self.chmod_disk,
            self.truncate_disk,
        ):
            _unlink_if_exists(path)
        _unlink_if_exists(self.rmdir_child)
        _rmdir_if_exists(self.rmdir_disk)
        _unlink_if_exists(self.list_child)
        _rmdir_if_exists(self.list_disk)
        _rmdir_if_exists(self.mkdir_disk)

        with open(self.read_disk, "wb") as fh:
            fh.write(self.read_data)
        os.makedirs(self.list_disk, exist_ok=True)
        with open(self.list_child, "wb") as fh:
            fh.write(b"listed\n")

        yield

        for path in (
            self.open_write_disk,
            self.rm_disk,
            self.mv_src_disk,
            self.mv_dst_disk,
            self.chmod_disk,
            self.truncate_disk,
            self.read_disk,
        ):
            _unlink_if_exists(path)
        _unlink_if_exists(self.rmdir_child)
        _rmdir_if_exists(self.rmdir_disk)
        _unlink_if_exists(self.list_child)
        _rmdir_if_exists(self.list_disk)
        _rmdir_if_exists(self.mkdir_disk)

    def _readonly_session(self):
        sock = _raw_session(READONLY_HOST, READONLY_PORT)
        _login_anon(sock)
        return sock

    def test_read_side_ops_still_work_on_readonly_listener(self, readonly_nginx):
        """The write gate must not accidentally turn the listener into no-access."""
        with self._readonly_session() as sock:
            status, body = _stat_path_raw(sock, self.read_remote.encode())
            assert status == kXR_OK
            assert str(len(self.read_data)).encode() in body

            status, body = _open_file_raw(
                sock, self.read_remote.encode(), kXR_open_read,
                streamid=b"\x00\x03",
            )
            assert status == kXR_OK
            fhandle = body[:4]

            status, body = _read_raw(
                sock, fhandle, 0, len(self.read_data),
                streamid=b"\x00\x04",
            )
            assert status == kXR_OK
            assert body == self.read_data

            status, body = _readv_raw(sock, fhandle, 0, 4, streamid=b"\x00\x05")
            assert status == kXR_OK
            assert len(body) >= 20
            assert body[16:20] == self.read_data[:4]

            status, body = _dirlist_raw(
                sock, self.list_remote.encode(),
                streamid=b"\x00\x06",
            )
            assert status == kXR_OK
            assert b"child.txt" in body

            _close_handle_raw(sock, fhandle, streamid=b"\x00\x07")

    @pytest.mark.parametrize(
        "case",
        [
            "open_write",
            "write",
            "pgwrite",
            "writev",
            "sync",
            "truncate",
            "mkdir",
            "rm",
            "rmdir",
            "mv",
            "chmod",
        ],
    )
    def test_mutating_opcode_rejected_by_readonly_listener(
            self, readonly_nginx, case):
        """Every mutating opcode should fail with kXR_fsReadOnly before side effects."""
        with self._readonly_session() as sock:
            if case == "open_write":
                payload = b"/_priv_ro_open_write.txt"
                req = struct.pack(
                    "!2sHHH2s6s4sI",
                    b"\x00\x03", kXR_open,
                    0o644,
                    kXR_open_wrto | kXR_new,
                    b"\x00\x00",
                    b"\x00" * 6,
                    b"\x00" * 4,
                    len(payload),
                )
                sock.sendall(req + payload)
                status, body = _read_response(sock)
                _assert_readonly_response(status, body)
                assert not os.path.exists(self.open_write_disk)
                return

            if case == "write":
                data = b"blocked"
                req = struct.pack(
                    "!2sH4sq1s3sI",
                    b"\x00\x03", kXR_write,
                    b"\x00" * 4,
                    0,
                    b"\x00",
                    b"\x00" * 3,
                    len(data),
                )
                sock.sendall(req + data)
                status, body = _read_response(sock)
                _assert_readonly_response(status, body)
                return

            if case == "pgwrite":
                data = b"\x00\x00\x00\x00blocked"
                req = struct.pack(
                    "!2sH4sq1s1s2sI",
                    b"\x00\x03", kXR_pgwrite,
                    b"\x00" * 4,
                    0,
                    b"\x00",
                    b"\x00",
                    b"\x00" * 2,
                    len(data),
                )
                sock.sendall(req + data)
                status, body = _read_response(sock)
                _assert_readonly_response(status, body)
                return

            if case == "writev":
                req = struct.pack(
                    "!2sH16sI",
                    b"\x00\x03", kXR_writev,
                    b"\x00" * 16,
                    0,
                )
                sock.sendall(req)
                status, body = _read_response(sock)
                _assert_readonly_response(status, body)
                return

            if case == "sync":
                status, body = _open_file_raw(
                    sock, self.read_remote.encode(), kXR_open_read,
                    streamid=b"\x00\x03",
                )
                assert status == kXR_OK
                fhandle = body[:4]
                req = struct.pack(
                    "!2sH4s12sI",
                    b"\x00\x04", kXR_sync,
                    fhandle,
                    b"\x00" * 12,
                    0,
                )
                sock.sendall(req)
                status, body = _read_response(sock)
                _assert_readonly_response(status, body)
                _close_handle_raw(sock, fhandle, streamid=b"\x00\x05")
                return

            if case == "truncate":
                with open(self.truncate_disk, "wb") as fh:
                    fh.write(b"do not truncate\n")
                payload = b"/_priv_ro_truncate.txt"
                req = struct.pack(
                    "!2sH4sq4sI",
                    b"\x00\x03", kXR_truncate,
                    b"\x00" * 4,
                    0,
                    b"\x00" * 4,
                    len(payload),
                )
                sock.sendall(req + payload)
                status, body = _read_response(sock)
                _assert_readonly_response(status, body)
                assert os.path.getsize(self.truncate_disk) == len(b"do not truncate\n")
                return

            if case == "mkdir":
                payload = b"/_priv_ro_mkdir"
                req = struct.pack(
                    "!2sH1s13sHI",
                    b"\x00\x03", kXR_mkdir,
                    b"\x00",
                    b"\x00" * 13,
                    0o755,
                    len(payload),
                )
                sock.sendall(req + payload)
                status, body = _read_response(sock)
                _assert_readonly_response(status, body)
                assert not os.path.exists(self.mkdir_disk)
                return

            if case == "rm":
                with open(self.rm_disk, "wb") as fh:
                    fh.write(b"keep me\n")
                payload = b"/_priv_ro_rm.txt"
                req = struct.pack(
                    "!2sH16sI",
                    b"\x00\x03", kXR_rm,
                    b"\x00" * 16,
                    len(payload),
                )
                sock.sendall(req + payload)
                status, body = _read_response(sock)
                _assert_readonly_response(status, body)
                with open(self.rm_disk, "rb") as fh:
                    assert fh.read() == b"keep me\n"
                return

            if case == "rmdir":
                os.makedirs(self.rmdir_disk, exist_ok=True)
                with open(self.rmdir_child, "wb") as fh:
                    fh.write(b"keep dir non-empty\n")
                payload = b"/_priv_ro_rmdir"
                req = struct.pack(
                    "!2sH16sI",
                    b"\x00\x03", kXR_rmdir,
                    b"\x00" * 16,
                    len(payload),
                )
                sock.sendall(req + payload)
                status, body = _read_response(sock)
                _assert_readonly_response(status, body)
                assert os.path.isdir(self.rmdir_disk)
                assert os.path.exists(self.rmdir_child)
                return

            if case == "mv":
                with open(self.mv_src_disk, "wb") as fh:
                    fh.write(b"do not move\n")
                src = b"/_priv_ro_mv_src.txt"
                dst = b"/_priv_ro_mv_dst.txt"
                payload = src + b" " + dst
                req = struct.pack(
                    "!2sH14shI",
                    b"\x00\x03", kXR_mv,
                    b"\x00" * 14,
                    len(src),
                    len(payload),
                )
                sock.sendall(req + payload)
                status, body = _read_response(sock)
                _assert_readonly_response(status, body)
                assert os.path.exists(self.mv_src_disk)
                assert not os.path.exists(self.mv_dst_disk)
                return

            if case == "chmod":
                with open(self.chmod_disk, "wb") as fh:
                    fh.write(b"do not chmod\n")
                os.chmod(self.chmod_disk, 0o644)
                payload = b"/_priv_ro_chmod.txt"
                req = struct.pack(
                    "!2sH14sHI",
                    b"\x00\x03", kXR_chmod,
                    b"\x00" * 14,
                    0o600,
                    len(payload),
                )
                sock.sendall(req + payload)
                status, body = _read_response(sock)
                _assert_readonly_response(status, body)
                assert (os.stat(self.chmod_disk).st_mode & 0o777) == 0o644
                return

        pytest.fail(f"unhandled read-only test case: {case}")


# ===========================================================================
# Read-side symlink escape checks
# ===========================================================================
