from split_continuation import reexport as _reexport
_reexport(globals(), "_test_fattr_query_helpers")

class TestFattrRecurse:
    """Tests for the kXR_fa_recurse local extension (options bit 0x20).

    The XRootD Python client has no API for custom option bits, so these
    tests use raw socket protocol to send kXR_fattr list with the recurse
    flag and verify the response format.

    Wire format — ClientFattrRequest (24 bytes total):
      streamid[2]  requestid[2]=3020  fhandle[4]
      subcode[1]=2  numattr[1]=0  options[1]  reserved[9]  dlen[4]

    Recursive response entries: "<relpath>:<U.name>\\0" per attribute.
    """

    _kXR_fattr     = 3020
    _kXR_fattrList = 2
    _kXR_fa_recurse = 0x20

    # ── Helpers ────────────────────────────────────────────────────────────

    def _send_fattr_list(self, sock: socket.socket, path: str,
                         options: int) -> tuple[int, bytes]:
        """Send kXR_fattr list for *path* and return (status, body)."""
        payload = path.encode() + b"\x00"
        # 2(sid) + 2(requestid) + 4(fhandle) + 1(subcode) + 1(numattr) +
        # 1(options) + 9(reserved) + 4(dlen) = 24 bytes
        hdr = struct.pack(
            ">BB H 4x B B B 9x I",
            0, 1,                    # streamid
            self._kXR_fattr,         # requestid = 3020
            self._kXR_fattrList,     # subcode   = 2
            0,                       # numattr   = 0 (required for list)
            options,                 # options   = kXR_fa_recurse etc.
            len(payload),            # dlen
        )
        sock.sendall(hdr + payload)
        hdr_bytes = _recvall(sock, 8)
        _sid0, _sid1, status, dlen = struct.unpack(">BBHI", hdr_bytes)
        body = _recvall(sock, dlen) if dlen else b""
        return status, body

    def _parse_entries(self, body: bytes) -> list[str]:
        """Split NUL-terminated entry list into a list of decoded strings."""
        return [p.decode(errors="replace") for p in body.split(b"\x00") if p]

    # ── Setup / teardown ──────────────────────────────────────────────────

    def setup_method(self) -> None:
        """Create a two-level directory tree with user.U.* xattrs."""
        pid = os.getpid()
        self.dir_name = f"fattr_recurse_{pid}"
        self.dir_fs   = os.path.join(DATA_DIR, self.dir_name)
        os.makedirs(self.dir_fs, exist_ok=True)

        # Top-level file with one xattr
        self.top_file_fs = os.path.join(self.dir_fs, "top.txt")
        with open(self.top_file_fs, "w") as f:
            f.write("top\n")
        try:
            os.setxattr(self.top_file_fs, b"user.U.color", b"blue")
        except OSError:
            pytest.skip("xattr not supported on test filesystem")

        # Subdirectory + nested file with a different xattr
        sub_fs = os.path.join(self.dir_fs, "sub")
        os.makedirs(sub_fs, exist_ok=True)
        self.nested_file_fs = os.path.join(sub_fs, "nested.txt")
        with open(self.nested_file_fs, "w") as f:
            f.write("nested\n")
        os.setxattr(self.nested_file_fs, b"user.U.project", b"cms")

    def teardown_method(self) -> None:
        import shutil
        shutil.rmtree(self.dir_fs, ignore_errors=True)

    # ── Tests ─────────────────────────────────────────────────────────────

    def test_recurse_returns_top_level_file_attrs(self) -> None:
        """kXR_fa_recurse on a directory returns attrs from top-level files."""
        sock = _raw_session(ANON_HOST, ANON_PORT)
        try:
            status, body = self._send_fattr_list(
                sock, "/" + self.dir_name, self._kXR_fa_recurse)
        finally:
            sock.close()

        assert status == _kXR_ok, f"fattr list returned status={status}"
        entries = self._parse_entries(body)
        # Entry format is "<relpath>:<name>" where <name> is the WIRE attr name
        # WITHOUT the internal "user.U." prefix (src/protocols/root/fattr/list.c strips it so the
        # listing matches stock and stays round-trippable: a re-get of "U.color"
        # would resolve to "user.U.U.color").  So expect "top.txt:color".
        assert any("top.txt" in e and e.endswith(":color") for e in entries), \
            f"top-level attr 'color' not found in recurse result: {entries}"

    def test_recurse_finds_nested_subdir_attrs(self) -> None:
        """kXR_fa_recurse descends into subdirectories and returns nested attrs."""
        sock = _raw_session(ANON_HOST, ANON_PORT)
        try:
            status, body = self._send_fattr_list(
                sock, "/" + self.dir_name, self._kXR_fa_recurse)
        finally:
            sock.close()

        assert status == _kXR_ok, f"fattr list returned status={status}"
        entries = self._parse_entries(body)
        # Wire attr name, no "user.U." prefix (see test_recurse_returns_top_level_
        # file_attrs): expect "sub/nested.txt:project".
        assert any("nested.txt" in e and e.endswith(":project") for e in entries), \
            f"nested attr 'project' not found in recurse result: {entries}"

    def test_recurse_flag_absent_does_not_list_children(self) -> None:
        """Without kXR_fa_recurse, listing a directory uses single-file semantics
        (the directory's own xattrs only, not its children's attrs)."""
        sock = _raw_session(ANON_HOST, ANON_PORT)
        try:
            # options=0: no recurse — directory has no user.U.* xattrs itself
            status, body = self._send_fattr_list(
                sock, "/" + self.dir_name, 0)
        finally:
            sock.close()

        assert status == _kXR_ok, f"fattr list returned status={status}"
        entries = self._parse_entries(body)
        # Children's attributes must not appear when recurse is not requested
        assert not any("top.txt" in e for e in entries), \
            f"child file attr appeared without recurse flag: {entries}"
        assert not any("nested.txt" in e for e in entries), \
            f"nested file attr appeared without recurse flag: {entries}"
