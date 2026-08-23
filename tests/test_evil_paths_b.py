from split_continuation import reexport as _reexport
_reexport(globals(), "_test_evil_paths_helpers")

class TestS3EvilWrites:
    BUCKET = "testbucket"

    def test_write_escapes_blocked(self, write_zone):
        z = write_zone
        sd, sf, zb = z["sl_dir"], z["sl_file"], z["zone_base"]
        attacks = []
        if sd:
            attacks += [("PUT", f"/{self.BUCKET}/{sd}/PWNED_{uuid.uuid4().hex}", b"x"),
                        ("DELETE", f"/{self.BUCKET}/{sd}/victim.txt", None)]
        if sf:
            attacks += [("PUT", f"/{self.BUCKET}/{sf}", b"x"),
                        ("DELETE", f"/{self.BUCKET}/{sf}", None)]
        attacks += [
            ("PUT", f"/{self.BUCKET}/../{zb}/PWNED_{uuid.uuid4().hex}", b"x"),
            ("PUT", f"/{self.BUCKET}/%2e%2e/{zb}/PWNED_{uuid.uuid4().hex}", b"x"),
            ("DELETE", f"/{self.BUCKET}/../{zb}/victim.txt", None),
        ]
        for method, path, b in attacks:
            try:
                _raw(NGINX_S3_PORT, method, path, body=b)
            except OSError:
                pass
        _assert_zone_pristine(z)


# --- root:// evil writes -----------------------------------------------------

class TestRootEvilWrites:

    def _op(self, s, opcode, path, body=b"\x00" * 16, open_opts=None):
        p = path.encode() + b"\x00"
        try:
            if open_opts is not None:
                s.sendall(make_open_req(p, options=open_opts))
            else:
                s.sendall(make_request(b"\x00\xA0", opcode, body=body, payload=p))
            st, _ = _recv_response(s)
            return st, s
        except (socket.timeout, ConnectionError, OSError):
            s = _connect(); _full_anon_login(s)
            return None, s

    def _dir_targets(self, name):
        if not name:
            return []
        suffix = uuid.uuid4().hex
        return [
            (kXR_open, f"/{name}/PWNED_{suffix}", kXR_new | kXR_open_updt),
            (kXR_mkdir, f"/{name}/pwndir_{suffix}", None),
            (kXR_rm, f"/{name}/victim.txt", None),
        ]

    def _file_targets(self, name):
        if not name:
            return []
        return [
            (kXR_open, f"/{name}", kXR_new | kXR_open_updt),
            (kXR_truncate, f"/{name}", None),
        ]

    def _traversal_targets(self, zone_base):
        suffix = uuid.uuid4().hex
        return [
            (kXR_open, f"/../{zone_base}/PWNED_{suffix}", kXR_new | kXR_open_updt),
            (kXR_mkdir, f"/../{zone_base}/pwndir_{suffix}", None),
            (kXR_rm, f"/../{zone_base}/victim.txt", None),
            (kXR_rmdir, f"/../{zone_base}", None),
        ]

    def _assert_writes_blocked(self, connection, targets):
        for opcode, path, options in targets:
            status, connection = self._op(
                connection, opcode, path, open_opts=options
            )
            assert status != kXR_ok, (
                f"root write {path!r} (op {opcode}) succeeded — escape!"
            )
        return connection

    def _remove_file_symlink(self, connection, name):
        if not name:
            return connection
        status, connection = self._op(connection, kXR_rm, f"/{name}")
        assert status == kXR_ok, f"rm of in-root symlink /{name} should remove the link"
        return connection

    def _move_destinations(self, dir_symlink, zone_base):
        destinations = [f"/../{zone_base}/moved"]
        if dir_symlink:
            destinations.insert(0, f"/{dir_symlink}/moved")
        return destinations

    def _move(self, connection, zone, destination):
        payload = (f"/{zone['src_key']}\n{destination}").encode() + b"\x00"
        try:
            connection.sendall(
                make_request(
                    b"\x00\xA0", kXR_mv, body=b"\x00" * 16, payload=payload
                )
            )
            status, _ = _recv_response(connection)
            return status, connection
        except (socket.timeout, ConnectionError, OSError):
            connection = _connect()
            _full_anon_login(connection)
            return 4003, connection

    def _assert_moves_blocked(self, connection, zone, destinations):
        for destination in destinations:
            status, connection = self._move(connection, zone, destination)
            assert status != kXR_ok, (
                f"root mv to {destination!r} succeeded — escape!"
            )
        return connection

    def test_write_escapes_blocked(self, write_zone):
        z = write_zone
        sd, sf, zb = z["sl_dir"], z["sl_file"], z["zone_base"]
        s = _connect(); _full_anon_login(s)
        targets = self._dir_targets(sd)
        targets.extend(self._file_targets(sf))
        targets.extend(self._traversal_targets(zb))
        s = self._assert_writes_blocked(s, targets)
        s = self._remove_file_symlink(s, sf)
        s = self._assert_moves_blocked(s, z, self._move_destinations(sd, zb))
        s.close()
        _assert_zone_pristine(z)
