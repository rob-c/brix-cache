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

    def test_write_escapes_blocked(self, write_zone):
        z = write_zone
        sd, sf, zb = z["sl_dir"], z["sl_file"], z["zone_base"]
        s = _connect(); _full_anon_login(s)

        targets = []
        if sd:
            targets += [
                (kXR_open, f"/{sd}/PWNED_{uuid.uuid4().hex}", kXR_new | kXR_open_updt),
                (kXR_mkdir, f"/{sd}/pwndir_{uuid.uuid4().hex}", None),
                (kXR_rm, f"/{sd}/victim.txt", None),
            ]
        if sf:
            targets += [
                (kXR_open, f"/{sf}", kXR_new | kXR_open_updt),   # create/trunc victim
                (kXR_truncate, f"/{sf}", None),
                # NOTE: kXR_rm of the symlink itself is NOT an escape — unlink operates
                # on the in-root link (lstat/POSIX semantics), never the external target.
                # It legitimately succeeds; checked separately below, and
                # _assert_zone_pristine proves the victim survived.
            ]
        # pure "../" escapes into the writable zone
        targets += [
            (kXR_open, f"/../{zb}/PWNED_{uuid.uuid4().hex}", kXR_new | kXR_open_updt),
            (kXR_mkdir, f"/../{zb}/pwndir_{uuid.uuid4().hex}", None),
            (kXR_rm, f"/../{zb}/victim.txt", None),
            (kXR_rmdir, f"/../{zb}", None),
        ]
        for opcode, path, opts in targets:
            st, s = self._op(s, opcode, path, open_opts=opts)
            assert st != kXR_ok, f"root write {path!r} (op {opcode}) succeeded — escape!"

        # rm of the in-root symlink-to-victim must SUCCEED (removes the link only) and
        # must NOT delete the external victim — that is the real confinement property.
        if sf:
            st, s = self._op(s, kXR_rm, f"/{sf}")
            assert st == kXR_ok, f"rm of in-root symlink /{sf} should remove the link"

        # kXR_mv: move an in-root file OUT (src in root, dst escaping)
        for dst in ([f"/{sd}/moved"] if sd else []) + [f"/../{zb}/moved"]:
            payload = (f"/{z['src_key']}\n{dst}").encode() + b"\x00"
            try:
                s.sendall(make_request(b"\x00\xA0", kXR_mv,
                                       body=b"\x00" * 16, payload=payload))
                st, _ = _recv_response(s)
            except (socket.timeout, ConnectionError, OSError):
                s = _connect(); _full_anon_login(s); st = 4003
            assert st != kXR_ok, f"root mv to {dst!r} succeeded — escape!"

        s.close()
        _assert_zone_pristine(z)
