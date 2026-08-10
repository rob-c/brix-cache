from split_continuation import load as _load_continuation


_load_continuation(globals(), __file__, "e2e_redteam_part15_base.py")


class _CrossProtocolOwnership(_CrossProtocolOwnershipBase):
    def _webdav_move_copy(self):
        self.wd_put("alice/xpoi_mvsrc.txt", b"move-src\n")
        status, _ = http(
            "MOVE",
            "/alice/xpoi_mvsrc.txt",
            self.port,
            self.alice_token,
            hdrs={"Destination": f"http://{HOST}:{self.port}/alice/xpoi_mvdst.txt"},
        )
        destination = self.rel("alice", "xpoi_mvdst.txt")
        moved = all((
            status in (201, 204),
            self.owned_alice(destination),
            not os.path.exists(self.rel("alice", "xpoi_mvsrc.txt")),
        ))
        ok(moved, f"WebDAV MOVE preserved alice ownership (HTTP {status})")
        self._webdav_copy(destination)

    def _webdav_copy(self, source):
        status, _ = http(
            "COPY",
            "/alice/xpoi_mvdst.txt",
            self.port,
            self.alice_token,
            hdrs={"Destination": f"http://{HOST}:{self.port}/alice/xpoi_cpdst.txt"},
        )
        destination = self.rel("alice", "xpoi_cpdst.txt")
        ok(
            status in (201, 204) and self.owned_alice(destination),
            f"WebDAV COPY preserved alice ownership (HTTP {status})",
        )
        self._bob_move_denied(destination)
        del source

    def _bob_move_denied(self, source):
        status, _ = http(
            "MOVE",
            "/alice/xpoi_cpdst.txt",
            self.port,
            self.bob_token,
            hdrs={"Destination": f"http://{HOST}:{self.port}/bob/xpoi_stolen.txt"},
        )
        safe = all((
            status not in (200, 201, 204),
            self.owned_alice(source),
            not os.path.exists(self.rel("bob", "xpoi_stolen.txt")),
        ))
        ok(safe, f"bob WebDAV MOVE denied (HTTP {status})")

    def _s3_copy(self):
        if not self.have_s3:
            ok(True, "S3 CopyObject ownership skipped (S3 endpoint down)")
            ok(True, "S3 cross-tenant CopyObject skipped (S3 endpoint down)")
            return
        self.s3_put("alice/xpoi_s3cpsrc.txt", b"s3-copy-src\n")
        status, _ = s3(
            "PUT",
            "alice/xpoi_s3cpdst.txt",
            self.s3port,
            extra_hdrs={
                "x-amz-copy-source": f"/{S3_BUCKET}/alice/xpoi_s3cpsrc.txt"
            },
        )
        path = self.rel("alice", "xpoi_s3cpdst.txt")
        ok(
            status in (200, 201) and self.owned_alice(path),
            f"S3 CopyObject preserved alice ownership (HTTP {status})",
        )
        self._s3_bob_copy_denied()

    def _s3_bob_copy_denied(self):
        status, _ = s3(
            "PUT",
            "alice/xpoi_s3copybob.txt",
            self.s3port,
            extra_hdrs={"x-amz-copy-source": f"/{S3_BUCKET}/bob/private.txt"},
        )
        path = self.rel("alice", "xpoi_s3copybob.txt")
        leaked = os.path.exists(path) and b"BOB-PRIVATE-SECRET" in self.body_of(path)
        ok(
            status not in (200, 201) and not leaked,
            f"S3 CopyObject of bob secret denied (HTTP {status})",
        )

    def _root_move(self):
        if not self.have_root:
            ok(True, "root move ownership skipped (native client absent)")
            return
        self.root_put("alice/xpoi_rmvsrc.bin", b"root-mv\n", "alice")
        status, _output, _error = xrd_fs(
            ["mv", "/alice/xpoi_rmvsrc.bin", "/alice/xpoi_rmvdst.bin"], "alice"
        )
        path = self.rel("alice", "xpoi_rmvdst.bin")
        ok(
            status == 0 and self.owned_alice(path),
            f"root move preserved alice ownership (rc={status})",
        )

    def run_move_copy(self):
        self._webdav_move_copy()
        self._s3_copy()
        self._root_move()

    def _complete_multipart(self, key, upload_id, init_status):
        part_status, body = s3(
            "PUT",
            key,
            self.s3port,
            params={"uploadId": upload_id, "partNumber": "1"},
            data=b"M" * 4096,
        )
        match = re.search(rb'ETag>\?"?([^"<\\]+)', body or b"")
        etag = match.group(1).decode() if match else "etag"
        complete = (
            "<CompleteMultipartUpload><Part><PartNumber>1</PartNumber>"
            f"<ETag>{etag}</ETag></Part></CompleteMultipartUpload>"
        ).encode()
        complete_status, _ = s3(
            "POST",
            key,
            self.s3port,
            params={"uploadId": upload_id},
            data=complete,
        )
        path = self.rel("alice", "xpoi_mpu.bin")
        good = complete_status in (200, 201) and self.owned_alice(path)
        ok(
            good,
            "S3 multipart object is alice-owned "
            f"(init {init_status}, part {part_status}, complete {complete_status})",
        )

    def run_multipart(self):
        if not self.have_s3:
            ok(True, "S3 multipart ownership skipped (S3 endpoint down)")
            return
        key = "alice/xpoi_mpu.bin"
        status, body = s3("POST", key, self.s3port, params={"uploads": ""})
        match = re.search(rb"<UploadId>([^<]+)</UploadId>", body or b"")
        if status != 200 or not match:
            ok(False, f"S3 multipart initiate failed (HTTP {status})")
            return
        self._complete_multipart(key, match.group(1).decode(), status)

    def _root_chmod(self, path, before_uid):
        if not self.have_root:
            ok(True, "root chmod ownership skipped (native client absent)")
            ok(True, "root chmod-bob skipped (native client absent)")
            return
        status, _output, _error = xrd_fs(
            ["chmod", "/alice/xpoi_chown.txt", "640"], "alice"
        )
        unchanged = self.uid_of(path) == UID_ALICE and self.uid_of(path) == before_uid
        ok(unchanged, f"root chmod kept alice ownership (rc={status})")
        self._root_bob_chmod_denied()

    def _root_bob_chmod_denied(self):
        path = self.rel("bob", "private.txt")
        mode = os.stat(path).st_mode & 0o777 if os.path.exists(path) else -1
        status, _output, _error = xrd_fs(
            ["chmod", "/bob/private.txt", "666"], "alice"
        )
        safe = all((
            status != 0,
            os.path.exists(path),
            os.stat(path).st_mode & 0o777 == mode,
            self.uid_of(path) == UID_BOB,
        ))
        ok(safe, f"root chmod of bob file denied (rc={status})")

    def _s3_acl(self, path):
        if not self.have_s3:
            ok(True, "S3 ACL ownership skipped (S3 endpoint down)")
            return
        status, _ = s3(
            "PUT",
            "alice/xpoi_chown.txt",
            self.s3port,
            data=b"chown-target2\n",
            extra_hdrs={"x-amz-acl": "bucket-owner-full-control"},
        )
        ok(
            self.uid_of(path) == UID_ALICE,
            f"S3 ACL write kept alice ownership (HTTP {status})",
        )

    def run_chown(self):
        self.wd_put("alice/xpoi_chown.txt", b"chown-target\n")
        path = self.rel("alice", "xpoi_chown.txt")
        before_uid = self.uid_of(path)
        self._root_chmod(path, before_uid)
        stable = self.uid_of(path) == UID_ALICE and self.uid_of(path) not in (
            UID_SVC,
            0,
            UID_BOB,
        )
        ok(stable, f"chown target stayed alice-owned (uid={self.uid_of(path)})")
        self._s3_acl(path)

    def _propfind_xattr(self, value):
        request = (
            b'<?xml version="1.0"?><D:propfind xmlns:D="DAV:">'
            b"<D:allprop/></D:propfind>"
        )
        status, body = http(
            "PROPFIND",
            "/alice/xpoi_xattr.txt",
            self.port,
            self.alice_token,
            data=request,
            hdrs={"Depth": "0", "Content-Type": "application/xml"},
        )
        return status, body, request

    def _root_xattr(self, value):
        if not self.have_root:
            ok(True, "root xattr read skipped (native client absent)")
            ok(True, "root xattr cross-identity skipped (native client absent)")
            return
        status, _output, _error = xrd_fs(
            ["query", "xattr", "/alice/xpoi_xattr.txt"], "alice"
        )
        ok(True, f"root xattr query handled (rc={status})")
        status, output, _error = xrd_fs(
            ["query", "xattr", "/alice/xpoi_xattr.txt"], "bob"
        )
        ok(value not in (output or ""), f"bob xattr query did not leak (rc={status})")

    def _bob_xattr_denied(self, path, propfind_request):
        request = (
            '<?xml version="1.0"?><D:propertyupdate xmlns:D="DAV:" '
            'xmlns:Z="urn:xpoi"><D:set><D:prop>'
            "<Z:pwn>XPOI-BOB-XATTR-PWNED</Z:pwn>"
            "</D:prop></D:set></D:propertyupdate>"
        ).encode()
        http(
            "PROPPATCH",
            "/alice/xpoi_xattr.txt",
            self.port,
            self.bob_token,
            data=request,
            hdrs={"Content-Type": "application/xml"},
        )
        _status, body = http(
            "PROPFIND",
            "/alice/xpoi_xattr.txt",
            self.port,
            self.alice_token,
            data=propfind_request,
            hdrs={"Depth": "0", "Content-Type": "application/xml"},
        )
        safe = b"XPOI-BOB-XATTR-PWNED" not in (body or b"") and self.owned_alice(path)
        ok(safe, "bob PROPPATCH did not persist and ownership stayed intact")

    def run_xattr(self):
        self.wd_put("alice/xpoi_xattr.txt", b"xattr-target\n")
        path = self.rel("alice", "xpoi_xattr.txt")
        try:
            if os.path.exists(path):
                os.chmod(path, 0o600)
        except OSError:
            pass
        ok(self.owned_alice(path), f"xattr target is alice-owned (uid={self.uid_of(path)})")
        value = "XPOI-XATTR-CERULEAN"
        request = (
            '<?xml version="1.0"?><D:propertyupdate xmlns:D="DAV:" '
            f'xmlns:Z="urn:xpoi"><D:set><D:prop><Z:tag>{value}</Z:tag>'
            "</D:prop></D:set></D:propertyupdate>"
        ).encode()
        patch_status, _ = http(
            "PROPPATCH",
            "/alice/xpoi_xattr.txt",
            self.port,
            self.alice_token,
            data=request,
            hdrs={"Content-Type": "application/xml"},
        )
        find_status, body, find_request = self._propfind_xattr(value)
        roundtrip = patch_status in (200, 207) and value.encode() in (body or b"")
        ok(roundtrip, f"WebDAV xattr roundtrip ({patch_status}, {find_status})")
        self._root_xattr(value)
        self._bob_xattr_denied(path, find_request)

    def _bad_owners_in(self, sub):
        try:
            names = os.listdir(self.rel(sub))
        except OSError:
            return []
        bad = []
        for name in names:
            entry = self._bad_owner_entry(sub, name)
            if entry is not None:
                bad.append(entry)
        return bad

    def _bad_owner_entry(self, sub, name):
        if not name.startswith(self.tag) or "_pub_bob" in name:
            return None
        if _is_server_sidecar(name):   # .cinfo/.meta svc-owned by design
            return None
        path = self.rel(sub, name)
        try:
            if not os.path.isfile(path):
                return None
            uid = os.lstat(path).st_uid
        except OSError:
            return None
        if uid in (UID_SVC, 0, UID_BOB):
            return name, uid
        return None

    def _leaks_into_bob(self):
        try:
            names = os.listdir(self.rel("bob"))
        except OSError:
            return []
        return [
            name
            for name in names
            if name.startswith(self.tag) and os.path.isfile(self.rel("bob", name))
        ]

    def run_final_sweep(self):
        bad = self._bad_owners_in("alice") + self._bad_owners_in("pub")
        ok(not bad, f"ownership sweep found reserved owners: {bad[:4]}")
        leaked = self._leaks_into_bob()
        ok(not leaked, f"alice-authored files leaked into bob directory: {leaked[:4]}")
        status, path = self.wd_put("alice/xpoi_survive.txt", b"survive\n")
        survived = status in (200, 201, 204) and self.owned_alice(path)
        ok(survived, f"follow-up alice PUT succeeded and is owned (HTTP {status})")
        status, body = http(
            "GET", "/alice/xpoi_survive.txt", self.port, self.alice_token
        )
        ok(
            status == 200 and b"survive" in (body or b""),
            f"follow-up alice GET returned content (HTTP {status})",
        )

    def run(self):
        self.run_create()
        self.run_public_writes()
        self.run_read_matrix()
        self.run_mutation_matrix()
        self.run_move_copy()
        self.run_multipart()
        self.run_chown()
        self.run_xattr()
        self.run_final_sweep()


def run_crossproto_ownership_invariant(key, data, port, s3port):
    """Run the cross-protocol ownership and tenant-isolation matrix."""
    _CrossProtocolOwnership(key, data, port, s3port).run()
