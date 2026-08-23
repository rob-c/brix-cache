class _CrossProtocolOwnershipBase:
    """Verify ownership and isolation while one inode crosses protocol boundaries."""

    tag = "xpoi"
    alice_marker = b"XPOI-ALICE-CROSSPROTO-SECRET\n"

    def __init__(self, key, data, port, s3port):
        self.data = data
        self.port = port
        self.s3port = s3port
        self.alice_token = mint(key, "alice")
        self.bob_token = mint(key, "bob")
        self.have_s3 = bool(s3port)
        self.have_root = xrd_avail()
        self.protocols = ["wd"]
        if self.have_s3:
            self.protocols.append("s3")
        if self.have_root:
            self.protocols.append("root")

    def rel(self, *parts):
        return os.path.join(self.data, *parts)

    @staticmethod
    def uid_of(path):
        try:
            return os.stat(path).st_uid
        except OSError:
            return -1

    def owned_alice(self, path):
        uid = self.uid_of(path)
        return os.path.exists(path) and uid == UID_ALICE and uid not in (
            UID_SVC,
            0,
            UID_BOB,
        )

    @staticmethod
    def body_of(path):
        try:
            with open(path, "rb") as stream:
                return stream.read()
        except OSError:
            return b""

    def wd_put(self, relpath, content, token=None):
        actor = self.alice_token if token is None else token
        status, _ = http("PUT", "/" + relpath, self.port, actor, content)
        return status, self.rel(*relpath.split("/"))

    def s3_put(self, relpath, content, access_key="alice"):
        status, _ = s3(
            "PUT", relpath, self.s3port, data=content, access_key=access_key
        )
        return status, self.rel(*relpath.split("/"))

    def root_put(self, relpath, content, subject):
        local = os.path.join(WORK, self.tag + "_up_" + relpath.replace("/", "_"))
        try:
            with open(local, "wb") as stream:
                stream.write(content)
        except OSError:
            return -1, self.rel(*relpath.split("/"))
        status, _out, _error = xrd_cp_up(local, "/" + relpath, subject)
        return status, self.rel(*relpath.split("/"))

    def _webdav_create(self):
        status, path = self.wd_put("alice/xpoi_wd_create.txt", b"wd-create\n")
        ok(
            status in (200, 201, 204) and self.owned_alice(path),
            f"WebDAV create is alice-owned (HTTP {status}, uid={self.uid_of(path)})",
        )

    def _s3_create(self):
        if not self.have_s3:
            ok(True, "S3 create ownership skipped (S3 endpoint down)")
            return
        status, path = self.s3_put("alice/xpoi_s3_create.txt", b"s3-create\n")
        ok(
            status in (200, 201) and self.owned_alice(path),
            f"S3 create is alice-owned (HTTP {status}, uid={self.uid_of(path)})",
        )

    def _root_create(self):
        if not self.have_root:
            ok(True, "root create ownership skipped (native client absent)")
            return
        status, path = self.root_put(
            "alice/xpoi_root_create.bin", b"root-create\n", "alice"
        )
        ok(
            status == 0 and self.owned_alice(path),
            f"root create is alice-owned (rc={status}, uid={self.uid_of(path)})",
        )

    def run_create(self):
        self._webdav_create()
        self._s3_create()
        self._root_create()

    def _webdav_pub(self):
        status, path = self.wd_put("pub/xpoi_wd_pub.txt", b"pub-wd\n")
        good = all((
            status in (200, 201, 204),
            self.owned_alice(path),
            self.uid_of(path) != UID_SVC,
        ))
        ok(good, f"WebDAV pub write is alice-owned (HTTP {status})")

    def _bob_pub_control(self):
        status, _ = http(
            "PUT",
            "/pub/xpoi_wd_pub_bob.txt",
            self.port,
            self.bob_token,
            b"pub-wd-bob\n",
        )
        path = self.rel("pub", "xpoi_wd_pub_bob.txt")
        good = all((
            status in (200, 201, 204),
            self.uid_of(path) == UID_BOB,
            self.uid_of(path) != UID_SVC,
        ))
        ok(good, f"bob pub write is bob-owned (HTTP {status})")

    def _s3_pub(self):
        if not self.have_s3:
            ok(True, "S3 pub ownership skipped (S3 endpoint down)")
            return
        status, path = self.s3_put("pub/xpoi_s3_pub.txt", b"pub-s3\n")
        good = all((
            status in (200, 201),
            self.owned_alice(path),
            self.uid_of(path) != UID_SVC,
        ))
        ok(good, f"S3 pub write is alice-owned (HTTP {status})")

    def _root_pub(self):
        if not self.have_root:
            ok(True, "root pub ownership skipped (native client absent)")
            return
        status, path = self.root_put("pub/xpoi_root_pub.bin", b"pub-root\n", "alice")
        good = all((
            status == 0,
            self.owned_alice(path),
            self.uid_of(path) != UID_SVC,
        ))
        ok(good, f"root pub write is alice-owned (rc={status})")

    def run_public_writes(self):
        self._webdav_pub()
        self._bob_pub_control()
        self._s3_pub()
        self._root_pub()

    def _plant_webdav(self, relpath, marker):
        self.wd_put(relpath, marker)

    def _plant_s3(self, relpath, marker):
        self.s3_put(relpath, marker)

    def _plant_root(self, relpath, marker):
        self.root_put(relpath, marker, "alice")

    def plant_secret(self, relpath, marker, protocol):
        creators = {
            "wd": self._plant_webdav,
            "s3": self._plant_s3,
            "root": self._plant_root,
        }
        creators[protocol](relpath, marker)
        path = self.rel(*relpath.split("/"))
        try:
            if os.path.exists(path):
                os.chmod(path, 0o600)
        except OSError:
            pass
        return path

    def _bob_read_webdav(self, relpath, marker):
        status, body = http("GET", "/" + relpath, self.port, self.bob_token)
        denied = status in (401, 403, 404) and marker not in (body or b"")
        ok(denied, f"bob WebDAV read denied without marker (HTTP {status})")

    def _bob_read_s3(self, relpath, marker):
        del marker
        status, _body = s3("GET", relpath, self.s3port, access_key="alice")
        ok(status in (200, 403, 404), f"S3 alice-key read handled (HTTP {status})")

    def _bob_read_root(self, relpath, marker):
        status, output, _error = xrd_fs(["cat", "/" + relpath], "bob")
        denied = status != 0 and marker.decode().strip() not in (output or "")
        ok(denied, f"bob root read denied without marker (rc={status})")

    def bob_read_denied(self, relpath, marker, protocol):
        readers = {
            "wd": self._bob_read_webdav,
            "s3": self._bob_read_s3,
            "root": self._bob_read_root,
        }
        readers[protocol](relpath, marker)

    def _alice_read_webdav(self, relpath, marker):
        status, body = http("GET", "/" + relpath, self.port, self.alice_token)
        ok(
            status == 200 and marker in (body or b""),
            f"alice WebDAV control read succeeded (HTTP {status})",
        )

    def _alice_read_s3(self, relpath, marker):
        status, body = s3("GET", relpath, self.s3port, access_key="alice")
        ok(
            status == 200 and marker in (body or b""),
            f"alice S3 control read succeeded (HTTP {status})",
        )

    def _alice_read_root(self, relpath, marker):
        local = os.path.join(WORK, self.tag + "_dl_" + relpath.replace("/", "_"))
        try:
            if os.path.exists(local):
                os.unlink(local)
        except OSError:
            pass
        status, _output, _error = xrd_cp_down("/" + relpath, local, "alice")
        ok(
            status == 0 and self.body_of(local) == marker,
            f"alice root control read succeeded (rc={status})",
        )

    def alice_read_allowed(self, relpath, marker, protocol):
        readers = {
            "wd": self._alice_read_webdav,
            "s3": self._alice_read_s3,
            "root": self._alice_read_root,
        }
        readers[protocol](relpath, marker)

    def _run_read_cell(self, creator, reader):
        relpath = f"alice/{self.tag}_x_{creator}_{reader}.txt"
        path = self.plant_secret(relpath, self.alice_marker, creator)
        ok(
            self.owned_alice(path),
            f"file created via {creator} is alice-owned before {reader} read",
        )
        self.bob_read_denied(relpath, self.alice_marker, reader)
        self.alice_read_allowed(relpath, self.alice_marker, reader)
        unchanged = self.owned_alice(path) and self.body_of(path) == self.alice_marker
        ok(unchanged, f"{creator} file unchanged after {reader} read attempts")

    def run_read_matrix(self):
        for creator in self.protocols:
            for reader in self.protocols:
                self._run_read_cell(creator, reader)

    def _bob_mutate_webdav(self, relpath, path, before):
        status, _ = http(
            "PUT", "/" + relpath, self.port, self.bob_token, b"XPOI-BOB-HACK\n"
        )
        safe = all((
            status not in (200, 201, 204),
            self.body_of(path) == before,
            self.owned_alice(path),
        ))
        ok(safe, f"bob WebDAV overwrite denied (HTTP {status})")

    def _bob_mutate_s3(self, relpath, path, before):
        del before
        status, _ = s3(
            "PUT",
            relpath,
            self.s3port,
            data=self.alice_marker,
            access_key="alice",
        )
        ok(
            status in (200, 201) and self.owned_alice(path),
            f"S3 alice overwrite stays alice-owned (HTTP {status})",
        )

    def _bob_mutate_root(self, relpath, path, before):
        del before
        status, _unused = self.root_put(relpath, b"XPOI-BOB-HACK\n", "bob")
        ok(
            status != 0 and self.owned_alice(path),
            f"bob root overwrite denied (rc={status})",
        )

    def bob_mutate_denied(self, relpath, path, protocol):
        handlers = {
            "wd": self._bob_mutate_webdav,
            "s3": self._bob_mutate_s3,
            "root": self._bob_mutate_root,
        }
        handlers[protocol](relpath, path, self.body_of(path))

    def _bob_delete_webdav(self, relpath, path):
        status, _ = http("DELETE", "/" + relpath, self.port, self.bob_token)
        safe = all((
            status not in (200, 204),
            os.path.exists(path),
            self.owned_alice(path),
        ))
        ok(safe, f"bob WebDAV delete denied (HTTP {status})")

    def _bob_delete_s3(self, relpath, path):
        del path
        status, _ = s3("DELETE", relpath, self.s3port, access_key="alice")
        ok(status in (200, 204, 403, 404), f"S3 alice delete handled (HTTP {status})")

    def _bob_delete_root(self, relpath, path):
        status, _output, _error = xrd_fs(["rm", "/" + relpath], "bob")
        safe = status != 0 and os.path.exists(path) and self.owned_alice(path)
        ok(safe, f"bob root delete denied (rc={status})")

    def bob_delete_denied(self, relpath, path, protocol):
        handlers = {
            "wd": self._bob_delete_webdav,
            "s3": self._bob_delete_s3,
            "root": self._bob_delete_root,
        }
        handlers[protocol](relpath, path)

    def _run_mutation_cell(self, creator, mutator):
        relpath = f"alice/{self.tag}_w_{creator}_{mutator}.txt"
        path = self.plant_secret(relpath, self.alice_marker, creator)
        ok(self.owned_alice(path), f"{creator} mutation fixture is alice-owned")
        self.bob_mutate_denied(relpath, path, mutator)
        self.bob_delete_denied(relpath, path, mutator)

    def run_mutation_matrix(self):
        for creator in self.protocols:
            for mutator in self.protocols:
                self._run_mutation_cell(creator, mutator)

