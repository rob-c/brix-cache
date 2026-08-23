class _ConcurrentCrossProtocol:
    TAG = "ccxp"
    SIZE = 48 * 1024
    SECRET = b"CCXP-A-SIBLING-SECRET-" + b"S" * 256

    def __init__(self, key, data, port, s3port):
        self.data = data
        self.port = port
        self.s3port = s3port
        self.alice_token = mint(key, "alice")
        self.bob_token = mint(key, "bob")
        self.have_s3 = bool(s3port)
        self.have_root = xrd_avail()
        self.alice_old = self.whole("AAAA-OLD")
        self.alice_new = self.whole("AAAA-NEW")
        self.bob_value = self.whole("BBBB-BOB")

    def rel(self, *parts):
        return os.path.join(self.data, *parts)

    @staticmethod
    def uid(path):
        try:
            return os.stat(path).st_uid
        except OSError:
            return -1

    @staticmethod
    def body(path):
        try:
            with open(path, "rb") as stream:
                return stream.read()
        except OSError:
            return b""

    @classmethod
    def whole(cls, tag):
        unit = (tag + "-CCXP-WHOLE|").encode()
        return (unit * (cls.SIZE // len(unit) + 1))[:cls.SIZE]

    @staticmethod
    def is_whole(body, *candidates):
        return any(body == candidate for candidate in candidates)

    @staticmethod
    def marker_count(body):
        markers = (b"AAAA-OLD", b"AAAA-NEW", b"BBBB-BOB")
        return sum(marker in body for marker in markers)

    @staticmethod
    def run_threads(*targets):
        threads = [threading.Thread(target=target) for target in targets]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

    @staticmethod
    def chmod(path, mode):
        try:
            if os.path.exists(path):
                os.chmod(path, mode)
        except OSError:
            pass

    @staticmethod
    def write_local(path, body):
        try:
            with open(path, "wb") as stream:
                stream.write(body)
        except OSError:
            pass

    @staticmethod
    def remove(path):
        try:
            os.unlink(path)
        except OSError:
            pass

    def webdav_root_race(self):
        relative = f"alice/{self.TAG}_a_x.txt"
        disk_path = self.rel("alice", f"{self.TAG}_a_x.txt")
        status, _ = http(
            "PUT", "/" + relative, self.port, self.alice_token, self.alice_old
        )
        self.chmod(disk_path, 0o644)
        ok(status in (200, 201, 204) and self.uid(disk_path) == UID_ALICE,
           f"(a) seed alice/X is alice-owned (HTTP {status})")
        if self.have_root:
            self._run_webdav_root_race(relative, disk_path)
        else:
            self._skip("a", "root reader", 4)
        self._sibling_secret_race(relative, disk_path)

    def _run_webdav_root_race(self, relative, disk_path):
        reads, errors, torn = [], [], []
        writer = lambda: self._alternate_webdav(relative, errors)
        readers = [lambda index=index: self._root_read(
            relative, index, reads, torn
        ) for index in range(5)]
        self.run_threads(writer, *readers)
        ok(not torn, f"(a) root reads during WebDAV PUT were never torn ({torn[:2]})")
        ok(all(self.is_whole(body, self.alice_old, self.alice_new) for body in reads),
           f"(a) successful root reads were whole (n={len(reads)})")
        ok(self.uid(disk_path) == UID_ALICE,
           f"(a) raced inode stayed alice-owned ({self.uid(disk_path)})")
        ok(self.is_whole(self.body(disk_path), self.alice_old, self.alice_new),
           "(a) raced inode ended with a whole writer value")

    def _alternate_webdav(self, relative, errors):
        for _ in range(4):
            try:
                http("PUT", "/" + relative, self.port, self.alice_token, self.alice_new)
                http("PUT", "/" + relative, self.port, self.alice_token, self.alice_old)
            except Exception as error:
                errors.append(repr(error))

    def _root_read(self, relative, index, reads, torn):
        destination = os.path.join(WORK, f"{self.TAG}_a_dl_{index}.bin")
        self.remove(destination)
        status, _output, _error = xrd_cp_down("/" + relative, destination, "bob")
        if status != 0:
            return
        body = self.body(destination)
        reads.append(body)
        if self.marker_count(body) > 1:
            torn.append(len(body))

    def _sibling_secret_race(self, raced_relative, raced_path):
        relative = f"alice/{self.TAG}_a_secret.txt"
        disk_path = self.rel("alice", f"{self.TAG}_a_secret.txt")
        http("PUT", "/" + relative, self.port, self.alice_token, self.SECRET)
        self.chmod(disk_path, 0o600)
        leaked = []
        probe = lambda: self._secret_probe(relative, leaked)
        noise = lambda: self._webdav_noise(raced_relative)
        self.run_threads(probe, noise)
        ok(not leaked, "(a) bob's sibling-secret reads stayed denied")
        ok(self.SECRET[:24] not in self.body(raced_path),
           "(a) sibling-secret bytes never bled into raced file")

    def _secret_probe(self, relative, leaked):
        for _ in range(6):
            status, body = http("GET", "/" + relative, self.port, self.bob_token)
            if status == 200 or self.SECRET[:24] in (body or b""):
                leaked.append(status)

    def _webdav_noise(self, relative):
        for _ in range(6):
            http("PUT", "/" + relative, self.port, self.alice_token, self.alice_new)

    def s3_webdav_race(self):
        if not self.have_s3:
            self._skip("b", "S3/WebDAV race", 5)
            return
        relative = f"alice/{self.TAG}_b_obj.txt"
        disk_path = self.rel("alice", f"{self.TAG}_b_obj.txt")
        s3("PUT", relative, self.s3port, data=self.alice_old)
        reads, errors, torn = [], [], []
        writer = lambda: self._alternate_s3(relative, errors)
        readers = [lambda: self._webdav_read(relative, reads, torn) for _ in range(5)]
        self.run_threads(writer, *readers)
        self._assert_s3_webdav_race(disk_path, reads, errors, torn)

    def _alternate_s3(self, relative, errors):
        for _ in range(4):
            try:
                s3("PUT", relative, self.s3port, data=self.alice_new)
                s3("PUT", relative, self.s3port, data=self.alice_old)
            except Exception as error:
                errors.append(repr(error))

    def _webdav_read(self, relative, reads, torn):
        status, body = http("GET", "/" + relative, self.port, self.alice_token)
        if status != 200 or not body:
            return
        reads.append(body)
        if self.marker_count(body) > 1:
            torn.append(len(body))

    def _assert_s3_webdav_race(self, disk_path, reads, errors, torn):
        ok(not torn, f"(b) WebDAV reads during S3 PUT were never torn ({torn[:2]})")
        ok(all(self.is_whole(body, self.alice_old, self.alice_new) for body in reads),
           f"(b) successful WebDAV reads were whole (n={len(reads)})")
        ok(self.uid(disk_path) == UID_ALICE,
           f"(b) cross-protocol object stayed alice-owned ({self.uid(disk_path)})")
        ok(self.is_whole(self.body(disk_path), self.alice_old, self.alice_new),
           "(b) S3/WebDAV-raced inode ended whole")
        ok(not errors, f"(b) S3/WebDAV race raised no exceptions ({errors[:2]})")

    def root_s3_race(self):
        if not self.have_root or not self.have_s3:
            self._skip("c", "root/S3 race", 5)
            return
        relative = f"alice/{self.TAG}_c_path.bin"
        disk_path = self.rel("alice", f"{self.TAG}_c_path.bin")
        s3("PUT", relative, self.s3port, data=self.alice_old)
        new_path = os.path.join(WORK, f"{self.TAG}_c_new.bin")
        old_path = os.path.join(WORK, f"{self.TAG}_c_old.bin")
        self.write_local(new_path, self.alice_new)
        self.write_local(old_path, self.alice_old)
        reads, torn = [], []
        writer = lambda: self._alternate_root(relative, new_path, old_path)
        readers = [lambda: self._s3_read(relative, reads, torn) for _ in range(5)]
        self.run_threads(writer, *readers)
        self._assert_root_s3_race(disk_path, reads, torn)

    def _alternate_root(self, relative, new_path, old_path):
        for _ in range(4):
            xrd_cp_up(new_path, "/" + relative, "alice")
            xrd_cp_up(old_path, "/" + relative, "alice")

    def _s3_read(self, relative, reads, torn):
        status, body = s3("GET", relative, self.s3port, access_key="alice")
        if status != 200 or not body:
            return
        reads.append(body)
        if self.marker_count(body) > 1:
            torn.append(len(body))

    def _assert_root_s3_race(self, disk_path, reads, torn):
        ok(not torn, f"(c) S3 reads during root writes were never torn ({torn[:2]})")
        ok(all(self.is_whole(body, self.alice_old, self.alice_new) for body in reads),
           f"(c) successful S3 reads were whole (n={len(reads)})")
        ok(self.bob_value not in b"".join(reads),
           "(c) no foreign-tenant bytes reached the S3 reader")
        ok(self.uid(disk_path) == UID_ALICE,
           f"(c) root/S3-raced inode stayed alice-owned ({self.uid(disk_path)})")
        ok(self.is_whole(self.body(disk_path), self.alice_old, self.alice_new),
           "(c) root/S3-raced inode ended whole")

    def shared_writer_race(self):
        relative = f"pub/{self.TAG}_d_shared.bin"
        disk_path = self.rel("pub", f"{self.TAG}_d_shared.bin")
        bob_local = os.path.join(WORK, f"{self.TAG}_d_bob.bin")
        self.write_local(bob_local, self.bob_value)
        errors = []
        alice = lambda: self._alice_shared_writer(relative, errors)
        targets = [alice]
        if self.have_root:
            targets.append(lambda: self._bob_shared_writer(relative, bob_local))
        self.run_threads(*targets)
        self._assert_shared_writer_result(disk_path)
        ok(not errors, f"(d) shared-writer race raised no exceptions ({errors[:2]})")

    def _alice_shared_writer(self, relative, errors):
        for _ in range(5):
            try:
                http("PUT", "/" + relative, self.port,
                     self.alice_token, self.alice_new)
            except Exception as error:
                errors.append(repr(error))

    @staticmethod
    def _bob_shared_writer(relative, local):
        for _ in range(5):
            xrd_cp_up(local, "/" + relative, "bob")

    def _assert_shared_writer_result(self, disk_path):
        if not os.path.exists(disk_path):
            self._skip("d", "shared file missing", 4, passed=False)
            return
        owner = self.uid(disk_path)
        body = self.body(disk_path)
        candidates = [self.alice_new]
        if self.have_root:
            candidates.append(self.bob_value)
        ok(owner in (UID_ALICE, UID_BOB),
           f"(d) shared inode belongs to a mapped writer ({owner})")
        ok(self.is_whole(body, *candidates), "(d) shared inode contains one whole value")
        ok(self.marker_count(body) <= 1, "(d) shared inode contains no spliced values")
        self._assert_winning_owner(owner, body)

    def _assert_winning_owner(self, owner, body):
        if body == self.alice_new:
            ok(owner == UID_ALICE, f"(d) alice value is alice-owned ({owner})")
            return
        if self.have_root and body == self.bob_value:
            ok(owner == UID_BOB, f"(d) bob value is bob-owned ({owner})")
            return
        ok(False, "(d) shared inode has no recognized winner")

    def tenant_read_storm(self):
        alice_rel = f"alice/{self.TAG}_e_alice.txt"
        bob_rel = f"bob/{self.TAG}_e_bob.txt"
        alice_path = self.rel("alice", f"{self.TAG}_e_alice.txt")
        bob_path = self.rel("bob", f"{self.TAG}_e_bob.txt")
        http("PUT", "/" + alice_rel, self.port, self.alice_token, self.alice_new)
        http("PUT", "/" + bob_rel, self.port, self.bob_token, self.bob_value)
        self.chmod(alice_path, 0o644)
        self.chmod(bob_path, 0o644)
        ok(self.uid(alice_path) == UID_ALICE and self.uid(bob_path) == UID_BOB,
           "(e) per-tenant fixtures have correct ownership")
        cross, mismatches = [], []
        targets = self._tenant_reader_targets(alice_rel, bob_rel, cross, mismatches)
        self.run_threads(*targets)
        ok(not cross, f"(e) zero cross-tenant contamination ({cross[:3]})")
        ok(not mismatches, f"(e) each reader received its tenant bytes ({mismatches[:3]})")
        self._tenant_read_controls(alice_rel, bob_rel)
        self._secret_storm(alice_rel, bob_rel)

    def _tenant_reader_targets(self, alice_rel, bob_rel, cross, mismatches):
        return (
            lambda: self._webdav_tenant_reader(
                alice_rel, self.alice_token, self.alice_new,
                self.bob_value, "wd-alice", cross, mismatches),
            lambda: self._webdav_tenant_reader(
                bob_rel, self.bob_token, self.bob_value,
                self.alice_new, "wd-bob", cross, mismatches),
            lambda: self._s3_tenant_reader(alice_rel, cross, mismatches),
            lambda: self._root_tenant_reader(bob_rel, cross, mismatches),
        )

    def _webdav_tenant_reader(self, relative, token, expected, foreign,
                              label, cross, mismatches):
        for _ in range(4):
            status, body = http("GET", "/" + relative, self.port, token)
            self._record_tenant_read(
                label, status, body, expected, foreign, cross, mismatches
            )

    @staticmethod
    def _record_tenant_read(label, status, body, expected, foreign,
                            cross, mismatches):
        if status != 200:
            return
        if body != expected:
            mismatches.append((label, status, len(body or b"")))
        if foreign[:16] in (body or b""):
            cross.append((label, "foreign bytes"))

    def _s3_tenant_reader(self, relative, cross, mismatches):
        if not self.have_s3:
            return
        for _ in range(4):
            status, body = s3("GET", relative, self.s3port, access_key="alice")
            self._record_tenant_read(
                "s3-alice", status, body, self.alice_new,
                self.bob_value, cross, mismatches,
            )

    def _root_tenant_reader(self, relative, cross, mismatches):
        if not self.have_root:
            return
        for index in range(3):
            destination = os.path.join(WORK, f"{self.TAG}_e_root_{index}.bin")
            self.remove(destination)
            status, _output, _error = xrd_cp_down(
                "/" + relative, destination, "bob"
            )
            if status != 0:
                continue
            self._record_tenant_read(
                "root-bob", 200, self.body(destination), self.bob_value,
                self.alice_new, cross, mismatches,
            )

    def _tenant_read_controls(self, alice_rel, bob_rel):
        status, body = http("GET", "/" + alice_rel, self.port, self.alice_token)
        ok(status == 200 and body == self.alice_new,
           f"(e) WebDAV alice control returned alice bytes (HTTP {status})")
        status, body = http("GET", "/" + bob_rel, self.port, self.bob_token)
        ok(status == 200 and body == self.bob_value,
           f"(e) WebDAV bob control returned bob bytes (HTTP {status})")
        self._s3_read_control(alice_rel)
        self._root_read_control(bob_rel)

    def _s3_read_control(self, relative):
        if not self.have_s3:
            ok(True, "(e) S3 alice-read control skipped")
            return
        status, body = s3("GET", relative, self.s3port, access_key="alice")
        ok(status == 200 and body == self.alice_new,
           f"(e) S3 alice control returned alice bytes (HTTP {status})")

    def _root_read_control(self, relative):
        if not self.have_root:
            ok(True, "(e) root bob-read control skipped")
            return
        destination = os.path.join(WORK, f"{self.TAG}_e_ctrl.bin")
        self.remove(destination)
        status, _output, _error = xrd_cp_down("/" + relative, destination, "bob")
        body = self.body(destination)
        ok(status == 0 and body == self.bob_value,
           f"(e) root bob control returned bob bytes (rc={status})")

    def _secret_storm(self, alice_rel, bob_rel):
        relative = f"alice/{self.TAG}_a_secret.txt"
        disk_path = self.rel("alice", f"{self.TAG}_a_secret.txt")
        http("PUT", "/" + relative, self.port, self.alice_token, self.SECRET)
        self.chmod(disk_path, 0o600)
        leaked = []
        noise = lambda: self._read_noise(alice_rel, bob_rel)
        probe = lambda: self._secret_probe(relative, leaked)
        self.run_threads(noise, probe)
        ok(not leaked, "(e) bob's 0600-secret reads stayed denied during storm")
        status, body = http("GET", "/" + relative, self.port, self.alice_token)
        ok(status == 200 and self.SECRET[:24] in (body or b""),
           f"(e) control: alice read her secret after storm (HTTP {status})")

    def _read_noise(self, alice_rel, bob_rel):
        for _ in range(6):
            http("GET", "/" + alice_rel, self.port, self.alice_token)
            if self.have_s3:
                s3("GET", bob_rel, self.s3port, access_key="alice")

    def survival(self):
        relative = f"alice/{self.TAG}_f_after.txt"
        disk_path = self.rel("alice", f"{self.TAG}_f_after.txt")
        body = b"CCXP-AFTER-WEBDAV\n"
        status, _ = http("PUT", "/" + relative, self.port, self.alice_token, body)
        ok(status in (200, 201, 204) and self.uid(disk_path) == UID_ALICE,
           f"(f) WebDAV PUT survived and is alice-owned (HTTP {status})")
        status, received = http("GET", "/" + relative, self.port, self.alice_token)
        ok(status == 200 and received == body,
           f"(f) WebDAV GET survived byte-exact (HTTP {status})")
        self._s3_survival()
        self._root_survival(relative)
        self._assert_no_service_residue()

    def _s3_survival(self):
        if not self.have_s3:
            ok(True, "(f) S3 survival skipped")
            return
        relative = f"alice/{self.TAG}_f_s3.txt"
        status, _ = s3("PUT", relative, self.s3port, data=b"CCXP-AFTER-S3\n")
        path = self.rel("alice", f"{self.TAG}_f_s3.txt")
        ok(status in (200, 201) and self.uid(path) == UID_ALICE,
           f"(f) S3 PUT survived and is alice-owned (HTTP {status})")

    def _root_survival(self, relative):
        if not self.have_root:
            self._skip("f", "root survival", 2)
            return
        status, _output, _error = xrd_fs(["stat", "/" + relative], "alice")
        ok(status == 0, f"(f) root stat survived (rc={status})")
        local = os.path.join(WORK, f"{self.TAG}_f_root.bin")
        self.write_local(local, b"CCXP-AFTER-ROOT\n")
        status, _output, _error = xrd_cp_up(
            local, f"/alice/{self.TAG}_f_root.bin", "alice"
        )
        path = self.rel("alice", f"{self.TAG}_f_root.bin")
        ok(status == 0 and self.uid(path) == UID_ALICE,
           f"(f) root write survived and is alice-owned (rc={status})")

    def _assert_no_service_residue(self):
        residue = []
        for tenant in ("alice", "bob"):
            residue.extend(self._service_residue(tenant))
        ok(not residue, f"(f) no svc/root residue under tenant trees ({residue[:3]})")

    def _service_residue(self, tenant):
        directory = self.rel(tenant)
        try:
            names = os.listdir(directory)
        except OSError:
            return []
        paths = (os.path.join(directory, name)
                 for name in names if name.startswith(self.TAG))
        return [(tenant, os.path.basename(path), self.uid(path))
                for path in paths if self.uid(path) in (UID_SVC, 0)]

    @staticmethod
    def _skip(section, reason, count, passed=True):
        for index in range(count):
            ok(passed, f"({section}) {reason} ({index + 1}/{count})")

    def run(self):
        self.webdav_root_race()
        self.s3_webdav_race()
        self.root_s3_race()
        self.shared_writer_race()
        self.tenant_read_storm()
        self.survival()


def run_combo_concurrent_crossproto(key, data, port, s3port):
    """Exercise concurrent access to shared resources across protocols."""
    _ConcurrentCrossProtocol(key, data, port, s3port).run()
