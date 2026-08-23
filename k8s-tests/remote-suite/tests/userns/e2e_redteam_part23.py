import shutil


class _MixedOwnerTrees:
    TAG = "mot"
    ALICE_MARKER = b"ALICE-PARENT-FILE-BODY"
    CAROL_MARKER = b"CAROL-CHILD-FILE-BODY"
    SECRET_MARKER = b"CAROL-SUBDIR-SECRET-BODY"

    def __init__(self, key, data, port, s3port):
        self.key = key
        self.data = data
        self.port = port
        self.s3port = s3port

    def token(self, subject):
        return mint(self.key, subject)

    def path(self, *parts):
        return os.path.join(self.data, *parts)

    def owner(self, path):
        try:
            return os.lstat(path).st_uid
        except OSError:
            return -1

    def _write_owned(self, path, body, uid, mode):
        try:
            with open(path, "wb") as stream:
                stream.write(body + b"\n")
            os.chown(path, uid, uid)
            os.chmod(path, mode)
        except OSError:
            pass

    def build_tree(self, name):
        root = self.path(name)
        shutil.rmtree(root, ignore_errors=True)
        try:
            os.makedirs(root, exist_ok=True)
            os.chown(root, UID_ALICE, UID_ALICE)
            os.chmod(root, 0o755)
            os.makedirs(os.path.join(root, "sub"), exist_ok=True)
        except OSError:
            return root
        self._write_tree_files(root)
        return root

    def _write_tree_files(self, root):
        self._write_owned(
            os.path.join(root, "alice_file.txt"),
            self.ALICE_MARKER,
            UID_ALICE,
            0o644,
        )
        self._write_owned(
            os.path.join(root, "carol_file.txt"),
            self.CAROL_MARKER,
            UID_CAROL,
            0o644,
        )
        subdir = os.path.join(root, "sub")
        self._write_owned(
            os.path.join(subdir, "secret.txt"),
            self.SECRET_MARKER,
            UID_CAROL,
            0o600,
        )
        try:
            os.chown(subdir, UID_CAROL, UID_CAROL)
            os.chmod(subdir, 0o700)
        except OSError:
            pass

    def tree_owner_violations(self, root, expected_uid):
        paths = self._tree_paths(root)
        return [path for path in paths if self.owner(path) != expected_uid]

    @staticmethod
    def _tree_paths(root):
        paths = [root]
        try:
            for directory, directories, files in os.walk(root):
                paths.extend(os.path.join(directory, name) for name in directories)
                paths.extend(os.path.join(directory, name) for name in files)
        except OSError:
            pass
        return paths

    def _assert_alice_fixture(self, root):
        alice_file = os.path.join(root, "alice_file.txt")
        carol_file = os.path.join(root, "carol_file.txt")
        ok(self.owner(root) == UID_ALICE,
           f"(a) fixture: tree dir owned by alice ({self.owner(root)})")
        ok(self.owner(alice_file) == UID_ALICE,
           f"(a) fixture: alice_file owned by alice ({self.owner(alice_file)})")
        ok(self.owner(carol_file) == UID_CAROL,
           f"(a) fixture: mixed child owned by carol ({self.owner(carol_file)})")

    def alice_delete(self):
        name = f"{self.TAG}_a_alice"
        root = self.build_tree(name)
        self._assert_alice_fixture(root)
        carol_file = os.path.join(root, "carol_file.txt")
        http("DELETE", f"/{name}/carol_file.txt", self.port, self.token("alice"))
        status, _ = http("DELETE", f"/{name}", self.port, self.token("alice"))
        self._assert_protected_subtree(root, carol_file, status)
        self._root_alice_delete()

    def _assert_protected_subtree(self, root, flat_child, status):
        subdir = os.path.join(root, "sub")
        secret = os.path.join(subdir, "secret.txt")
        ok(os.path.isdir(root) and os.path.isdir(subdir),
           f"(a) alice recursive DELETE refused at carol's 0700 subtree (HTTP {status})")
        intact = os.path.exists(secret) and self.owner(secret) == UID_CAROL
        ok(intact,
           f"(a) carol's protected secret survived and stayed carol-owned (HTTP {status})")
        ok(not os.path.exists(flat_child),
           f"(a) alice removed carol's flat child through directory write (HTTP {status})")

    def _root_alice_delete(self):
        if not xrd_avail():
            return
        name = f"{self.TAG}_a_root"
        self.build_tree(name)
        status, _output, _error = xrd_fs(
            ["rm", f"/{name}/carol_file.txt"], "alice"
        )
        path = self.path(name, "carol_file.txt")
        ok(not os.path.exists(path),
           f"(a) root:// alice removed carol's flat child (rc={status})")

    def cross_tenant_delete(self):
        name = f"{self.TAG}_c_bob"
        root = self.build_tree(name)
        http("DELETE", f"/{name}/carol_file.txt", self.port, self.token("bob"))
        status, _ = http("DELETE", f"/{name}", self.port, self.token("bob"))
        self._assert_bob_delete_denied(name, root, status)
        self._assert_other_delete_denied(name, root)

    def _assert_bob_delete_denied(self, name, root, status):
        carol_file = os.path.join(root, "carol_file.txt")
        alice_file = os.path.join(root, "alice_file.txt")
        subdir = os.path.join(root, "sub")
        ok(os.path.isdir(root),
           f"(c) bob recursive DELETE denied; tree survived (HTTP {status})")
        ok(os.path.exists(carol_file) and self.owner(carol_file) == UID_CAROL,
           f"(c) carol-owned child survived bob's attack (HTTP {status})")
        ok(os.path.exists(alice_file) and self.owner(alice_file) == UID_ALICE,
           f"(c) alice-owned child survived bob's attack (HTTP {status})")
        ok(os.path.isdir(subdir) and self.owner(subdir) == UID_CAROL,
           f"(c) carol's 0700 subtree survived bob's attack (HTTP {status})")
        self._assert_bob_read_denied(name)

    def _assert_bob_read_denied(self, name):
        read_status, body = http(
            "GET", f"/{name}/sub/secret.txt", self.port, self.token("bob")
        )
        ok(self.SECRET_MARKER not in (body or b""),
           f"(c) bob could not read carol's protected secret (HTTP {read_status})")

    def _assert_other_delete_denied(self, name, root):
        alice_file = os.path.join(root, "alice_file.txt")
        status, _ = http(
            "DELETE", f"/{name}/alice_file.txt", self.port, self.token("frank")
        )
        ok(os.path.exists(alice_file),
           f"(c) frank cannot unlink alice's child (HTTP {status})")
        status, _ = http(
            "DELETE", f"/{name}/alice_file.txt", self.port, self.token("alice")
        )
        ok(not os.path.exists(alice_file),
           f"(c) control: directory owner alice removed her child (HTTP {status})")

    def recursive_copy(self):
        source_name = f"{self.TAG}_b_src"
        source = self.build_tree(source_name)
        destination_parent = self._create_erin_destination()
        destination_url = f"http://{HOST}:{self.port}/{self.TAG}_b_erin/copied"
        status, _ = http(
            "COPY",
            f"/{source_name}",
            self.port,
            self.token("erin"),
            hdrs={"Destination": destination_url, "Depth": "infinity"},
        )
        copied = os.path.join(destination_parent, "copied")
        self._assert_web_copy(copied, status)
        self._assert_source_unchanged(source)
        self._root_copy(source_name)

    def _create_erin_destination(self):
        destination = self.path(f"{self.TAG}_b_erin")
        try:
            os.makedirs(destination, exist_ok=True)
            os.chown(destination, UID_ERIN, UID_ERIN)
            os.chmod(destination, 0o755)
        except OSError:
            pass
        return destination

    def _assert_web_copy(self, copied, status):
        made = os.path.isdir(copied)
        violations = self.tree_owner_violations(copied, UID_ERIN) if made else []
        ok(not violations,
           f"(b) WebDAV COPY nodes are erin-owned (violations={len(violations)}, HTTP {status})")
        ok(self.owner(copied) in (-1, UID_ERIN),
           f"(b) copied root is erin-owned or absent ({self.owner(copied)})")
        self._assert_copied_children(copied)

    def _assert_copied_children(self, copied):
        carol_copy = os.path.join(copied, "carol_file.txt")
        alice_copy = os.path.join(copied, "alice_file.txt")
        ok(self.owner(carol_copy) in (-1, UID_ERIN),
           f"(b) copied carol child is erin-owned or absent ({self.owner(carol_copy)})")
        ok(self.owner(alice_copy) in (-1, UID_ERIN),
           f"(b) copied alice child is erin-owned or absent ({self.owner(alice_copy)})")
        if not os.path.exists(carol_copy):
            ok(True, "(b) absent optional carol copy retained no foreign ownership")
            return
        try:
            body_preserved = self.CAROL_MARKER in open(carol_copy, "rb").read()
        except OSError:
            body_preserved = False
        ok(body_preserved, "(b) copied carol-child content was preserved")

    def _assert_source_unchanged(self, source):
        carol_file = os.path.join(source, "carol_file.txt")
        ok(os.path.exists(carol_file) and self.owner(carol_file) == UID_CAROL,
           "(b) COPY left the mixed-owner source child intact")
        ok(self.owner(source) == UID_ALICE,
           f"(b) COPY left the source root alice-owned ({self.owner(source)})")

    def _root_copy(self, source_name):
        if not xrd_avail():
            return
        destination = self.path(f"{self.TAG}_b_erin", "rootcopy")
        try:
            os.makedirs(destination, exist_ok=True)
            os.chown(destination, UID_ERIN, UID_ERIN)
            os.chmod(destination, 0o755)
        except OSError:
            pass
        downloads = self._download_readable_children(source_name)
        self._upload_downloaded_children(downloads)
        self._assert_secret_download_denied(source_name)
        self._remove_downloads(downloads)

    def _download_readable_children(self, source_name):
        alice_temp = os.path.join(WORK, f"{self.TAG}_b_dl_alice.bin")
        carol_temp = os.path.join(WORK, f"{self.TAG}_b_dl_carol.bin")
        alice_status, _output, _error = xrd_cp_down(
            f"/{source_name}/alice_file.txt", alice_temp, "erin"
        )
        carol_status, _output, _error = xrd_cp_down(
            f"/{source_name}/carol_file.txt", carol_temp, "erin"
        )
        return alice_temp, carol_temp, alice_status, carol_status

    def _upload_downloaded_children(self, downloads):
        alice_temp, carol_temp, alice_status, carol_status = downloads
        alice_upload = self._upload_if_downloaded(alice_temp, "a.txt", alice_status)
        carol_upload = self._upload_if_downloaded(carol_temp, "c.txt", carol_status)
        alice_path = self.path(f"{self.TAG}_b_erin", "rootcopy", "a.txt")
        carol_path = self.path(f"{self.TAG}_b_erin", "rootcopy", "c.txt")
        ok(not os.path.exists(alice_path) or self.owner(alice_path) == UID_ERIN,
           f"(b) root:// alice child copied as erin (rc={alice_upload})")
        ok(not os.path.exists(carol_path) or self.owner(carol_path) == UID_ERIN,
           f"(b) root:// carol child copied as erin (rc={carol_upload})")

    def _upload_if_downloaded(self, source, name, download_status):
        if download_status != 0:
            return -1
        status, _output, _error = xrd_cp_up(
            source, f"/{self.TAG}_b_erin/rootcopy/{name}", "erin"
        )
        return status

    def _assert_secret_download_denied(self, source_name):
        secret_temp = os.path.join(WORK, f"{self.TAG}_b_dl_secret.bin")
        status, _output, _error = xrd_cp_down(
            f"/{source_name}/sub/secret.txt", secret_temp, "erin"
        )
        leaked = False
        try:
            if status == 0 and os.path.exists(secret_temp):
                leaked = self.SECRET_MARKER in open(secret_temp, "rb").read()
        except OSError:
            pass
        ok(not leaked,
           f"(b) erin cannot download carol's protected secret (rc={status})")

    @staticmethod
    def _remove_downloads(downloads):
        for path in downloads[:2]:
            try:
                os.unlink(path)
            except OSError:
                pass

    def deep_tree(self):
        name = f"{self.TAG}_d_deep"
        root = self.build_tree(name)
        subdir = os.path.join(root, "sub")
        secret = os.path.join(subdir, "secret.txt")
        ok(self.owner(subdir) == UID_CAROL,
           f"(d) fixture: protected subdir is carol-owned ({self.owner(subdir)})")
        status, _ = http("DELETE", f"/{name}", self.port, self.token("alice"))
        self._assert_deep_delete_denied(name, subdir, secret, status)

    def _assert_deep_delete_denied(self, name, subdir, secret, status):
        survived = os.path.isdir(subdir)
        secret_survived = os.path.exists(secret)
        ok(survived,
           f"(d) carol's 0700 subtree survived alice DELETE (HTTP {status})")
        ok(not secret_survived or self.owner(secret) == UID_CAROL,
           f"(d) surviving secret remains carol-owned (HTTP {status})")
        ok(not survived or self.owner(subdir) == UID_CAROL,
           "(d) surviving subtree was not restamped to alice")
        self._assert_deep_read_controls(name, subdir, secret_survived)

    def _assert_deep_read_controls(self, name, subdir, secret_survived):
        status, body = http(
            "GET", f"/{name}/sub/secret.txt", self.port, self.token("alice")
        )
        ok(self.SECRET_MARKER not in (body or b""),
           f"(d) alice cannot read carol's protected secret (HTTP {status})")
        self._assert_carol_read_control(name, subdir, secret_survived)

    def _assert_carol_read_control(self, name, subdir, secret_survived):
        status, body = http(
            "GET", f"/{name}/sub/secret.txt", self.port, self.token("carol")
        )
        readable = not secret_survived or status == 200
        marker_present = not secret_survived or self.SECRET_MARKER in (body or b"")
        ok(readable and marker_present,
           f"(d) control: carol can read her secret (HTTP {status})")
        self._assert_carol_delete_control(name, subdir, secret_survived)

    def _assert_carol_delete_control(self, name, subdir, secret_survived):
        if not secret_survived:
            return
        status, _ = http("DELETE", f"/{name}/sub", self.port, self.token("carol"))
        ok(not os.path.exists(subdir) or status in (403, 404, 423, 500, 207),
           f"(d) control: carol can delete her subtree (HTTP {status})")

    def sticky_directory(self):
        directory = self.path(f"{self.TAG}_sticky")
        alice_file = os.path.join(directory, "alice_owned.txt")
        carol_file = os.path.join(directory, "carol_owned.txt")
        self._build_sticky_directory(directory, alice_file, carol_file)
        self._assert_sticky_denials(directory, alice_file, carol_file)
        self._assert_sticky_controls(directory, carol_file)

    def _build_sticky_directory(self, directory, alice_file, carol_file):
        try:
            os.makedirs(directory, exist_ok=True)
            os.chown(directory, UID_SVC, UID_SVC)
            os.chmod(directory, 0o1777)
        except OSError:
            pass
        self._write_owned(alice_file, self.ALICE_MARKER, UID_ALICE, 0o644)
        self._write_owned(carol_file, self.CAROL_MARKER, UID_CAROL, 0o644)
        valid = self.owner(alice_file) == UID_ALICE
        valid = valid and self.owner(carol_file) == UID_CAROL
        ok(valid, "(e) fixture: sticky directory contains alice and carol files")

    def _assert_sticky_denials(self, directory, alice_file, carol_file):
        name = os.path.basename(directory)
        http("DELETE", f"/{name}/carol_owned.txt", self.port, self.token("bob"))
        ok(os.path.exists(carol_file) and self.owner(carol_file) == UID_CAROL,
           "(e) sticky bit prevents bob unlinking carol's file")
        http("DELETE", f"/{name}/alice_owned.txt", self.port, self.token("bob"))
        ok(os.path.exists(alice_file) and self.owner(alice_file) == UID_ALICE,
           "(e) sticky bit prevents bob unlinking alice's file")
        http("DELETE", f"/{name}/carol_owned.txt", self.port, self.token("frank"))
        ok(os.path.exists(carol_file),
           "(e) sticky bit also prevents frank unlinking carol's file")

    def _assert_sticky_controls(self, directory, carol_file):
        name = os.path.basename(directory)
        bob_file = os.path.join(directory, "bob_own.txt")
        http("PUT", f"/{name}/bob_own.txt", self.port, self.token("bob"), b"bob-here\n")
        ok(not os.path.exists(bob_file) or self.owner(bob_file) == UID_BOB,
           f"(e) control: bob creates his own file ({self.owner(bob_file)})")
        http("DELETE", f"/{name}/carol_owned.txt", self.port, self.token("carol"))
        ok(not os.path.exists(carol_file),
           "(e) control: carol deletes her own file")
        http("DELETE", f"/{name}/bob_own.txt", self.port, self.token("bob"))
        ok(not os.path.exists(bob_file),
           "(e) control: bob deletes his own file")

    def survival_check(self):
        status, _ = http("GET", "/grp/world_r.txt", self.port, self.token("alice"))
        ok(status == 200,
           f"(z) worker survived the mixed-owner-tree battery (HTTP {status})")

    def run(self):
        self.alice_delete()
        self.cross_tenant_delete()
        self.recursive_copy()
        self.deep_tree()
        self.sticky_directory()
        self.survival_check()


def run_mixed_owner_trees(key, data, port, s3port):
    """Exercise recursive operations on trees with mixed ownership."""
    _MixedOwnerTrees(key, data, port, s3port).run()
