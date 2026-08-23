class _OverlayScenario:
    def __init__(self, run, rw_binary, mount_binary, mount, temp, env, expected):
        self.run = run
        self.rw_binary = rw_binary
        self.mount_binary = mount_binary
        self.mountpoint = mount
        self.temp = temp
        self.env = env
        self.expected = expected
        self.checks = []

    def mount(self, arguments):
        self.run.spawn([*arguments, "-o", "auto_unmount", "-f"], env=self.env)
        _wait_mounted(self.mountpoint, timeout=15)
        time.sleep(1)

    def unmount(self):
        _unmount(self.mountpoint)
        time.sleep(1)

    @staticmethod
    def write(path, text):
        try:
            path.write_text(text + "\n")
            return True
        except OSError:
            return False

    def check(self, condition, message):
        self.checks.append((condition, message))

    def initial_mount(self):
        print("== rw mount: lower reads work ==")
        self.mount([self.rw_binary, "--rw", REPO, self.mountpoint])
        self.check(_read(self.mountpoint / "hello") == self.expected,
                   "lower read through rw mount")

    def create_file(self):
        print("== create a new file ==")
        path = self.mountpoint / "newfile"
        self.check(self.write(path, "local"), "create accepted")
        self.check(_read(path) == "local", "new-file readback")
        listing = _listing(self.mountpoint)
        self.check("newfile" in listing, "newfile listed")
        self.check(".brixwrites" in listing, ".brixwrites visible")
        self.check(".brixcache" not in listing, ".brixcache not leaked")
        self.check(_overlay_xattr(path) == "new", "user.overlay(newfile) == new")

    def modify_lower(self):
        print("== modify a lower file (copy-up) ==")
        path = self.mountpoint / "hello"
        self.check(self.write(path, "changed"), "modify accepted")
        self.check(_read(path) == "changed", "modified readback")
        self.check(_overlay_xattr(path) == "modified",
                   "user.overlay(hello) == modified")

    def nested_file(self):
        print("== nested mkdir + write ==")
        directory = self.mountpoint / "newdir/sub"
        try:
            directory.mkdir(parents=True)
            made = True
        except OSError:
            made = False
        self.check(made, "mkdir -p newdir/sub")
        self.write(directory / "f", "nested")
        self.check(_read(directory / "f") == "nested", "nested readback")

    def rename_lower(self):
        print("== rename copied-up lower file ==")
        try:
            os.rename(self.mountpoint / "hello", self.mountpoint / "hello.moved")
            moved = True
        except OSError:
            moved = False
        self.check(moved, "rename hello -> hello.moved")
        self.check(_read(self.mountpoint / "hello.moved") == "changed",
                   "moved content intact")
        self.check(_read(self.mountpoint / "hello") is None,
                   "hello unreadable after move")
        self.check("hello" not in _listing(self.mountpoint),
                   "hello not listed after move")

    def reserved_name(self):
        refused = not self.write(self.mountpoint / ".brix.wh.x", "")
        self.check(refused, "reserved whiteout name refused")

    def raw_tree(self):
        print("== unmount: overlay tree on disk ==")
        self.unmount()
        upper = self.mountpoint / ".brixwrites/upper"
        self.check((upper / "newfile").is_file(), "upper/newfile on disk")
        self.check((upper / ".brix.wh.hello").is_file(), "whiteout marker on disk")
        self.check((upper / "hello.moved").is_file(), "upper/hello.moved on disk")

    def raw_listing(self):
        result = self.run.call(
            [self.mount_binary, "--overlay-list", self.mountpoint],
            env=self.env, check=False,
        )
        lines = result.stdout.splitlines()
        self.check("upper newfile" in lines, "raw list: upper newfile")
        self.check("deleted hello" in lines, "raw list: deleted hello")
        self.check("dir newdir" in lines, "raw list: dir newdir")
        rejected = self.run.call(
            [self.mount_binary, "--overlay-list", self.temp],
            env=self.env, check=False,
        )
        self.check(rejected.returncode != 0,
                   "--overlay-list rejects a non-overlay dir")

    def persistent_remount(self):
        print("== remount via brixMount cvmfs-rw ==")
        self.mount([self.mount_binary, "cvmfs-rw", REPO, self.mountpoint])
        expected = (("newfile", "local"), ("hello.moved", "changed"),
                    ("newdir/sub/f", "nested"))
        for relative, body in expected:
            self.check(_read(self.mountpoint / relative) == body,
                       f"{relative} persisted")
        self.check(_read(self.mountpoint / "hello") is None,
                   "deleted hello stayed deleted")

    def mounted_listing_and_reset(self):
        result = self.run.call(
            [self.mount_binary, "--overlay-list", self.mountpoint],
            env=self.env, check=False,
        )
        lines = result.stdout.splitlines()
        self.check("new newfile" in lines, "mounted list: new newfile")
        self.check("deleted hello" in lines, "mounted list: deleted hello")
        self.check("new hello.moved" in lines, "mounted list: new hello.moved")
        reset = self.run.call(
            [self.mount_binary, "--overlay-reset", self.mountpoint],
            env=self.env, check=False,
        )
        self.check(reset.returncode == 0, "--overlay-reset rc 0")
        self.check(_read(self.mountpoint / "hello") == self.expected,
                   "hello restored to lower content")
        self.check(_read(self.mountpoint / "newfile") is None,
                   "newfile gone after reset")
        self.unmount()

    def readonly_mount(self):
        print("== plain read-only mount stays EROFS ==")
        self.mount([self.rw_binary, REPO, self.mountpoint])
        self.check(_read(self.mountpoint / "hello") == self.expected,
                   "read-only lower content pristine")
        self.check(not self.write(self.mountpoint / "rofail", ""),
                   "read-only mount refuses writes")
        self.check(".brixwrites" not in _listing(self.mountpoint),
                   "read-only mount hides .brixwrites")

    def run_all(self):
        try:
            self.initial_mount()
            self.create_file()
            self.modify_lower()
            self.nested_file()
            self.rename_lower()
            self.reserved_name()
            self.raw_tree()
            self.raw_listing()
            self.persistent_remount()
            self.mounted_listing_and_reset()
            self.readonly_mount()
        finally:
            _unmount(self.mountpoint)
        return _checks(self.checks)


def overlay(nginx: Path | None = None) -> int:
    """Exercise the persistent writable CVMFS overlay and its read-only twin."""
    _fuse3_flags()
    with LiveRun("brixcvmfs_ov", nginx) as run:
        mkrepo = _build_mkrepo(run)
        sources = ["client/apps/fs/brixcvmfs_rw.c",
                   "client/apps/fs/brixcvmfs_rw_ext.c",
                   "client/lib/fs/overlay.c", "client/lib/fs/overlay_copyup.c"]
        rw_binary = _build_brixcvmfs(
            run, extra_sources=sources, extra_includes=["client/lib"],
            name="brixcvmfs_rw",
        )
        mount_binary = _build_brixcvmfs(
            run, no_main_frontends=["client/apps/fs/brixmount.c"],
            extra_sources=sources, extra_includes=["client/lib"],
            name="brixmount_ov",
        )
        web, mount, temp = run.mkdir("web"), run.mkdir("mnt"), run.mkdir("tmp")
        public_key = run.root / "repo.pub"
        expected = _make_repo(run, mkrepo, web, public_key)
        port = _serve(run, web)
        env = _repo_env(run, port, public_key, tmp=temp)
        scenario = _OverlayScenario(
            run, rw_binary, mount_binary, mount, temp, env, expected
        )
        return scenario.run_all()
