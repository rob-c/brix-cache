class LiveRun(AbstractContextManager["LiveRun"]):
    """Own a temporary live-test topology and every process it starts."""

    def __init__(self, label: str, nginx: str | Path | None = None) -> None:
        self.root = Path(tempfile.mkdtemp(prefix=f"{label}."))
        self.nginx = freeze_nginx(nginx or os.environ.get("NGINX_BIN", "/tmp/nginx-1.28.3/objs/nginx"))
        self.processes: list[subprocess.Popen[str]] = []
        self.pidfiles: list[Path] = []

    def __enter__(self) -> "LiveRun":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def close(self) -> None:
        _terminate_pidfiles(self.pidfiles)
        _terminate_processes(self.processes)
        _wait_processes(self.processes)
        _reap_fuse_mounts(self.root)
        if os.environ.get("BRIX_LIVE_KEEP_TREE"):
            # Debug aid: preserve the ephemeral LiveRun tree (nginx configs +
            # error/access logs) for post-mortem instead of rmtree'ing it.
            sys.stderr.write(f"[LiveRun] KEEP_TREE: {self.root}\n")
            return
        shutil.rmtree(self.root, ignore_errors=True)

    def mkdir(self, *parts: str) -> Path:
        path = self.root.joinpath(*parts)
        path.mkdir(parents=True, exist_ok=True)
        # Root harness: a dir made after start_nginx's tree-wide chmod is
        # root-owned 0755, unwritable by the de-escalated worker — open it.
        if os.geteuid() == 0:
            for p in [path, *path.parents]:
                if p == self.root or not str(p).startswith(str(self.root)):
                    break
                os.chmod(p, 0o777)
        return path

    def write(self, path: Path, text: str) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        return path

    def call(
        self,
        argv: Iterable[str | Path],
        *,
        cwd: Path | None = None,
        input: str | bytes | None = None,
        env: dict[str, str] | None = None,
        check: bool = True,
        binary: bool = False,
    ) -> subprocess.CompletedProcess[str]:
        command = [str(item) for item in argv]
        # Text mode is inferred from `input`, which is wrong for a command that
        # WRITES binary (xrdfs cat of a random payload): decoding then raises
        # UnicodeDecodeError inside communicate() and the caller never sees a
        # return code.  `binary=True` opts the streams out explicitly.
        text = _call_text_mode(input, binary)
        proc = subprocess.Popen(
            command,
            cwd=_call_cwd(cwd),
            env=_call_environment(env),
            stdin=_call_stdin(input),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=text,
        )
        stdout, stderr = proc.communicate(input)
        result = subprocess.CompletedProcess(command, proc.returncode, stdout, stderr)
        if check and result.returncode:
            _raise_call_failure(result)
        return result

    def spawn(
        self,
        argv: Iterable[str | Path],
        *,
        cwd: Path | None = None,
        env: dict[str, str] | None = None,
    ) -> subprocess.Popen[str]:
        proc = subprocess.Popen(
            [str(item) for item in argv],
            cwd=str(cwd) if cwd else None,
            env={**os.environ, **(env or {})},
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            text=True,
        )
        self.processes.append(proc)
        return proc

    def start_nginx(self, prefix: Path, config: Path, port: int, *, timeout: float = 10) -> None:
        prefix.mkdir(parents=True, exist_ok=True)
        inject_nginx_load_modules(config, self.nginx)
        inject_nginx_runtime_paths(config, prefix, pid_path=prefix / "nginx.pid")
        # Self-heal against a LEAKED live nginx squatting this port: if a prior
        # test's teardown was skipped (crash, kill, xdist worker death) its master
        # keeps the fixed port bound and every later run of the same test dies with
        # "bind() ... Address already in use". Live-cmd ports (11600-11999) are a
        # dedicated range disjoint from the standing fleet (<=~11251), so reaping
        # whatever holds this exact port cannot touch a fleet server.
        _reap_port(port)
        cmd = [self.nginx, "-p", prefix, "-c", config]
        # Root harness: worker de-escalation is ALWAYS-ON and fail-closed
        # (brix_imp_worker_deescalate) — a root-launched worker is forced to a
        # confined account (brix_worker_user, default `nobody`) in every mode;
        # `user root;` / `-g` cannot keep it root, and root worker accounts are
        # refused by design.  That confined worker cannot traverse the 0700
        # mkdtemp LiveRun tree nor read/write its backends and cache store, so
        # export-root opens fail the worker and every cache fill 504s.  Open the
        # whole ephemeral tree (plus in-tree keys, the shared PKI and any
        # credential store in the config) for the de-escalated worker
        # (unprivileged the invoking user already owns the tree — no-op).
        from cmdscripts import open_tree_for_worker  # noqa: PLC0415 — cycle
        open_tree_for_worker(self.root, config)
        result = self.call(cmd, check=False)
        if result.returncode:
            raise LiveFailure(result.stderr or result.stdout or f"nginx failed to start for {config}")
        pidfile = prefix / "nginx.pid"
        self.pidfiles.append(pidfile)
        if not wait_tcp(BIND_HOST, port, timeout):
            detail = _nginx_error_detail(prefix)
            raise LiveFailure(f"nginx was not ready on {port}: {detail}")

    def stop_nginx(self, prefix: Path) -> None:
        pidfile = prefix / "nginx.pid"
        try:
            os.kill(int(pidfile.read_text().strip()), signal.SIGTERM)
        except (OSError, ValueError):
            return
        deadline = time.monotonic() + 3
        while pidfile.exists() and time.monotonic() < deadline:
            time.sleep(0.05)

    def curl_status(self, url: str, *extra: str, timeout: int = 25) -> int:
        result = self.call(
            ["curl", "-sS", "--max-time", str(timeout), "-o", os.devnull, "-w", "%{http_code}", *extra, url],
            check=False,
        )
        return int(result.stdout.strip() or 0) if result.stdout.strip().isdigit() else 0

    def curl_bytes(self, url: str, *extra: str, timeout: int = 25) -> bytes:
        proc = subprocess.Popen(
            ["curl", "-sS", "--max-time", str(timeout), *extra, url],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        stdout, stderr = proc.communicate()
        if proc.returncode:
            raise LiveFailure(stderr.decode(errors="replace"))
        return stdout


def random_file(path: Path, size: int) -> str:
    path.write_bytes(os.urandom(size))
    return sha256(path)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def nginx_binary_from_args(argv: list[str] | None = None) -> tuple[Path | None, list[str]]:
    values = list(argv or [])
    if values and not values[0].startswith("-"):
        return Path(values.pop(0)), values
    return None, values


def _proxy_fresh(proxy: str) -> bool:
    if not os.path.isfile(proxy):
        return False
    return subprocess.run(
        ["openssl", "x509", "-in", proxy, "-noout", "-checkend", "300"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    ).returncode == 0


def _pki_provisioning_command(ca_ok: bool, pki_dir: str) -> list[str]:
    if ca_ok:
        return ["python3", str(REPO_ROOT / "utils" / "make_proxy.py"), pki_dir]
    return [
        "python3", "-c", "import pki_helpers; pki_helpers.blitz_test_pki()"
    ]


def _write_pki_log(log_dir: Path | str | None, output: str) -> None:
    if log_dir is None:
        return
    try:
        directory = Path(log_dir)
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "pki.log").write_text(output, encoding="utf-8")
    except OSError:
        pass


def _pki_certificates_present(ca_cert: str, server_cert: str) -> bool:
    if not os.path.isfile(ca_cert):
        return False
    return os.path.isfile(server_cert)


def _pki_ready(ca_ok: bool, want_proxy: bool, proxy: str) -> bool:
    if not ca_ok:
        return False
    if not want_proxy:
        return True
    return _proxy_fresh(proxy)


def _pki_output(result: subprocess.CompletedProcess[str]) -> str:
    return result.stdout if result.stdout else ""


def _pki_outcome(result: subprocess.CompletedProcess[str]) -> tuple[bool, str]:
    if result.returncode == 0:
        return True, ""
    return False, "PKI provisioning failed: " + _pki_output(result)[-1000:]


def refresh_shared_pki(log_dir: Path | str | None = None, *, want_proxy: bool = True) -> tuple[bool, str]:
    """Ensure the shared TEST_ROOT/pki has a fresh user proxy WITHOUT churning the CA.

    ``pki_helpers.blitz_test_pki()`` rmtree's and regenerates the ENTIRE PKI — a
    brand-new CA and hostcert. The standing fleet loads its certs once at startup,
    so a mid-run blitz desyncs it: the fleet keeps serving the OLD CA while a
    freshly-minted client proxy chains to the NEW CA, and EVERY concurrent
    TLS/GSI/HTTPS handshake across all xdist workers then fails (this was the
    fast-lane's biggest flakiness source — a stale proxy in one gsi cmd scenario
    would blow up ~130 unrelated TLS tests).

    So: full-blitz ONLY when the CA/hostcert are genuinely absent (first-time
    provisioning, before any fleet exists). When they are present but the proxy is
    merely stale, refresh ONLY the proxy via ``utils/make_proxy.py`` (it reads the
    existing usercert/userkey and rewrites proxy_std.pem) — the CA and hostcert,
    and therefore the fleet, are left untouched. Returns ``(ok, err_message)``.
    """
    from settings import CA_CERT, SERVER_CERT, TEST_ROOT  # noqa: PLC0415 — avoid import cycle

    pki_dir = os.path.join(TEST_ROOT, "pki")
    proxy = os.path.join(pki_dir, "user", "proxy_std.pem")
    ca_ok = _pki_certificates_present(CA_CERT, SERVER_CERT)
    if _pki_ready(ca_ok, want_proxy, proxy):
        return True, ""
    argv = _pki_provisioning_command(ca_ok, pki_dir)
    result = subprocess.run(
        argv,
        cwd=str(REPO_ROOT / "tests"),
        env={**os.environ, "PYTHONPATH": "."},
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )
    _write_pki_log(log_dir, _pki_output(result))
    return _pki_outcome(result)


__all__ = ["LiveFailure", "LiveRun", "REPO_ROOT", "nginx_binary_from_args", "random_file", "sha256"]
