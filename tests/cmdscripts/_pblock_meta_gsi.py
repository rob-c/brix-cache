"""Pblock GSI metadata-storm scenario phases."""


def _integer_option(value, environment_name, default):
    if value is not None:
        return value
    return int(os.environ.get(environment_name, default))


def _p99_option(value):
    if value is not None:
        return value
    cores = os.cpu_count() or 8
    default = 50 if cores >= 8 else 50 * 8 // max(cores, 1)
    return int(os.environ.get("P99_CEIL_MS", str(default)))


def _proxy_option(value):
    if value is not None:
        return value
    return os.environ.get("MB_PROXY_OVERRIDE")


def _meta_options(workers, ops_per_worker, p99_ceil_ms, proxy_override):
    worker_count = _integer_option(workers, "WORKERS", "8")
    operation_count = _integer_option(
        ops_per_worker, "OPS_PER_WORKER", "125")
    return (
        worker_count,
        operation_count,
        _p99_option(p99_ceil_ms),
        _proxy_option(proxy_override),
    )


def _meta_requirements(nginx):
    nginx_bin = Path(
        nginx or os.environ.get("NGINX_BIN", "/tmp/nginx-1.28.3/objs/nginx"))
    required = (nginx_bin, XRDFS, XRDDIAG, LIBXRDC, PROTOLIB)
    for path in required:
        if not Path(path).exists():
            print(f"SKIP: missing {path}")
            return False
    return True


def _meta_config(run, port, block_size):
    text = f"""daemon on;
error_log {run.root}/logs/error.log info;
pid {run.root}/nginx.pid;
events {{ worker_connections 256; }}
thread_pool default threads=8 max_queue=512;
stream {{
    server {{
        listen {BIND_HOST}:{port};
        brix_root on;
        brix_export            {run.root}/root;
        brix_auth            gsi;
        brix_certificate     {SERVER_CERT};
        brix_certificate_key {SERVER_KEY};
        brix_trusted_ca      {CA_CERT};
        brix_allow_write     on;
        brix_upload_resume   off;
        brix_storage_backend pblock;
        brix_pblock_block_size {block_size};
        brix_access_log {run.root}/logs/access.log;
    }}
}}
"""
    return run.write(run.root / "nginx.conf", text)


class _PblockMetaScenario:
    def __init__(self, run, workers, operations, ceiling, env, host):
        self.run = run
        self.workers = workers
        self.operations = operations
        self.ceiling = ceiling
        self.env = env
        self.host = host
        self.bench = _build_meta_bench(run)
        self.plan = [
            "--workers", str(workers),
            "--ops-per-worker", str(operations),
            "--p99-ceil-ms", str(ceiling),
        ]
        self.checks = []
        self.data_dir = run.root / "root/data"

    def _bench_phase(self, phase):
        result = self.run.call(
            [self.bench, *self.plan, "--phase", phase, "--json", self.host],
            env=self.env, check=False)
        print(result.stdout)
        return result

    def layer_a_create(self):
        print("== Layer (a): libbrix direct code ==")
        create = self._bench_phase("create")
        if create.returncode != 0:
            time.sleep(1)
            self._bench_phase("remove")
            create = self._bench_phase("create")
        self.checks.append((
            create.returncode == 0,
            "layer-a create: zero failures + "
            f"p99<={self.ceiling}ms (rc={create.returncode})",
        ))

    def _expected_entries(self):
        result = self.run.call(
            [self.bench, *self.plan, "--print-expected", self.host],
            env=self.env, check=False)
        return sorted(result.stdout.splitlines())

    @staticmethod
    def _missing_paths(expected, listing):
        missing = 0
        for line in expected:
            fields = line.split()
            if len(fields) >= 3 and fields[2] not in listing:
                missing += 1
        return missing

    @staticmethod
    def _expected_file_count(expected):
        return sum(
            1 for line in expected
            if len(line.split()) >= 2 and line.split()[1] == "0")

    def _block_count(self):
        if not self.data_dir.exists():
            return 0
        return sum(1 for path in self.data_dir.rglob("*") if path.is_file())

    def catalog_integrity(self):
        print("== verify: catalog integrity ==")
        expected = self._expected_entries()
        listing = self.run.call(
            [XRDFS, self.host, "ls", "-R", "/"],
            env=self.env, check=False).stdout
        missing = self._missing_paths(expected, listing)
        self.checks.append((
            missing == 0,
            f"namespace readback: {missing} expected path(s) missing"
            if missing else "namespace readback: all expected paths present",
        ))
        wanted = self._expected_file_count(expected)
        actual = self._block_count()
        self.checks.append((
            actual == wanted,
            f"block catalog integrity: {actual} blocks == {wanted} files",
        ))

    def _permission_column(self):
        listing = self.run.call(
            [XRDFS, self.host, "ls", "-l", "/w0/d0"],
            env=self.env, check=False).stdout
        for line in listing.splitlines():
            if line.rstrip().endswith("/f0"):
                return line.split()[0]
        return ""

    def chmod_persistence(self):
        self.run.call(
            [XRDFS, self.host, "chmod", "/w0/d0/f0", "0644"],
            env=self.env, check=False)
        first = self._permission_column()
        self.run.call(
            [XRDFS, self.host, "chmod", "/w0/d0/f0", "0600"],
            env=self.env, check=False)
        second = self._permission_column()
        self.checks.append((
            bool(first) and first != second,
            f"chmod persists through driver (0644 '{first}' != 0600 '{second}')",
        ))

    @staticmethod
    def _p99_only_failure(result):
        compact = result.stdout.replace(" ", "")
        return result.returncode != 0 and '"failures":0' in compact

    def layer_a_remove(self):
        print("== Layer (a): remove phase + leak check ==")
        remove = self._bench_phase("remove")
        if self._p99_only_failure(remove):
            time.sleep(1)
            self._bench_phase("create")
            remove = self._bench_phase("remove")
        self.checks.append((
            remove.returncode == 0,
            f"layer-a remove: zero failures (rc={remove.returncode})",
        ))
        self._check_removed_state()

    def _check_removed_state(self):
        listing = self.run.call(
            [XRDFS, self.host, "ls", "/"],
            env=self.env, check=False).stdout
        self.checks.append((
            "/w0" not in listing,
            "store empty after remove (no namespace leak)",
        ))
        blocks = self._block_count()
        self.checks.append((
            blocks == 0,
            f"no leftover blocks after remove ({blocks} left)",
        ))
        healthy = self.run.call(
            [XRDFS, self.host, "stat", "/"],
            env=self.env, check=False).returncode
        self.checks.append((
            healthy == 0,
            "fresh GSI login + stat OK after storm",
        ))

    def _worker_chain(self, index, results):
        result = 0
        base = f"/wb{index}"
        operations = (
            ["mkdir", base],
            ["mkdir", f"{base}/d0"],
            ["chmod", f"{base}/d0", "700"],
            ["touch", f"{base}/d0/f0"],
            ["chmod", f"{base}/d0/f0", "640"],
            ["stat", f"{base}/d0/f0"],
        )
        for arguments in operations:
            process = subprocess.run(
                [str(XRDFS), self.host, *arguments],
                env={**os.environ, **self.env},
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            if process.returncode:
                result = 1
        results[index] = result

    def _run_worker_chains(self):
        results = {}
        threads = [
            threading.Thread(target=self._worker_chain, args=(index, results))
            for index in range(self.workers)
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        return results

    def _cleanup_worker(self, index):
        base = f"/wb{index}"
        for arguments in (
            ["rm", f"{base}/d0/f0"],
            ["rmdir", f"{base}/d0"],
            ["rmdir", base],
        ):
            self.run.call(
                [XRDFS, self.host, *arguments], env=self.env, check=False)

    def _record_worker_results(self, results):
        failures = sum(
            1 for index in range(self.workers) if results.get(index) != 0)
        self.checks.append((
            failures == 0,
            f"xrdfs chain: {self.workers - failures}/{self.workers} "
            "concurrent sessions clean (incl. nested mkdir)",
        ))

    def _record_worker_listing(self):
        listing = self.run.call(
            [XRDFS, self.host, "ls", "-R", "/"],
            env=self.env, check=False).stdout
        missing = sum(
            1 for index in range(self.workers)
            if f"/wb{index}/d0/f0" not in listing)
        self.checks.append((
            missing == 0,
            f"xrdfs chain: namespace readback complete ({missing} missing)",
        ))

    def layer_b(self):
        print("== Layer (b): full xrdfs CLI chain (concurrent GSI sessions) ==")
        results = self._run_worker_chains()
        self._record_worker_results(results)
        self._record_worker_listing()
        for index in range(self.workers):
            self._cleanup_worker(index)

    def _metabench(self):
        command = [
            XRDDIAG, "metabench", "-S", str(self.workers),
            "--count", str(self.operations), self.host,
        ]
        result = self.run.call(command, env=self.env, check=False)
        if result.returncode != 0:
            time.sleep(1)
            result = self.run.call(command, env=self.env, check=False)
        return result

    def layer_c(self):
        print("== Layer (c): xrddiag client validation ==")
        check = self.run.call(
            [XRDDIAG, "check", self.host], env=self.env, check=False)
        output = check.stdout + check.stderr
        self.checks.append((
            "Result: 0 failure" in output,
            "xrddiag check: client conformance all-green",
        ))
        benchmark = self._metabench()
        for line in (benchmark.stdout + benchmark.stderr).splitlines():
            print(f"  {line}")
        self.checks.append((
            benchmark.returncode == 0,
            "xrddiag metabench: client performs "
            f"(0 fail, p99 within ceiling) (rc={benchmark.returncode})",
        ))

    def run_all(self):
        self.layer_a_create()
        self.catalog_integrity()
        self.chmod_persistence()
        self.layer_a_remove()
        self.layer_b()
        self.layer_c()
        return _checks(self.checks)


def pblock_meta_gsi(nginx: Path | None = None, *,
                    workers: int | None = None,
                    ops_per_worker: int | None = None,
                    p99_ceil_ms: int | None = None,
                    proxy_override: str | None = None) -> int:
    """Run the three-layer concurrent GSI metadata reliability scenario."""
    options = _meta_options(
        workers, ops_per_worker, p99_ceil_ms, proxy_override)
    worker_count, operation_count, ceiling, proxy = options
    if not _meta_requirements(nginx):
        return 0
    block_size = os.environ.get("PBLOCK_BLOCK_SIZE", "1m")
    port = _PORTS[6]
    with LiveRun("pblock_meta_gsi", nginx) as run:
        run.mkdir("root")
        run.mkdir("logs")
        if not _ensure_pki(run):
            return 0
        environment = {
            "X509_USER_PROXY": proxy or str(PROXY_STD),
            "X509_CERT_DIR": str(CA_DIR),
        }
        host = f"root://{HOST}:{port}/"
        config = _meta_config(run, port, block_size)
        run.start_nginx(run.root, config, port)
        time.sleep(1)
        scenario = _PblockMetaScenario(
            run, worker_count, operation_count, ceiling, environment, host)
        return scenario.run_all()
