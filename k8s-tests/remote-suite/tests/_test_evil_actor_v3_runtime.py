# ------------------------------- the server ---------------------------------

class _Srv:
    def __init__(self, prefix, conf, pidfile, ports, datadir, tsandir):
        self.prefix = prefix; self.conf = conf; self.pidfile = pidfile
        (self.root_port, self.root_tls_port,
         self.https_port, self.metrics_port) = ports
        self.datadir = datadir; self.tsandir = tsandir
        self.master: "int | None" = None
        self._mark = 0
        self.have_xattr = False
        self.frm_ok = False
        self.near_names: "list[str]" = []
        self.audit = ""
        self.queue = ""

    @property
    def logfile(self):
        return os.path.join(self.prefix, "logs", "error.log")

    def mark(self):
        try:
            self._mark = os.path.getsize(self.logfile)
        except OSError:
            self._mark = 0

    def _delta(self):
        try:
            with open(self.logfile, errors="replace") as f:
                f.seek(self._mark); return f.read()
        except OSError:
            return ""

    @staticmethod
    def _module_race(text):
        markers = (
            "/src/core/aio/", "/src/protocols/root/read/",
            "/src/protocols/root/write/", "/src/fs/cache/",
            "/src/protocols/root/session/", "/src/protocols/root/connection/",
            "/src/frm/", "_aio_thread", "_aio_done", "read_scratch",
            "payload_to_free", "ctx->destroyed", "brix_",
        )
        return "data race" in text and any(marker in text for marker in markers)

    def _tsan_file_has_module_race(self, filename):
        try:
            with open(os.path.join(self.tsandir, filename), errors="replace") as source:
                text = source.read()
        except OSError:
            return False
        return self._module_race(text)

    def _tsan_module_races(self):
        if not self.tsandir or not os.path.isdir(self.tsandir):
            return ""
        hits = [name for name in os.listdir(self.tsandir)
                if self._tsan_file_has_module_race(name)]
        return ",".join(hits)

    def assert_no_crash(self, phase):
        """Crash/race/liveness check WITHOUT a fresh ping — safe to call mid-flight
        while attack threads saturate the listeners (a fresh ping would race the
        load and false-positive)."""
        delta = self._delta()
        for pat in CRASH_PATTERNS:
            assert pat not in delta, (
                "WORKER BROKE during %s — %r in error log:\n%s"
                % (phase, pat, delta[-2000:]))
        races = self._tsan_module_races()
        assert not races, "TSan module-frame DATA RACE during %s: %s" % (phase, races)
        assert _alive(self.master), "master died during %s" % phase
        assert _workers(self.master), "no workers after %s" % phase

    def assert_healthy(self, phase):
        self.assert_no_crash(phase)
        assert _ping_ok_retry(self.root_port), "server not serving after %s" % phase


def _build_shim(workdir):
    src = os.path.join(os.path.dirname(__file__), "race_shim.c")
    so = os.path.join(workdir, "librace.so")
    cmd = ["cc", "-shared", "-fPIC", "-O0", "-g", "-o", so, src, "-ldl", "-lpthread"]
    if SHIM_SAN in ("address", "thread"):
        cmd[1:1] = ["-fsanitize=" + SHIM_SAN]
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        return None, r.stderr
    return so, ""


def _xattr_ok(tmp):
    try:
        p = os.path.join(tmp, ".xattrprobe")
        open(p, "w").close()
        os.setxattr(p, "user.frm.test", b"1")
        os.remove(p)
        return True
    except Exception:
        return False


def _gen_cert(prefix):
    cert = os.path.join(prefix, "cert.pem")
    key = os.path.join(prefix, "key.pem")
    r = subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-keyout", key,
         "-out", cert, "-days", "1", "-nodes", "-subj", "/CN=127.0.0.1",
         "-addext", "subjectAltName=IP:127.0.0.1"],
        capture_output=True, text=True)
    if r.returncode != 0 or not os.path.exists(cert):
        return None, None
    return cert, key


def _require_fixture_ready():
    if REMOTE_SERVER:
        pytest.skip("self-contained; not REMOTE")
    if not os.path.exists(NGINX_BIN):
        pytest.skip("nginx not built at %s" % NGINX_BIN)
    for tool in ("pgrep", "cc", "openssl"):
        if shutil.which(tool) is None:
            pytest.skip("%s required" % tool)


def _fixture_paths(prefix):
    paths = (
        os.path.join(prefix, "data"),
        os.path.join(prefix, "tape"),
        os.path.join(prefix, "tsan"),
    )
    for path in (os.path.join(prefix, "logs"), *paths):
        os.makedirs(path, exist_ok=True)
    return paths


def _skip_fixture(prefix, message):
    shutil.rmtree(prefix, ignore_errors=True)
    pytest.skip(message)


def _required_shim_and_cert(prefix):
    shim, error = _build_shim(prefix)
    if shim is None:
        _skip_fixture(prefix, "could not build race shim: %s" % error[-300:])
    cert, key = _gen_cert(prefix)
    if cert is None:
        _skip_fixture(prefix, "could not generate self-signed cert")
    return shim, cert, key


def _populate_base_data(datadir):
    chunk = bytes((index * 31 + 7) & 0xFF for index in range(65536))
    with open(os.path.join(datadir, "big.bin"), "wb") as target:
        for _ in range(BIGFILE_MB * 16):
            target.write(chunk)
    for name in ("shared.bin", "w.bin", "xp.bin"):
        with open(os.path.join(datadir, name), "wb") as target:
            target.write(chunk * 8)


def _write_nearline(datadir, tapedir, name, content):
    with open(os.path.join(tapedir, name), "wb") as target:
        target.write(content)
    open(os.path.join(datadir, name), "wb").close()
    os.setxattr(
        os.path.join(datadir, name), "user.frm.residency", b"nearline"
    )


def _populate_nearline_pool(datadir, tapedir):
    names = []
    for index in range(60):
        name = "near%03d.dat" % index
        _write_nearline(
            datadir, tapedir, name, b"T%03d" % index + b"q" * 512
        )
        names.append("/" + name)
    return names


def _prepare_frm(prefix, datadir, tapedir, enabled):
    copy_command = os.path.join(prefix, "copycmd.sh")
    shutil.copy(
        os.path.join(os.path.dirname(__file__), "frm_fake_mss.sh"), copy_command
    )
    os.chmod(copy_command, 0o755)
    audit = os.path.join(prefix, "audit.log")
    if not enabled:
        return copy_command, audit, []
    _write_nearline(
        datadir, tapedir, "near.dat", b"TAPE-" + b"z" * 4096 + b"\n"
    )
    return copy_command, audit, _populate_nearline_pool(datadir, tapedir)


def _frm_block(queue, copy_command, enabled):
    if not enabled:
        return ""
    return (
        "        brix_frm on; brix_frm_queue_path %s;\n"
        "        brix_frm_copycmd %s; brix_frm_copymax 4;\n"
        "        brix_frm_async_recall on; brix_frm_stage_ttl 30s;\n"
        "        brix_frm_xfrhold 50ms;\n"
        "        brix_frm_max_inflight 64; brix_frm_max_per_source 16;\n"
        % (queue, copy_command)
    )


def _unused_ports(prefix):
    ports = _free_ports(4)
    for port in ports:
        if _reachable(port):
            _skip_fixture(prefix, "port %d in use" % port)
    return ports


def _sanitizer_candidate(line, wanted):
    if wanted not in line or "=>" not in line:
        return ""
    candidate = line.split("=>", 1)[1].strip().split(" ", 1)[0]
    if not candidate or not os.path.exists(candidate):
        return ""
    return candidate


def _sanitizer_runtime():
    wanted = {"address": "libasan.so", "thread": "libtsan.so"}.get(SHIM_SAN)
    if wanted is None:
        return ""
    try:
        output = subprocess.run(
            ["ldd", NGINX_BIN], capture_output=True, text=True
        ).stdout
    except Exception:
        return ""
    for line in output.splitlines():
        candidate = _sanitizer_candidate(line, wanted)
        if candidate:
            return candidate
    return ""


def _write_tsan_suppressions(prefix):
    path = os.path.join(prefix, "tsan.supp")
    with open(path, "w") as target:
        target.write(
            "race:ngx_atomic_\nrace:^brix_metrics_\nrace:ngx_thread_pool_cycle\n"
            "race:ngx_time_update\nrace:ngx_event_\ncalled_from_lib:libssl\n"
            "called_from_lib:libcrypto\ncalled_from_lib:libjansson\n"
        )
    return path


def _set_sanitizer_options(environment, prefix, tsandir):
    if SHIM_SAN == "thread":
        suppressions = _write_tsan_suppressions(prefix)
        environment["TSAN_OPTIONS"] = (
            "suppressions=%s:halt_on_error=0:exitcode=0:"
            "history_size=4:log_path=%s/tsan" % (suppressions, tsandir)
        )
    if SHIM_SAN == "address":
        environment["ASAN_OPTIONS"] = (
            "detect_leaks=0:abort_on_error=1:halt_on_error=1:"
            "verify_asan_link_order=0"
        )


def _server_environment(shim, prefix, datadir, tapedir, tsandir, audit):
    environment = dict(os.environ)
    preload = (_sanitizer_runtime(), environment.get("LD_PRELOAD", ""), shim)
    environment["LD_PRELOAD"] = " ".join(item for item in preload if item)
    environment["XRD_RACE_DELAY_US"] = str(SHIM_DELAY_US)
    environment.update(
        FRM_DATA_DIR=os.path.realpath(datadir), FRM_TAPE_DIR=tapedir,
        FRM_LATENCY_MS=str(FRM_LATENCY_MS), FRM_AUDIT_LOG=audit,
    )
    _set_sanitizer_options(environment, prefix, tsandir)
    return environment


def _stop_nginx(prefix, config_path, environment):
    subprocess.run(
        [NGINX_BIN, "-p", prefix, "-c", config_path, "-s", "stop"],
        capture_output=True, env=environment,
    )


def _validate_and_start(prefix, config_path, environment, root_port):
    check = subprocess.run(
        [NGINX_BIN, "-t", "-p", prefix, "-c", config_path],
        capture_output=True, text=True, env=environment,
    )
    if check.returncode != 0:
        tail = (check.stderr or check.stdout).strip()[-500:]
        _skip_fixture(prefix, "nginx rejected config: %s" % tail)
    run = subprocess.run(
        [NGINX_BIN, "-p", prefix, "-c", config_path],
        capture_output=True, text=True, env=environment,
    )
    if run.returncode == 0 and _wait_port(root_port):
        return
    tail = (run.stderr or run.stdout).strip()[-500:]
    _stop_nginx(prefix, config_path, environment)
    _skip_fixture(prefix, "nginx did not start: %s" % tail)


def _frm_available(enabled, metrics_port):
    if not enabled:
        return False
    try:
        request = __import__("urllib.request", fromlist=["request"])
        with request.urlopen(
            "http://%s:%d/metrics" % (HOST, metrics_port), timeout=5
        ) as response:
            return b"brix_frm_" in response.read()
    except Exception:
        return False


def _fixture_server(prefix, config_path, ports, datadir, tsandir, frm):
    server = _Srv(
        prefix, config_path, os.path.join(prefix, "logs", "nginx.pid"),
        ports, datadir, tsandir,
    )
    server.master = _master_pid(server.pidfile)
    server.have_xattr = frm["enabled"]
    server.near_names = frm["names"]
    server.audit = frm["audit"]
    server.queue = frm["queue"]
    server.frm_ok = _frm_available(frm["enabled"], ports[3])
    return server


def _require_master(server, environment):
    if server.master and _alive(server.master):
        return
    _stop_nginx(server.prefix, server.conf, environment)
    _skip_fixture(server.prefix, "master pid never appeared")


def _report_fixture(server):
    print(
        "\n[evil3] master=%d root=%d roots_tls=%d https=%d metrics=%d "
        "shim=%s delay=%dus workers=%s xattr=%s"
        % (server.master, server.root_port, server.root_tls_port,
           server.https_port, server.metrics_port, SHIM_SAN or "plain",
           SHIM_DELAY_US, _workers(server.master), server.have_xattr)
    )


def _cleanup_fixture(server, environment):
    _stop_nginx(server.prefix, server.conf, environment)
    time.sleep(0.3)
    if server.master and _alive(server.master):
        try:
            os.kill(server.master, 9)
        except OSError:
            pass
    shutil.rmtree(server.prefix, ignore_errors=True)


@pytest.fixture(scope="module")
def srv(tmp_path_factory):
    _require_fixture_ready()
    prefix = tempfile.mkdtemp(prefix="evil3-")
    datadir, tapedir, tsandir = _fixture_paths(prefix)
    have_xattr = _xattr_ok(datadir)
    shim, cert, key = _required_shim_and_cert(prefix)
    _populate_base_data(datadir)
    copycmd, audit, near_names = _prepare_frm(
        prefix, datadir, tapedir, have_xattr
    )
    queue = os.path.join(prefix, "frm.queue")
    frm_block = _frm_block(queue, copycmd, have_xattr)
    ports = _unused_ports(prefix)
    root_port, root_tls_port, https_port, metrics_port = ports

    conf = ("""
worker_processes %d;
daemon on;
master_process on;
pid %s/logs/nginx.pid;
error_log %s/logs/error.log info;
thread_pool aiopool threads=4 max_queue=8192;
env FRM_DATA_DIR; env FRM_TAPE_DIR; env FRM_LATENCY_MS; env FRM_AUDIT_LOG; env FRM_FAIL_MODE;
events { worker_connections 1024; }
stream {
    server {
        listen %s:%d reuseport;
        brix_root on; brix_storage_backend posix:%s; brix_auth none; brix_allow_write on;
        brix_thread_pool aiopool; brix_memory_budget 6m;
%s    }
    server {
        listen %s:%d reuseport;
        brix_root on; brix_storage_backend posix:%s; brix_auth none; brix_allow_write on;
        brix_thread_pool aiopool; brix_memory_budget 6m;
        brix_tls on; brix_certificate %s; brix_certificate_key %s;
    }
}
http {
    access_log off;
    client_body_temp_path %s/logs/cbt; proxy_temp_path %s/logs/pt;
    fastcgi_temp_path %s/logs/ft; uwsgi_temp_path %s/logs/ut; scgi_temp_path %s/logs/st;
    server {
        listen %s:%d ssl;
        ssl_certificate %s; ssl_certificate_key %s;
        location = /metrics { brix_metrics on; }
        location /s3b/ { brix_s3 on; brix_storage_backend posix:%s; brix_s3_bucket s3b;
                         brix_s3_region us-east-1; }
        location / { brix_webdav on; brix_storage_backend posix:%s; brix_webdav_auth none;
                     brix_allow_write on; }
    }
    server {
        listen %s:%d;
        location = /metrics { brix_metrics on; }
    }
}
""" % (WORKERS, prefix, prefix,
       BIND_HOST, root_port, datadir, frm_block,
       BIND_HOST, root_tls_port, datadir, cert, key,
       prefix, prefix, prefix, prefix, prefix,
       BIND_HOST, https_port, cert, key, datadir, datadir,
       BIND_HOST, metrics_port))
    conf_path = os.path.join(prefix, "nginx.conf")
    with open(conf_path, "w") as target:
        target.write(conf)
    env = _server_environment(shim, prefix, datadir, tapedir, tsandir, audit)
    _validate_and_start(prefix, conf_path, env, root_port)
    frm = {
        "enabled": have_xattr, "names": near_names,
        "audit": audit, "queue": queue,
    }
    server = _fixture_server(
        prefix, conf_path, ports, datadir, tsandir, frm
    )
    _require_master(server, env)
    _report_fixture(server)
    try:
        yield server
    finally:
        _cleanup_fixture(server, env)


# ----------------------- A1: roots:// TLS bring-up ---------------------------

def _tls_available(srv):
    try:
        t = _roots_tls_connect(srv.root_tls_port)
        t.close()
        return True
    except Exception:
        return False


# ----------------------- A2: TLS disconnect-mid-AIO --------------------------

# ----------------------- B6: cross-worker bind -------------------------------

# ----------------- B7: bind-vs-teardown TOCTOU + handle ABA ------------------

# ------------- C1: FRM async asynresp deliver-into-recycled-conn -------------

def _frm_skip(srv):
    if not srv.have_xattr:
        pytest.skip("filesystem lacks user xattrs (FRM residency)")
    if not srv.frm_ok:
        pytest.skip("FRM not compiled/enabled (nearline open not intercepted)")


# ------------- C2: FRM reqid forgery — owner check ---------------------------

# ------------------------- C3: FRM admission flood ---------------------------

# --------------------------- D: chaos capstone -------------------------------

__all__ = [n for n in dir() if not n.startswith('__')]
