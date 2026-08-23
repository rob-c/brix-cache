def _require_fixture_ready():
    if REMOTE_SERVER:
        pytest.skip("self-contained; not REMOTE")
    if not os.path.exists(NGINX_BIN):
        pytest.skip("nginx not built at %s" % NGINX_BIN)
    if shutil.which("pgrep") is None or shutil.which("cc") is None:
        pytest.skip("pgrep + cc required")


def _fixture_directories(prefix):
    datadir = os.path.join(prefix, "data")
    tsandir = os.path.join(prefix, "tsan")
    for path in (os.path.join(prefix, "logs"), datadir, tsandir):
        os.makedirs(path, exist_ok=True)
    return datadir, tsandir


def _skip_fixture(prefix, message):
    shutil.rmtree(prefix, ignore_errors=True)
    pytest.skip(message)


def _required_shim(prefix):
    shim, error = _build_shim(prefix)
    if shim is not None:
        return shim
    _skip_fixture(prefix, "could not build race shim: %s" % error[-300:])


def _populate_data(datadir):
    chunk = bytes((index * 31 + 7) & 0xFF for index in range(65536))
    with open(os.path.join(datadir, "big.bin"), "wb") as target:
        for _ in range(BIGFILE_MB * 16):
            target.write(chunk)
    for name in ("shared.bin", "w.bin", "xp.bin"):
        with open(os.path.join(datadir, name), "wb") as target:
            target.write(chunk * 8)


def _unused_ports(prefix):
    ports = _free_ports(2)
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
            "detect_leaks=0:abort_on_error=1:halt_on_error=1"
        )


def _server_environment(shim, prefix, tsandir):
    environment = dict(os.environ)
    preload = (_sanitizer_runtime(), environment.get("LD_PRELOAD", ""), shim)
    environment["LD_PRELOAD"] = " ".join(item for item in preload if item)
    environment["XRD_RACE_DELAY_US"] = str(SHIM_DELAY_US)
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
        tail = (check.stderr or check.stdout).strip()[-400:]
        _skip_fixture(prefix, "nginx rejected config: %s" % tail)
    run = subprocess.run(
        [NGINX_BIN, "-p", prefix, "-c", config_path],
        capture_output=True, text=True, env=environment,
    )
    if run.returncode == 0 and _wait_port(root_port):
        return
    tail = (run.stderr or run.stdout).strip()[-400:]
    _stop_nginx(prefix, config_path, environment)
    _skip_fixture(prefix, "nginx did not start: %s" % tail)


def _fixture_server(prefix, config_path, ports, datadir, tsandir):
    pidfile = os.path.join(prefix, "logs", "nginx.pid")
    server = _Srv(prefix, config_path, pidfile, ports, datadir, tsandir)
    server.master = _master_pid(pidfile)
    return server


def _require_master(server, environment):
    if server.master and _alive(server.master):
        return
    _stop_nginx(server.prefix, server.conf, environment)
    _skip_fixture(server.prefix, "master pid never appeared")


def _report_fixture(server):
    print(
        "\n[evil2] master=%d root=%d http=%d shim=%s delay=%dus workers=%s"
        % (server.master, server.root_port, server.http_port,
           SHIM_SAN or "plain", SHIM_DELAY_US, _workers(server.master))
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
    prefix = tempfile.mkdtemp(prefix="evil2-")
    datadir, tsandir = _fixture_directories(prefix)
    shim = _required_shim(prefix)
    _populate_data(datadir)
    ports = _unused_ports(prefix)
    root_port, http_port = ports

    conf = ("""
worker_processes 3;
daemon on;
master_process on;
pid %s/logs/nginx.pid;
error_log %s/logs/error.log info;
thread_pool aiopool threads=4 max_queue=8192;
events { worker_connections 1024; }
stream {
    server {
        listen %s:%d;
        brix_root on; brix_storage_backend posix:%s; brix_auth none; brix_allow_write on;
        brix_thread_pool aiopool; brix_memory_budget 6m;
    }
}
http {
    access_log off;
    client_body_temp_path %s/logs/cbt; proxy_temp_path %s/logs/pt;
    fastcgi_temp_path %s/logs/ft; uwsgi_temp_path %s/logs/ut; scgi_temp_path %s/logs/st;
    server {
        listen %s:%d;
        location = /metrics { brix_metrics on; }
        location /s3b/ { brix_s3 on; brix_storage_backend posix:%s; brix_s3_bucket s3b;
                         brix_s3_region us-east-1; }
        location / { brix_webdav on; brix_storage_backend posix:%s; brix_webdav_auth none;
                     brix_allow_write on; }
    }
}
""" % (prefix, prefix, BIND_HOST, root_port, datadir,
       prefix, prefix, prefix, prefix, prefix,
       BIND_HOST, http_port, datadir, datadir))
    conf_path = os.path.join(prefix, "nginx.conf")
    with open(conf_path, "w") as target:
        target.write(conf)
    environment = _server_environment(shim, prefix, tsandir)
    _validate_and_start(prefix, conf_path, environment, root_port)
    server = _fixture_server(prefix, conf_path, ports, datadir, tsandir)
    _require_master(server, environment)
    _report_fixture(server)
    try:
        yield server
    finally:
        _cleanup_fixture(server, environment)


# --------------------------- P1: cross-connection bind handle races ----------

def _send_readv_attack(connection, handle, offset):
    segments = b"".join(
        struct.pack("!4siq", handle, 1 << 20, offset + index * (1 << 20))
        for index in range(8)
    )
    connection.sendall(_frame(kXR_readv, b"", segments))


def _send_write_attack(connection, handle):
    status, body = _open(connection, "/w.bin", flags=0x0010 | 0x0020)
    write_handle = body[:4] if status == kXR_ok and len(body) >= 4 else handle
    request = struct.pack("!4sqB3s", write_handle, 0, 0, b"\x00" * 3)
    connection.sendall(_frame(kXR_write, request, b"Z" * (1 << 20)))


def _send_aio_attack(connection, rng, handle):
    operation = rng.choice(("pgread", "readv", "write"))
    offset = rng.randrange(0, (BIGFILE_MB - 8) * 1024 * 1024)
    if operation == "pgread":
        length = rng.choice((8 << 20, 16 << 20))
        connection.sendall(_frame(
            kXR_pgread, struct.pack("!4sqi", handle, offset, length)
        ))
        return
    if operation == "readv":
        _send_readv_attack(connection, handle, offset)
        return
    _send_write_attack(connection, handle)


def _aio_rst_round(port, rng):
    connection = None
    try:
        connection = _connect(port, 4)
        _login(connection)
        status, body = _open(connection, "/big.bin", flags=0x0010)
        if status == kXR_ok and len(body) >= 4:
            _send_aio_attack(connection, rng, body[:4])
    except Exception:
        pass
    finally:
        if connection is not None:
            delay = rng.choice((0, 0.0005, 0.003))
            if delay:
                time.sleep(delay)
            _rst(connection)


def _aio_rst_worker(port, datadir, rounds, stop_at, counter):
    rng = random.Random(threading.get_ident())
    while time.time() < stop_at and counter[0] < rounds:
        counter[0] += 1
        _aio_rst_round(port, rng)


def _http(method, path, body=None, timeout=4, port=None):
    import urllib.request, urllib.error
    url = "http://%s:%d%s" % (HOST, port or _XP_HTTP[0], path)
    req = urllib.request.Request(url, data=body, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code
    except Exception:
        return None


_XP_HTTP = [0]
_XP_S3 = [0]

__all__ = [name for name in dir() if not name.startswith("__")]
