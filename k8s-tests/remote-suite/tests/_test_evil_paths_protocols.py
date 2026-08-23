# ===========================================================================
# HTTP / HTTPS WebDAV and S3
# ===========================================================================

def _http_conn(port, tls):
    if tls:
        context = ssl._create_unverified_context()
        return http.client.HTTPSConnection(
            SERVER_HOST, port, timeout=8, context=context
        )
    return http.client.HTTPConnection(SERVER_HOST, port, timeout=8)


def _raw(port, method, raw_path, tls=False, body=None, headers=None):
    """Send a verbatim request target so the server performs normalization."""
    connection = _http_conn(port, tls)
    try:
        connection.putrequest(
            method, raw_path, skip_host=False, skip_accept_encoding=True
        )
        for key, value in (headers or {}).items():
            connection.putheader(key, value)
        if body is not None:
            connection.putheader("Content-Length", str(len(body)))
        connection.endheaders()
        if body is not None:
            connection.send(body)
        response = connection.getresponse()
        return response.status, response.read()
    finally:
        connection.close()


def _port_up(port):
    try:
        with socket.create_connection((SERVER_HOST, port), timeout=2):
            return True
    except OSError:
        return False


def _assert_webdav_reads_confined(port, tls):
    for path in TRAVERSAL_HTTP_ENCODED:
        status, data = _raw(port, "GET", path, tls=tls)
        assert HOST_SECRET not in data, f"GET {path} leaked host content ({status})"


def _assert_webdav_creates_confined(port, tls):
    name = f"evildav_{uuid.uuid4().hex}"
    paths = (
        f"/../{name}",
        f"/%2e%2e/{name}",
        f"/foo/%2e%2e/%2e%2e/{name}",
    )
    for path in paths:
        try:
            _raw(port, "PUT", path, tls=tls, body=b"pwn")
            _raw(port, "MKCOL", path, tls=tls)
        except OSError:
            pass
    _assert_nothing_escaped(name)


def _assert_webdav_delete_confined(port, tls):
    victim = _outside(f"victim_dav_{uuid.uuid4().hex}")
    with open(victim, "wb") as handle:
        handle.write(b"keep")
    try:
        paths = (
            f"/../{os.path.basename(victim)}",
            f"/%2e%2e/{os.path.basename(victim)}",
        )
        for path in paths:
            try:
                _raw(port, "DELETE", path, tls=tls)
            except OSError:
                pass
        assert os.path.exists(victim), "WebDAV DELETE escaped the root"
    finally:
        if os.path.exists(victim):
            os.remove(victim)


def _webdav_evil_suite(port, tls):
    _assert_webdav_reads_confined(port, tls)
    _assert_webdav_creates_confined(port, tls)
    _assert_webdav_delete_confined(port, tls)


def _webdav_symlink_suite(port, tls, evil_symlinks):
    for key, probe in evil_symlinks.items():
        status, data = _raw(port, "GET", "/" + probe, tls=tls)
        assert HOST_SECRET not in data, (
            f"WebDAV GET via symlink {key} ({probe}) leaked host content "
            f"(st={status})"
        )
        assert status in (403, 404), (
            f"WebDAV GET via symlink {key} should be 403/404, got {status}"
        )


@pytest.mark.skipif(
    not _port_up(NGINX_HTTP_WEBDAV_PORT),
    reason="http WebDAV (8080) not reachable",
)
class TestWebDavHttpEvil:
    def test_evil_battery(self):
        _webdav_evil_suite(NGINX_HTTP_WEBDAV_PORT, tls=False)

    def test_symlink_escapes(self, evil_symlinks):
        _webdav_symlink_suite(
            NGINX_HTTP_WEBDAV_PORT, tls=False, evil_symlinks=evil_symlinks
        )


@pytest.mark.skipif(
    not _port_up(NGINX_WEBDAV_PORT), reason="https WebDAV (8443) not reachable"
)
class TestWebDavHttpsEvil:
    def test_evil_battery(self):
        _webdav_evil_suite(NGINX_WEBDAV_PORT, tls=True)

    def test_symlink_escapes(self, evil_symlinks):
        _webdav_symlink_suite(
            NGINX_WEBDAV_PORT, tls=True, evil_symlinks=evil_symlinks
        )


@pytest.mark.skipif(not _port_up(NGINX_S3_PORT), reason="S3 (9001) not reachable")
class TestS3Evil:
    BUCKET = "testbucket"

    def test_traversal_get_blocked(self):
        for path in TRAVERSAL_HTTP_ENCODED:
            _, data = _raw(NGINX_S3_PORT, "GET", f"/{self.BUCKET}{path}")
            assert HOST_SECRET not in data, f"S3 GET {path} leaked host content"

    def test_symlink_escapes(self, evil_symlinks):
        for key, value in evil_symlinks.items():
            probe = _symlink_probe(value)
            status, data = _raw(
                NGINX_S3_PORT, "GET", f"/{self.BUCKET}/{probe}"
            )
            if key == "legit_inroot":
                continue
            assert HOST_SECRET not in data, (
                f"S3 GET via symlink {key} ({probe}) leaked host content "
                f"(st={status})"
            )
            assert status in (403, 404), (
                f"S3 GET via symlink {key} should be 403/404, got {status}"
            )

    def test_put_traversal_creates_nothing_outside(self):
        name = f"evils3_{uuid.uuid4().hex}"
        paths = (
            f"/{self.BUCKET}/../{name}",
            f"/{self.BUCKET}/%2e%2e/{name}",
        )
        for path in paths:
            try:
                _raw(NGINX_S3_PORT, "PUT", path, body=b"pwn")
            except OSError:
                pass
        _assert_nothing_escaped(name)


# ===========================================================================
# cms:// manager probes
# ===========================================================================

CMS_RR_LOGIN = 0
CMS_RR_STATE = 20
CMS_RR_HAVE = 15
CMS_RR_STATUS = 22
CMS_RR_LOAD = 16
CMS_HDR = 8


def _cms_read_frame(sock, timeout=3.0):
    sock.settimeout(timeout)
    try:
        header = b""
        while len(header) < CMS_HDR:
            chunk = sock.recv(CMS_HDR - len(header))
            if not chunk:
                return None
            header += chunk
        code = header[4]
        data_length = struct.unpack(">H", header[6:8])[0]
        body = b""
        while len(body) < data_length:
            chunk = sock.recv(data_length - len(body))
            if not chunk:
                break
            body += chunk
        return code, body
    except socket.timeout:
        return None


def _cms_state(sock, stream_id, path):
    payload = path.encode() + b"\x00"
    header = struct.pack(">IBBH", stream_id, CMS_RR_STATE, 0x20, len(payload))
    sock.sendall(header + payload)


def _cms_listener():
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((BIND_HOST, 0))
    manager_port = listener.getsockname()[1]
    listener.listen(4)
    listener.settimeout(20)
    return listener, manager_port


def _cms_config(prefix, data_port, manager_port):
    return f"""
daemon off;
worker_processes 1;
pid {prefix}/nginx.pid;
error_log {prefix}/logs/error.log info;
events {{ worker_connections 64; }}
stream {{
    server {{
        listen {data_port};
        brix_root on;
        brix_storage_backend posix:{DATA_ROOT};
        brix_allow_write on;
        brix_cms_manager {url_host(HOST)}:{manager_port};
        brix_cms_interval 2;
    }}
}}
"""


def _start_cms_node(nginx_bin, manager_port):
    prefix = tempfile.mkdtemp(prefix="cms_evil_")
    os.makedirs(os.path.join(prefix, "logs"), exist_ok=True)
    os.makedirs(os.path.join(prefix, "conf"), exist_ok=True)
    config_path = os.path.join(prefix, "conf", "nginx.conf")
    with open(config_path, "w") as handle:
        handle.write(_cms_config(prefix, _free_port(), manager_port))
    return subprocess.Popen(
        [nginx_bin, "-p", prefix, "-c", "conf/nginx.conf"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def _accept_cms_connection(listener, process):
    try:
        connection, _ = listener.accept()
        return connection
    except socket.timeout:
        process.terminate()
        listener.close()
        pytest.skip("nginx CMS client never connected to mock manager")


def _drain_cms_connection(connection):
    time.sleep(0.5)
    connection.setblocking(False)
    try:
        while connection.recv(4096):
            pass
    except (BlockingIOError, OSError):
        pass
    connection.setblocking(True)


def _close_cms_resources(connection, listener, process):
    try:
        connection.close()
    except OSError:
        pass
    listener.close()
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()


def _cms_symlink_breaches(connection, evil_symlinks):
    breaches = []
    stream_id = 1000
    for key, value in evil_symlinks.items():
        if key == "legit_inroot":
            continue
        probe = _symlink_probe(value)
        _cms_state(connection, stream_id, "/" + probe)
        stream_id += 1
        frame = _cms_read_frame(connection, timeout=2.0)
        if frame is not None and frame[0] == CMS_RR_HAVE:
            breaches.append((key, probe))
    return breaches


class TestCmsStateEvil:
    @pytest.fixture(scope="class")
    def cms_node(self, evil_symlinks):
        nginx_bin = os.environ.get("NGINX_BIN", "/tmp/nginx-1.28.3/objs/nginx")
        if not os.path.exists(nginx_bin):
            pytest.skip("nginx binary not found for CMS data-node test")
        listener, manager_port = _cms_listener()
        process = _start_cms_node(nginx_bin, manager_port)
        connection = _accept_cms_connection(listener, process)
        _drain_cms_connection(connection)
        yield connection
        _close_cms_resources(connection, listener, process)

    def test_state_symlink_escape_no_have(self, cms_node, evil_symlinks):
        breaches = _cms_symlink_breaches(cms_node, evil_symlinks)
        assert not breaches, (
            f"CMS kYR_state symlink escapes returned kYR_have: {breaches}"
        )

    def test_state_dotdot_no_have(self, cms_node):
        breaches = []
        stream_id = 2000
        paths = ("/../etc/passwd", "/../../etc/passwd", "/a/../../etc/passwd")
        for path in paths:
            _cms_state(cms_node, stream_id, path)
            stream_id += 1
            frame = _cms_read_frame(cms_node, timeout=2.0)
            if frame is not None and frame[0] == CMS_RR_HAVE:
                breaches.append(path)
        assert not breaches, f"CMS kYR_state '..' escapes returned kYR_have: {breaches}"


def _free_port():
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind((BIND_HOST, 0))
    port = listener.getsockname()[1]
    listener.close()
    return port
