"""Phase-115 W1, live half — boot each compose stack and run its own smoke.sh.

Continuation shard of test_phase115_example_configs.py (loaded through
split_continuation), not a standalone module: it shares that file's imports,
markers and helpers (``lib``, ``COMPOSE``, ``LOCAL_STACKS``, ``needs_nginx``,
the port-lease helpers) and is executed straight after it.  Split out because
the parent had grown past the 600-line limit; the seam is the one place the
suite stops reading shipped configs and starts running them.
"""

# --------------------------------------------------------------------------- #
# live: boot each stack on this host and run its own smoke.sh                 #
# --------------------------------------------------------------------------- #

# Container ports → published ports come from the compose file; 9100 is the
# per-container observability port, so it is remapped per conf, not per stack.
OBS_PORT = 9100
SMOKE_PORT_ENV = {
    "standalone":      {"ROOT_PORT": 1094, "DAV_PORT": 8443},
    "xrootd-proxy":    {"ROOT_PORT": 1094, "ORIGIN_PORT": 1095},
    "webdav-edge":     {"DAV_PORT": 8443},
    "gridftp-gateway": {"GSIFTP_PORT": 2811, "FTP_PORT": 2121},
    "httpg-proxy":     {"FRONT_PORT": 8443, "BACKEND_PORT": 8444},
    "cms-cluster":     {"MANAGER_PORT": 1094, "DS1_PORT": 1095, "DS2_PORT": 1096},
    "s3-frontend":     {"S3_PORT": 9000, "DAV_PORT": 8443},
    "xcache":          {"CACHE_PORT": 1094, "ORIGIN_PORT": 1095},
}
# Which conf carries the stack's published 9100 (the client's OBS_PORT).
OBS_CONF = {"xrootd-proxy": "nginx-proxy.conf", "httpg-proxy": "nginx-front.conf",
            "cms-cluster": "nginx-manager.conf", "xcache": "nginx-cache.conf"}


def _published_ports(stack):
    ports = set()
    for svc in _compose(stack)["services"].values():
        for p in svc.get("ports", []):
            container = str(p).split(":")[-1]
            if "-" not in container:
                ports.add(int(container))
    ports.discard(OBS_PORT)
    return sorted(ports)


#: A pinned FTP passive data range makes concurrent copies of the same stack
#: fight for the same ports — the loser answers "425 Can't open data
#: connection".  Each rendered config gets its own leased block instead.
_PASV_RANGE = re.compile(r"(brix_gridftp_pasv_port_range\s+)(\d+)(\s+)(\d+)")


def _lease_pasv_ranges(text):
    def swap(m):
        width = int(m.group(4)) - int(m.group(2)) + 1
        low, high = lease_port_range(width)
        return f"{m.group(1)}{low}{m.group(3)}{high}"
    return _PASV_RANGE.sub(swap, text)


def _remap(text, mapping):
    for old, new in mapping.items():
        text = re.sub(rf"(?<![\d.]){old}(?![\d.])", str(new), text)
    return text


_RUNTIME_HOSTS = lib._SERVICE_HOST_RE


def _localise(text):
    """Point every server-side `<service>:<port>` at loopback for a local run.

    In the compose stacks the service names resolve through Docker's DNS; on
    this host they do not resolve at all (HOSTALIASES is a gethostbyname-era
    mechanism, and every lookup that matters here — nginx's config-time upstream
    parse, a worker's remote root:// open, a CMS join — goes through
    getaddrinfo, which never consults it).  Only `host:port` positions change;
    server_name / proxy_ssl_name / paths and the client-facing smoke environment
    keep the service names.

    One implementation, shared with the renderer: tools/ci/example_config_lib
    localises the same positions for `nginx -t`, and a second copy here would be
    free to drift from the alias list it is derived from.
    """
    return lib.localise_service_hosts(text)


def _wait_ports(ports, log, deadline=30.0):
    end = time.monotonic() + deadline
    for port in ports:
        while True:
            try:
                with socket.create_connection((HOST, port), timeout=0.5):
                    break
            except OSError:
                if time.monotonic() > end:
                    pytest.fail(f"port {port} never opened\n{log.read_text()[-4000:]}")
                time.sleep(0.1)



class _Stack:
    """Every nginx*.conf of one compose stack, running on this host."""

    def __init__(self, stack, base):
        self.stack, self.base, self.procs = stack, base, []
        self.ports = {p: _lease_bindable() for p in _published_ports(stack)}
        self.obs_ports = {}
        pki_root = base / "shared"
        self.pki = lib._demo_pki(pki_root)[2].parent
        self.env = dict(os.environ, HOSTALIASES=str(base / "hostaliases"))
        (base / "hostaliases").write_text("".join(f"{h} localhost\n" for h in lib.HOST_ALIASES))  # net-literal-allow: the host-alias mechanism is the subject under test
        for conf in sorted((COMPOSE / stack).glob("nginx*.conf")):
            self._boot(conf)

    def _boot(self, conf):
        prefix = self.base / conf.stem
        prefix.mkdir()
        os.symlink(self.pki, prefix / "_pki")
        obs = _lease_bindable()
        self.obs_ports[conf.name] = obs
        text = _localise(_remap(conf.read_text(), {**self.ports, OBS_PORT: obs}))
        text = _lease_pasv_ranges(text)
        r = lib.render(lib.Example(f"{self.stack}/{conf.name}", text, "full"), prefix)
        lib.prepare_nginx(r, NGINX)
        # This is the one boot in the suite the registry does not arrange, so
        # the de-escalation courtesy `_prepare_nginx_permissions` does for every
        # other instance has to be spelled here.  The master starts as root and
        # its workers drop to `nobody` (always — `lifecycle_worker.c` refuses a
        # uid-0 worker), while the whole stack lives under a 0700 `tmp_path`:
        # every worker died "cannot open export root ... (13: Permission
        # denied)" with the master still holding the listener, so smoke.sh saw
        # a port that accepts and never answers ("curl: (28) Operation timed
        # out", "xrdcp: read timed out") and named nothing about permissions.
        # The base rather than the prefix: the stacks share one PKI tree and
        # one hostaliases file beside it.  Credential modes survive — the
        # helper snapshots and restores every key it widened.
        open_tree_for_worker(self.base, r.conf)
        log = prefix / "stderr.log"
        proc = subprocess.Popen([NGINX, "-p", str(prefix), "-c", str(r.conf), "-g", "daemon off;"],
                                env=self.env, stdout=log.open("wb"), stderr=subprocess.STDOUT)
        self.procs.append(proc)
        listens = [int(p) for p in re.findall(r"^\s*listen\s+(\d+)", text, re.M)]
        _wait_ports(listens, log)

    def smoke_env(self):
        env = {k: str(self.ports[v]) for k, v in SMOKE_PORT_ENV[self.stack].items()}
        obs_conf = OBS_CONF.get(self.stack, "nginx.conf")
        env.update(BRIX_HOST="localhost", OBS_PORT=str(self.obs_ports[obs_conf]),  # net-literal-allow: the host-alias mechanism is the subject under test
                   XRDCP=str(XRDCP), BRIX_PKI_DIR=str(self.pki),
                   SMOKE_TMP=str(self.base / "smoke-tmp"), PATH=os.environ["PATH"],
                   HOME=os.environ.get("HOME", "/tmp"))
        return env

    def logs(self):
        return "\n".join(f"--- {p}\n{p.read_text()[-3000:]}" for p in self.base.glob("*/stderr.log"))

    def stop(self):
        for proc in self.procs:
            proc.terminate()
        for proc in self.procs:
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()


@needs_nginx
@needs_xrdcp
@pytest.mark.parametrize("stack", LOCAL_STACKS)
def test_stack_boots_and_passes_its_smoke(stack, tmp_path):
    if shutil.which("curl") is None:
        pytest.skip("curl not installed")
    _require_stack_nginx(stack)
    st = _Stack(stack, tmp_path)
    try:
        rc = subprocess.run(["sh", str(COMPOSE / stack / "smoke.sh")], env=st.smoke_env(),
                            capture_output=True, text=True, timeout=300)
        assert rc.returncode == 0, f"smoke.sh failed\n{rc.stdout}\n{rc.stderr}\n{st.logs()}"
        # A Grid CA dir holds <hash>.signing_policy next to <hash>.0; loading
        # it used to leave PEM_R_NO_START_LINE on OpenSSL's error queue and
        # every later handshake logged "ignoring stale global SSL error".
        logs = st.logs()
        assert "stale global SSL error" not in logs, logs
        assert "no start line" not in logs, logs
        assert f"SMOKE OK: {stack}" in rc.stdout
    finally:
        st.stop()


def _require_stack_nginx(stack):
    for conf in sorted((COMPOSE / stack).glob("nginx*.conf")):
        ex = lib.Example(str(conf.relative_to(ROOT)), conf.read_text(), "full")
        reason = lib.unsupported_reason(ex, NGINX)
        if reason:
            pytest.skip(reason)


@needs_nginx
def test_stack_port_remap_is_word_bounded(tmp_path):
    # 1094 must not rewrite 11094 or 1094.5; 9100 must be independent per conf.
    text = "listen 1094;\nlisten 11094;\nbrix_cms_manager manager:1213;\nx 1094.5;\n"
    out = _remap(text, {1094: 40000, 1213: 40001})
    assert out == "listen 40000;\nlisten 11094;\nbrix_cms_manager manager:40001;\nx 1094.5;\n"


def test_localise_points_only_service_host_ports_at_loopback():
    text = ("brix_storage_backend root://origin:1095;\nbrix_cms_manager manager:1213;\n"
            "proxy_pass https://backend:8444;\nbrix_tap_proxy_upstream origin:1095;\n")
    assert _localise(text) == ("brix_storage_backend root://127.0.0.1:1095;\n"  # net-literal-allow: config directive text is the parser's input
                               "brix_cms_manager 127.0.0.1:1213;\nproxy_pass https://127.0.0.1:8444;\n"
                               "brix_tap_proxy_upstream 127.0.0.1:1095;\n")


def test_localise_leaves_names_that_are_not_resolved_at_runtime():
    # TLS names, server_name, real DNS names, paths and env assignments stay.
    text = ("server_name origin;\nproxy_ssl_name backend;\nlisten localhost:1094;\n"  # net-literal-allow: config directive text is the parser's input
            "upstream x { server origin.example.org:1095; server my-origin:1095; }\n"
            "brix_export /data/origin;\nBRIX_HOST=origin\n")
    assert _localise(text) == text


def test_localise_does_not_reach_the_client_facing_smoke_environment(tmp_path):
    # The smoke scripts talk to localhost by name; only the servers' own
    # upstream references are rewritten, so a smoke that resolved `origin`
    # would still exercise the HOSTALIASES path exactly as nginx -t does.
    env_names = {v for v in SMOKE_PORT_ENV.get("xcache", {})}
    assert env_names == {"CACHE_PORT", "ORIGIN_PORT"}
    assert not _RUNTIME_HOSTS.search("localhost:1094 origin origin/1095 origin:x")  # net-literal-allow: config directive text is the parser's input
