from split_continuation import reexport as _reexport
_reexport(globals(), "_test_evil_paths_helpers")

class TestRootEvil:

    def test_traversal_read_blocked(self):
        s = _connect(); _full_anon_login(s)
        for p in TRAVERSAL_READ:
            st, body = _root_stat(s, p)
            if st is None:
                s = _connect(); _full_anon_login(s); continue
            assert st != kXR_ok, f"root stat {p!r} returned kXR_ok"
            assert HOST_SECRET not in body
        s.close()

    def test_traversal_open_read_blocked(self):
        s = _connect(); _full_anon_login(s)
        for p in TRAVERSAL_READ:
            try:
                s.sendall(make_open_req(p + b"\x00", options=0x0000))
                st, body = _recv_response(s)
            except (socket.timeout, ConnectionError, OSError):
                s = _connect(); _full_anon_login(s); continue
            assert st != kXR_ok, f"root open(read) {p!r} succeeded"
            assert HOST_SECRET not in body
        s.close()

    def test_traversal_nul_read_blocked(self):
        """Embedded-NUL paths must error and never leak host content (stat+open)."""
        s = _connect(); _full_anon_login(s)
        for p in TRAVERSAL_NUL:
            st, body = _root_stat(s, p)
            if st is None:
                s = _connect(); _full_anon_login(s); continue
            assert st != kXR_ok, f"root stat NUL {p!r} returned kXR_ok"
            assert HOST_SECRET not in body, f"root stat NUL {p!r} leaked host content"
            try:
                s.sendall(make_open_req(p + b"\x00", options=0x0000))
                st2, body2 = _recv_response(s)
            except (socket.timeout, ConnectionError, OSError):
                s = _connect(); _full_anon_login(s); continue
            assert st2 != kXR_ok, f"root open(read) NUL {p!r} succeeded"
            assert HOST_SECRET not in body2, f"root open NUL {p!r} leaked host content"
        s.close()

    def test_traversal_nul_write_creates_nothing_outside(self):
        """Embedded-NUL create/mkdir must not place anything outside the root."""
        s = _connect(); _full_anon_login(s)
        name = f"evilnul_{uuid.uuid4().hex}"
        for tmpl in (b"/x\x00/../" + name.encode(),
                     b"/../" + name.encode() + b"\x00.txt",
                     b"/" + name.encode() + b"\x00/../../" + name.encode()):
            p = tmpl + b"\x00"
            for op, opts in ((kXR_mkdir, None), (kXR_open, kXR_new | kXR_open_updt)):
                try:
                    if op == kXR_open:
                        s.sendall(make_open_req(p, options=opts))
                    else:
                        s.sendall(make_request(b"\x00\xA0", op,
                                               body=b"\x00" * 16, payload=p))
                    st, _ = _recv_response(s)
                except (socket.timeout, ConnectionError, OSError):
                    s = _connect(); _full_anon_login(s); st = 4003
                assert st != kXR_ok, f"root NUL write {tmpl!r} succeeded — escape!"
        _assert_nothing_escaped(name)
        s.close()

    def test_traversal_write_creates_nothing_outside(self):
        s = _connect(); _full_anon_login(s)
        name = f"evilroot_{uuid.uuid4().hex}"
        for op, opts in ((kXR_mkdir, None), (kXR_open, kXR_new | kXR_open_updt)):
            for tmpl in (f"/../{name}", f"/a/../../{name}", f"/./../{name}"):
                p = tmpl.encode() + b"\x00"
                try:
                    if op == kXR_open:
                        s.sendall(make_open_req(p, options=opts))
                    else:
                        s.sendall(make_request(b"\x00\xA0", op,
                                               body=b"\x00" * 16, payload=p))
                    st, _ = _recv_response(s)
                except (socket.timeout, ConnectionError, OSError):
                    s = _connect(); _full_anon_login(s); st = 4003
                assert st != kXR_ok, f"root write {tmpl!r} succeeded — escape!"
        _assert_nothing_escaped(name)
        s.close()

    def test_symlink_escapes_blocked(self, evil_symlinks):
        s = _connect(); _full_anon_login(s)
        for key, val in evil_symlinks.items():
            if key == "legit_inroot":
                continue
            probe = (val if isinstance(val, str) else val[0]).encode()
            st, body = _root_stat(s, b"/" + probe)
            if st is None:
                s = _connect(); _full_anon_login(s); continue
            assert st != kXR_ok, f"root stat via symlink {key} ({probe!r}) ok!"
            assert HOST_SECRET not in body
            # also try open-read through the link
            try:
                s.sendall(make_open_req(b"/" + probe + b"\x00", options=0x0000))
                st2, body2 = _recv_response(s)
            except (socket.timeout, ConnectionError, OSError):
                s = _connect(); _full_anon_login(s); continue
            assert st2 != kXR_ok, f"root open via symlink {key} succeeded!"
            assert HOST_SECRET not in body2
        s.close()


# ===========================================================================
# roots:// — native XRootD over GSI + in-protocol TLS (port 11096).
# Proves confinement holds on the TLS transport explicitly, not just
# transitively from plain root://.  Driven through the real XRootD client so the
# gotoTLS upgrade + GSI auth are negotiated for us.  Symlink escapes are the
# sharpest probe: they use literal in-root names (no "../" the client could
# normalise away client-side), so any leak is an unambiguous server-side breach.
# ===========================================================================

@pytest.mark.skipif(not _HAVE_XRD,
                    reason="pyxrootd (XRootD python client) not installed")
class TestRootsTlsEvil:

    @pytest.fixture(scope="class", autouse=True)
    def _require_roots(self):
        if not os.path.exists(PROXY_STD):
            pytest.skip(f"GSI proxy cert not found at {PROXY_STD}")
        os.environ.setdefault("X509_USER_PROXY", PROXY_STD)
        if not _port_up(NGINX_GSI_TLS_PORT):
            pytest.skip(f"roots:// (GSI+TLS) port {NGINX_GSI_TLS_PORT} not reachable")

    def _stat(self, path):
        return _xrd_client.FileSystem(GSI_TLS_URL).stat(path)[0]

    def _open_read(self, path):
        f = _xrd_client.File()
        status, _ = f.open(f"{GSI_TLS_URL}//{path.lstrip('/')}")
        data = b""
        try:
            if status.ok:
                st2, info = f.stat()
                if st2.ok and getattr(info, "size", 0):
                    rs, data = f.read(0, info.size)
                    if not rs.ok:
                        data = b""
        finally:
            try:
                f.close()
            except Exception:
                pass
        return status, data or b""

    def test_traversal_read_blocked(self):
        for p in TRAVERSAL_READ:
            path = p.decode("latin-1")
            assert not self._stat(path).ok, f"roots:// stat {path!r} returned ok"
            ost, data = self._open_read(path)
            assert not ost.ok, f"roots:// open(read) {path!r} succeeded"
            assert HOST_SECRET not in data, f"roots:// {path!r} leaked host content"

    def test_symlink_escapes_blocked(self, evil_symlinks):
        for key, val in evil_symlinks.items():
            if key == "legit_inroot":
                continue
            probe = val if isinstance(val, str) else val[0]
            assert not self._stat("/" + probe).ok, \
                f"roots:// stat via symlink {key} ({probe}) returned ok!"
            ost, data = self._open_read("/" + probe)
            assert not ost.ok, f"roots:// open via symlink {key} ({probe}) succeeded!"
            assert HOST_SECRET not in data, \
                f"roots:// symlink {key} ({probe}) leaked host content"


# ===========================================================================
# HTTP / HTTPS WebDAV  and  S3   (shared raw-request helpers)
# ===========================================================================


class TestWebDavHttpEvil:
    def test_evil_battery(self):
        _webdav_evil_suite(NGINX_HTTP_WEBDAV_PORT, tls=False)

    def test_symlink_escapes(self, evil_symlinks):
        _webdav_symlink_suite(NGINX_HTTP_WEBDAV_PORT, tls=False, evil_symlinks=evil_symlinks)


@pytest.mark.skipif(not _port_up(NGINX_WEBDAV_PORT),
                    reason="https WebDAV (8443) not reachable")
class TestWebDavHttpsEvil:
    def test_evil_battery(self):
        _webdav_evil_suite(NGINX_WEBDAV_PORT, tls=True)

    def test_symlink_escapes(self, evil_symlinks):
        _webdav_symlink_suite(NGINX_WEBDAV_PORT, tls=True, evil_symlinks=evil_symlinks)


@pytest.mark.skipif(not _port_up(NGINX_S3_PORT),
                    reason="S3 (9001) not reachable")
class TestS3Evil:
    BUCKET = "testbucket"

    def test_traversal_get_blocked(self):
        for path in TRAVERSAL_HTTP_ENCODED:
            st, data = _raw(NGINX_S3_PORT, "GET", f"/{self.BUCKET}{path}")
            assert HOST_SECRET not in data, f"S3 GET {path} leaked host content"

    def test_symlink_escapes(self, evil_symlinks):
        for key, val in evil_symlinks.items():
            probe = val if isinstance(val, str) else val[0]
            st, data = _raw(NGINX_S3_PORT, "GET", f"/{self.BUCKET}/{probe}")
            if key == "legit_inroot":
                continue
            assert HOST_SECRET not in data, \
                f"S3 GET via symlink {key} ({probe}) leaked host content (st={st})"
            assert st in (403, 404), \
                f"S3 GET via symlink {key} should be 403/404, got {st}"

    def test_put_traversal_creates_nothing_outside(self):
        name = f"evils3_{uuid.uuid4().hex}"
        for path in (f"/{self.BUCKET}/../{name}",
                     f"/{self.BUCKET}/%2e%2e/{name}"):
            try:
                _raw(NGINX_S3_PORT, "PUT", path, body=b"pwn")
            except OSError:
                pass
        _assert_nothing_escaped(name)


# ===========================================================================
# cms:// — hostile MANAGER probes a data node with kYR_state for evil paths.
# The node must answer kYR_have ONLY for files genuinely inside the export
# root; symlink/".." escapes must be rejected (confined stat_beneath).
# ===========================================================================

CMS_RR_LOGIN = 0
CMS_RR_STATE = 20
CMS_RR_HAVE = 15
CMS_RR_STATUS = 22
CMS_RR_LOAD = 16
CMS_HDR = 8



class TestCmsStateEvil:
    """Stand up a mock CMS manager + a dedicated nginx data node pointing at it,
    then probe the node's kYR_state handler with escaping paths."""

    @pytest.fixture(scope="class")
    def cms_node(self, evil_symlinks):
        # mock manager listening socket
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        from ephemeral_port import free_port
        mgr_port = free_port(BIND_HOST)
        srv.bind((BIND_HOST, mgr_port))
        srv.listen(4)
        srv.settimeout(20)

        harness = LifecycleHarness()
        try:
            harness.start(NginxInstanceSpec(
                name="lc-evil-cms-node",
                template="nginx_evil_cms_node.conf",
                protocol="root", readiness="tcp",
                data_root=DATA_ROOT,
                template_values={"CMS_MANAGER": f"{url_host(HOST)}:{mgr_port}"}))
        except Exception:
            harness.close()
            srv.close()
            raise

        # accept the node's CMS client connection
        try:
            conn, _ = srv.accept()
        except socket.timeout:
            harness.close()
            srv.close()
            pytest.skip("nginx CMS client never connected to mock manager")

        # Drain the node's login/status/load frames so our state frames are
        # processed cleanly.
        time.sleep(0.5)
        conn.setblocking(False)
        try:
            while True:
                if not conn.recv(4096):
                    break
        except (BlockingIOError, OSError):
            pass
        conn.setblocking(True)

        yield conn

        try:
            conn.close()
        except OSError:
            pass
        srv.close()
        harness.close()

    def test_state_symlink_escape_no_have(self, cms_node, evil_symlinks):
        conn = cms_node
        sid = 1000
        breaches = []
        for key, val in evil_symlinks.items():
            if key == "legit_inroot":
                continue
            probe = val if isinstance(val, str) else val[0]
            _cms_state(conn, sid, "/" + probe)
            sid += 1
            fr = _cms_read_frame(conn, timeout=2.0)
            # A kYR_have reply for an escaping path = the node falsely claims to
            # hold a file outside its root.  Silence (None) or any non-HAVE is OK.
            if fr is not None and fr[0] == CMS_RR_HAVE:
                breaches.append((key, probe))
        assert not breaches, f"CMS kYR_state symlink escapes returned kYR_have: {breaches}"

    def test_state_dotdot_no_have(self, cms_node):
        conn = cms_node
        sid = 2000
        breaches = []
        for p in ("/../etc/passwd", "/../../etc/passwd", "/a/../../etc/passwd"):
            _cms_state(conn, sid, p)
            sid += 1
            fr = _cms_read_frame(conn, timeout=2.0)
            if fr is not None and fr[0] == CMS_RR_HAVE:
                breaches.append(p)
        assert not breaches, f"CMS kYR_state '..' escapes returned kYR_have: {breaches}"


# ===========================================================================
# EVIL WRITES — the dangerous half: can a bad actor CREATE / OVERWRITE / DELETE
# / MOVE a real file OUTSIDE the export root?  Unlike the read tests (which only
# need to deny content), these target a genuinely WRITABLE directory outside the
# root (TEST_ROOT itself, which the test user owns) reached via symlinks and
# "..", and assert the outside zone is left perfectly pristine.
# ===========================================================================

kXR_mv = 3009
kXR_rmdir = 3015
kXR_truncate = 3028
ORIGINAL = b"ORIGINAL-DO-NOT-TOUCH"
class TestWebDavHttpEvilWrites:
    def test_write_escapes_blocked(self, write_zone):
        _webdav_write_attacks(NGINX_HTTP_WEBDAV_PORT, False, write_zone)


@pytest.mark.skipif(not _port_up(NGINX_WEBDAV_PORT),
                    reason="https WebDAV (8443) not reachable")
class TestWebDavHttpsEvilWrites:
    def test_write_escapes_blocked(self, write_zone):
        _webdav_write_attacks(NGINX_WEBDAV_PORT, True, write_zone)


# --- S3 evil writes ----------------------------------------------------------
