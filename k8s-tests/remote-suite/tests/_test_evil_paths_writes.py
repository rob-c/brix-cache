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


@pytest.fixture()
def write_zone():
    """A writable directory OUTSIDE the export root + a victim file, plus
    symlinks planted INSIDE the root that point at them.  Yields names; on
    teardown asserts nothing leaked and cleans up."""
    tag = uuid.uuid4().hex[:10]
    zone = os.path.join(SERVER_OUTSIDE, f"evil_wzone_{tag}")
    klib.svc_mkdir(SERVER_SVC, zone)
    victim = os.path.join(zone, "victim.txt")
    klib.svc_write(SERVER_SVC, victim, ORIGINAL)

    links = []

    def link(name, target):
        p = os.path.join(SERVER_DATA, name)
        try:
            klib.svc_symlink(SERVER_SVC, target, p)
            links.append(p)
            return name
        except OSError:
            return None

    sl_dir = link(f"wdir_{tag}", zone)         # symlink → writable outside dir
    sl_file = link(f"wfile_{tag}", victim)     # symlink → victim file
    # an in-root regular file, used as a MOVE/COPY source trying to escape
    src = os.path.join(SERVER_DATA, f"wsrc_{tag}.txt")
    klib.svc_write(SERVER_SVC, src, b"in-root-source")

    yield {
        "zone": zone, "victim": victim, "zone_base": os.path.basename(zone),
        "sl_dir": sl_dir, "sl_file": sl_file,
        "src_key": f"wsrc_{tag}.txt",
    }

    for p in links:
        klib.svc_rm(SERVER_SVC, p)
    klib.svc_rm(SERVER_SVC, src)
    klib.svc_rmtree(SERVER_SVC, zone)


def _assert_zone_pristine(z):
    """The outside zone must be untouched: victim present + original content,
    and NO extra entry created."""
    assert klib.svc_exists(SERVER_SVC, z["victim"]), \
        f"CONFINEMENT BREACH: victim {z['victim']} was deleted from outside the root"
    assert klib.svc_read(SERVER_SVC, z["victim"]) == ORIGINAL, \
        f"CONFINEMENT BREACH: victim {z['victim']} was overwritten/truncated"
    leftover = sorted(klib.svc_listdir(SERVER_SVC, z["zone"]))
    assert leftover == ["victim.txt"], \
        f"CONFINEMENT BREACH: outside zone gained entries {leftover}"


# --- WebDAV (http + https) evil writes --------------------------------------

def _webdav_dir_symlink_attacks(name):
    if not name:
        return []
    return [
        ("PUT", f"/{name}/PWNED_{uuid.uuid4().hex}", b"PWNED"),
        ("MKCOL", f"/{name}/pwndir_{uuid.uuid4().hex}", None),
        ("DELETE", f"/{name}/victim.txt", None),
    ]


def _webdav_file_symlink_attacks(name):
    if not name:
        return []
    return [("PUT", f"/{name}", b"PWNED"), ("DELETE", f"/{name}", None)]


def _webdav_traversal_attacks(zone_base):
    return [
        ("PUT", f"/../{zone_base}/PWNED_{uuid.uuid4().hex}", b"PWNED"),
        ("PUT", f"/%2e%2e/{zone_base}/PWNED_{uuid.uuid4().hex}", b"PWNED"),
        ("DELETE", f"/../{zone_base}/victim.txt", None),
        ("MKCOL", f"/../{zone_base}/pwndir_{uuid.uuid4().hex}", None),
    ]


def _send_webdav_write_attacks(port, tls, attacks):
    for method, path, b in attacks:
        try:
            _raw(port, method, path, tls=tls, body=b)
        except OSError:
            pass


def _webdav_write_destinations(dir_symlink, zone_base):
    destinations = [f"/../{zone_base}/moved_{uuid.uuid4().hex}"]
    if dir_symlink:
        destinations.insert(0, f"/{dir_symlink}/moved_{uuid.uuid4().hex}")
    return destinations


def _send_webdav_write_moves(port, tls, source, destinations):
    for destination in destinations:
        for method in ("MOVE", "COPY"):
            try:
                _raw(port, method, source, tls=tls,
                     headers={"Destination": destination})
            except OSError:
                pass


def _webdav_write_attacks(port, tls, z):
    attacks = _webdav_dir_symlink_attacks(z["sl_dir"])
    attacks += _webdav_file_symlink_attacks(z["sl_file"])
    attacks += _webdav_traversal_attacks(z["zone_base"])
    _send_webdav_write_attacks(port, tls, attacks)
    destinations = _webdav_write_destinations(z["sl_dir"], z["zone_base"])
    _send_webdav_write_moves(port, tls, "/" + z["src_key"], destinations)
    _assert_zone_pristine(z)


@pytest.mark.skipif(not _port_up(NGINX_HTTP_WEBDAV_PORT),
                    reason="http WebDAV (8080) not reachable")
class TestWebDavHttpEvilWrites:
    def test_write_escapes_blocked(self, write_zone):
        _webdav_write_attacks(NGINX_HTTP_WEBDAV_PORT, False, write_zone)


@pytest.mark.skipif(not _port_up(NGINX_WEBDAV_PORT),
                    reason="https WebDAV (8443) not reachable")
class TestWebDavHttpsEvilWrites:
    def test_write_escapes_blocked(self, write_zone):
        _webdav_write_attacks(NGINX_WEBDAV_PORT, True, write_zone)


# --- S3 evil writes ----------------------------------------------------------

@pytest.mark.skipif(not _port_up(NGINX_S3_PORT),
                    reason="S3 (9001) not reachable")
class TestS3EvilWrites:
    BUCKET = "testbucket"

    def test_write_escapes_blocked(self, write_zone):
        z = write_zone
        sd, sf, zb = z["sl_dir"], z["sl_file"], z["zone_base"]
        attacks = []
        if sd:
            attacks += [("PUT", f"/{self.BUCKET}/{sd}/PWNED_{uuid.uuid4().hex}", b"x"),
                        ("DELETE", f"/{self.BUCKET}/{sd}/victim.txt", None)]
        if sf:
            attacks += [("PUT", f"/{self.BUCKET}/{sf}", b"x"),
                        ("DELETE", f"/{self.BUCKET}/{sf}", None)]
        attacks += [
            ("PUT", f"/{self.BUCKET}/../{zb}/PWNED_{uuid.uuid4().hex}", b"x"),
            ("PUT", f"/{self.BUCKET}/%2e%2e/{zb}/PWNED_{uuid.uuid4().hex}", b"x"),
            ("DELETE", f"/{self.BUCKET}/../{zb}/victim.txt", None),
        ]
        for method, path, b in attacks:
            try:
                _raw(NGINX_S3_PORT, method, path, body=b)
            except OSError:
                pass
        _assert_zone_pristine(z)


# --- root:// evil writes -----------------------------------------------------

class TestRootEvilWrites:

    def _op(self, s, opcode, path, body=b"\x00" * 16, open_opts=None):
        p = path.encode() + b"\x00"
        try:
            if open_opts is not None:
                s.sendall(make_open_req(p, options=open_opts))
            else:
                s.sendall(make_request(b"\x00\xA0", opcode, body=body, payload=p))
            st, _ = _recv_response(s)
            return st, s
        except (socket.timeout, ConnectionError, OSError):
            s = _connect(); _full_anon_login(s)
            return None, s

    def _dir_targets(self, name):
        if not name:
            return []
        suffix = uuid.uuid4().hex
        return [
            (kXR_open, f"/{name}/PWNED_{suffix}", kXR_new | kXR_open_updt),
            (kXR_mkdir, f"/{name}/pwndir_{suffix}", None),
            (kXR_rm, f"/{name}/victim.txt", None),
        ]

    def _file_targets(self, name):
        if not name:
            return []
        return [
            (kXR_open, f"/{name}", kXR_new | kXR_open_updt),
            (kXR_truncate, f"/{name}", None),
        ]

    def _traversal_targets(self, zone_base):
        suffix = uuid.uuid4().hex
        return [
            (kXR_open, f"/../{zone_base}/PWNED_{suffix}", kXR_new | kXR_open_updt),
            (kXR_mkdir, f"/../{zone_base}/pwndir_{suffix}", None),
            (kXR_rm, f"/../{zone_base}/victim.txt", None),
            (kXR_rmdir, f"/../{zone_base}", None),
        ]

    def _assert_writes_blocked(self, connection, targets):
        for opcode, path, options in targets:
            status, connection = self._op(
                connection, opcode, path, open_opts=options
            )
            assert status != kXR_ok, (
                f"root write {path!r} (op {opcode}) succeeded — escape!"
            )
        return connection

    def _remove_file_symlink(self, connection, name):
        if not name:
            return connection
        status, connection = self._op(connection, kXR_rm, f"/{name}")
        assert status == kXR_ok, f"rm of in-root symlink /{name} should remove the link"
        return connection

    def _move_destinations(self, dir_symlink, zone_base):
        destinations = [f"/../{zone_base}/moved"]
        if dir_symlink:
            destinations.insert(0, f"/{dir_symlink}/moved")
        return destinations

    def _move(self, connection, zone, destination):
        payload = (f"/{zone['src_key']}\n{destination}").encode() + b"\x00"
        try:
            connection.sendall(
                make_request(
                    b"\x00\xA0", kXR_mv, body=b"\x00" * 16, payload=payload
                )
            )
            status, _ = _recv_response(connection)
            return status, connection
        except (socket.timeout, ConnectionError, OSError):
            connection = _connect()
            _full_anon_login(connection)
            return 4003, connection

    def _assert_moves_blocked(self, connection, zone, destinations):
        for destination in destinations:
            status, connection = self._move(connection, zone, destination)
            assert status != kXR_ok, (
                f"root mv to {destination!r} succeeded — escape!"
            )
        return connection

    def test_write_escapes_blocked(self, write_zone):
        z = write_zone
        sd, sf, zb = z["sl_dir"], z["sl_file"], z["zone_base"]
        s = _connect(); _full_anon_login(s)
        targets = self._dir_targets(sd)
        targets.extend(self._file_targets(sf))
        targets.extend(self._traversal_targets(zb))
        s = self._assert_writes_blocked(s, targets)
        s = self._remove_file_symlink(s, sf)
        s = self._assert_moves_blocked(s, z, self._move_destinations(sd, zb))
        s.close()
        _assert_zone_pristine(z)
