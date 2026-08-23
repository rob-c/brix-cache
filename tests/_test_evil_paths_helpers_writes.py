@pytest.fixture()
def write_zone():
    """A writable directory OUTSIDE the export root + a victim file, plus
    symlinks planted INSIDE the root that point at them.  Yields names; on
    teardown asserts nothing leaked and cleans up."""
    tag = uuid.uuid4().hex[:10]
    zone = os.path.join(OUTSIDE, f"evil_wzone_{tag}")
    os.makedirs(zone, exist_ok=True)
    victim = os.path.join(zone, "victim.txt")
    with open(victim, "wb") as fh:
        fh.write(ORIGINAL)

    links = []

    def link(name, target):
        p = os.path.join(DATA_ROOT, name)
        try:
            if os.path.islink(p) or os.path.exists(p):
                os.remove(p)
            os.symlink(target, p)
            links.append(p)
            return name
        except OSError:
            return None

    sl_dir = link(f"wdir_{tag}", zone)         # symlink → writable outside dir
    sl_file = link(f"wfile_{tag}", victim)     # symlink → victim file
    # an in-root regular file, used as a MOVE/COPY source trying to escape
    src = os.path.join(DATA_ROOT, f"wsrc_{tag}.txt")
    with open(src, "wb") as fh:
        fh.write(b"in-root-source")

    yield {
        "zone": zone, "victim": victim, "zone_base": os.path.basename(zone),
        "sl_dir": sl_dir, "sl_file": sl_file,
        "src_key": f"wsrc_{tag}.txt",
    }

    for p in links:
        try:
            os.remove(p)
        except OSError:
            pass
    try:
        os.remove(src)
    except OSError:
        pass
    shutil.rmtree(zone, ignore_errors=True)


def _assert_zone_pristine(z):
    """The outside zone must be untouched: victim present + original content,
    and NO extra entry created."""
    assert os.path.exists(z["victim"]), \
        f"CONFINEMENT BREACH: victim {z['victim']} was deleted from outside the root"
    with open(z["victim"], "rb") as fh:
        assert fh.read() == ORIGINAL, \
            f"CONFINEMENT BREACH: victim {z['victim']} was overwritten/truncated"
    leftover = sorted(os.listdir(z["zone"]))
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
    for method, path, body in attacks:
        try:
            _raw(port, method, path, tls=tls, body=body)
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
                _raw(
                    port, method, source, tls=tls,
                    headers={"Destination": destination},
                )
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
