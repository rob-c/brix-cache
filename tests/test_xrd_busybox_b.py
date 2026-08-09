from split_continuation import reexport as _reexport
_reexport(globals(), "_test_xrd_busybox_helpers")

def test_download_roundtrip_and_default_name(rw, tmp_path):
    blob = b"download-me\n" * 5000
    (rw["data"] / "dl_src.bin").write_bytes(blob)
    out = tmp_path / "got.bin"
    p = _run("download", _url(rw, "/dl_src.bin"), str(out))
    assert p.returncode == 0, p.stderr
    assert out.read_bytes() == blob
    # default local name = remote basename, created in cwd
    p2 = subprocess.run([XRD, "download", _url(rw, "/dl_src.bin")],
                        capture_output=True, text=True, cwd=str(tmp_path), timeout=30)
    assert p2.returncode == 0, p2.stderr
    assert (tmp_path / "dl_src.bin").read_bytes() == blob


def test_download_rate_limit_paces(rw):
    (rw["data"] / "dlr.bin").write_bytes(b"q" * (4 << 20))
    t0 = time.monotonic()
    p = _run("download", "-f", "rate=4M", _url(rw, "/dlr.bin"), "-")
    dt = time.monotonic() - t0
    assert p.returncode == 0, p.stderr
    assert len(p.stdout) == (4 << 20)          # "q" bytes decode 1:1 as text
    assert 0.6 < dt < 4.0, f"download rate pacing off: {dt:.3f}s"


def test_download_no_overwrite_without_force(rw, tmp_path):
    (rw["data"] / "dl2.bin").write_bytes(b"data\n")
    out = tmp_path / "exists.bin"
    out.write_bytes(b"old\n")
    p = _run("download", _url(rw, "/dl2.bin"), str(out))
    assert p.returncode != 0
    assert out.read_bytes() == b"old\n"        # untouched


# ===================== diagnostics: caps/whoami/clockskew/certinfo/doctor ====

def test_caps_lists_qconfig(rw):
    p = _run("caps", _url(rw))
    assert p.returncode == 0, p.stderr
    assert "role=server" in p.stdout
    assert "chksum" in p.stdout and "xrdfs.ext" in p.stdout


def test_whoami_anonymous(rw):
    p = _run("whoami", _url(rw))
    assert p.returncode == 0, p.stderr
    assert "anonymous" in p.stdout
    assert "presenting:" in p.stdout


def test_clockskew_in_sync(rw):
    # server is localhost → offset ~0; root:// uses touch+stat (server is writable)
    p = _run("clockskew", _url(rw))
    assert p.returncode == 0, p.stderr
    assert "clock offset:" in p.stdout and "server time:" in p.stdout


def test_certinfo_cleartext_is_clean(rw):
    # the rw fixture is cleartext root:// → no peer cert, reported cleanly (exit 0)
    p = _run("certinfo", _url(rw))
    assert p.returncode == 0, p.stderr
    assert "no server certificate" in p.stdout


def test_certinfo_tls_when_available():
    """If the shared GSI+TLS server (:11096) is up, exercise real cert parsing."""
    if not os.path.exists(XRD):
        pytest.skip("xrd not built")
    if not _port_up(HOST, 11096):
        pytest.skip("no TLS server on :11096")
    p = subprocess.run([XRD, "certinfo", f"roots://{HOST}:11096//"],
                       capture_output=True, text=True, timeout=30)
    assert p.returncode in (0, 1), p.stderr      # 0 valid, 1 expired/not-yet
    assert "server certificate for" in p.stdout
    assert "validity:" in p.stdout and "issuer:" in p.stdout



def test_doctor_human(rw, tmp_path):
    p = subprocess.run([XRD, "doctor", _url(rw)], capture_output=True, text=True,
                       env=_clean_cred_env(tmp_path), timeout=30)
    assert p.returncode == 0, f"{p.stdout}\n{p.stderr}"
    assert "== endpoint" in p.stdout
    assert "connect:  OK" in p.stdout
    assert "caps:" in p.stdout and "clock:" in p.stdout


def test_doctor_json(rw):
    p = _run("doctor", _url(rw), "--json")
    assert p.returncode == 0, p.stderr
    doc = json.loads(p.stdout)                   # must be valid JSON
    assert doc["connected"] is True
    assert doc["role"] == "server"
    assert doc["port"] == rw["port"]
    assert "chksum" in doc["capabilities"]
    assert doc["capabilities"]["xrdfs.ext"]
    assert doc["clock"] is not None              # root:// touch+stat measured it
    assert "credentials" in doc


def test_doctor_readonly_battery_json(rw):
    """doctor (no --rw) runs the read-only root:// method battery; writes skipped."""
    p = _run("doctor", _url(rw), "--json")
    assert p.returncode == 0, p.stderr
    doc = json.loads(p.stdout)
    assert "tests" in doc and len(doc["tests"]) == 1
    t = doc["tests"][0]
    assert t["protocol"] == "root" and t["reachable"] is True
    names = {c["name"]: c["status"] for c in t["checks"]}
    assert names.get("stat") == "pass" and names.get("dirlist") == "pass"
    assert names.get("path-confinement") == "pass"
    assert names.get("write-suite") == "skip"     # read-only by default


def test_doctor_rw_battery_json(rw, tmp_path):
    """doctor --rw runs the full write/read/verify/checksum/metadata cycle; zero fails
    (the symlink-unlink limitation surfaces as a SKIP, not a FAIL)."""
    p = subprocess.run([XRD, "doctor", _url(rw), "--rw", "--json"],
                       capture_output=True, text=True,
                       env=_clean_cred_env(tmp_path), timeout=60)
    assert p.returncode == 0, f"{p.stdout}\n{p.stderr}"
    doc = json.loads(p.stdout)
    t = doc["tests"][0]
    assert t["protocol"] == "root" and t["reachable"] is True
    assert t["failed"] == 0, [c for c in t["checks"] if c["status"] == "fail"]
    names = {c["name"]: c["status"] for c in t["checks"]}
    for step in ("write", "read-verify", "readv", "checksum-verify", "rename", "rm"):
        assert names.get(step) == "pass", (step, names)


def test_doctor_rw_human(rw, tmp_path):
    p = subprocess.run([XRD, "doctor", _url(rw), "--rw"], capture_output=True, text=True,
                       env=_clean_cred_env(tmp_path), timeout=60)
    assert p.returncode == 0, f"{p.stdout}\n{p.stderr}"
    assert "== root tests:" in p.stdout
    assert "[PASS] write" in p.stdout and "[PASS] read-verify" in p.stdout
    assert "checksum-verify" in p.stdout


def test_doctor_also_webdav_when_available(rw):
    """If the shared davs endpoint (:8443) is up, --also runs the WebDAV battery."""
    if not _port_up(HOST, NGINX_WEBDAV_PORT):
        pytest.skip(f"no davs server on :{NGINX_WEBDAV_PORT}")
    p = subprocess.run([XRD, "doctor", _url(rw), "--rw", "--insecure",
                        "--also", f"https://{HOST}:{NGINX_WEBDAV_PORT}/", "--json"],
                       capture_output=True, text=True, timeout=60)
    doc = json.loads(p.stdout)
    web = [t for t in doc["tests"] if t["protocol"] in ("http", "https")]
    assert web and web[0]["reachable"] is True
    names = {c["name"]: c["status"] for c in web[0]["checks"]}
    assert names.get("OPTIONS") == "pass" and names.get("PUT") == "pass"
    assert names.get("GET-verify") == "pass"


def test_doctor_also_s3_when_available(rw):
    """If the shared S3 endpoint (:9001) is up, --also runs the S3 battery."""
    if not _port_up(HOST, 9001):
        pytest.skip("no S3 server on :9001")
    env = dict(os.environ, AWS_ACCESS_KEY_ID="testkey",
               AWS_SECRET_ACCESS_KEY="testsecret", AWS_DEFAULT_REGION="us-east-1")
    p = subprocess.run([XRD, "doctor", _url(rw), "--rw", "--insecure",
                        "--also", f"s3://{HOST}:9001/testbucket", "--json"],
                       capture_output=True, text=True, env=env, timeout=60)
    doc = json.loads(p.stdout)
    s3 = [t for t in doc["tests"] if t["protocol"] == "s3"]
    assert s3 and s3[0]["reachable"] is True
    names = {c["name"]: c["status"] for c in s3[0]["checks"]}
    assert names.get("list-objects") == "pass"
    assert names.get("PUT") == "pass" and names.get("GET-verify") == "pass"


def test_sync_uploads_tree(rw, tmp_path):
    """`xrd sync` mirrors a local tree to a remote dir with rsync-style trailing-
    slash semantics: a source WITHOUT a trailing slash nests the directory itself
    under the destination; a source WITH a trailing slash copies its contents in
    flat."""
    src = tmp_path / "srctree"
    src.mkdir()
    (src / "x.txt").write_text("one\n")
    (src / "y.txt").write_text("two\n")

    # no trailing slash -> nest the source dir under the destination
    p = _run("sync", str(src), _url(rw, "/nested"))
    assert p.returncode == 0, f"{p.stdout}\n{p.stderr}"
    assert (rw["data"] / "nested" / "srctree" / "x.txt").read_text() == "one\n"
    assert (rw["data"] / "nested" / "srctree" / "y.txt").read_text() == "two\n"

    # trailing slash -> flat mirror of the contents into the destination
    p = _run("sync", str(src) + "/", _url(rw, "/flat"))
    assert p.returncode == 0, f"{p.stdout}\n{p.stderr}"
    assert (rw["data"] / "flat" / "x.txt").read_text() == "one\n"
    assert (rw["data"] / "flat" / "y.txt").read_text() == "two\n"
