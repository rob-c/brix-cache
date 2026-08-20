# tests/test_oci_brixoci_copy.py — brixoci CLI against the mock registry
# (phase-104 D5.5): pull/push/copy/tags/rm/inspect success lanes, fault and
# not-found error lanes, and the security negatives (auth-file mode gate,
# wrong Basic creds, third-party token realm, Authorization-strip on a
# cross-host blob redirect). D15.2 adds the IPv6-literal reference lane.
# Port block 14140–14145 (oci_registry lanes).
import hashlib, json, os, subprocess, sys, time, urllib.request
import pytest
from settings import HOST

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BRIXOCI = os.path.join(REPO_ROOT, "client", "bin", "brixoci")
# conftest chdir()s into a scratch dir at session start — resolve the mock
# script against this file, never the cwd.
MOCK = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                    "oci", "mock_registry.py")

PORT_PLAIN = 14140          # anonymous + push + --page-tags 1
PORT_BASIC = 14141          # --auth --basic user:secret
PORT_EVIL = 14142           # --auth --realm on a third-party host
PORT_REDIR = 14143          # --auth + blob redirect to the CDN twin
PORT_CDN = 14144            # --cdn twin on a DIFFERENT host string
PORT_V6 = 14145             # the same mock, bound to the IPv6 loopback
CDN_HOST = "127.0.0.2"      # at_origin compares host strings — must differ
V6_HOST = "::1"             # net-literal-allow: IPv6 loopback, the point of the lane

pytestmark = pytest.mark.skipif(
    not os.path.exists(BRIXOCI),
    reason="client/bin/brixoci not built (make -C client brixoci)")


def _spawn(port, *extra):
    return subprocess.Popen([sys.executable, MOCK, "--port", str(port),
                             *extra])


def _wait_ready(base):
    for _ in range(50):
        try:
            urllib.request.urlopen(base + "/ctl/log", timeout=0.2)
            return
        except Exception:
            time.sleep(0.1)
    raise RuntimeError("mock at %s never came up" % base)


def _ctl(base, path):
    return json.load(urllib.request.urlopen(base + path))


@pytest.fixture(scope="module")
def mocks():
    procs = [
        _spawn(PORT_PLAIN, "--push", "--page-tags", "1"),
        _spawn(PORT_BASIC, "--auth", "--basic", "user:secret"),
        _spawn(PORT_EVIL, "--auth", "--realm", "http://evil.example/token"),
        _spawn(PORT_REDIR, "--auth", "--blob-redirect",
               "http://%s:%d" % (CDN_HOST, PORT_CDN)),
        _spawn(PORT_CDN, "--cdn", "--bind", CDN_HOST),
        _spawn(PORT_V6, "--bind", V6_HOST),
    ]
    bases = {PORT_PLAIN: f"http://{HOST}:{PORT_PLAIN}",
             PORT_BASIC: f"http://{HOST}:{PORT_BASIC}",
             PORT_EVIL: f"http://{HOST}:{PORT_EVIL}",
             PORT_REDIR: f"http://{HOST}:{PORT_REDIR}",
             PORT_CDN: f"http://{CDN_HOST}:{PORT_CDN}",
             PORT_V6: f"http://[{V6_HOST}]:{PORT_V6}"}
    for b in bases.values():
        _wait_ready(b)
    yield bases
    for p in procs:
        p.terminate()
    for p in procs:
        p.wait()


@pytest.fixture()
def home(tmp_path):
    # brixoci reads ~/.config/brix/oci-auth: always point HOME at a scratch
    # dir so a developer's real credentials can never leak into a lane.
    (tmp_path / ".config" / "brix").mkdir(parents=True)
    return tmp_path


def _auth_file(home, password="secret"):
    f = home / ".config" / "brix" / "oci-auth"
    f.write_text("machine %s login user password %s\n" % (HOST, password))
    f.chmod(0o600)
    return f


def brixoci(*args, home=None, timeout=60):
    env = dict(os.environ)
    if home is not None:
        env["HOME"] = str(home)
    return subprocess.run([BRIXOCI, *args, "--insecure"],
                          capture_output=True, text=True, timeout=timeout,
                          env=env)


def _ref(port, name_tag):
    return "%s:%d/%s" % (HOST, port, name_tag)


# ---- success ------------------------------------------------------------

def test_pull_creates_verified_layout(mocks, tmp_path, home):
    dst = tmp_path / "app-v1"
    r = brixoci("pull", _ref(PORT_PLAIN, "lab/app:v1"), "--to", str(dst),
                home=home)
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip().startswith("sha256:")
    assert (dst / "oci-layout").exists() and (dst / "index.json").exists()
    blobs = list((dst / "blobs" / "sha256").iterdir())
    assert len(blobs) >= 4                # manifest + config + 2 layers
    for b in blobs:
        assert hashlib.sha256(b.read_bytes()).hexdigest() == b.name

def test_pull_platform_selects_from_index(mocks, tmp_path, home):
    dst = tmp_path / "multi-arm"
    r = brixoci("pull", _ref(PORT_PLAIN, "lab/multi:latest"),
                "--platform", "linux/arm64", "--to", str(dst), home=home)
    assert r.returncode == 0, r.stderr

def test_push_roundtrip_same_digest(mocks, tmp_path, home):
    lay = tmp_path / "lay"
    r1 = brixoci("pull", _ref(PORT_PLAIN, "lab/app:v1"), "--to", str(lay),
                 home=home)
    assert r1.returncode == 0, r1.stderr
    r2 = brixoci("push", _ref(PORT_PLAIN, "lab/pushed:v1"),
                 "--from", str(lay), home=home)
    assert r2.returncode == 0, r2.stderr
    assert r2.stdout.strip() == r1.stdout.strip()
    r3 = brixoci("inspect", _ref(PORT_PLAIN, "lab/pushed:v1"), home=home)
    assert r3.returncode == 0, r3.stderr

def test_copy_reg_to_reg(mocks, home):
    r = brixoci("copy", _ref(PORT_PLAIN, "lab/app:v1"),
                _ref(PORT_PLAIN, "lab/copied:v1"), home=home)
    assert r.returncode == 0, r.stderr
    r = brixoci("inspect", _ref(PORT_PLAIN, "lab/copied:v1"), home=home)
    assert r.returncode == 0, r.stderr

def test_tags_follows_link_pagination(mocks, home):
    # the mock pages one tag at a time (--page-tags 1): both tags listed
    # proves the client followed the Link rel="next" chain.
    r = brixoci("tags", "%s:%d/lab/app" % (HOST, PORT_PLAIN), home=home)
    assert r.returncode == 0, r.stderr
    assert set(r.stdout.split()) >= {"v1", "v2"}

def test_rm_removes_manifest(mocks, home):
    # rm deletes BY DIGEST (registries have no delete-by-tag), so the copy
    # must come from v2: v1's manifest is shared with lanes that run later.
    r = brixoci("copy", _ref(PORT_PLAIN, "lab/app:v2"),
                _ref(PORT_PLAIN, "lab/doomed:v1"), home=home)
    assert r.returncode == 0, r.stderr
    r = brixoci("rm", _ref(PORT_PLAIN, "lab/doomed:v1"), home=home)
    assert r.returncode == 0, r.stderr
    r = brixoci("inspect", _ref(PORT_PLAIN, "lab/doomed:v1"), home=home)
    assert r.returncode == 4

# ---- error --------------------------------------------------------------

def test_unknown_ref_exit4_with_registry_message(mocks, home):
    r = brixoci("inspect", _ref(PORT_PLAIN, "lab/app:v99"), home=home)
    assert r.returncode == 4
    assert "manifest unknown" in r.stderr        # the envelope's own words

def test_platform_not_in_index_exit4_lists_available(mocks, tmp_path, home):
    # (no --platform auto-selects the host platform, docker-style — the
    # error lane is a platform the index does not carry)
    r = brixoci("pull", _ref(PORT_PLAIN, "lab/multi:latest"),
                "--platform", "linux/s390x", "--to", str(tmp_path / "x"),
                home=home)
    assert r.returncode == 4
    assert "linux/s390x" in r.stderr and "available" in r.stderr

def test_corrupt_blob_exit5_no_stage_leftovers(mocks, tmp_path, home):
    urllib.request.urlopen(urllib.request.Request(
        mocks[PORT_PLAIN] + "/ctl/fault", method="POST",
        data=json.dumps({"kind": "corrupt", "path_re": "/blobs/"}).encode()))
    dst = tmp_path / "bad"
    r = brixoci("pull", _ref(PORT_PLAIN, "lab/app:v1"), "--to", str(dst),
                home=home)
    assert r.returncode == 5, r.stderr
    assert "sha256:" in r.stderr                 # names the digests
    leftovers = [p for p in dst.rglob(".stage.*")]
    assert leftovers == []

# ---- security-negative --------------------------------------------------

def test_world_readable_auth_file_refused_then_ok(mocks, tmp_path, home):
    f = _auth_file(home)
    f.chmod(0o644)
    r = brixoci("pull", _ref(PORT_BASIC, "lab/app:v1"),
                "--to", str(tmp_path / "a"), home=home)
    assert r.returncode == 3
    assert "0600" in r.stderr
    f.chmod(0o600)
    r = brixoci("pull", _ref(PORT_BASIC, "lab/app:v1"),
                "--to", str(tmp_path / "b"), home=home)
    assert r.returncode == 0, r.stderr
    assert _ctl(mocks[PORT_BASIC], "/ctl/token_count")["count"] >= 1

def test_wrong_basic_creds_exit3(mocks, tmp_path, home):
    _auth_file(home, password="letmein")
    r = brixoci("pull", _ref(PORT_BASIC, "lab/app:v1"),
                "--to", str(tmp_path / "a"), home=home)
    assert r.returncode == 3

def test_third_party_realm_refused_without_contact(mocks, tmp_path, home):
    _auth_file(home)
    r = brixoci("pull", _ref(PORT_EVIL, "lab/app:v1"),
                "--to", str(tmp_path / "a"), home=home)
    assert r.returncode == 3
    assert _ctl(mocks[PORT_EVIL], "/ctl/token_count")["count"] == 0

def test_cross_host_redirect_strips_authorization(mocks, tmp_path, home):
    r = brixoci("pull", _ref(PORT_REDIR, "lab/app:v1"),
                "--to", str(tmp_path / "a"), home=home)
    assert r.returncode == 0, r.stderr
    # auth was live at the origin…
    assert _ctl(mocks[PORT_REDIR], "/ctl/token_count")["count"] >= 1
    # …and never followed the blob redirect to the other host.
    assert _ctl(mocks[PORT_CDN], "/ctl/saw_authorization")["count"] == 0


# ---- IPv6-literal references (D15.2) ------------------------------------

def _v6_ref(name_tag):
    """The bracketed spelling, as podman and every registry client write it."""
    return "[%s]:%d/%s" % (V6_HOST, PORT_V6, name_tag)


def test_pull_over_ipv6_literal_host(mocks, tmp_path, home):
    """A v6-only registry is reachable by literal, brackets and all.

    This exercises the whole chain, not just the parse: the reference splits
    into an unbracketed host, the socket layer dials AF_INET6, and the Host:
    header is re-bracketed on the way out — a mismatch anywhere and the mock
    would answer 400 or never be dialled at all.
    """
    dst = tmp_path / "v6"
    r = brixoci("pull", _v6_ref("lab/app:v1"), "--to", str(dst), home=home)
    assert r.returncode == 0, r.stderr
    assert (dst / "oci-layout").exists()
    assert r.stdout.strip().startswith("sha256:")

def test_tags_over_ipv6_literal_host(mocks, home):
    r = brixoci("tags", _v6_ref("lab/app"), home=home)
    assert r.returncode == 0, r.stderr
    assert "v1" in r.stdout

@pytest.mark.parametrize("ref", [
    "[::1zz]:5000/lab/app",              # not a v6 literal at all
    "[::1:5000/lab/app",                 # unterminated bracket
    "[]:5000/lab/app",                   # empty literal
    "[::1]:0/lab/app",                   # port zero
    "[::1]:70000/lab/app",               # port out of range
    "[::1]:5000",                        # a host and no repository
])
def test_malformed_ipv6_reference_refused(ref, home):
    """A literal that does not parse never becomes a connection."""
    r = brixoci("inspect", ref, home=home)
    assert r.returncode != 0
    assert "registry host" in r.stderr

@pytest.mark.parametrize("ref", [
    "user@[::1]:5000/lab/app",           # userinfo: reads as one host, dials another
    "[::1]evil.example:5000/lab/app",    # junk trailing the literal
    "[::1]:5000@evil.example/lab/app",   # userinfo after the port
    "[::1/lab]:5000/app",                # a '/' smuggled inside the brackets
])
def test_authority_confusion_refused(ref, home):
    """The host a human reads must be the host the tool dials.

    Every spelling here puts two plausible hosts in one reference; the parser
    refuses rather than picking, which is the only answer that cannot be
    argued with later.
    """
    r = brixoci("inspect", ref, home=home)
    assert r.returncode != 0
    assert "evil.example" not in r.stdout
