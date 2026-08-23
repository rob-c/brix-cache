# tests/test_rpm_mirror_dnf.py — RPM/dnf pull-through mirror (phase-104 D11).
# Port block 14160–14162: 14160 mirror, 14161 upstream repo, 14162 a second
# mirror whose repomd TTL is shortened so the expiry leg does not sleep 60 s.
#
# The lane drives deploy/rpm-mirror/nginx.conf.example itself rather than a
# copy, so the file operators deploy is the file under test. It runs on the
# SYSTEM nginx: the recipe is stock proxy_pass + proxy_cache grammar with no
# brix directives, and running it on /usr/sbin/nginx is what proves that.
#
# Three legs, per the standing rule:
#   success  — dnf installs through the mirror; with upstream killed a second
#              install still succeeds from cache;
#   error    — upstream down + expired repomd fails promptly instead of hanging;
#   security — a repo re-signed with the wrong GPG key is refused by dnf
#              *through* the mirror: the mirror passes bytes, it does not
#              launder trust.
import os
import shutil
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "rpm"))

import make_fixtures                                            # noqa: E402

from settings import HOST                                       # noqa: E402

BRIXRPM = os.path.join(REPO_ROOT, "client", "bin", "brixrpm")
CONF_EXAMPLE = os.path.join(REPO_ROOT, "deploy", "rpm-mirror",
                            "nginx.conf.example")
NGINX = shutil.which("nginx") or "/usr/sbin/nginx"

PORT_MIRROR = 14160
PORT_UPSTREAM = 14161
PORT_MIRROR_FAST = 14162     # same recipe, repomd TTL 1s (see _render)

REPO_SUBDIR = "el9"          # the recipe keys on ^/.*/repodata/ — needs a prefix

pytestmark = pytest.mark.timeout(600)


def _missing():
    for tool in ("dnf", "unshare", "rpmbuild", "gpg"):
        if shutil.which(tool) is None:
            return f"{tool} not installed"
    if not os.path.exists(NGINX):
        return "nginx not installed"
    if not os.path.exists(BRIXRPM):
        return "client/bin/brixrpm not built (make -C client brixrpm)"
    return ""


def _port_open(port):
    with socket.socket() as s:
        s.settimeout(0.2)
        return s.connect_ex((HOST, port)) == 0


def _wait_port(port, timeout=20.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if _port_open(port):
            return
        time.sleep(0.1)
    raise RuntimeError(f"nothing listening on {HOST}:{port}")


def _wait_port_free(port, timeout=20.0):
    """`nginx -s quit` is graceful: it returns before the master drops the
    listening socket. Probe by *binding*, which is the precondition the next
    nginx actually needs — a failed connect() only proves nobody is accepting.
    """
    deadline = time.time() + timeout
    while time.time() < deadline:
        with socket.socket() as s:
            # Both servers bind with SO_REUSEADDR; probing without it would be
            # stricter than they are and would trip over TIME_WAIT sockets
            # left by the dnf connections rather than a live listener.
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                s.bind(("0.0.0.0", port))  # net-literal-allow: the probe must bind the wildcard, which is the address under test
                return
            except OSError:
                time.sleep(0.1)
    raise RuntimeError(f"port {port} still bound after quit")


def _render(dest_dir, port, cachedir, origin, repomd_ttl=None):
    """Instantiate the shipped example config.

    repomd_ttl rewrites only the freshness-root TTL. The example is canonical
    at 60 s; the expiry leg needs it to lapse inside a test, and rewriting the
    one value keeps every other line of the recipe under test.
    """
    with open(CONF_EXAMPLE) as fh:
        text = fh.read()
    text = (text.replace("@PORT@", str(port))
                .replace("@CACHEDIR@", cachedir)
                .replace("@ORIGIN@", origin))
    if repomd_ttl is not None:
        text = text.replace("proxy_cache_valid 200 60s;",
                            f"proxy_cache_valid 200 {repomd_ttl};")
    path = os.path.join(dest_dir, f"mirror-{port}.conf")
    with open(path, "w") as fh:
        fh.write(text)
    return path


def _nginx_argv(conf, cachedir, *extra):
    # -e keeps nginx off the compiled-in /var/log/nginx/error.log, which it
    # opens before it has parsed our error_log directive and cannot write to
    # as an unprivileged user.
    return [NGINX, "-c", conf, "-p", cachedir,
            "-e", os.path.join(cachedir, "startup.log"), *extra]


def _start_nginx(conf, cachedir, port):
    # nginx creates only the last component of a *_temp_path, so the parent
    # has to exist first. The operator equivalent is the `install -d` in
    # docs/05-operations/rpm-mirror.md §2.
    for sub in ("store", "tmp"):
        os.makedirs(os.path.join(cachedir, sub), exist_ok=True)
    check = subprocess.run(_nginx_argv(conf, cachedir, "-t"),
                           capture_output=True, text=True)
    assert check.returncode == 0, check.stderr
    run = subprocess.run(_nginx_argv(conf, cachedir),
                         capture_output=True, text=True)
    assert run.returncode == 0, run.stderr
    _wait_port(port)
    return os.path.join(cachedir, "nginx.pid")


def _stop_nginx(conf, cachedir, port):
    subprocess.run(_nginx_argv(conf, cachedir, "-s", "quit"),
                   capture_output=True, text=True)
    try:
        _wait_port_free(port)
    except RuntimeError:
        pidfile = os.path.join(cachedir, "nginx.pid")
        if os.path.exists(pidfile):
            with open(pidfile) as fh:
                os.kill(int(fh.read().strip()), 9)
            _wait_port_free(port)


def _dnf(base, baseurl, *pkgs, tag="t", reposdir=None, extra=()):
    root = os.path.join(base, f"root.{tag}")
    cache = os.path.join(base, f"cache.{tag}")
    cmd = ["unshare", "-r", "--", "dnf", "--disablerepo=*",
           f"--installroot={root}", "--releasever=9",
           f"--setopt=cachedir={cache}", *extra]
    if reposdir is not None:
        cmd += [f"--setopt=reposdir={reposdir}", "--enablerepo=brixmirror"]
    else:
        cmd += [f"--repofrompath=brixmirror,{baseurl}",
                "--enablerepo=brixmirror", "--setopt=gpgcheck=0"]
    return subprocess.run(cmd + ["-y", "install", *pkgs],
                          capture_output=True, text=True)


class Upstream:
    """The origin repo, stoppable and restartable.

    Two lanes need it *down* mid-test. Killing a module-scoped fixture's
    process would strand every test after them, so ownership of the lifecycle
    lives here and an autouse fixture puts it back up between tests.
    """

    def __init__(self, docroot):
        self.docroot = docroot
        self.proc = None

    def start(self):
        if self.proc is not None and self.proc.poll() is None:
            return
        self.proc = subprocess.Popen(
            [sys.executable, "-m", "http.server", str(PORT_UPSTREAM),
             "--bind", HOST, "--directory", str(self.docroot)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        _wait_port(PORT_UPSTREAM)

    def stop(self):
        if self.proc is not None and self.proc.poll() is None:
            self.proc.kill()
            self.proc.wait(timeout=10)
        _wait_port_free(PORT_UPSTREAM)


@pytest.fixture(scope="module")
def upstream(tmp_path_factory):
    """A real RPM repo served over plain HTTP — the mirror's origin."""
    blocked = _missing()
    if blocked:
        pytest.skip(blocked)

    base = tmp_path_factory.mktemp("rpmmirror")
    docroot = base / "upstream"
    repo = docroot / REPO_SUBDIR / "Packages"
    repo.mkdir(parents=True)
    for src in make_fixtures.build():
        shutil.copy2(src, repo / src.name)
    cr = subprocess.run([BRIXRPM, "createrepo", str(docroot / REPO_SUBDIR)],
                        capture_output=True, text=True)
    assert cr.returncode == 0, cr.stderr

    up = Upstream(docroot)
    try:
        yield base, up
    finally:
        up.stop()


@pytest.fixture(autouse=True)
def upstream_running(request):
    """Every test starts with the origin reachable, whatever the last did."""
    if "upstream" in request.fixturenames:
        request.getfixturevalue("upstream")[1].start()


def _mirror_instance(base, port, ttl):
    cachedir = str(base / f"cache{port}")
    os.makedirs(cachedir, exist_ok=True)
    conf = _render(str(base), port, cachedir,
                   f"{HOST}:{PORT_UPSTREAM}", repomd_ttl=ttl)
    _start_nginx(conf, cachedir, port)
    return conf, cachedir


@pytest.fixture(scope="module")
def mirror(upstream):
    """The mirror under test, started once on the shipped recipe.

    Module-scoped deliberately: a cache that persists across tests is both the
    realistic shape and the only way the upstream-loss lane means anything.
    """
    base, _up = upstream
    conf, cachedir = _mirror_instance(base, PORT_MIRROR, None)
    try:
        yield base, f"http://{HOST}:{PORT_MIRROR}/{REPO_SUBDIR}", cachedir
    finally:
        _stop_nginx(conf, cachedir, PORT_MIRROR)


@pytest.fixture
def fast_mirror(upstream):
    """A second instance whose repomd TTL is 1 s, so the expiry leg does not
    have to sleep out the recipe's canonical 60 s."""
    base, _up = upstream
    conf, cachedir = _mirror_instance(base, PORT_MIRROR_FAST, "1s")
    try:
        yield base, f"http://{HOST}:{PORT_MIRROR_FAST}/{REPO_SUBDIR}", cachedir
    finally:
        _stop_nginx(conf, cachedir, PORT_MIRROR_FAST)


# ---------------------------------------------------------------- success ---

def test_install_through_mirror_then_survive_upstream_loss(upstream, mirror):
    """dnf installs through the mirror; killing upstream does not break the
    next install, because packages and digest-named metadata are cached."""
    base, baseurl, cachedir = mirror
    _base, up = upstream

    first = _dnf(str(base), baseurl, "brixtest-app", tag="m1")
    assert first.returncode == 0, (first.stdout + first.stderr)[-1500:]
    for want in ("brixtest-app-0.9-4", "brixtest-lib-2:2.0-1",
                 "brixtest-tools-1.2-3"):
        assert want in first.stdout, first.stdout

    # the mirror really did cache: its store is non-empty
    store = os.path.join(cachedir, "store")
    cached = sum(len(files) for _r, _d, files in os.walk(store))
    assert cached > 0, "mirror cached nothing"

    # upstream goes away; a fresh install root still resolves from cache
    up.stop()
    second = _dnf(str(base), baseurl, "brixtest-app", tag="m2")
    def _assert_test_install_through_mirror_then_survive_upstream_loss_1():
        assert second.returncode == 0, (second.stdout + second.stderr)[-1500:]
        assert "brixtest-app-0.9-4" in second.stdout

    _assert_test_install_through_mirror_then_survive_upstream_loss_1()


def test_immutable_objects_report_a_cache_hit(upstream, mirror):
    """X-Brix-Cache is the operator's view of which policy a URL landed in."""
    _base, baseurl, _cachedir = mirror
    url = baseurl + "/repodata/repomd.xml"
    urllib.request.urlopen(url, timeout=10).read()          # prime
    with urllib.request.urlopen(url, timeout=10) as resp:
        assert resp.headers.get("X-Brix-Cache") in ("HIT", "REVALIDATED"), \
            dict(resp.headers)


def test_mirror_is_read_only(mirror):
    """A mirror has no write surface (recipe §3.5)."""
    _base, baseurl, _cachedir = mirror
    req = urllib.request.Request(baseurl + "/repodata/repomd.xml",
                                 method="DELETE")
    with pytest.raises(urllib.error.HTTPError) as exc:
        urllib.request.urlopen(req, timeout=10)
    assert exc.value.code == 405


# ------------------------------------------------------------------ error ---

def test_upstream_down_and_expired_repomd_errors_promptly(upstream,
                                                          fast_mirror):
    """`proxy_cache_use_stale off` on the freshness root means an unreachable
    upstream is an error dnf reports, not a hang and not a stale answer."""
    base, baseurl, _cachedir = fast_mirror
    _base, up = upstream

    assert _dnf(str(base), baseurl, "brixtest-tools", tag="e0").returncode == 0

    up.stop()
    time.sleep(2)                      # let the 1 s repomd TTL lapse

    started = time.time()
    out = _dnf(str(base), baseurl, "brixtest-tools", tag="e1")
    elapsed = time.time() - started

    assert out.returncode != 0, "mirror served an expired repomd from cache"
    assert elapsed < 120, f"took {elapsed:.0f}s — that is a hang, not an error"
    combined = (out.stdout + out.stderr).lower()
    assert any(w in combined for w in ("error", "failed", "cannot")), combined[-600:]


# ------------------------------------------------------- security-negative ---

def _gpg(home, *args, **kw):
    env = dict(os.environ, GNUPGHOME=home)
    return subprocess.run(["gpg", "--batch", "--yes", *args],
                          capture_output=True, text=True, env=env, **kw)


@pytest.fixture(scope="module")
def two_keys(upstream):
    """Two independent signing keys: one signs, the other is published."""
    base, _up = upstream
    home = base / "gnupg"
    home.mkdir(mode=0o700, exist_ok=True)
    exported = {}
    for name in ("signer", "impostor"):
        gen = _gpg(str(home), "--passphrase", "", "--quick-generate-key",
                   f"{name} <{name}@brix.invalid>", "rsa2048", "sign", "never")
        if gen.returncode != 0:
            pytest.skip("gpg could not generate a key: " + gen.stderr[-300:])
        pub = base / f"{name}.asc"
        out = _gpg(str(home), "--armor", "--export", f"{name}@brix.invalid")
        pub.write_text(out.stdout)
        exported[name] = pub
    return home, exported


def test_wrong_gpg_key_is_refused_through_the_mirror(upstream, mirror,
                                                     two_keys):
    """The mirror must pass bytes through faithfully enough that client-side
    verification still works — and must not be able to launder a bad signature.

    repomd.xml is signed by `signer`; the .repo file publishes `impostor` as
    the trusted key. dnf must refuse, and it must refuse having fetched the
    signature through the mirror.
    """
    base, baseurl, _cachedir = mirror
    _base, up = upstream
    docroot = up.docroot
    home, keys = two_keys

    repomd = docroot / REPO_SUBDIR / "repodata" / "repomd.xml"
    sig = _gpg(str(home), "--local-user", "signer@brix.invalid",
               "--detach-sign", "--armor", "--output", str(repomd) + ".asc",
               str(repomd))
    assert sig.returncode == 0, sig.stderr

    reposdir = base / "reposd"
    reposdir.mkdir(exist_ok=True)
    (reposdir / "brixmirror.repo").write_text(
        "[brixmirror]\n"
        "name=mirror under test\n"
        f"baseurl={baseurl}\n"
        "enabled=1\n"
        "gpgcheck=0\n"
        "repo_gpgcheck=1\n"
        f"gpgkey=file://{keys['impostor']}\n")

    out = _dnf(str(base), None, "brixtest-tools", tag="s1",
               reposdir=str(reposdir))
    assert out.returncode != 0, "dnf accepted a repo signed by the wrong key"
    combined = (out.stdout + out.stderr).lower()
    assert any(w in combined for w in
               ("gpg", "signature", "not signed", "verification")), \
        combined[-800:]

    # and the signature really did travel through the mirror
    with urllib.request.urlopen(baseurl + "/repodata/repomd.xml.asc",
                                timeout=10) as resp:
        assert b"BEGIN PGP SIGNATURE" in resp.read()
