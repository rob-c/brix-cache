"""Password auth across every protocol scheme against one POSIX backend.

One throwaway nginx serves the SAME export three ways: root:// (stream
``brix_auth pwd``, the XrdSecpwd DH handshake), plain http:// and TLS
https:// (``brix_webdav_pwd_file`` → HTTP Basic verified against the same
``user:salthex:hashhex`` db).  WebDAV coverage rides the http(s) listeners
with real WebDAV verbs (PROPFIND/MKCOL), since dav:// IS WebDAV-over-HTTP.

Each scheme gets the mandated trio — success, error (wrong password), and a
security-negative (no credential) — plus a check that the config-time
"do NOT rely on password auth in production" warning is logged for BOTH the
stream and HTTP sides.

The fixture spawns everything on private high ports (no shared fleet) and
self-generates a throwaway TLS cert, so it runs anywhere the native client
is built.  Skips cleanly otherwise.
"""
import hashlib
import os
import subprocess
import time

import pytest

from settings import NGINX_BIN  # noqa: E402
from config_templates import render_config

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
NATIVE_XRDCP = os.path.join(REPO, "client", "bin", "xrdcp")

P_ROOT = 21144                      # private ports, clear of the fleet band
P_HTTP = 21145
P_HTTPS = 21146
PW = "multi-proto-pw"
USER = "protouser"


def _run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=120, **kw)


def _free_port(port):
    subprocess.run(["bash", "-c", f"fuser -k {port}/tcp 2>/dev/null"],
                   capture_output=True)
    for _ in range(20):
        if _run(["bash", "-c", f"ss -tln | grep -q ':{port} '"]).returncode != 0:
            return
        time.sleep(0.1)


def _wait_listen(proc, port, what):
    for _ in range(60):
        assert proc.poll() is None, f"{what} exited before binding {port}"
        if _run(["bash", "-c", f"ss -tln | grep -q ':{port} '"]).returncode == 0:
            return
        time.sleep(0.1)
    proc.terminate()
    raise AssertionError(f"{what} did not come up on {port}")


def _pwd_hash(password, salt):
    """The exact KDF stock XrdSecpwd uses: PBKDF2-HMAC-SHA1, 10000 iters, 24 B."""
    return hashlib.pbkdf2_hmac("sha1", password.encode(), salt, 10000, 24)


@pytest.fixture(scope="module")
def multi_server(tmp_path_factory):
    if not os.path.exists(NATIVE_XRDCP):
        pytest.skip("native client/bin/xrdcp must be built (make -C client)")

    base = tmp_path_factory.mktemp("pwdmp")
    data = base / "data"
    logs = base / "logs"
    data.mkdir()
    logs.mkdir()
    (data / "hello.txt").write_text("hello-multi-proto\n")

    salt = bytes(range(8))
    pwdfile = base / "pwd.db"
    pwdfile.write_text(f"{USER}:{salt.hex()}:{_pwd_hash(PW, salt).hex()}\n")

    cert = base / "tls.crt"
    key = base / "tls.key"
    r = _run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
              "-keyout", str(key), "-out", str(cert), "-days", "2",
              "-subj", "/CN=127.0.0.1"])
    assert r.returncode == 0, f"throwaway TLS cert generation failed: {r.stderr}"

    cfg = base / "nginx.conf"
    cfg.write_text(render_config("nginx_pwd_multiproto.conf",
                                 LOG_DIR=logs,
                                 PID_FILE=base / "nginx.pid",
                                 BASE_DIR=base,
                                 ROOT_PORT=P_ROOT,
                                 HTTP_PORT=P_HTTP,
                                 HTTPS_PORT=P_HTTPS,
                                 DATA_DIR=data,
                                 PWD_FILE=pwdfile,
                                 SERVER_CERT=cert,
                                 SERVER_KEY=key))

    for port in (P_ROOT, P_HTTP, P_HTTPS):
        _free_port(port)
    # Config-parse-time messages (including the pwd production warnings) are
    # written to stderr — the configured error_log is not open yet at that
    # phase — so capture stderr to a file the warning test can grep.
    startup_log = logs / "startup.log"
    proc = subprocess.Popen([NGINX_BIN, "-c", str(cfg)],
                            stdout=subprocess.DEVNULL,
                            stderr=open(startup_log, "wb"))
    for port in (P_ROOT, P_HTTP, P_HTTPS):
        _wait_listen(proc, port, "multiproto nginx")
    yield {"data": data, "log": startup_log,
           "root": f"root://127.0.0.1:{P_ROOT}",
           "http": f"http://127.0.0.1:{P_HTTP}",
           "https": f"https://127.0.0.1:{P_HTTPS}"}
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()


def _env(password=PW, user=USER):
    e = dict(os.environ)
    e.pop("XrdSecCREDS", None)
    if password is None:
        e.pop("XRDC_PWD", None)
    else:
        e["XRDC_PWD"] = password
    e["XRDC_PWD_USER"] = user
    return e


def _curl(url, *args, user=USER, password=PW):
    cmd = ["curl", "-ks", "-o", "/dev/null", "-w", "%{http_code}"]
    if password is not None:
        cmd += ["-u", f"{user}:{password}"]
    cmd += list(args) + [url]
    r = _run(cmd)
    assert r.returncode == 0, f"curl transport error: {r.stderr}"
    return r.stdout.strip()


# ---- root:// (stream pwd handshake) ----------------------------------------- #

def test_root_pwd_roundtrip(multi_server, tmp_path):
    out = str(tmp_path / "got.txt")
    r = _run([NATIVE_XRDCP, "--auth", "pwd", "-f",
              f"{multi_server['root']}//hello.txt", out], env=_env())
    assert r.returncode == 0, f"root:// pwd download failed: {r.stderr}"
    assert open(out).read() == "hello-multi-proto\n"

    src = str(tmp_path / "up.txt")
    open(src, "w").write("root-upload\n")
    r = _run([NATIVE_XRDCP, "--auth", "pwd", "-f", src,
              f"{multi_server['root']}//root-up.txt"], env=_env())
    assert r.returncode == 0, f"root:// pwd upload failed: {r.stderr}"
    assert (multi_server["data"] / "root-up.txt").read_text() == "root-upload\n"


def test_root_pwd_wrong_password_rejected(multi_server, tmp_path):
    out = str(tmp_path / "bad.txt")
    r = _run([NATIVE_XRDCP, "--auth", "pwd", "-f",
              f"{multi_server['root']}//hello.txt", out],
             env=_env(password="wrong"))
    assert r.returncode != 0, "root:// wrong password must be rejected"


def test_root_pwd_no_credential_rejected(multi_server, tmp_path):
    out = str(tmp_path / "none.txt")
    r = _run([NATIVE_XRDCP, "--auth", "pwd", "-f",
              f"{multi_server['root']}//hello.txt", out],
             env=_env(password=None))
    assert r.returncode != 0, "root:// missing credential must be rejected"


# ---- http:// (Basic against the same pwd db) -------------------------------- #

def test_http_basic_roundtrip(multi_server, tmp_path):
    assert _curl(f"{multi_server['http']}/hello.txt") == "200"

    src = tmp_path / "up.txt"
    src.write_text("http-upload\n")
    code = _curl(f"{multi_server['http']}/http-up.txt",
                 "-T", str(src))
    assert code in ("201", "204"), f"http PUT got {code}"
    assert (multi_server["data"] / "http-up.txt").read_text() == "http-upload\n"


def test_http_basic_wrong_password_rejected(multi_server):
    code = _curl(f"{multi_server['http']}/hello.txt", password="wrong")
    assert code == "401", f"wrong password must be rejected with 401, got {code}"


def test_http_basic_no_credential_rejected(multi_server):
    code = _curl(f"{multi_server['http']}/hello.txt", password=None)
    assert code == "401", f"anonymous must be rejected (auth required), got {code}"


def test_http_basic_unknown_user_rejected(multi_server):
    """Unknown user must fail exactly like a wrong password (no enumeration)."""
    code = _curl(f"{multi_server['http']}/hello.txt", user="ghost")
    assert code == "401", f"unknown user must be rejected, got {code}"


# ---- https:// (Basic over TLS) ----------------------------------------------- #

def test_https_basic_roundtrip(multi_server, tmp_path):
    assert _curl(f"{multi_server['https']}/hello.txt") == "200"

    src = tmp_path / "up.txt"
    src.write_text("https-upload\n")
    code = _curl(f"{multi_server['https']}/https-up.txt", "-T", str(src))
    assert code in ("201", "204"), f"https PUT got {code}"
    assert (multi_server["data"] / "https-up.txt").read_text() == "https-upload\n"


def test_https_basic_wrong_password_rejected(multi_server):
    code = _curl(f"{multi_server['https']}/hello.txt", password="wrong")
    assert code == "401", f"wrong password must be rejected with 401, got {code}"


def test_https_basic_no_credential_rejected(multi_server):
    code = _curl(f"{multi_server['https']}/hello.txt", password=None)
    assert code == "401", f"anonymous must be rejected (auth required), got {code}"


# ---- webdav:// (WebDAV verbs over both listeners) ---------------------------- #

def test_webdav_basic_propfind_and_mkcol(multi_server):
    code = _curl(f"{multi_server['http']}/", "-X", "PROPFIND",
                 "-H", "Depth: 1")
    assert code == "207", f"PROPFIND with Basic must succeed, got {code}"

    code = _curl(f"{multi_server['https']}/newdir", "-X", "MKCOL")
    assert code == "201", f"MKCOL with Basic must succeed, got {code}"
    assert (multi_server["data"] / "newdir").is_dir()


def test_webdav_basic_wrong_password_rejected(multi_server):
    code = _curl(f"{multi_server['http']}/", "-X", "PROPFIND",
                 "-H", "Depth: 1", password="wrong")
    assert code == "401", f"PROPFIND wrong password must be rejected, got {code}"


def test_webdav_basic_no_credential_rejected(multi_server):
    code = _curl(f"{multi_server['https']}/nodir", "-X", "MKCOL",
                 password=None)
    assert code == "401", f"anonymous MKCOL must be rejected, got {code}"
    assert not (multi_server["data"] / "nodir").exists()


# ---- browser challenge --------------------------------------------------------- #

def test_browser_basic_challenge_header(multi_server):
    """The 401 must carry a WWW-Authenticate: Basic challenge so browsers pop
    the native login prompt (and re-prompt on a wrong password)."""
    for base in (multi_server["http"], multi_server["https"]):
        r = _run(["curl", "-ksi", f"{base}/hello.txt"])
        assert r.returncode == 0, f"curl transport error: {r.stderr}"
        head = r.stdout.split("\r\n\r\n", 1)[0]
        assert " 401" in head.splitlines()[0], \
            f"anonymous request must get 401, got: {head.splitlines()[0]}"
        assert 'WWW-Authenticate: Basic realm="brix"' in head, \
            f"Basic challenge header missing from 401:\n{head}"


def test_browser_challenge_absent_on_success(multi_server):
    """An authenticated 200 must NOT carry a challenge header."""
    r = _run(["curl", "-ksi", "-u", f"{USER}:{PW}",
              f"{multi_server['http']}/hello.txt"])
    assert r.returncode == 0, f"curl transport error: {r.stderr}"
    head = r.stdout.split("\r\n\r\n", 1)[0]
    assert " 200" in head.splitlines()[0]
    assert "WWW-Authenticate" not in head


# ---- operator warning --------------------------------------------------------- #

def test_production_warning_logged_for_both_sides(multi_server):
    """Both the stream (brix_auth pwd) and HTTP (brix_webdav_pwd_file) sides
    must log the do-not-rely-on-password-auth-in-production warning."""
    log = multi_server["log"].read_text()
    assert "password (pwd) authentication is enabled" in log, \
        "stream-side pwd warning missing from error log"
    assert "password (Basic) authentication is enabled" in log, \
        "HTTP-side Basic warning missing from error log"
    assert log.count("do NOT rely on password auth in production") >= 2
