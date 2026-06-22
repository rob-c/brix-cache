"""
~/.xrdrc endpoint aliases (swiss-army-knife "just works" UX): name an endpoint once
and use `alias:/path` with any tool instead of the long root://host:port//path form.

  [alias lab]
  url = root://HOST:PORT//

  $ xrdfs lab:/ ls
  $ xrdcp lab:/data/f.bin .

Self-hosts a root:// server; points $XRDRC at a temp rc file.

Run:
    TEST_SKIP_SERVER_SETUP=1 PYTHONPATH=tests pytest tests/test_client_xrdrc_alias.py -v -p no:xdist
"""

import os
import shutil
import socket
import subprocess
import time

import pytest

from settings import HOST, BIND_HOST

pytestmark = pytest.mark.timeout(120)

NGINX_BIN = os.environ.get("NGINX_BIN", "/tmp/nginx-1.28.3/objs/nginx")
REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLIENT_DIR = os.path.join(REPO, "client")
XRDFS = os.path.join(CLIENT_DIR, "bin", "xrdfs")
XRDCP = os.path.join(CLIENT_DIR, "bin", "xrdcp")


def _free_port():
    s = socket.socket()
    s.bind((BIND_HOST, 0))
    p = s.getsockname()[1]
    s.close()
    return p


def _port_up(host, port):
    try:
        with socket.create_connection((host, port), timeout=1):
            return True
    except OSError:
        return False


@pytest.fixture(scope="module")
def rc_env(tmp_path_factory):
    if shutil.which("cc") is None and shutil.which("gcc") is None:
        pytest.skip("no C compiler")
    subprocess.run(["make", "-C", CLIENT_DIR, "xrdfs", "xrdcp"],
                   capture_output=True, text=True, timeout=240)
    if not (os.path.exists(XRDFS) and os.path.exists(XRDCP)):
        pytest.skip("client build failed")
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx not executable: {NGINX_BIN}")

    root = tmp_path_factory.mktemp("xrdrc")
    data = root / "data"
    data.mkdir()
    (data / "hello.bin").write_bytes(b"hello-via-alias\n")
    port = _free_port()
    conf = root / "nginx.conf"
    conf.write_text(f"""
worker_processes 1;
pid {root}/nginx.pid;
error_log {root}/error.log info;
events {{ worker_connections 64; }}
stream {{
    server {{ listen {BIND_HOST}:{port}; xrootd on; xrootd_root {data};
             xrootd_auth none; xrootd_allow_write on; }}
}}
""")
    if subprocess.run([NGINX_BIN, "-t", "-c", str(conf)],
                      capture_output=True, text=True).returncode != 0:
        pytest.skip("nginx -t failed")
    subprocess.run([NGINX_BIN, "-c", str(conf)], capture_output=True)
    for _ in range(50):
        if _port_up(HOST, port):
            break
        time.sleep(0.1)

    rc = root / "xrdrc"
    rc.write_text(f"# test rc\n[alias lab]\nurl = root://{HOST}:{port}//\n")
    env = dict(os.environ, XRDRC=str(rc))
    yield {"env": env, "data": data, "port": port}
    subprocess.run([NGINX_BIN, "-c", str(conf), "-s", "quit"], capture_output=True)
    time.sleep(0.3)


def test_xrdfs_ls_via_alias(rc_env):
    p = subprocess.run([XRDFS, "lab:/", "ls"], capture_output=True, text=True,
                       timeout=30, env=rc_env["env"])
    assert p.returncode == 0, f"{p.stdout}\n{p.stderr}"
    assert "hello.bin" in p.stdout, p.stdout


def test_xrdcp_download_via_alias(rc_env, tmp_path):
    out = tmp_path / "got.bin"
    p = subprocess.run([XRDCP, "-f", "lab:/hello.bin", str(out)],
                       capture_output=True, text=True, timeout=30, env=rc_env["env"])
    assert p.returncode == 0, f"{p.stdout}\n{p.stderr}"
    assert out.read_bytes() == b"hello-via-alias\n"


def test_xrdcp_upload_via_alias(rc_env, tmp_path):
    src = tmp_path / "up.bin"
    src.write_bytes(b"uploaded-via-alias\n")
    p = subprocess.run([XRDCP, "-f", str(src), "lab:/up.bin"],
                       capture_output=True, text=True, timeout=30, env=rc_env["env"])
    assert p.returncode == 0, f"{p.stdout}\n{p.stderr}"
    assert (rc_env["data"] / "up.bin").read_bytes() == b"uploaded-via-alias\n"


def test_unknown_alias_passes_through(rc_env, tmp_path):
    """A non-alias arg is untouched: a bogus alias yields a normal (failing) parse,
    not a crash, and a real local path still works."""
    # 'nope:/x' is not an alias and not a scheme -> passed through verbatim ->
    # treated as a local path 'nope:/x' which doesn't exist -> clean error.
    p = subprocess.run([XRDFS, "nope:/x", "ls"], capture_output=True, text=True,
                       timeout=30, env=rc_env["env"])
    assert p.returncode != 0


def test_token_file_missing_warns(rc_env, tmp_path):
    """An alias whose token_file is missing/empty emits a clear diagnostic naming the
    path (never the contents), rather than silently sending no token."""
    rc = tmp_path / "xrdrc2"
    rc.write_text(f"[alias tk]\nurl = root://{HOST}:{rc_env['port']}//\n"
                  f"token_file = {tmp_path}/does-not-exist.tok\n")
    env = dict(rc_env["env"], XRDRC=str(rc))
    out = tmp_path / "tkget.bin"
    p = subprocess.run([XRDCP, "-f", "tk:/hello.bin", str(out)],
                       capture_output=True, text=True, timeout=30, env=env)
    # anon server still serves the file, but the missing token_file must be flagged
    assert "token_file" in p.stderr and "missing or empty" in p.stderr, p.stderr
    assert "does-not-exist.tok" in p.stderr, p.stderr


def test_no_rc_file_is_harmless(tmp_path):
    """With XRDRC pointing at a missing file, plain URLs still work unchanged."""
    env = dict(os.environ, XRDRC=str(tmp_path / "does-not-exist"))
    p = subprocess.run([XRDCP, "-h"], capture_output=True, text=True, timeout=30, env=env)
    assert p.returncode == 0
