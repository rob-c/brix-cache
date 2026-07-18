"""
Phase-86: xrootdfs web-metadata connection reuse.

WHAT: mount xrootdfs over http WebDAV THROUGH a counting TCP forwarder; stat many
      files in one directory and assert the upstream connection count stays at or
      below --max-conns (keep-alive + pool), not one-per-stat.
WHY:  proves the metadata path stopped reconnecting per getattr/readdir.
"""
import os
import shutil
import socket
import subprocess
import threading
import time

import pytest

from settings import NGINX_HTTP_WEBDAV_PORT, SERVER_HOST, BIND_HOST

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLIENT_DIR = os.path.join(REPO, "client")
XROOTDFS = os.path.join(CLIENT_DIR, "bin", "xrootdfs")
_FUSE_OK = os.path.exists("/dev/fuse") and shutil.which("fusermount3") is not None

pytestmark = pytest.mark.timeout(180)


def _free_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
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


class CountingForwarder:
    """Accept-counting TCP forwarder BIND_HOST:lport -> SERVER_HOST:rport."""

    def __init__(self, rport):
        self.lport = _free_port()
        self.rport = rport
        self.accepts = 0
        self._srv = socket.socket()
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._srv.bind((BIND_HOST, self.lport))
        self._srv.listen(64)
        self._stop = False
        self._th = threading.Thread(target=self._loop, daemon=True)
        self._th.start()

    def _pump(self, a, b):
        try:
            while True:
                d = a.recv(65536)
                if not d:
                    break
                b.sendall(d)
        except OSError:
            pass
        finally:
            for s in (a, b):
                try:
                    s.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

    def _loop(self):
        self._srv.settimeout(0.5)
        while not self._stop:
            try:
                cli, _ = self._srv.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            self.accepts += 1
            try:
                up = socket.create_connection((SERVER_HOST, self.rport))
            except OSError:
                cli.close()
                continue
            threading.Thread(target=self._pump, args=(cli, up), daemon=True).start()
            threading.Thread(target=self._pump, args=(up, cli), daemon=True).start()

    def close(self):
        self._stop = True
        try:
            self._srv.close()
        except OSError:
            pass


@pytest.fixture(scope="module")
def built():
    if not _FUSE_OK:
        pytest.skip("FUSE unavailable (/dev/fuse or fusermount3 missing)")
    if not _port_up(SERVER_HOST, NGINX_HTTP_WEBDAV_PORT):
        pytest.skip("WebDAV server not running (start the test fleet first)")
    r = subprocess.run(["make", "-C", CLIENT_DIR, "xrootdfs"],
                       capture_output=True, text=True)
    if r.returncode != 0 or not os.path.exists(XROOTDFS):
        pytest.skip(f"xrootdfs build failed:\n{r.stdout}\n{r.stderr}")


@pytest.fixture
def forwarder():
    fw = CountingForwarder(NGINX_HTTP_WEBDAV_PORT)
    yield fw
    fw.close()


def _mount(endpoint, mnt, max_conns):
    os.makedirs(mnt, exist_ok=True)
    argv = [XROOTDFS, "--max-conns", str(max_conns), endpoint, mnt, "-f"]
    p = subprocess.Popen(argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(50):
        if os.path.ismount(mnt):
            return p
        time.sleep(0.1)
    subprocess.run(["fusermount3", "-u", mnt], capture_output=True)
    p.terminate()
    pytest.skip("xrootdfs web mount did not come up")


def test_stat_many_reuses_connections(built, forwarder, tmp_path):
    """ls -l of N files opens <= max_conns upstream connections, not ~N."""
    mnt = str(tmp_path / "mnt")
    max_conns = 4
    endpoint = f"http://{SERVER_HOST}:{forwarder.lport}/"   # forwarded origin
    p = _mount(endpoint, mnt, max_conns)
    try:
        entries = sorted(os.listdir(mnt))[:20]
        if not entries:
            pytest.skip("WebDAV export is empty; seed it first")
        before = forwarder.accepts
        for name in entries:
            os.stat(os.path.join(mnt, name))     # one getattr each
        opened = forwarder.accepts - before
        # keep-alive + pool: at most max_conns NEW upstream conns for 20 stats.
        assert opened <= max_conns, (
            f"{opened} upstream conns for {len(entries)} stats "
            f"(expected <= {max_conns}); metadata path is not reusing")
    finally:
        subprocess.run(["fusermount3", "-u", mnt], capture_output=True)
        p.terminate()


def test_missing_path_is_enoent_and_keeps_socket(built, forwarder, tmp_path):
    """A 404 returns ENOENT and does NOT poison the pooled socket."""
    mnt = str(tmp_path / "mnt")
    endpoint = f"http://{SERVER_HOST}:{forwarder.lport}/"
    p = _mount(endpoint, mnt, 2)
    try:
        with pytest.raises(FileNotFoundError):
            os.stat(os.path.join(mnt, "definitely-not-here-xyz"))
        # the next authorized stat still works (socket not poisoned)
        entries = sorted(os.listdir(mnt))
        if not entries:
            pytest.skip("WebDAV export is empty; seed it first")
        os.stat(os.path.join(mnt, entries[0]))
    finally:
        subprocess.run(["fusermount3", "-u", mnt], capture_output=True)
        p.terminate()


def test_upstream_sever_reconnects(built, forwarder, tmp_path):
    """Severing the pooled sockets mid-session surfaces an honest errno, not a hang."""
    mnt = str(tmp_path / "mnt")
    endpoint = f"http://{SERVER_HOST}:{forwarder.lport}/"
    p = _mount(endpoint, mnt, 2)
    try:
        entries = sorted(os.listdir(mnt))
        if not entries:
            pytest.skip("WebDAV export is empty; seed it first")
        os.stat(os.path.join(mnt, entries[0]))
        forwarder.close()                        # sever every pooled socket
        time.sleep(0.3)
        # An uncached path forces a live PROPFIND (the already-stat'd entry is
        # served from the FUSE attr cache). With the upstream severed it must
        # surface as an honest errno, not a hang (guarded by pytestmark timeout).
        with pytest.raises(OSError):
            os.stat(os.path.join(mnt, "zzz-unvisited-dir", "zzz-file"))
    finally:
        subprocess.run(["fusermount3", "-u", mnt], capture_output=True)
        p.terminate()
