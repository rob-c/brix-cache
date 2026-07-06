"""XRootD ``host`` (host-based) auth — Phase 52 WS-C.

The native client selects ``host`` (asserting no identity); the server reverse-
resolves the peer socket and authenticates it against ``brix_host_allow`` (exact
hostnames or ``.suffix`` domains), fail-closed.  Covers the mandated trio: success
(peer host in the allowlist), error/security-negative (peer host NOT in the
allowlist must be denied — the allowlist is the only gate).

Spawns a throwaway nginx on a private high port; skips if the client isn't built.
The loopback peer reverse-resolves to ``localhost`` on essentially every host.
"""
import os
import subprocess
import time

import pytest

from settings import NGINX_BIN  # noqa: E402

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
NATIVE_XRDCP = os.path.join(REPO, "client", "bin", "xrdcp")

P_OK = 21143        # allowlist includes localhost
P_DENY = 21144      # allowlist excludes the loopback host


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


def _loopback_host():
    r = _run(["bash", "-c", "getent hosts 127.0.0.1 | awk '{print $2}' | head -1"])
    return r.stdout.strip()


def _spawn(base, port, allow):
    data = base / f"data{port}"
    logs = base / f"logs{port}"
    data.mkdir()
    logs.mkdir()
    (data / "h.txt").write_text("hello-host-auth\n")
    cfg = base / f"nginx{port}.conf"
    cfg.write_text(
        "daemon off;\n"
        "worker_processes 1;\n"
        f"error_log {logs}/error.log info;\n"
        f"pid {base}/nginx{port}.pid;\n"
        "events { worker_connections 64; }\n"
        "stream {\n"
        "    server {\n"
        f"        listen 127.0.0.1:{port};\n"
        "        brix_root on;\n"
        f"        brix_storage_backend posix:{data};\n"
        "        brix_auth host;\n"
        f"        brix_host_allow {allow};\n"
        "    }\n"
        "}\n")
    _free_port(port)
    proc = subprocess.Popen([NGINX_BIN, "-c", str(cfg)],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    _wait_listen(proc, port, f"host nginx :{port}")
    return proc


@pytest.fixture(scope="module")
def host_servers(tmp_path_factory):
    if not os.path.exists(NATIVE_XRDCP):
        pytest.skip("native client/bin/xrdcp must be built (make -C client)")
    lh = _loopback_host()
    if not lh:
        pytest.skip("127.0.0.1 has no reverse-DNS name on this host")

    base = tmp_path_factory.mktemp("host")
    # P_OK allows the loopback name; P_DENY allows only an unrelated host.
    ok = _spawn(base, P_OK, f"{lh} localhost localhost.localdomain")
    deny = _spawn(base, P_DENY, "not-this-host.invalid .nope.example")
    yield {"ok": f"root://127.0.0.1:{P_OK}",
           "deny": f"root://127.0.0.1:{P_DENY}"}
    for p in (ok, deny):
        p.terminate()
        try:
            p.wait(timeout=5)
        except subprocess.TimeoutExpired:
            p.kill()


# ---- success ---------------------------------------------------------------- #

def test_host_allowed(host_servers, tmp_path):
    out = str(tmp_path / "got.txt")
    r = _run([NATIVE_XRDCP, "--auth", "host", "-f",
              f"{host_servers['ok']}//h.txt", out])
    assert r.returncode == 0, f"host auth (allowed) failed: {r.stderr}"
    assert open(out).read() == "hello-host-auth\n"


# ---- error / security-negative ---------------------------------------------- #

def test_host_not_in_allowlist_denied(host_servers, tmp_path):
    """Peer host absent from brix_host_allow must be denied — the reverse-DNS
    allowlist is the only gate, and it is fail-closed."""
    out = str(tmp_path / "deny.txt")
    r = _run([NATIVE_XRDCP, "--auth", "host", "-f",
              f"{host_servers['deny']}//h.txt", out])
    assert r.returncode != 0, "host not in allowlist must be denied"
    assert not os.path.exists(out) or os.path.getsize(out) == 0
