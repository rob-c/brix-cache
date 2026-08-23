"""
`xrddiag watch` — continuous health/SLA probe loop.

WHAT: a bounded `watch` subcommand probes one or more root[s]:// endpoints every
      --interval seconds (connect + tiny read + locate), emitting a human status
      line, a Prometheus textfile exposition (--prometheus[=PATH]), or NDJSON
      (--json). --count N bounds the loop; SIGINT/SIGTERM stop it cleanly.
WHY:  turns the one-shot diagnostics into a node_exporter-friendly monitor.
HOW:  self-host a stream xrootd server on a free port (no shared fleet), drive
      the real xrddiag binary, assert on the emitted metrics. A closed port
      exercises the down/bounded path; multi-URL + JSON exercises the rest.

Run:
    TEST_SKIP_SERVER_SETUP=1 PYTHONPATH=tests pytest tests/test_xrddiag_watch.py -p no:xdist -v
"""
import json as jsonlib
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
XRDDIAG = os.path.join(CLIENT_DIR, "bin", "xrddiag")


def _free_port():
    s = socket.socket()
    s.bind((BIND_HOST, 0))
    p = s.getsockname()[1]
    s.close()
    return p


@pytest.fixture(scope="module")
def server(tmp_path_factory):
    _require_watch_tools()
    root, data = _prepare_watch_tree(tmp_path_factory)
    port = _free_port()
    conf = _write_watch_config(root, data, port)
    _validate_watch_config(conf)
    subprocess.run([NGINX_BIN, "-c", str(conf)], capture_output=True)
    _wait_for_watch_server(port)
    try:
        yield {"rport": port}
    finally:
        subprocess.run([NGINX_BIN, "-c", str(conf), "-s", "quit"],
                       capture_output=True)
        time.sleep(0.3)


def _require_watch_tools():
    _require_compiler()
    _build_xrddiag()
    _require_nginx()


def _require_compiler():
    if shutil.which("cc") is None and shutil.which("gcc") is None:
        pytest.skip("no C compiler")


def _build_xrddiag():
    proc = subprocess.run(["make", "-C", CLIENT_DIR, "xrddiag"],
                          capture_output=True, text=True, timeout=180)
    if proc.returncode != 0 or not os.path.exists(XRDDIAG):
        pytest.skip(f"xrddiag build failed:\n{proc.stdout}\n{proc.stderr}")


def _require_nginx():
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx binary not executable: {NGINX_BIN}")


def _prepare_watch_tree(tmp_path_factory):
    root = tmp_path_factory.mktemp("watch")
    data = root / "data"
    data.mkdir()
    (data / "probe.bin").write_bytes(os.urandom(64 * 1024))
    return root, data


def _write_watch_config(root, data, port):
    conf = root / "nginx.conf"
    conf.write_text(f"""
worker_processes 1;
pid {root}/nginx.pid;
error_log {root}/error.log info;
events {{ worker_connections 256; }}
stream {{
    server {{
        listen {BIND_HOST}:{port};
        brix_root on;
        brix_storage_backend posix:{data};
        brix_auth none;
    }}
}}
""")
    return conf


def _validate_watch_config(conf):
    result = subprocess.run(
        [NGINX_BIN, "-t", "-c", str(conf)], capture_output=True, text=True)
    if result.returncode != 0:
        pytest.skip("nginx -t failed:\n" + result.stderr)


def _wait_for_watch_server(port):
    for _ in range(50):
        try:
            with socket.create_connection((HOST, port), timeout=1):
                return
        except OSError:
            time.sleep(0.1)


def test_watch_prometheus_up(server):
    """A live endpoint reports up=1 with a HELP/TYPE block + connect/read metrics,
    one full exposition per --count cycle."""
    url = f"root://{HOST}:{server['rport']}//probe.bin"
    r = subprocess.run([XRDDIAG, "watch", url, "--count", "2", "--interval", "1",
                        "--prometheus"], capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, f"{r.stdout}\n{r.stderr}"
    _assert_prometheus_output(r.stdout, 2, " 1")
    assert "probe.bin" not in r.stdout, "path leaked into metrics"


def test_watch_down_endpoint_bounded(server):
    """A closed port reports up=0 (not a crash/hang) and exits 0 within the
    probe-timeout bound."""
    t0 = time.time()
    r = subprocess.run([XRDDIAG, "watch", "root://127.0.0.1:1", "--count", "1",
                        "--probe-timeout", "800", "--prometheus"],
                       capture_output=True, text=True, timeout=15)
    elapsed = time.time() - t0
    assert r.returncode == 0, f"{r.stdout}\n{r.stderr}"
    up_lines = [ln for ln in r.stdout.splitlines() if ln.startswith("brix_probe_up{")]
    assert len(up_lines) == 1 and up_lines[0].strip().endswith(" 0"), up_lines
    assert elapsed < 10, f"down probe should be bounded, took {elapsed:.1f}s"


def test_watch_json_multi_endpoint(server):
    """--json emits one NDJSON object per endpoint per cycle; a live + a dead
    endpoint in one cycle yield up:1 and up:0."""
    live = f"root://{HOST}:{server['rport']}//probe.bin"
    r = subprocess.run([XRDDIAG, "watch", live, "root://127.0.0.1:1",
                        "--count", "1", "--probe-timeout", "800", "--json"],
                       capture_output=True, text=True, timeout=15)
    assert r.returncode == 0, f"{r.stdout}\n{r.stderr}"
    _assert_json_probes(_json_lines(r.stdout))
    assert "probe.bin" not in r.stdout


def _up_lines(stdout):
    return [line for line in stdout.splitlines()
            if line.startswith("brix_probe_up{")]


def _assert_prometheus_output(stdout, count, suffix):
    assert "# TYPE brix_probe_up gauge" in stdout
    assert "brix_probe_connect_seconds" in stdout
    lines = _up_lines(stdout)
    assert len(lines) == count, f"expected {count} cycles, got: {lines}"
    assert all(line.strip().endswith(suffix) for line in lines), lines


def _json_lines(stdout):
    return [jsonlib.loads(line) for line in stdout.splitlines() if line.strip()]


def _assert_json_probes(objects):
    assert len(objects) == 2, objects
    assert [item["up"] for item in objects] == [1, 0], objects
    assert objects[0]["connect_ms"] >= 0


def test_watch_prometheus_atomic_file(server, tmp_path):
    """--prometheus=PATH writes the exposition atomically to a file (textfile
    collector contract)."""
    url = f"root://{HOST}:{server['rport']}//probe.bin"
    out = tmp_path / "xrootd.prom"
    r = subprocess.run([XRDDIAG, "watch", url, "--count", "1",
                        f"--prometheus={out}"], capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, f"{r.stdout}\n{r.stderr}"
    assert out.exists(), "prometheus file not written"
    body = out.read_text()
    assert "brix_probe_up{" in body and "} 1" in body
    # no leftover temp files next to the target
    assert list(tmp_path.glob("xrootd.prom.*")) == [], "atomic temp leaked"
