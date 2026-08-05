"""Phase 94 / Phase 2 — bound-write fan-out to a **gateway in front of a remote
root:// origin**, proving the transfer lands byte-exact ON THE REMOTE ORIGIN.

The refactor doc (docs/refactor/phase-94-bound-write-substreams.md) originally
GATED Phase 2 on the assumption that a writable gateway routes writes through the
driver-backed whole-object staged writer (``file->writer != NULL``, sequential,
unpublishable).  In reality a writable root:// gateway with the default
``brix_upload_resume on`` (and POSC, which is always implemented) stages the upload
to a LOCAL, export-rooted ``.part`` file — a real kernel fd with a real local path.
That is exactly the fd-backed shape Phase-1 already publishes to the cross-worker
SHM handle table and fans bound writes across; the existing resume/POSC commit then
flushes the COMPLETE ``.part`` (all bytes, including those written by bound
secondaries on another worker) onto the remote origin at close.

So gateway parallel upload already works.  This test PROVES it end-to-end:
  * stand up a root:// origin and a BriX gateway (``brix_storage_backend
    root://origin``) with ``worker_processes 2`` so secondaries land cross-worker;
  * upload an 8 MiB file with the client's default fan-out (``--streams 4``);
  * assert the client actually carried chunks on the secondaries
    (``chunks-on-secondaries>0`` — not a silent single-stream fallback);
  * assert the bytes are byte-exact **on the origin's own storage** (the gateway
    flushed the fanned-out ``.part`` to the origin).

The residual whole-object (S3/WebDAV PUT, ``needs_staged``) case still degrades to
the resilient primary and is covered by
``test_data_substreams_parallel.py::TestDataSubstreamWrites::
test_bound_write_unpublished_handle_refused``.

This rig is heavyweight (two real nginx instances) and env-specific: it needs an
nginx binary, the stream + brix module ``.so``s, and a world-traversable writable
base (the workers drop to a service uid).  It skips cleanly when any is absent.
Override via TEST_NGINX_BIN / TEST_NGX_STREAM_MODULE / BRIX_MODULE_SO /
TEST_P2_ORIGIN_PORT / TEST_P2_GATEWAY_PORT.
"""
import os
import signal
import socket
import subprocess
import time
from pathlib import Path

import pytest

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_XRDCP = os.path.join(_REPO, "client", "bin", "xrdcp")

_NGINX = os.environ.get("TEST_NGINX_BIN", "/usr/sbin/nginx")
_STREAM_MOD = os.environ.get(
    "TEST_NGX_STREAM_MODULE", "/usr/lib64/nginx/modules/ngx_stream_module.so")
_BRIX_MOD = os.environ.get(
    "BRIX_MODULE_SO",
    os.path.join(_REPO, "build", "modules", "ngx_stream_brix_module.so"))

_OPORT = int(os.environ.get("TEST_P2_ORIGIN_PORT", "21150"))
_GPORT = int(os.environ.get("TEST_P2_GATEWAY_PORT", "21151"))

_HAVE = (os.path.exists(_XRDCP) and os.path.exists(_NGINX)
         and os.path.exists(_STREAM_MOD) and os.path.exists(_BRIX_MOD))


def _det(n, seed=3):
    p = bytes((i * 7 + seed) % 251 for i in range(251))
    full, rem = divmod(n, 251)
    return (p * full + p[:rem])


def _origin_conf(base: Path) -> str:
    root, logs = base / "origin/root", base / "origin/logs"
    return (
        f"daemon on; error_log {logs}/e.log info; pid {base}/origin/nginx.pid;\n"
        f"load_module {_STREAM_MOD};\nload_module {_BRIX_MOD};\n"
        f"worker_processes 2;\nevents {{ worker_connections 64; }}\n"
        f"stream {{ server {{ listen 127.0.0.1:{_OPORT}; brix_root on;\n"
        f"    brix_export {root}; brix_auth none; brix_allow_write on; }} }}\n")


def _gateway_conf(base: Path) -> str:
    export, stage, logs = base / "gw/gw", base / "gw/stage", base / "gw/logs"
    return (
        f"daemon on; error_log {logs}/e.log info; pid {base}/gw/nginx.pid;\n"
        f"load_module {_STREAM_MOD};\nload_module {_BRIX_MOD};\n"
        f"worker_processes 2;\nthread_pool gwpool threads=4 max_queue=4096;\n"
        f"events {{ worker_connections 64; }}\n"
        f"stream {{ server {{\n"
        f"    listen 127.0.0.1:{_GPORT}; brix_root on; brix_auth none;\n"
        f"    brix_export {export}; brix_allow_write on; brix_thread_pool gwpool;\n"
        f"    brix_storage_backend root://127.0.0.1:{_OPORT};\n"
        f"    brix_stage on; brix_stage_store posix:{stage}; brix_stage_flush sync;\n"
        f"    brix_access_log {logs}/access.log;\n"
        f"}} }}\n")


def _wait_listen(port, deadline_s=8.0):
    end = time.monotonic() + deadline_s
    while time.monotonic() < end:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.1)
    return False


def _stop(pidfile: Path):
    try:
        pid = int(pidfile.read_text().strip())
        os.kill(pid, signal.SIGTERM)
    except (OSError, ValueError):
        pass


@pytest.fixture()
def gateway_rig():
    if not _HAVE:
        pytest.skip("gateway rig needs nginx + stream/brix modules + brix-xrdcp")
    base = Path(f"/tmp/brix_subs_gw_{os.getpid()}")
    subprocess.run(["rm", "-rf", str(base)], check=False)
    for sub in ("origin/root", "origin/logs", "gw/gw", "gw/stage", "gw/logs"):
        (base / sub).mkdir(parents=True, exist_ok=True)
    # workers drop to a service uid; make the whole tree world-usable so the
    # dropped worker can traverse+write (mirrors the standalone rig).
    subprocess.run(["chmod", "-R", "0777", str(base)], check=False)

    oconf, gconf = base / "origin.conf", base / "gw.conf"
    oconf.write_text(_origin_conf(base))
    gconf.write_text(_gateway_conf(base))

    started = []
    try:
        for conf in (oconf, gconf):
            r = subprocess.run([_NGINX, "-c", str(conf)],
                               capture_output=True, text=True, timeout=30)
            # nginx forks a daemon; a non-zero rc with only the cred-store [warn]
            # is fine, a real config error is not.
            if r.returncode != 0 and "emerg" in (r.stderr + r.stdout):
                pytest.skip(f"gateway nginx failed to start: {r.stderr[-400:]}")
        started = [base / "origin/nginx.pid", base / "gw/nginx.pid"]
        if not (_wait_listen(_OPORT) and _wait_listen(_GPORT)):
            pytest.skip("origin/gateway did not come up on the expected ports")
        yield base
    finally:
        for pf in started:
            _stop(pf)
        time.sleep(0.3)
        subprocess.run(["rm", "-rf", str(base)], check=False)


@pytest.mark.requires_local_server
class TestGatewayBoundWriteFanout:
    def test_gateway_upload_fans_out_byte_exact_on_origin(self, gateway_rig):
        base = gateway_rig
        size = 8 * 1024 * 1024                      # 128 × 64 KiB chunks
        content = _det(size)
        src = base / "src.bin"
        src.write_bytes(content)

        env = dict(os.environ, BRIX_STREAMS_DEBUG="1")
        res = subprocess.run(
            [_XRDCP, "-f", "--streams", "4", str(src),
             f"root://127.0.0.1:{_GPORT}//gwup.bin"],
            capture_output=True, text=True, env=env, timeout=180)
        assert res.returncode == 0, f"gateway upload failed: {res.stderr[-800:]}"

        # the client genuinely carried chunks on the bound secondaries
        dbg = [l for l in res.stderr.splitlines() if "upload substreams=" in l]
        assert dbg, f"no upload diagnostic emitted: {res.stderr[-400:]}"
        on_sec = int(dbg[-1].split("chunks-on-secondaries=")[1].split()[0])
        assert on_sec > 0, (
            "gateway upload did not fan out across secondaries "
            f"(silent single-stream fallback): {dbg[-1]}")

        # the bytes are byte-exact ON THE ORIGIN's own storage (the gateway
        # flushed the fanned-out .part — incl. cross-worker bound writes — to
        # the remote origin at close).
        origin_file = base / "origin/root/gwup.bin"
        assert origin_file.exists(), "object never reached the origin"
        assert origin_file.read_bytes() == content, (
            "gateway fan-out not byte-exact on the remote origin")
