"""Reload semantics — `nginx -s reload` makes new module settings live for NEW
connections (standard nginx drain model), and the reload is observable + safe.

What this pins (per the maintainer's "3 tests per change: success + error +
security-neg" rule, applied to the reload feature as a whole):

  * SUCCESS — a reload bumps the /healthz `config_generation` counter and the
    Prometheus `brix_config_generation` gauge; a NEW connection honours a
    changed directive (we flip the /metrics location on→off and watch the HTTP
    status change); editing the config changes `config_version` while a no-op
    reload leaves it stable.
  * ROBUSTNESS — changing a slot-count directive (`brix_session_slots`) across
    a reload logs the SHM-resize WARN (live table reset is not silent); and the
    nginx-managed access log is recreated by `-s reopen` after a rotation (the
    log-fd is owned by nginx, not a leaked raw fd).
  * SECURITY-NEG — an INVALID config is rejected by `nginx -t` AND by `-s
    reload`, and the already-running instance keeps serving the OLD config (no
    partial apply, generation unchanged).

Self-contained: builds its own minimal nginx config (one stream `xrootd` server
+ an http server exposing /healthz and /metrics) on OS-assigned free ports and
drives nginx directly.  Needs only the built module binary (settings.NGINX_BIN)
— no stock xrootd toolchain and no shared test instances.
"""

import json
import os
import signal
import subprocess
import time
import urllib.error
import urllib.request

import pytest

import settings

pytestmark = pytest.mark.timeout(120)

NGINX = settings.NGINX_BIN


# --------------------------------------------------------------------------- #
# Tiny HTTP helper (no third-party deps).
# --------------------------------------------------------------------------- #
def _http_get(port, path, timeout=3):
    """Return (status, body) for GET; HTTP errors come back as (code, body)."""
    url = "http://127.0.0.1:%d%s" % (port, path)
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")


def _healthz(port):
    status, body = _http_get(port, "/healthz")
    assert status == 200, "healthz status %d: %s" % (status, body)
    return json.loads(body)


def _wait(predicate, timeout=10.0, interval=0.1):
    """Poll predicate() until truthy; return its value or raise on timeout."""
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        try:
            last = predicate()
            if last:
                return last
        except Exception:  # noqa: BLE001 - readiness probing is best-effort
            last = None
        time.sleep(interval)
    raise AssertionError("condition not met within %.1fs (last=%r)" % (timeout, last))


# --------------------------------------------------------------------------- #
# A throwaway nginx instance driven entirely from this test.
# --------------------------------------------------------------------------- #
class Instance:
    def __init__(self, base):
        self.base = base
        self.prefix = os.path.join(base, "prefix")
        self.conf = os.path.join(self.prefix, "nginx.conf")
        self.data = os.path.join(base, "data")
        self.logs = os.path.join(self.prefix, "logs")
        self.access_log = os.path.join(self.logs, "brix_access.log")
        for d in (self.prefix, self.data, self.logs,
                  os.path.join(self.prefix, "tmp")):
            os.makedirs(d, exist_ok=True)
        self.stream_port, self.http_port = settings.free_ports(2)

    # -- config rendering --------------------------------------------------- #
    def render(self, *, session_slots=256, allow_write="off",
               metrics="on", broken=False):
        if broken:
            # Unparseable: a directive with no terminating ';'.
            return "this is not valid nginx config\n"
        tmp = os.path.join(self.prefix, "tmp")
        return f"""\
worker_processes 2;
daemon on;
master_process on;
error_log {self.logs}/error.log notice;
pid {self.prefix}/nginx.pid;
# Bound the drain window: old workers serve new connections with the OLD
# per-worker config until they exit, so a low shutdown timeout keeps the
# "new connection honours new directive" convergence fast and deterministic.
worker_shutdown_timeout 3s;
events {{ worker_connections 64; }}
stream {{
    server {{
        listen {self.stream_port};
        xrootd on;
        brix_storage_backend posix:{self.data};
        brix_auth none;
        brix_allow_write {allow_write};
        brix_session_slots {session_slots};
        brix_access_log {self.access_log};
    }}
}}
http {{
    access_log off;
    client_body_temp_path {tmp}/client;
    proxy_temp_path {tmp}/proxy;
    fastcgi_temp_path {tmp}/fastcgi;
    uwsgi_temp_path {tmp}/uwsgi;
    scgi_temp_path {tmp}/scgi;
    server {{
        listen {self.http_port};
        location = /healthz {{ brix_health on; }}
        location /metrics  {{ brix_metrics {metrics}; }}
    }}
}}
"""

    def write(self, **opts):
        with open(self.conf, "w") as fh:
            fh.write(self.render(**opts))

    # -- lifecycle ---------------------------------------------------------- #
    def _run(self, *args, check=True):
        return subprocess.run(
            [NGINX, "-p", self.prefix, "-c", self.conf, *args],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, check=check)

    def configtest_text(self, text):
        """Run `nginx -t` on arbitrary config text; return the CompletedProcess."""
        path = os.path.join(self.prefix, "candidate.conf")
        with open(path, "w") as fh:
            fh.write(text)
        return subprocess.run(
            [NGINX, "-p", self.prefix, "-t", "-c", path],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, check=False)

    def start(self, **opts):
        self.write(**opts)
        self._run()  # daemonizes; returns once the master is up
        _wait(lambda: _http_get(self.http_port, "/healthz")[0] == 200)

    def reload(self, **opts):
        """Rewrite the config and send SIGHUP; wait for generation to advance."""
        before = _healthz(self.http_port)["config_generation"]
        self.write(**opts)
        self._run("-s", "reload")
        _wait(lambda: _healthz(self.http_port)["config_generation"] > before)
        return _healthz(self.http_port)

    def reload_expect_fail(self, text):
        """Send a reload with a known-broken config; return CompletedProcess."""
        with open(self.conf, "w") as fh:
            fh.write(text)
        return self._run("-s", "reload", check=False)

    def stop(self):
        try:
            self._run("-s", "quit", check=False)
        finally:
            # Belt-and-suspenders: kill the master by pidfile if quit didn't.
            pidf = os.path.join(self.prefix, "nginx.pid")
            try:
                with open(pidf) as fh:
                    os.kill(int(fh.read().strip()), signal.SIGKILL)
            except (OSError, ValueError):
                pass

    def error_log(self):
        try:
            with open(os.path.join(self.logs, "error.log")) as fh:
                return fh.read()
        except OSError:
            return ""


@pytest.fixture()
def inst(tmp_path):
    server = Instance(str(tmp_path))
    try:
        server.start()
    except Exception:  # noqa: BLE001
        # Surface the error log to make a start failure debuggable.
        raise
    yield server
    server.stop()


# --------------------------------------------------------------------------- #
# SUCCESS
# --------------------------------------------------------------------------- #
def test_reload_bumps_generation_and_keeps_version_stable(inst):
    g1 = _healthz(inst.http_port)
    assert g1["config_generation"] == 1
    assert len(g1["config_version"]) == 16  # 64-bit hex fingerprint

    # No-op reload: generation advances, content fingerprint is unchanged.
    g2 = inst.reload()
    assert g2["config_generation"] == 2
    assert g2["config_version"] == g1["config_version"]

    g3 = inst.reload()
    assert g3["config_generation"] == 3

    # Prometheus gauge mirrors the healthz counter.
    status, body = _http_get(inst.http_port, "/metrics")
    assert status == 200
    assert "brix_config_generation 3" in body


def test_reload_changes_version_when_config_edited(inst):
    v1 = _healthz(inst.http_port)["config_version"]
    after = inst.reload(allow_write="on")  # a real settings change
    assert after["config_version"] != v1


def test_new_connection_honours_changed_directive(inst):
    # Baseline: /metrics is enabled and serves Prometheus text.
    assert _http_get(inst.http_port, "/metrics")[0] == 200

    # Flip the directive off and reload.  Under the standard drain model the OLD
    # workers keep serving new connections with the OLD per-worker config until
    # they finish draining, so the change is eventually-consistent: poll until a
    # NEW connection observes the new setting (bounded by worker_shutdown_timeout).
    inst.reload(metrics="off")
    _wait(lambda: _http_get(inst.http_port, "/metrics")[0] == 404, timeout=15)

    # Flip it back on to prove the change is directional, not a one-way latch.
    inst.reload(metrics="on")
    _wait(lambda: _http_get(inst.http_port, "/metrics")[0] == 200, timeout=15)


# --------------------------------------------------------------------------- #
# ROBUSTNESS
# --------------------------------------------------------------------------- #
def test_shm_slot_resize_logs_warning(inst):
    # Grow the session registry across a reload — nginx cannot resize the live
    # zone, so the module must WARN that the table was reset.
    inst.reload(session_slots=1024)
    log = inst.error_log()
    assert "brix_session_slots changed across reload" in log, \
        "expected SHM-resize WARN in error log:\n%s" % log[-2000:]


def test_managed_access_log_reopens_after_rotation(inst):
    # The access log fd is nginx-managed (cycle->open_files), so `-s reopen`
    # recreates the file at its original path even with no intervening writes —
    # proving rotation works and the fd is not a leaked raw descriptor.
    assert os.path.exists(inst.access_log)
    os.rename(inst.access_log, inst.access_log + ".rotated")
    inst._run("-s", "reopen")
    _wait(lambda: os.path.exists(inst.access_log))


# --------------------------------------------------------------------------- #
# SECURITY-NEG
# --------------------------------------------------------------------------- #
def test_invalid_config_is_rejected_and_old_config_keeps_serving(inst):
    before = _healthz(inst.http_port)["config_generation"]

    # `nginx -t` rejects the broken config.
    cp = inst.configtest_text(inst.render(broken=True))
    assert cp.returncode != 0, "nginx -t should fail on broken config:\n%s" % cp.stdout

    # `-s reload` with the broken config fails and does NOT swap the live config.
    rc = inst.reload_expect_fail(inst.render(broken=True))
    assert rc.returncode != 0

    # The running instance still serves and the generation never advanced.
    after = _healthz(inst.http_port)
    assert after["config_generation"] == before, \
        "broken reload must not bump generation (%d -> %d)" % (
            before, after["config_generation"])

    # Restore a valid config so the fixture teardown is clean.
    inst.write()
