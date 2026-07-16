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

Registry-backed: the throwaway instance is driven entirely through the
`lifecycle` harness (config template `nginx_lifecycle_reload.conf`, OS-assigned
free ports) — no hand-rolled nginx subprocess calls.
"""

import json
import os
import time
import urllib.error
import urllib.request

import pytest

import settings
from server_registry import NginxInstanceSpec

pytestmark = pytest.mark.timeout(120)


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
# A throwaway instance driven entirely through the registry lifecycle harness.
# --------------------------------------------------------------------------- #
NAME = "lc-reload"
DEFAULTS = {"SESSION_SLOTS": 256, "ALLOW_WRITE": "off", "METRICS": "on"}


class Instance:
    def __init__(self, harness, tmp_path):
        self.harness = harness
        (stream_port,) = settings.free_ports(1)
        self.endpoint = harness.start(
            NginxInstanceSpec(
                name=NAME,
                template="nginx_lifecycle_reload.conf",
                protocol="http",
                data_root=str(tmp_path / "data"),
                extra_ports={"STREAM_PORT": stream_port},
                template_values=dict(DEFAULTS),
                reason="reload-semantics lifecycle coverage",
            )
        )
        self.http_port = self.endpoint.port
        self.logs = os.path.join(self.endpoint.prefix, "logs")
        self.access_log = os.path.join(self.logs, "brix_access.log")
        _wait(lambda: _http_get(self.http_port, "/healthz")[0] == 200)

    # -- lifecycle ---------------------------------------------------------- #
    def reload(self, **opts):
        """Re-render the config and reload; wait for generation to advance."""
        before = _healthz(self.http_port)["config_generation"]
        self.harness.reconfigure(NAME, **{k.upper(): v for k, v in opts.items()})
        self.harness.reload(NAME)
        _wait(lambda: _healthz(self.http_port)["config_generation"] > before)
        return _healthz(self.http_port)

    def reload_expect_fail_with_broken_config(self):
        """Swap in a known-broken config; return the failed reload result."""
        self.harness.reconfigure(NAME, template="nginx_lifecycle_broken.conf")
        return self.harness.reload(NAME, check=False)

    def restore_valid_config(self):
        self.harness.reconfigure(NAME, template="nginx_lifecycle_reload.conf")

    def reopen(self):
        self.harness.reopen(NAME)

    def error_log(self):
        try:
            with open(os.path.join(self.logs, "error.log")) as fh:
                return fh.read()
        except OSError:
            return ""


@pytest.fixture()
def inst(lifecycle, tmp_path):
    yield Instance(lifecycle, tmp_path)
    # Teardown (stop + unregister) is owned by the lifecycle fixture.


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
    inst.reopen()
    _wait(lambda: os.path.exists(inst.access_log))


# --------------------------------------------------------------------------- #
# SECURITY-NEG
# --------------------------------------------------------------------------- #
def test_invalid_config_is_rejected_and_old_config_keeps_serving(inst, lifecycle):
    before = _healthz(inst.http_port)["config_generation"]

    # `nginx -t` rejects the broken config (fresh throwaway spec, never started).
    cp = lifecycle.expect_config_failure(
        NginxInstanceSpec(name="lc-reload-broken", template="nginx_lifecycle_broken.conf")
    )
    assert cp.returncode != 0, "nginx -t should fail on broken config:\n%s" % cp.stdout

    # `-s reload` with the broken config fails and does NOT swap the live config.
    rc = inst.reload_expect_fail_with_broken_config()
    assert rc.returncode != 0

    # The running instance still serves and the generation never advanced.
    after = _healthz(inst.http_port)
    assert after["config_generation"] == before, \
        "broken reload must not bump generation (%d -> %d)" % (
            before, after["config_generation"])

    # Restore a valid config so the fixture teardown is clean.
    inst.restore_valid_config()
