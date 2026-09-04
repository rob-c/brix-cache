"""The $brix_* HTTP variable surface — parse-and-serve cells (phase-110 W1/W6).

Split out of test_brix_http_variables.py to hold that file under the 600-line
logical cap (coding-standards §1). These two cells do not use the module-scoped
`node` fixture: each builds its OWN one-off nginx from a bespoke log_format, so
it can assert a property the shared cache-enabled node cannot express —

  * W6 — `$brix_duration` is BYTE-IDENTICAL to `$request_time`, not merely the
    same shape (the shared node's log_format carries no `$request_time` to
    compare against);
  * W1 — a location with NO cache tier logs `cache=-` (NONE), the vocabulary
    arm the cache-ENABLED shared node cannot produce.

Shared helpers (`_port_from_conf`, `_wait_listen`, the `NONE` sentinel) are
imported from the parent module so there is one definition, not a copy.

Run:
    PYTHONPATH=tests pytest tests/test_brix_http_variables_part2.py -v
"""

from __future__ import annotations

import http.client
import re
from pathlib import Path

import pytest

from server_launcher import LifecycleHarness
from server_registry import NginxInstanceSpec
from test_brix_http_variables import NONE

pytestmark = [pytest.mark.timeout(180),
              pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-brix-variables")]

TEMPLATE = "nginx_lc_brix_variables_probe.conf"


def _serve_and_read_log(tmp_path, log_name, log_format):
    data = tmp_path / "data"
    data.mkdir()
    (data / "probe.txt").write_bytes(b"variable probe\n")
    harness = LifecycleHarness()
    try:
        instance = harness.start(NginxInstanceSpec(
            name="lc-brix-variables",
            template=TEMPLATE,
            protocol="webdav",
            readiness="tcp",
            data_root=str(data),
            template_values={"LOG_NAME": log_name, "LOG_FORMAT": log_format},
            reason="phase-110 exact HTTP variable vocabulary",
        ))
        conn = http.client.HTTPConnection(instance.host, instance.port, timeout=15)
        try:
            conn.request("GET", "/probe.txt")
            resp = conn.getresponse()
            status, body = resp.status, resp.read()
        finally:
            conn.close()
    finally:
        harness.close()

    log = (Path(instance.prefix) / "logs" / log_name).read_text(errors="replace")
    return status, body, log


def _last_fields(log):
    assert log.strip(), "no access-log line was written"
    return dict(re.findall(r"(\w+)=(\S+)", log.splitlines()[-1]))


def test_brix_duration_is_byte_identical_to_request_time(tmp_path):
    """(success, phase-110 W6) $brix_duration exists for exactly one reason —
    nginx spells total wall time `$request_time` on HTTP and `$session_time` on
    stream, and one log_format must serve both planes (rule 6). So on HTTP it
    must be BYTE-IDENTICAL to $request_time, not merely the same shape: an
    operator who logs both on one line must see the same string."""
    status, _, log = _serve_and_read_log(
        tmp_path, "d.log", "dur=$brix_duration req=$request_time")
    assert status == 200, status
    fields = _last_fields(log)
    assert fields.get("dur") and fields.get("req"), log
    assert fields["dur"] == fields["req"], (
        f"$brix_duration must equal $request_time byte-for-byte, not just match "
        f"its shape: dur={fields['dur']!r} req={fields['req']!r}\n{log}")


def test_no_cache_tier_export_logs_cache_none_not_miss(tmp_path):
    """(error, phase-110 W1) The vocabulary distinction the doc pins explicitly
    (Appendix-B R-4): on an export with NO cache tier configured, a served GET
    logs `cache=-` (NONE) — never MISS (which means a tier was consulted and
    missed) and never BYPASS (a configured tier deliberately skipped). Getting
    this wrong desyncs the variable from brix_cache_misses_total and corrupts
    every hit-rate dashboard. The location omits brix_cache_root, so no tier
    exists and the honest disposition is the sentinel."""
    status, body, log = _serve_and_read_log(
        tmp_path, "c.log", "status=$status cache=$brix_cache_status")
    assert status == 200 and body == b"variable probe\n", status
    fields = _last_fields(log)
    assert fields.get("cache") == NONE, (
        "a no-cache-tier export must log cache=- (NONE), never MISS or BYPASS — "
        f"the '- means no tier' vocabulary rule:\n{log}")
