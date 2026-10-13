"""Phase-118 WRT-007 live quota/capacity fixture contract."""
import json
import os
import subprocess
from pathlib import Path

import pytest

from server_launcher import LifecycleHarness, NginxInstanceSpec
from settings import BIND_HOST, HOST, NGINX_BIN


ROOT = Path(__file__).resolve().parents[1]
XRD = ROOT / "client" / "bin" / "xrd"

pytestmark = [pytest.mark.timeout(120),
              pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-xrd-conform-capacity")]


@pytest.fixture(scope="module")
def capacity_endpoints(tmp_path_factory):
    """Launch distinct policy-quota and physical-capacity ROOT fronts."""
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx binary not executable: {NGINX_BIN}")
    if not os.access(XRD, os.X_OK):
        pytest.skip(f"native xrd client not executable: {XRD}")
    base = tmp_path_factory.mktemp("xrd-conform-capacity")
    quota_root = base / "quota"
    capacity_root = base / "capacity"
    quota_root.mkdir()
    capacity_root.mkdir()
    harness = LifecycleHarness()
    try:
        endpoint = harness.start(NginxInstanceSpec(
            name="lc-xrd-conform-capacity",
            template="nginx_xrd_conform_capacity.conf",
            protocol="root",
            data_root=str(quota_root),
            template_values={
                "BIND_HOST": BIND_HOST,
                "QUOTA_ROOT": str(quota_root),
                "CAPACITY_ROOT": str(capacity_root),
            },
            reason="Phase-118 WRT-007 exact refusal-code fixtures"))
        yield (f"root://{HOST}:{endpoint.port}//seed",
               f"root://{HOST}:{endpoint.extra_ports['CAPACITY_PORT']}//seed")
    finally:
        harness.close()


def _run(tmp_path, quota_target, capacity_target, verify=False):
    output = tmp_path / "report"
    command = [str(XRD), "conform", "full", quota_target,
               "--only", "WRT-007", "--allow-mutate", "--scratch", "/",
               "--fail-on", "divergent", "--wall-seconds", "30",
               "--request-limit", "64", "--byte-limit", "1048576",
               "--out", str(output), "--quota-target", quota_target,
               "--capacity-target", capacity_target]
    if verify:
        command.extend(["--verify-negative", "WRT-007"])
    result = subprocess.run(command, text=True, capture_output=True,
                            timeout=45, check=False)
    report = json.loads((output / "report.json").read_text(encoding="utf-8"))
    rows = {row["id"]: row for row in report["results"]}
    return result, rows["WRT-007"]


def test_distinguishes_quota_from_capacity(tmp_path, capacity_endpoints):
    """Success: policy and backend capacity return their exact distinct codes."""
    quota_target, capacity_target = capacity_endpoints
    result, row = _run(tmp_path, quota_target, capacity_target)
    assert result.returncode == 0, result.stderr + result.stdout
    assert row["verdict"] == "conformant"
    assert row["received"] == "quota=3021 capacity=3009"


def test_rejects_half_configured_fixture_before_network(capacity_endpoints):
    """Error: one labelled endpoint cannot silently stand in for both legs."""
    quota_target, _ = capacity_endpoints
    result = subprocess.run(
        [str(XRD), "conform", "full", quota_target, "--only", "WRT-007",
         "--allow-mutate", "--scratch", "/", "--quota-target", quota_target],
        text=True, capture_output=True, timeout=10, check=False)
    assert result.returncode == 4
    assert "must be supplied together" in result.stderr


def test_swapped_fixture_labels_are_divergent(tmp_path, capacity_endpoints):
    """Security-negative: endpoint labels cannot be swapped to claim success."""
    quota_target, capacity_target = capacity_endpoints
    result, row = _run(
        tmp_path, capacity_target, quota_target, verify=True,
    )
    assert result.returncode != 0
    assert row["verdict"] == "divergent"
    assert row["received"] == "quota=0 capacity=3021"
