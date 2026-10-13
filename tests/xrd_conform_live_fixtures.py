"""Shared live Phase-118 result fixtures kept outside the assertion module."""
import json
import subprocess
from pathlib import Path

import pytest

from settings import NGINX_ANON_PORT, SERVER_HOST


ROOT = Path(__file__).resolve().parents[1]
XRD = ROOT / "client" / "bin" / "xrd"


def _results(output, target, arguments, timeout):
    if not XRD.exists():
        pytest.skip(f"native xrd client is not built: {XRD}")
    result = subprocess.run(
        [str(XRD), "conform", "accept", target, *arguments,
         "--out", str(output)],
        text=True, capture_output=True, timeout=timeout, check=False,
    )
    assert result.returncode == 0, result.stderr + result.stdout
    report = json.loads((output / "report.json").read_text(encoding="utf-8"))
    return {row["id"]: row for row in report["results"]}


@pytest.fixture(scope="module")
def basic_results(tmp_path_factory):
    output = tmp_path_factory.mktemp("xrd-conform-basic")
    target = f"root://{SERVER_HOST}:{NGINX_ANON_PORT}//test.txt"
    return _results(output, target, [
        "--families", "FRM,HSK,PROT,LOG,SIG,OPN,RD,PGR,STA,DIR,LOC,FAT,QRY,ERR,ENV",
        "--budget", "boundary", "--fail-on", "divergent",
        "--wall-seconds", "30", "--request-limit", "512",
        "--byte-limit", "2097152",
    ], 45)


@pytest.fixture(scope="module")
def query_claim_results(tmp_path_factory):
    output = tmp_path_factory.mktemp("xrd-conform-query-claims")
    target = f"root://{SERVER_HOST}:{NGINX_ANON_PORT}//random.bin"
    return _results(output, target, [
        "--families", "QRY", "--budget", "boundary",
        "--fail-on", "divergent", "--wall-seconds", "60",
        "--request-limit", "256", "--byte-limit", "33554432",
    ], 75)


@pytest.fixture(scope="module")
def bound_stream_results(tmp_path_factory):
    output = tmp_path_factory.mktemp("xrd-conform-bound-stream")
    target = f"root://{SERVER_HOST}:{NGINX_ANON_PORT}//test.txt"
    return _results(output, target, [
        "--profile", "full", "--families", "BND", "--allow-disrupt",
        "--confirm-target", target, "--budget", "boundary",
        "--fail-on", "divergent", "--wall-seconds", "20",
        "--request-limit", "64", "--byte-limit", "1048576",
    ], 30)
