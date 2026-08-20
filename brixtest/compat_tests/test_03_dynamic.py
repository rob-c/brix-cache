"""Example 7: a per-test dynamic server (F24).

No declaration marker: dynamic servers are requested, not declared,
and their ports come from the dedicated block at the top of the lane
— they can never collide with a catalogued static port.
"""

from __future__ import annotations

import sys
import urllib.request
from pathlib import Path

STUB_ENV = {
    "BRIXTEST_PORT": "{port}",
    "BRIXTEST_STUB_NAME": "{name}",
    "PYTHONPATH": str(Path(__file__).resolve().parents[1] / "src"),
}


def test_07_dynamic_server_lifecycle(brix):
    """Request -> allocated port -> proven ready -> served bytes; the
    framework releases it (and proves quiescence) when the test ends."""
    origin = brix.request_server(
        kind="process",
        command=[sys.executable, "-m", "brixtest.stubs.origin"],
        env=STUB_ENV,
    )
    assert origin.name.startswith("dyn-test_07")
    port = origin.primary_port
    assert brix.fleet.dynamic.block_start <= port < brix.fleet.dynamic.block_end
    (origin.workdir / "hello.txt").write_text("dynamic bytes\n")
    body = urllib.request.urlopen(
        origin.url("http", path="/hello.txt"), timeout=5
    ).read()
    assert body == b"dynamic bytes\n"
    assert origin.name in brix.fleet.dynamic.names("test")
