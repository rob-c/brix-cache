"""Static source-tree guards (no nginx required).

Wraps the tools/ci shell guards so they run in the normal pytest gate:

- check_config_coverage.sh — every non-unittest ``.c`` under ``src/`` is
  either compiled via the repo-root ``./config`` or on a reasoned allowlist;
  stale ``./config`` entries and stale allowlist rows also fail.
- check_http_helper_reimpl.sh — protocol/observability handlers must not
  regrow private copies of the shared HTTP helpers in ``src/core/http/``
  (raw header-scan loops, local precondition logic, hand-rolled ETags).
"""

import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _run_guard(script_name: str) -> None:
    script = ROOT / "tools" / "ci" / script_name
    result = subprocess.run(
        [str(script)], cwd=ROOT, capture_output=True, text=True
    )
    assert result.returncode == 0, (
        f"{script_name} failed:\n{result.stdout}{result.stderr}"
    )


@pytest.mark.parametrize(
    "script",
    ["check_config_coverage.sh", "check_http_helper_reimpl.sh"],
)
def test_source_guard(script: str) -> None:
    _run_guard(script)
