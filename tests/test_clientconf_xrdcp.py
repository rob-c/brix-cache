"""
Client-conformance: xrdcp transfer tool (differential vs stock).

Thin shim over ``clientconf/cases/xrdcp_cases.py``.  Covers byte-exact download
parity, upload round-trips, multi-stream, and the project-only knobs (knob-off
parity, knob-on behavioural + bytes-invariant).
"""

import pytest

from clientconf import runner
from clientconf.cases import xrdcp_cases
from clientconf.fixtures import clientconf_env  # noqa: F401

pytestmark = pytest.mark.timeout(300)

_PARAMS = runner.expand(xrdcp_cases.CASES)


@pytest.mark.parametrize("param", _PARAMS, ids=runner.ids(_PARAMS))
def test_xrdcp(param, clientconf_env, tmp_path):  # noqa: F811
    runner.run_param("xrdcp", param, tmp_path, clientconf_env)
