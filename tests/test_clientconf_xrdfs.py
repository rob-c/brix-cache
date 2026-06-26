"""
Client-conformance: xrdfs metadata tool (differential vs stock).

Thin shim — the cases live in ``clientconf/cases/xrdfs_cases.py``; the runner
expands them across endpoints and executes the parity/skip logic.  See
``clientconf/README.md``.
"""

import pytest

from clientconf import runner
from clientconf.cases import xrdfs_cases
from clientconf.fixtures import clientconf_env  # noqa: F401  (pytest fixture)

pytestmark = pytest.mark.timeout(240)

_PARAMS = runner.expand(xrdfs_cases.CASES)


@pytest.mark.parametrize("param", _PARAMS, ids=runner.ids(_PARAMS))
def test_xrdfs(param, clientconf_env, tmp_path):  # noqa: F811
    runner.run_param("xrdfs", param, tmp_path, clientconf_env)
