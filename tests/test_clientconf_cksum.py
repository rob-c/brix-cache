"""
Client-conformance: xrdadler32 + xrdcrc32c (differential vs stock).

Both checksum tools share one case shape (``cksum_cases.cases_for``); parity is
on the checksum VALUE plus rc.  Each tool runs through the runner independently.
"""

import pytest

from clientconf import runner
from clientconf.cases import cksum_cases
from clientconf.fixtures import clientconf_env  # noqa: F401

pytestmark = pytest.mark.timeout(240)

_ADLER = runner.expand(cksum_cases.cases_for("xrdadler32"))
_CRC = runner.expand(cksum_cases.cases_for("xrdcrc32c"))


@pytest.mark.parametrize("param", _ADLER, ids=runner.ids(_ADLER))
def test_xrdadler32(param, clientconf_env, tmp_path):  # noqa: F811
    runner.run_param("xrdadler32", param, tmp_path, clientconf_env)


@pytest.mark.parametrize("param", _CRC, ids=runner.ids(_CRC))
def test_xrdcrc32c(param, clientconf_env, tmp_path):  # noqa: F811
    runner.run_param("xrdcrc32c", param, tmp_path, clientconf_env)
