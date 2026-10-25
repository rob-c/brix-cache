"""A known storage limit must never excuse an unrelated conformance failure."""

import pytest

from test_conf_fattr import _reference_native_name_limit


@pytest.mark.parametrize("host,length,status,expected", [
    ("darwin", 128, {"ok": False, "errno": 3002}, True),
    ("darwin", 240, {"ok": False, "errno": 3002}, True),
    ("linux", 240, {"ok": False, "errno": 3002}, False),
    ("darwin", 64, {"ok": False, "errno": 3002}, False),
    ("darwin", 240, {"ok": False, "errno": 3010}, False),
    ("darwin", 240, {"ok": True, "errno": 3002}, False),
    ("darwin", 240, None, False),
])
def test_only_the_confirmed_native_limit_is_recognized(host, length, status, expected):
    assert _reference_native_name_limit(length, status, host) is expected
