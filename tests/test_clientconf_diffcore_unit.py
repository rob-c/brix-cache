"""Reference-version formatting must not hide differences in stat metadata."""

import pytest

from clientconf.diffcore import normalize
from clientconf.endpoints import Endpoint
from settings import HOST


@pytest.mark.parametrize("field", ["MTime", "CTime", "ATime"])
def test_stat_utc_suffix_is_optional(field):
    stamp = f"{field}:  2026-11-08 10:51:21"
    assert normalize(stamp + " +0000\n") == normalize(stamp)


@pytest.mark.parametrize("field", ["MTime", "CTime", "ATime"])
@pytest.mark.parametrize("value", [
    "2026-11-08 10:51:22", "1970-01-01 00:00:00", "invalid", "-1",
])
def test_stat_timestamp_mismatch_is_preserved(field, value):
    expected = f"{field}:  2026-11-08 10:51:21"
    assert normalize(f"{field}:  {value}") != normalize(expected)


@pytest.mark.parametrize("suffix", [
    " +0100", " -0100", " +00000", " +0000 injected", " +0000\nOwner: attacker",
])
def test_stat_offset_or_injected_metadata_is_not_erased(suffix):
    stamp = "MTime:  2026-11-08 10:51:21"
    assert normalize(stamp + suffix) != normalize(stamp)


def test_diagnostic_timestamp_does_not_change_stat_fields():
    result = normalize("connected 2026-11-08 10:51:21\n"
                       "MTime:  2026-11-08 10:51:21 +0000\nSize:  19\n")
    assert result == "connected <TS>\nMTime:  2026-11-08 10:51:21\nSize:  19"


def test_client_timezone_is_deterministic(monkeypatch):
    monkeypatch.setenv("TZ", "Pacific/Honolulu")
    endpoint = Endpoint("utc-test", HOST, 1094, auth={"TZ": "Europe/Paris"})
    assert endpoint.auth_env()["TZ"] == "UTC"
