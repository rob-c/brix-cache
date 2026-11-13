"""Reference-client timestamp formatting must not hide differing stat values."""

import importlib.util
from pathlib import Path

import pytest


@pytest.fixture(params=["native", "remote"])
def stat_value(request):
    """Exercise both separately packaged conformance-suite helpers."""
    if request.param == "native":
        from _test_conf_client2_helpers import _stat_field_value
        return _stat_field_value
    path = (Path(__file__).resolve().parents[1] / "k8s-tests" / "remote-suite"
            / "tests" / "_test_conf_client2_helpers.py")
    spec = importlib.util.spec_from_file_location("remote_stat_fields", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module._stat_field_value


@pytest.mark.parametrize("key", ["MTime", "CTime", "ATime"])
def test_stat_timestamp_accepts_only_the_optional_utc_suffix(stat_value, key):
    timestamp = "2026-11-07 01:37:14"
    assert stat_value(key, timestamp + " +0000") == timestamp
    assert stat_value(key, timestamp) == timestamp


@pytest.mark.parametrize("value", [
    "2026-11-07 01:37:15 +0000",
    "2026-11-07 01:37:14 +0100",
    "2026-11-07 01:37:14 +0000 injected",
    None,
])
def test_stat_timestamp_differences_and_malformed_values_remain_visible(stat_value, value):
    expected = stat_value("MTime", "2026-11-07 01:37:14")
    assert stat_value("MTime", value) != expected


def test_stat_invalid_date_is_not_normalized(stat_value):
    value = "2026-99-07 01:37:14 +0000"
    assert stat_value("MTime", value) == value


@pytest.mark.parametrize("key", ["Path", "Owner", "Group"])
def test_stat_non_time_fields_keep_timestamp_shaped_content(stat_value, key):
    value = "2026-11-07 01:37:14 +0000"
    assert stat_value(key, value) == value
