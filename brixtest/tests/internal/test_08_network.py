"""Hostname mappings and container DNS handoff contracts (071-080)."""

import pytest

from brixtest import case, docker, host_mapping
from brixtest.errors import SpecError
from brixtest.isolation import build_launch


def test_071_hostname_mapping_normalizes_dns_name():
    item = host_mapping("origin", "Origin.Auth.Test.")
    assert item.hostname == "origin.auth.test"


def test_072_hostname_mapping_retains_canonical_and_aliases():
    item = host_mapping("origin", "origin.test", aliases=("one.test", "two.test"))
    assert item.hostnames == ("origin.test", "one.test", "two.test")


def test_073_invalid_dns_label_is_rejected():
    with pytest.raises(SpecError, match="DNS labels"):
        host_mapping("origin", "bad_name.test")


def test_074_invalid_address_is_rejected():
    with pytest.raises(SpecError, match="IPv4 or IPv6"):
        host_mapping("origin", "origin.test", address="not-an-address")


def test_075_duplicate_alias_is_rejected():
    with pytest.raises(SpecError, match="unique"):
        host_mapping("origin", "origin.test", aliases=("alias.test", "alias.test"))


def test_076_ipv6_address_is_normalized():
    item = host_mapping("origin", "origin.test", address="2001:0db8::1")
    assert item.address == "2001:db8::1"


def test_077_case_rejects_hostname_collision_across_mappings():
    one = host_mapping("one", "one.test", aliases=("shared.test",))
    two = host_mapping("two", "shared.test")
    with pytest.raises(SpecError, match="unique"):
        case(hosts=[one, two])


def test_078_case_rejects_ambiguous_reverse_address():
    one = host_mapping("one", "one.test", address="127.0.0.2")
    two = host_mapping("two", "two.test", address="127.0.0.2")
    with pytest.raises(SpecError, match="reverse-enabled"):
        case(hosts=[one, two])


def test_079_docker_launch_includes_canonical_and_alias_hosts(tmp_path):
    control = tmp_path / "control"
    control.mkdir()
    mapping = host_mapping(
        "origin", "origin.test", address="127.0.0.9",
        aliases=("alias.test",), libc=True, targets=("test",),
    )
    launch = build_launch(
        docker("example/image@sha256:" + "a" * 64), ["python", "-m", "pytest"],
        {"BRIXTEST_HELPER": "1"}, cwd=tmp_path, readonly_roots=(tmp_path,),
        writable_root=tmp_path, control_dir=control, validate_executable=False,
        host_aliases=(mapping,),
    )
    assert "origin.test:127.0.0.9" in launch.argv
    assert "alias.test:127.0.0.9" in launch.argv


def test_080_user_cannot_override_framework_host_mapping():
    with pytest.raises(SpecError, match="framework-owned"):
        docker(
            "example/image@sha256:" + "b" * 64,
            extra_args=("--add-host=attacker.test:127.0.0.1",),
        )
