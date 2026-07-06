"""Self-test for cache-state control (COLD path; unprivileged, no fleet)."""
from mu_authz_lib import cache_state


def test_cold_reports_absent():
    cache_state.force_cold()
    rec = cache_state.cache_is_resident("cms/secret.dat")
    assert rec.get("absent") is True


def test_force_cold_single_path_is_idempotent():
    # Removing a non-existent path must not raise.
    cache_state.force_cold("cms/never-existed.dat")
    assert cache_state.cache_is_resident("cms/never-existed.dat").get("absent") is True


def test_verify_hot_false_when_absent():
    cache_state.force_cold()
    assert cache_state.verify_hot("cms/secret.dat") is False
