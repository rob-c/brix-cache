"""Self-test for account provisioning. The unprivileged guard runs anywhere; the real
roundtrip is skipped unless run as root."""
import os
import pwd

import pytest

from mu_authz_lib import accounts, principals

privileged = pytest.mark.skipif(os.geteuid() != 0, reason="needs root")


def test_require_privileged_raises_when_unprivileged(monkeypatch):
    monkeypatch.setattr(os, "geteuid", lambda: 1000)
    with pytest.raises(PermissionError):
        accounts.require_privileged()


@privileged
def test_provision_and_reap_roundtrip():
    accounts.sweep_leftover()
    cast = principals.build_cast()
    accounts.provision(cast)
    try:
        assert pwd.getpwnam("brixtest_alice").pw_uid == cast["alice"].uid
        # collide shares alice's uid; only one account is created for that uid.
        assert cast["collide"].uid == cast["alice"].uid
    finally:
        accounts.reap()
    with pytest.raises(KeyError):
        pwd.getpwnam("brixtest_alice")
