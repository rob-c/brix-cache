"""Effective credentials distinguish protected logins from our test owners."""

import os
from types import SimpleNamespace

import pytest

from lib_py.process_host import _environment_tokens


@pytest.mark.parametrize('real_delta,effective_delta,expected', [
    (0, 0, None),  # An unreadable owner must still prevent cleanup.
    (0, 1, []),    # A setuid login is not our harness.
    (1, 0, None),  # Our effective identity remains protected despite real UID.
])
def test_unreadable_environment_uses_effective_ownership(real_delta, effective_delta, expected):
    uid = os.geteuid()
    credentials = SimpleNamespace(real=uid + real_delta, effective=uid + effective_delta)
    assert _environment_tokens({'environ': None, 'uids': credentials}) == expected
