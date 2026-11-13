"""A test run crossing UTC midnight must retain its positive proxy controls."""

import datetime
from pathlib import Path
import runpy
import sys
from types import SimpleNamespace

import pytest

from brix_suite.security.x509 import primitives


def fixture_epoch(monkeypatch, instant):
    """Load the real epoch definition with a controlled clock near midnight."""
    class Clock(datetime.datetime):
        @classmethod
        def now(cls, timezone=None):
            return instant.astimezone(timezone)

    clock = SimpleNamespace(datetime=Clock, timedelta=datetime.timedelta)
    clock.timezone = datetime.timezone
    source = Path(__file__).parent / 'brix_suite/security/x509/constants.py'
    with monkeypatch.context() as context:
        context.setitem(sys.modules, 'datetime', clock)
        return runpy.run_path(str(source))['_EPOCH']


@pytest.mark.parametrize('before,after,expected', [
    (-1, 1, 'valid'), (-2, -1, 'expired'), (1, 2, 'future')])
def test_proxy_dates_cross_midnight_without_changing_negative_controls(
        monkeypatch, before, after, expected):
    instant = datetime.datetime(2026, 11, 9, 23, 59, 58,
                                tzinfo=datetime.timezone.utc)
    monkeypatch.setattr(primitives, '_EPOCH', fixture_epoch(monkeypatch, instant))
    ca = primitives.make_ca('/CN=Epoch test CA')
    identity = primitives.make_eec(ca, '/CN=Epoch test user')
    proxy = primitives.make_proxy(identity, not_before_days=before,
                                   not_after_days=after)
    observed = instant + datetime.timedelta(seconds=4)
    start, end = proxy.cert.not_valid_before_utc, proxy.cert.not_valid_after_utc
    if expected == 'valid':
        assert start <= observed < end
    elif expected == 'expired':
        assert end < observed
    else:
        assert observed < start
