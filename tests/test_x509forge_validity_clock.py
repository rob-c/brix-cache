"""Hostile validity fixtures retain their meaning as the calendar advances."""

from datetime import datetime, timezone

import pytest
import x509forge


@pytest.mark.parametrize("before,after,expected", [
    (-1, 3650, "valid"),
    (-30, -1, "expired"),
    (300, 3650, "future"),
])
def test_certificate_validity_tracks_the_run_date(before, after, expected):
    ca = x509forge.make_ca("/CN=Validity clock test")
    cert = x509forge.make_eec(
        ca, "/CN=Validity subject", not_before_days=before,
        not_after_days=after).cert
    now = datetime.now(timezone.utc)
    if cert.not_valid_before_utc > now:
        actual = "future"
    elif cert.not_valid_after_utc < now:
        actual = "expired"
    else:
        actual = "valid"
    assert actual == expected
