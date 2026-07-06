"""F2 — cvmfs public-by-design guardrails (threat T2, spec D3/§4).

cvmfs is NOT an enforcing protocol: it is a public content cache. These tests do not assert
enforcement — they lock cvmfs to public semantics so it can never silently gain an
auth-derived privilege: (a) an authenticated principal gets EXACTLY what anonymous gets,
and (b) a token scoped elsewhere does not WIDEN access. Expected to PASS against current
behavior (handler.c hardcodes identity="anonymous").

Run: sudo -E env PYTHONPATH=tests pytest tests/test_mu_cvmfs_public.py -v
"""
import pytest

from mu_authz_lib import ports
from mu_authz_lib.adapters import measure_webdav

_SUBJECTS = ["alice", "bob", "mallory"]   # vs anonymous
_PATHS = ["/repo/public.txt", "/repo/nested/data.bin", "/repo/restricted.txt"]


def _cvmfs_url():
    return f"https://{ports.MU.HOST}:{ports.MU.CVMFS_CACHE}"


@pytest.mark.privileged
@pytest.mark.parametrize("path", _PATHS)
@pytest.mark.parametrize("op", ["read", "stat"])
@pytest.mark.parametrize("subject", _SUBJECTS)
def test_authenticated_equals_anonymous(mu_fleet, cast, subject, op, path):
    """cvmfs must ignore credentials: an authenticated principal gets the same verdict as
    anonymous — no more, no less."""
    anon = measure_webdav(_cvmfs_url(), path, op, principal=None)
    got = measure_webdav(_cvmfs_url(), path, op, principal=cast[subject])
    assert got == anon, f"cvmfs must ignore creds: {subject} got {got}, anon got {anon}"


@pytest.mark.privileged
@pytest.mark.parametrize("path", _PATHS)
def test_scoped_token_does_not_widen_access(mu_fleet, cast, path):
    """A token scoped to /cms must not grant MORE on cvmfs than anonymous (no inferred priv)."""
    anon = measure_webdav(_cvmfs_url(), path, "read", principal=None)
    scoped = measure_webdav(_cvmfs_url(), path, "read", principal=cast["alice"])
    assert scoped == anon, "cvmfs must not infer privilege from a presented token"
