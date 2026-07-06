"""F5 — cross-protocol cache poisoning + S3 scope parity (threat T5).

The read cache key is path-only (cache_key.c:21), so a cache entry filled via one protocol is
served by another. Each serve protocol must reach ITS OWN authoritative (direct-server)
verdict for the presented identity; a serve that ALLOWs where the serve protocol's cold path
DENIES is poisoning. S3 cells are the sharpest: S3 authorizes on SigV4 identity but never
checks token scope, so a file filled under a read-only-scoped principal can be served to an
S3 key its own authz would deny — RED today.

Run: sudo -E env PYTHONPATH=tests pytest tests/test_mu_cross_protocol.py -v
"""
import pytest

from mu_authz_lib import cache_state
from mu_authz_lib.oracle import Cell, authoritative, leak_report, measure

# (fill_proto, serve_proto): fill via one, serve via the other.
_PAIRS = [("root", "webdav"), ("root", "s3"), ("webdav", "root"), ("webdav", "s3"),
          ("s3", "root"), ("s3", "webdav")]
_DENIED = ["carol", "bob"]


@pytest.mark.leak
@pytest.mark.privileged
@pytest.mark.parametrize("fill_proto,serve_proto", _PAIRS,
                         ids=[f"{a}-to-{b}" for a, b in _PAIRS])
@pytest.mark.parametrize("subject", _DENIED)
def test_fill_one_protocol_serve_another(mu_fleet, cast, fill_proto, serve_proto, subject):
    """Filling the shared cache via `fill_proto` must not let `serve_proto` serve a denied
    subject bytes their own (serve-protocol) authz would refuse."""
    path = "/cms/secret.dat"
    rel = path.lstrip("/")
    truth = authoritative(serve_proto, path, "read", cast[subject])
    cache_state.force_cold(rel)
    cache_state.fill_as(cast["svc"], rel, proto=fill_proto)
    got = measure(serve_proto, "cache", path, "read", cast[subject])
    cell = Cell(proto=serve_proto, op="read", subject=subject, path=path, filler="svc")
    assert got == truth, leak_report(cell, truth, got, f"filled-via-{fill_proto}")
