"""The differential cache-transparency oracle (spec §5).

The cache-OFF `direct` server is the authoritative oracle: its verdict for (principal, path,
op) is ground truth, because it always runs the full authorization gate. Every cache/stage
server variant MUST reach the identical Verdict. A cache-cold or (privileged-)filled cache-hot
serve that ALLOWs where the direct server DENYs — or denies for a weaker tier — is a leak.
"""
from dataclasses import dataclass

from . import cache_state, fleet
from .adapters import measure_root, measure_webdav, measure_s3

_ADAPTER = {"root": measure_root, "webdav": measure_webdav, "s3": measure_s3}


@dataclass
class Cell:
    proto: str
    op: str
    subject: str
    path: str
    filler: str = "svc"
    expect_tier: "str | None" = None


def measure(proto: str, variant: str, path: str, op: str, principal):
    """Measure a single (protocol, server-variant) verdict for `principal`."""
    return _ADAPTER[proto](fleet.url(proto, variant), path, op, principal=principal)


def authoritative(proto: str, path: str, op: str, principal):
    """Ground-truth verdict: always the cache-OFF direct server (full gate)."""
    return measure(proto, "direct", path, op, principal)


def _fill(proto: str, path: str, filler_principal) -> None:
    rel = path.lstrip("/")
    cache_state.force_cold(rel)
    cache_state.fill_as(filler_principal, rel, proto=proto)


_SEAM = {
    "root": "open_cache.c:26 (cached read runs VO-only, skips authdb+token-scope)",
    "webdav": "webdav read-cache serve (shared path-only key, cache_key.c:21)",
    "s3": "s3 serve without scope parity (auth_sigv4 never checks token scope)",
}


def leak_report(cell: Cell, truth, observed, where: str) -> str:
    return (f"LEAK [{cell.proto}/{cell.op}] subject={cell.subject} filler={cell.filler} "
            f"path={cell.path}\n"
            f"  authoritative(direct) = {truth}\n"
            f"  observed({where})     = {observed}\n"
            f"  likely seam: {_SEAM.get(cell.proto, cell.proto)}")


def assert_cache_transparent(cell: Cell, cast) -> None:
    """Assert the cache server's verdict for `cell.subject` equals the direct server's,
    both cold and after a privileged fill. Raises AssertionError(leak_report) on mismatch."""
    subj = cast[cell.subject]
    filler = cast[cell.filler]
    truth = authoritative(cell.proto, cell.path, cell.op, subj)

    # 1) cache server, nothing filled yet.
    cache_state.force_cold(cell.path.lstrip("/"))
    cold = measure(cell.proto, "cache", cell.path, cell.op, subj)
    assert cold == truth, leak_report(cell, truth, cold, "cache-cold")

    # 2) cache server, hot — filled by the privileged filler, then served as the subject.
    _fill(cell.proto, cell.path, filler)
    hot = measure(cell.proto, "cache", cell.path, cell.op, subj)
    assert hot == truth, leak_report(cell, truth, hot, "cache-hot")

    if cell.expect_tier and truth.decision == "DENY":
        assert truth.tier == cell.expect_tier, (
            f"tier mismatch on {cell.proto}/{cell.op} {cell.subject}@{cell.path}: "
            f"expected {cell.expect_tier}, got {truth.tier} ({truth.reason})")
