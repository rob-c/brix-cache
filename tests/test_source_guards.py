"""Static source-tree guards (no nginx required).

Wraps the tools/ci shell guards so they run in the normal pytest gate:

- check_config_coverage.sh — every non-unittest ``.c`` under ``src/`` is
  either compiled via the repo-root ``./config`` or on a reasoned allowlist;
  stale ``./config`` entries and stale allowlist rows also fail.
- check_http_helper_reimpl.sh — protocol/observability handlers must not
  regrow private copies of the shared HTTP helpers in ``src/core/http/``
  (raw header-scan loops, local precondition logic, hand-rolled ETags).
- check_metric_cardinality.sh — Prometheus exporters must only interpolate
  metric-label values under a curated low-cardinality vocabulary (INVARIANT
  #8); a per-request-unbounded label value (path/user/DN/IP) is refused.
"""

import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]

MC_GUARD = ROOT / "tools" / "ci" / "check_metric_cardinality.sh"


def _run_guard(script_name: str) -> None:
    script = ROOT / "tools" / "ci" / script_name
    result = subprocess.run(
        [str(script)], cwd=ROOT, capture_output=True, text=True
    )
    assert result.returncode == 0, (
        f"{script_name} failed:\n{result.stdout}{result.stderr}"
    )


@pytest.mark.parametrize(
    "script",
    [
        "check_config_coverage.sh",
        "check_http_helper_reimpl.sh",
        "check_metric_cardinality.sh",
        "check_auth_verdict_sentinel.sh",
    ],
)
def test_source_guard(script: str) -> None:
    _run_guard(script)


# --- check_auth_verdict_sentinel.sh · C-3 verdict-sentinel discipline ---------
#
# The parametrized case above proves the REAL tree is clean (every
# `login.auth_done = 1` sits in a sanctioned auth setter).  These two inject a
# synthetic src tree so we can assert the guard's verdict directly: the flag that
# marks a session AUTHENTICATED may only be raised by a credential handler /
# session login-bind path — a proxy/dispatch/op file that raises it is refused.

_AV_GUARD = ROOT / "tools" / "ci" / "check_auth_verdict_sentinel.sh"
_SETTER = "void f(void) {{ ctx->login.auth_done = 1; }}\n"


def _run_av(scan_dir: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [str(_AV_GUARD), str(scan_dir)], cwd=ROOT, capture_output=True, text=True
    )


def test_auth_verdict_sanctioned_setter_passes(tmp_path: Path) -> None:
    """A setter in a sanctioned auth file is accepted."""
    f = tmp_path / "auth" / "gsi" / "auth.c"
    f.parent.mkdir(parents=True)
    f.write_text(_SETTER)
    r = _run_av(tmp_path)
    assert r.returncode == 0, r.stdout + r.stderr


def test_auth_verdict_rogue_setter_fails(tmp_path: Path) -> None:
    """SECURITY-NEG: raising the verdict from a proxy/dispatch file is refused —
    the exact sentinel-confusion shape C-3 guards against."""
    f = tmp_path / "net" / "proxy" / "connect_upstream.c"
    f.parent.mkdir(parents=True)
    f.write_text(_SETTER)
    r = _run_av(tmp_path)
    assert r.returncode == 1, r.stdout + r.stderr
    assert "net/proxy/connect_upstream.c" in r.stdout


# --- check_metric_cardinality.sh · injected-fixture behaviour -----------------
#
# Point the guard at a scratch dir so we can assert its verdict on synthetic
# exporter sources without touching the real tree (the parametrized case above
# already proves the real tree is clean).

_EMIT = (
    "static void emit(metrics_writer_t *mw) {{\n"
    '    mw_printf(mw, "brix_x_total{{{label}=\\"%s\\"}} %lu\\n", v, n);{tail}\n'
    "}}\n"
)


def _run_mc(scan_dir: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [str(MC_GUARD), str(scan_dir)], cwd=ROOT, capture_output=True, text=True
    )


def test_metric_cardinality_approved_label_passes(tmp_path: Path) -> None:
    """An enum-valued label from the curated vocabulary is accepted."""
    (tmp_path / "ok.c").write_text(_EMIT.format(label="proto", tail=""))
    r = _run_mc(tmp_path)
    assert r.returncode == 0, r.stdout + r.stderr


def test_metric_cardinality_path_label_fails(tmp_path: Path) -> None:
    """SECURITY-NEG: a per-request path-valued label trips the guard."""
    (tmp_path / "evil.c").write_text(_EMIT.format(label="path", tail=""))
    r = _run_mc(tmp_path)
    assert r.returncode == 1, r.stdout + r.stderr
    assert "path" in r.stderr and "INVARIANT #8" in r.stderr


def test_metric_cardinality_marker_overrides(tmp_path: Path) -> None:
    """A per-line metric-cardinality-allow marker whitelists a bounded value."""
    (tmp_path / "marked.c").write_text(
        _EMIT.format(
            label="user", tail=" /* metric-cardinality-allow: bounded set */"
        )
    )
    r = _run_mc(tmp_path)
    assert r.returncode == 0, r.stdout + r.stderr
