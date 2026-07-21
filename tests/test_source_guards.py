"""Static source-tree guards (no nginx, and no bash — pure-Python ports).

The `tools/ci/*.py` guards are the CI / pre-push copies
(`.github/workflows/guards.yml`); the fleet was ported `.sh` -> `.py` on
2026-07-21 and no bash remains. This module asserts each guard's verdict via
its in-process `source_guards_lib` twin (fast, and able to drive injected
trees for the negative cases below); `test_ci_guards.py` additionally executes
the real `tools/ci/*.py` scripts end-to-end. Guards covered here:

- config_coverage — every non-unittest ``.c`` under ``src/`` is compiled via the
  repo-root ``./config`` or on a reasoned allowlist; stale ``./config`` entries
  and stale allowlist rows also fail.
- http_helper_reimpl — protocol/observability handlers must not regrow private
  copies of the shared HTTP helpers in ``src/core/http/`` (raw header-scan loops,
  local precondition logic, hand-rolled ETags).
- metric_cardinality — Prometheus exporters may only interpolate metric-label
  values under a curated low-cardinality vocabulary (INVARIANT #8); a
  per-request-unbounded label value (path/user/DN/IP) is refused.
- auth_verdict_sentinel — ``login.auth_done = 1`` (the AUTHENTICATED verdict) may
  be raised only by a credential handler / session login-bind path (C-3).
- todo_fixme — no source file gains a new TODO/FIXME/XXX/HACK marker over its
  frozen count (deferred-work ratchet, QUALITY_ROADMAP §3.7).
- complexity — no function under ``src/``/``client/`` crosses the CCN 15 cap
  unless grandfathered in ``complexity_backlog.txt`` (McCabe ratchet,
  QUALITY_ROADMAP §1). Skipped when the ``lizard`` analyzer is not installed;
  CI pip-installs it before the run.
"""

from pathlib import Path

import pytest

import source_guards_lib as g

# Zero-arg guards asserted against the real tree.
_REAL_TREE_GUARDS = {
    "config_coverage": g.config_coverage,
    "http_helper_reimpl": g.http_helper_reimpl,
    "metric_cardinality": g.metric_cardinality,
    "auth_verdict_sentinel": g.auth_verdict_sentinel,
    "todo_fixme": g.todo_fixme,
}


@pytest.mark.parametrize("name", sorted(_REAL_TREE_GUARDS))
def test_source_guard(name: str) -> None:
    ok, msgs = _REAL_TREE_GUARDS[name]()
    assert ok, f"{name} failed:\n" + "\n".join(msgs)


# --- complexity (CCN 15) ratchet · lizard-gated -------------------------------
#
# Same lizard-backed gate the CI guards.yml step runs, so a new over-cap function
# (or one grown past its frozen ceiling) reddens the local pytest loop too. Skip
# when lizard is absent rather than hard-fail — CI pip-installs it first.


@pytest.mark.skipif(
    not g.lizard_available(),
    reason="lizard not installed (pip install --user lizard)",
)
def test_complexity_ratchet() -> None:
    ok, msgs = g.complexity()
    assert ok, "complexity ratchet failed:\n" + "\n".join(msgs)


# --- check_auth_verdict_sentinel · injected-tree behaviour --------------------
#
# The parametrized case proves the REAL tree is clean (every `login.auth_done =
# 1` sits in a sanctioned setter). These two inject a synthetic tree to assert
# the verdict directly: the AUTHENTICATED flag may be raised only by a credential
# handler / session login-bind path — a proxy/dispatch/op file that raises it is
# refused.

_SETTER = "void f(void) { ctx->login.auth_done = 1; }\n"


def test_auth_verdict_sanctioned_setter_passes(tmp_path: Path) -> None:
    """A setter in a sanctioned auth file is accepted."""
    f = tmp_path / "auth" / "gsi" / "auth.c"
    f.parent.mkdir(parents=True)
    f.write_text(_SETTER)
    ok, msgs = g.auth_verdict_sentinel(tmp_path)
    assert ok, msgs


def test_auth_verdict_rogue_setter_fails(tmp_path: Path) -> None:
    """SECURITY-NEG: raising the verdict from a proxy/dispatch file is refused —
    the exact sentinel-confusion shape C-3 guards against."""
    f = tmp_path / "net" / "proxy" / "connect_upstream.c"
    f.parent.mkdir(parents=True)
    f.write_text(_SETTER)
    ok, msgs = g.auth_verdict_sentinel(tmp_path)
    assert not ok
    assert any("net/proxy/connect_upstream.c" in m for m in msgs)


# --- check_metric_cardinality · injected-fixture behaviour --------------------
#
# Point the guard at a scratch dir to assert its verdict on synthetic exporter
# sources without touching the real tree (the parametrized case proves the real
# tree is clean).

_EMIT = (
    "static void emit(metrics_writer_t *mw) {{\n"
    '    mw_printf(mw, "brix_x_total{{{label}=\\"%s\\"}} %lu\\n", v, n);{tail}\n'
    "}}\n"
)


def test_metric_cardinality_approved_label_passes(tmp_path: Path) -> None:
    """An enum-valued label from the curated vocabulary is accepted."""
    (tmp_path / "ok.c").write_text(_EMIT.format(label="proto", tail=""))
    ok, msgs = g.metric_cardinality(tmp_path)
    assert ok, msgs


def test_metric_cardinality_path_label_fails(tmp_path: Path) -> None:
    """SECURITY-NEG: a per-request path-valued label trips the guard."""
    (tmp_path / "evil.c").write_text(_EMIT.format(label="path", tail=""))
    ok, msgs = g.metric_cardinality(tmp_path)
    assert not ok
    assert any("path" in m for m in msgs)


def test_metric_cardinality_marker_overrides(tmp_path: Path) -> None:
    """A per-line metric-cardinality-allow marker whitelists a bounded value."""
    (tmp_path / "marked.c").write_text(
        _EMIT.format(
            label="user", tail=" /* metric-cardinality-allow: bounded set */"
        )
    )
    ok, msgs = g.metric_cardinality(tmp_path)
    assert ok, msgs
