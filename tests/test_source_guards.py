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
- client_build_coverage — every ``.c`` under ``client/`` and the client-only
  ``shared/{cvmfs,cache}`` trees is named by ``client/Makefile`` (which promises
  "every .c must be listed (no wildcards)"), is a standalone-built ``*_unit.c`` /
  ``*_unittest.c`` driver, or is on a reasoned allowlist. The client-side twin of
  config_coverage: an orphaned split sibling used to surface only as a link-time
  ``undefined reference``. It also cross-checks the hand-written live-scenario
  rebuild in ``tests/cmdscripts/brixcvmfs_live.py`` against the Makefile's
  ``BRIXCVMFS_SPLIT``, since that list is a second build of the same TUs.
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
- complexity — no native function under ``src/``/``client/``/``shared/``
  crosses the absolute CCN 15 cap (QUALITY_ROADMAP §1). Skipped when the
  ``lizard`` analyzer is not installed;
  CI pip-installs it before the run.
"""

from pathlib import Path

import pytest
import source_guards_lib as g

# Zero-arg guards asserted against the real tree.
_REAL_TREE_GUARDS = {
    "config_coverage": g.config_coverage,
    "client_build_coverage": g.client_build_coverage,
    "http_helper_reimpl": g.http_helper_reimpl,
    "metric_cardinality": g.metric_cardinality,
    "auth_verdict_sentinel": g.auth_verdict_sentinel,
    "todo_fixme": g.todo_fixme,
}


@pytest.mark.parametrize("name", sorted(_REAL_TREE_GUARDS))
def test_source_guard(name: str) -> None:
    ok, msgs = _REAL_TREE_GUARDS[name]()
    assert ok, f"{name} failed:\n" + "\n".join(msgs)


# --- complexity (absolute CCN 15 cap) · lizard-gated --------------------------
#
# Same lizard-backed gate the CI guards.yml step runs, so any over-cap function
# reddens the local pytest loop. Skip
# when lizard is absent rather than hard-fail — CI pip-installs it first.


@pytest.mark.timeout(300)   # lizard over src/client/shared is ~11s idle and
                            # single-threaded; the 30s session default loses
                            # under xdist load (same allowance as test_ci_guards)
@pytest.mark.skipif(
    not g.lizard_available(),
    reason="lizard not installed (pip install --user lizard)",
)
def test_complexity_limit() -> None:
    ok, msgs = g.complexity()
    assert ok, "complexity limit failed:\n" + "\n".join(msgs)


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


# --- client_build_coverage · the hand-written rebuilds of the split ----------
#
# The brixcvmfs driver is compiled by more than `make`: tests/cmdscripts/*.py
# rebuild it with one gcc line each and tests/c/*.c include a member outright.
# Phase-116 put the libcurl address pin in its own TU; client/Makefile and one
# cmdscripts list learned about it, five other sites did not, and each of them
# died at link on `undefined reference to cvmfs_curl_perform_pinned`. The guard
# therefore asks per site "does what this site compiles actually link", not
# "is this TU named somewhere". These drive injected trees — the parametrized
# case above proves the real tree is clean.

_SPLIT_MAKEFILE = (
    "BRIXCVMFS_SPLIT := apps/fs/brixcvmfs_transport.o \\\n"
    "                   apps/fs/brixcvmfs_curl_pin.o apps/fs/brixcvmfs_ops.o\n"
)
_TRANSPORT_C = (
    "#include \"apps/fs/brixcvmfs_curl_pin.h\"\n"
    "int transport_cleanup(void) {\n"
    "    return cvmfs_curl_perform_pinned(0, 0, \"http://h/o\");\n"
    "}\n"
)
_PIN_C = "CURLcode\ncvmfs_curl_perform_pinned(CURL *c, const void *t, const char *u)\n{ return 0; }\n"
_OPS_C = "int brixcvmfs_op_open(const char *p) { return 0; }\n"
_SPLIT_C = {
    "brixcvmfs_transport.c": _TRANSPORT_C,
    "brixcvmfs_curl_pin.c": _PIN_C,
    "brixcvmfs_ops.c": _OPS_C,
}


def _split_tree(tmp_path: Path, sites: dict[str, str]) -> Path:
    """A minimal tree: the three split TUs, a Makefile naming them, and `sites`
    (repo-relative path -> file text) as the hand-written build sites."""
    (tmp_path / "client" / "apps" / "fs").mkdir(parents=True)
    for name, text in _SPLIT_C.items():
        (tmp_path / "client" / "apps" / "fs" / name).write_text(text)
    (tmp_path / "client" / "Makefile").write_text(_SPLIT_MAKEFILE)
    for rel, text in sites.items():
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    return tmp_path


def _py_site(*sources: str) -> str:
    return "SRCS = [" + ", ".join(f'"client/apps/fs/{s}"' for s in sources) + "]\n"


def _gaps(root: Path) -> list[str]:
    return g._live_build_gaps(root, _SPLIT_MAKEFILE)


def test_site_naming_every_tu_it_calls_into_passes(tmp_path: Path) -> None:
    """A gcc line that names the transport and the pin it calls links."""
    root = _split_tree(
        tmp_path,
        {"tests/cmdscripts/live.py": _py_site("brixcvmfs_transport.c",
                                              "brixcvmfs_curl_pin.c")},
    )
    assert _gaps(root) == [], _gaps(root)


def test_site_missing_the_called_tu_fails(tmp_path: Path) -> None:
    """The regression itself: the transport without the pin TU it calls."""
    root = _split_tree(
        tmp_path, {"tests/cmdscripts/live.py": _py_site("brixcvmfs_transport.c")}
    )
    msgs = _gaps(root)
    assert msgs and "cvmfs_curl_perform_pinned" in msgs[0]
    assert "tests/cmdscripts/live.py" in msgs[0]
    assert "brixcvmfs_curl_pin.c" in msgs[0]


def test_each_site_is_judged_alone(tmp_path: Path) -> None:
    """The bug the first guard shipped with: it concatenated the lists, so ONE
    complete site made every other site look complete. Five real sites were
    broken behind a green guard until a suite reached them."""
    root = _split_tree(
        tmp_path,
        {
            "tests/cmdscripts/live.py": _py_site("brixcvmfs_transport.c",
                                                 "brixcvmfs_curl_pin.c"),
            "tests/cmdscripts/units.py": _py_site("brixcvmfs_transport.c"),
        },
    )
    msgs = _gaps(root)
    assert len(msgs) == 1, msgs
    assert "tests/cmdscripts/units.py" in msgs[0]


def test_site_omitting_a_tu_it_never_calls_passes(tmp_path: Path) -> None:
    """Not a list-equality check: a site that compiles only the ops TU calls
    nothing in the other members, so its build links and the guard stays quiet.
    A set comparison against BRIXCVMFS_SPLIT would redden every such site and
    train people to add TUs their binary does not need."""
    root = _split_tree(
        tmp_path, {"tests/cmdscripts/units.py": _py_site("brixcvmfs_ops.c")}
    )
    assert _gaps(root) == [], _gaps(root)


def test_a_shard_inherits_the_sources_of_the_module_that_execs_it(tmp_path: Path) -> None:
    """`_load_continuation(globals(), __file__, ...)` runs a shard inside its
    loader's namespace, so the two files are one build site. Reading the shard
    alone reports a gap that does not exist at runtime."""
    parent = ('SPLIT = ["client/apps/fs/brixcvmfs_curl_pin.c"]\n'
              '_load_continuations(globals(), __file__, "shard.py",\n'
              '                    "other.py")\n')
    root = _split_tree(
        tmp_path,
        {
            "tests/cmdscripts/live.py": parent,
            "tests/cmdscripts/shard.py": _py_site("brixcvmfs_transport.c"),
        },
    )
    assert _gaps(root) == [], _gaps(root)


def test_a_shard_that_rebinds_the_loaders_list_is_judged_on_its_own(tmp_path: Path) -> None:
    """Inheritance stops at a rebinding. tests/cmdscripts/cvmfs_driver_units_part2.py
    assigns its own BRIXCVMFS_DRIVER_SRCS, so the loader's list is replaced, not
    extended — reading the chain as one flat namespace declared that site fixed
    while its gcc line was still missing the pin TU."""
    parent = "SRCS = [\"client/apps/fs/brixcvmfs_transport.c\", \"client/apps/fs/brixcvmfs_curl_pin.c\"]\n"
    root = _split_tree(
        tmp_path,
        {
            "tests/cmdscripts/units.py": (
                parent + '_load_continuation(globals(), __file__, "part2.py")\n'
            ),
            "tests/cmdscripts/part2.py": "SRCS = [\"client/apps/fs/brixcvmfs_transport.c\"]\n",
        },
    )
    msgs = _gaps(root)
    assert len(msgs) == 1, msgs
    assert "tests/cmdscripts/part2.py" in msgs[0]
    assert "cvmfs_curl_perform_pinned" in msgs[0]


def test_prefix_lookalike_does_not_satisfy_the_call(tmp_path: Path) -> None:
    """SECURITY-NEG: a same-prefix sibling must not stand in for the real TU.
    A stem-substring test would accept `brixcvmfs_curl_pin_stub.c` — a file
    that defines nothing — and hand the live scenarios a link error again."""
    root = _split_tree(
        tmp_path, {"tests/cmdscripts/live.py": _py_site("brixcvmfs_transport.c",
                                                        "brixcvmfs_curl_pin_stub.c")},
    )
    (root / "client/apps/fs/brixcvmfs_curl_pin_stub.c").write_text("int unrelated;\n")
    msgs = _gaps(root)
    assert msgs and "cvmfs_curl_perform_pinned" in msgs[0]


def test_a_c_unit_that_includes_a_tu_may_stub_the_sibling(tmp_path: Path) -> None:
    """tests/c units include a TU and stub its externals by design; a stub the
    unit defines itself is a definition, so that build links."""
    unit = (_PIN_C + '#include "apps/fs/brixcvmfs_transport.c"\n')
    root = _split_tree(tmp_path, {"tests/c/url_test.c": unit})
    assert _gaps(root) == [], _gaps(root)


def test_a_c_unit_with_neither_the_tu_nor_a_stub_fails(tmp_path: Path) -> None:
    """The same unit without the stub: the include pulls in a call that nothing
    defines, which is exactly how tests/c/cvmfs_url_rewrite_test.c broke."""
    root = _split_tree(
        tmp_path,
        {"tests/c/url_test.c": '#include "apps/fs/brixcvmfs_transport.c"\n'},
    )
    msgs = _gaps(root)
    assert msgs and "tests/c/url_test.c" in msgs[0]
    assert "cvmfs_curl_perform_pinned" in msgs[0]


# --- client_build_coverage · the seam under the split (phase-116 am. 13) -----
#
# The pin does not stand alone either: it resolves every name through the
# client DNS seam (client/lib/net/resolve.c, netpref.c). Ten sites learned the
# pin and stopped there, so the link moved one TU down and failed on
# brix_resolve/brix_resolve_ntop/brix_netpref_family instead.

_SEAM_C = ("int\nbrix_resolve(const char *host, int port)\n{ return 0; }\n"
           "const char *\nbrix_resolve_ntop(const void *sa)\n{ return \"\"; }\n")
_PIN_CALLING_SEAM = (
    "CURLcode\ncvmfs_curl_perform_pinned(CURL *c, const void *t, const char *u)\n"
    "{ return brix_resolve(u, 443) + (int) (long) brix_resolve_ntop(0); }\n"
)


def _seam_tree(tmp_path: Path, sites: dict[str, str], pin: str = _PIN_CALLING_SEAM,
               transport: str | None = None) -> Path:
    """`_split_tree` plus the client net seam the pin calls into."""
    root = _split_tree(tmp_path, sites)
    (root / "client" / "apps" / "fs" / "brixcvmfs_curl_pin.c").write_text(pin)
    if transport is not None:
        (root / "client" / "apps" / "fs" / "brixcvmfs_transport.c").write_text(transport)
    net = root / "client" / "lib" / "net"
    net.mkdir(parents=True)
    (net / "resolve.c").write_text(_SEAM_C)
    return root


def _site(*sources: str) -> str:
    return "SRCS = [" + ", ".join(f'"{s}"' for s in sources) + "]\n"


def test_a_site_that_stops_at_the_split_misses_the_seam_below_it(tmp_path: Path) -> None:
    """The second half of the same regression: naming every split TU is not enough
    when one of them calls out of the split."""
    root = _seam_tree(
        tmp_path,
        {"tests/cmdscripts/live.py": _site("client/apps/fs/brixcvmfs_transport.c",
                                           "client/apps/fs/brixcvmfs_curl_pin.c")},
    )
    msgs = _gaps(root)
    assert msgs and all("brixcvmfs_curl_pin.c" in m for m in msgs), msgs
    assert any("brix_resolve" in m and "client/lib/net/resolve.c" in m for m in msgs)


def test_a_site_that_names_the_seam_passes(tmp_path: Path) -> None:
    """The fix: the seam source on the same gcc line."""
    root = _seam_tree(
        tmp_path,
        {"tests/cmdscripts/live.py": _site("client/apps/fs/brixcvmfs_transport.c",
                                           "client/apps/fs/brixcvmfs_curl_pin.c",
                                           "client/lib/net/resolve.c")},
    )
    assert _gaps(root) == [], _gaps(root)


def test_an_archive_supplies_the_library_but_never_the_split(tmp_path: Path) -> None:
    """tests/cmdscripts/tap_proxy_live_part2.py links client/libbrix.a, which holds
    lib/net/* — demanding resolve.c there would be a false red. The archive holds
    no app-side split member, so the split symbol is still owed."""
    root = _seam_tree(
        tmp_path,
        {
            "tests/cmdscripts/archive_ok.py": _site(
                "client/apps/fs/brixcvmfs_transport.c",
                "client/apps/fs/brixcvmfs_curl_pin.c", "client/libbrix.a"),
            "tests/cmdscripts/archive_short.py": _site(
                "client/apps/fs/brixcvmfs_transport.c", "client/libbrix.a"),
        },
    )
    msgs = _gaps(root)
    assert not [m for m in msgs if "archive_ok.py" in m], msgs
    short = [m for m in msgs if "archive_short.py" in m]
    assert len(short) == 1 and "cvmfs_curl_perform_pinned" in short[0], msgs


def test_a_symbol_named_only_in_a_comment_is_not_a_call(tmp_path: Path) -> None:
    """The transport documents brix_resolve() in prose twice and calls it never;
    a word-match guard demanded the seam at every site that compiles the transport,
    including a C unit that had stubbed the pin away."""
    prose = ("/* every hop is resolved through brix_resolve(), never by libcurl */\n"
             "int transport_cleanup(void) { return 0; }\n")
    root = _seam_tree(
        tmp_path,
        {"tests/cmdscripts/live.py": _site("client/apps/fs/brixcvmfs_transport.c")},
        pin=_PIN_C,
        transport=prose,
    )
    assert _gaps(root) == [], _gaps(root)
