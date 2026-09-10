"""2.0 readiness F14 — label cardinality stays bounded under a unique-path
storm, and counters survive a reload.

INVARIANT 8 says every label is low-cardinality; the cheapest way to break it
is a client that touches a thousand distinct paths.  Legs: after 1000 unique
stats + mkdirs the SET of series is unchanged and no label carries a path
(success); a SIGHUP reload keeps the SHM counters (persistence); and a label-
shaped path (``a"}b``) never reaches the exposition text (security negative —
a client cannot inject a series or break the parser).
"""
from __future__ import annotations

import pytest

import re

from _test_release20_metrics_helpers import samples, scrape, series_keys, total, value, wait_for, wait_port
from server_registry import NginxInstanceSpec
from settings import BIND_HOST, HOST

pytestmark = [pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-r20-card")]

NAME = "lc-r20-stream-metrics"
STORM = 1000
_SAMPLE_LINE = re.compile(r'^[A-Za-z_:][A-Za-z0-9_:]*(\{[^{}]*\})? -?[0-9.eE+-]+$')
POISON = 'card/a"}brix_injected{x="y"} 1\nbrix_injected_total 1'


@pytest.fixture
def subject(lifecycle, tmp_path):
    data = tmp_path / "data"
    data.mkdir()
    ep = lifecycle.start(NginxInstanceSpec(
        name=NAME, template="nginx_lc_r20_stream_metrics.conf",
        data_root=str(data), template_values={"BIND_HOST": BIND_HOST},
        reason="2.0 readiness F14: cardinality + reload persistence"))
    if not wait_port(ep.extra_ports["METRICS_PORT"]):
        pytest.skip("stream+metrics instance did not become ready")
    return ep


def _storm(ep, n):
    """n unique missing-path stats and n/4 unique mkdirs on one session."""
    from XRootD import client
    fs = client.FileSystem(f"root://{HOST}:{ep.port}")
    errors = 0
    for i in range(n):
        st, _ = fs.stat(f"/card/missing-{i}")
        errors += 0 if st.ok else 1
    for i in range(n // 4):
        fs.mkdir(f"/card/dir-{i}")
    return errors


def _stat_errors(body, port):
    return value(body, "brix_requests_total", port=str(port), op="stat", status="error") or 0.0


def _scrape_when_errors_reach(ep, floor, timeout):
    """The first scrape whose stat error counter is >= floor, else None."""
    mport = ep.extra_ports["METRICS_PORT"]

    def probe():
        body = scrape(mport)
        return body if _stat_errors(body, ep.port) >= floor else None

    return wait_for(probe, timeout=timeout)


def _assert_no_path_leaked(body):
    for needle in ("/card/", "missing-", "dir-"):
        assert needle not in body, f"a client path ({needle}) reached a label"


def test_a_unique_path_storm_adds_no_series(subject):
    warm = _storm(subject, 4)
    before = scrape(subject.extra_ports["METRICS_PORT"])
    keys0 = series_keys(before)
    assert _storm(subject, STORM) == STORM
    after = _scrape_when_errors_reach(subject, warm + STORM, 15)
    assert after is not None, "stat error counter never reached the storm size"
    keys1 = series_keys(after)
    assert keys1 == keys0, {"new": keys1 - keys0, "lost": keys0 - keys1}
    _assert_no_path_leaked(after)
    assert len(after) < 1.10 * len(before)


def test_counters_survive_a_reload(subject, lifecycle):
    _storm(subject, 50)
    before = _scrape_when_errors_reach(subject, 50, 15)
    assert before is not None
    floor = _stat_errors(before, subject.port)
    conns = total(before, "brix_connections_total")
    lifecycle.reload(NAME)
    assert wait_port(subject.extra_ports["METRICS_PORT"])
    after = _scrape_when_errors_reach(subject, floor, 10)
    assert after is not None, "reload zeroed the stat error counter"
    assert total(after, "brix_connections_total") >= conns


def _assert_every_line_parses(body):
    for line in body.splitlines():
        assert not line or line[0] == "#" or _SAMPLE_LINE.match(line), line


def _assert_no_label_carries(body, *needles):
    for name, labels, _ in samples(body):
        leaked = [v for v in labels.values() if any(n in v for n in needles)]
        assert not leaked, (name, labels)


def test_a_label_shaped_path_never_reaches_the_exposition(subject):
    """Security negative: a path shaped like a label + a fake series never
    reaches the text — every line still parses, and no label carries it."""
    from XRootD import client
    fs = client.FileSystem(f"root://{HOST}:{subject.port}")
    for _ in range(3):
        fs.stat("/" + POISON)
        fs.mkdir("/" + POISON)
    body = scrape(subject.extra_ports["METRICS_PORT"])
    assert "brix_injected" not in body
    assert "brix_requests_total" in {name for name, _, _ in samples(body)}
    _assert_every_line_parses(body)
    _assert_no_label_carries(body, "card", "{", "}")
