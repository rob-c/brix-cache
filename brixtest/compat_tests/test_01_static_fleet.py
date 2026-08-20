"""Examples 1-2: the static fleet and scoped log views.

This file reaches ``alpha``, so it carries the declaration marker.
Deleting the marker makes the selective-boot contract explicit at
collection time.
"""

from __future__ import annotations

import json
import urllib.request

import pytest

pytestmark = pytest.mark.registry_server("alpha")


def test_01_static_server_is_addressed_not_assembled(brix):
    """A test never builds a URL out of port constants: the endpoint
    (spec x kind x lane) is the one way to spell where alpha lives."""
    endpoint = brix.server("alpha")
    assert endpoint.primary_port == brix.fleet.lane.port_base + 1
    assert endpoint.host in ("127.0.0.1", "localhost")
    body = urllib.request.urlopen(
        brix.url("alpha", path="/health"), timeout=5
    ).read()
    assert body == b"ok\n"


def test_02_log_views_are_marked_and_scoped(brix):
    """``mark()`` then ``wait_for(..., since=mark)``: a test only ever
    sees log lines it caused, so a noisy fleet cannot fake a match."""
    view = brix.log("alpha")
    mark = view.mark()
    urllib.request.urlopen(brix.url("alpha", path="/health"), timeout=5).read()
    line = view.wait_for("stub.access", since=mark, timeout=5.0)
    record = json.loads(line)
    assert record["path"] == "/health"
    assert record["status"] == 200
    # the startup line predates the mark, so the scoped view excludes it
    assert not any("stub.ready" in seen for seen in view.lines(mark))
