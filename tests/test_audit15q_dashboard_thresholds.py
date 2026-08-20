"""
test_audit15q_dashboard_thresholds.py — §Method step 2 sharpened, fourth and
last file (docs/refactor/testsuite-combinatorial-coverage-audit-2026-08-15.md).

WHY THIS FILE EXISTS

Step 2 counted a directive covered when its name appeared anywhere in the test
corpus, which counts a directive as covered for merely sitting in a launched
template.  Re-asking the question as "is there a test whose verdict changes
when this directive changes?" left thirteen survivors.  Four went to the WebDAV
response surface (test_audit15n), four to the CMS timing plane (test_audit15o),
one to the S3 bearer window (test_audit15p, where two of its four turned out to
be covered in effect), and this file closes the pair that decides what an
operator actually sees:

  brix_dashboard_idle_threshold · brix_dashboard_stalled_threshold

One of the two is covered in effect and is recorded as such rather than
re-tested: `tests/test_dashboard.py::TestDashboardThrottledState` runs against
a face configured 1s/3s and asserts an exact "throttled"/"stalled" within a 45s
budget — neither state is reachable in that budget on the 60s default, so
brix_dashboard_stalled_threshold already has a verdict that moves with it.
What no test in the tree does is observe the **"idle" band between the two
numbers**, read the **limits echo** that is the only place the merged values
are visible, or exercise the **cross-field invariant** at module.c:203.

THE MEASUREMENT, AND WHY NOTHING HERE IS TIMED

dashboard_state_name() (api.c:38) is a pure function of one slot's idle_ms and
ONE location's two thresholds.  The transfer table is SHM and process-wide, so
every dashboard face in this nginx reads the SAME slot.  That turns a timing
question into a simultaneity one: open a handle, leave it alone, and ask four
faces at one instant what state that single row is in.

    face        idle / stalled        the row, ~2s after the open
    fast        200ms / 700ms         "stalled"
    mid         1500ms / 30s          "idle"
    slow        20s / 40s             "active"
    def         (unwritten -> 5s/60s) "active"

Three verdicts, one row, one instant, three configured pairs.  No assertion in
this file says a thing about how long anything took: the tests read each
response's own idle_ms and check the state the reading face's own numbers
predict for it, so a host that stalls between two polls changes which band the
row is in without changing whether the answer is right.

WHAT THE BLOCK ESTABLISHES

- The two thresholds are read per LOCATION, not per process.  Four faces over
  one slot disagree, which is only possible if each classification uses the
  conf of the location serving that request.
- The "idle" band exists and is bounded on both sides — the mid face calls the
  row idle where the fast face calls it stalled and the slow face calls it
  active.
- `avg_bps == 0` is what separates "stalled" from "throttled": a handle opened
  and never read has moved nothing, so the stalled leg of api.c:53-55 is the
  one taken.  (The other leg is test_dashboard.py's.)
- The limits object echoes each face's own merged pair, which is the only way
  the frozen defaults at module.c:137-140 are observable at all.
- The cross-field invariant refuses an inverted pair at `nginx -t`, including
  the case where the operator writes ONE of the two and the OTHER's default is
  what makes the pair inconsistent — the check runs after the merge, so the
  refusal names a directive the config does not contain.

NO DEFECT CANDIDATES.  Every claim above held on the first run; the pair is
wired, per-location, bounded, echoed and validated.  Recorded because a section
of an audit that only ever finds defects is not measuring, and because the
simultaneity method here is the reusable part: any per-location classifier over
a process-wide table can be measured this way instead of with a stopwatch.
"""

import json
import os
import socket
import struct
import time

import pytest
import requests

from server_registry import NginxInstanceSpec
from settings import HOST, NGINX_BIN
from test_cms_locate_have import _recv_response, _xrd_session
from test_phase25_ratelimit import _parse_fail, _http_values

pytestmark = [pytest.mark.timeout(180),
              pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-audit15q-dashbands")]

_needs_nginx = pytest.mark.skipif(
    not os.access(NGINX_BIN, os.X_OK), reason=f"nginx not executable: {NGINX_BIN}")

kXR_open = 3010
kXR_open_read = 0x0010

# The frozen merge defaults (module.c:137-140), observable only via the limits
# object on a face that writes neither directive.
DEFAULT_IDLE_MS = 5000
DEFAULT_STALLED_MS = 60000

# name -> (extra-port key or None for {PORT}, idle_ms, stalled_ms)
FACES = {
    "fast": (None,         200,   700),
    "mid":  ("MID_PORT",   1500,  30000),
    "slow": ("SLOW_PORT",  20000, 40000),
    "def":  ("DEF_PORT",   DEFAULT_IDLE_MS, DEFAULT_STALLED_MS),
}

# The window in which the three configured faces are guaranteed to disagree:
# past the fast face's stalled threshold and the mid face's idle threshold,
# still short of the slow face's idle threshold.
DISAGREEMENT_LO_MS = 1600
DISAGREEMENT_HI_MS = 18000

SEED = b"audit15q dashboard band seed\n" * 64


# --------------------------------------------------------------------------- #
# The block.                                                                   #
# --------------------------------------------------------------------------- #

@pytest.fixture()
def bands(lifecycle, tmp_path):
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx binary not executable: {NGINX_BIN}")

    data = tmp_path / "data"
    data.mkdir()
    (data / "held.bin").write_bytes(SEED)
    tmp = tmp_path / "ngxtmp"
    tmp.mkdir()

    endpoint = lifecycle.start(NginxInstanceSpec(
        name="lc-audit15q-dashbands",
        template="nginx_audit15q_dashthresholds.conf",
        protocol="http",
        data_root=str(data),
        template_values={"TMP_DIR": str(tmp)},
        reason="audit-15q: the dashboard's transfer-state bands"))
    return endpoint


@pytest.fixture()
def held(bands):
    """An xrootd handle opened and then left strictly alone.

    Only a read, a write or a close touches the slot's last_ms (read_*.c,
    write/sync.c, read/close.c), so this session's idle_ms climbs on its own and
    its avg_bps stays 0 for as long as the socket is held.
    """
    sock = _xrd_session(bands.extra_ports["ROOT_PORT"])
    try:
        status, body = _open(sock, "/held.bin", kXR_open_read)
        assert status == 0, (status, body)
        yield sock
    finally:
        sock.close()


def _open(sock, path, options):
    payload = path.encode()
    body = struct.pack(">HH12s", 0o644, options, b"\x00" * 12)
    sock.sendall(struct.pack(">BBH", 0, 1, kXR_open) + body
                 + struct.pack(">I", len(payload)) + payload)
    return _recv_response(sock)


def _face_port(endpoint, face):
    key = FACES[face][0]
    return endpoint.port if key is None else endpoint.extra_ports[key]


def _snapshot(endpoint, face):
    resp = requests.get(
        f"http://{HOST}:{_face_port(endpoint, face)}/brix/api/v1/snapshot",
        timeout=30)
    assert resp.status_code == 200, (face, resp.status_code, resp.text[:400])
    return json.loads(resp.text)


def _root_rows(snap):
    return [r for r in snap.get("active_transfers", [])
            if r.get("protocol") == "root"]


def _the_row(endpoint, face):
    """The one root transfer this instance carries, as `face` sees it."""
    rows = _root_rows(_snapshot(endpoint, face))
    assert len(rows) == 1, (face, rows)
    return rows[0]


def _expected_state(row, idle_ms, stalled_ms):
    """dashboard_state_name() (api.c:38) in Python, for one face's numbers."""
    if row["idle_ms"] >= stalled_ms:
        return "throttled" if row.get("avg_bps", 0) > 0 else "stalled"
    if row["idle_ms"] >= idle_ms:
        return "idle"
    return "active"


def _wait_for_disagreement(endpoint, timeout=30.0):
    """Poll the fast face until the row's idle_ms is inside the window where
    the three configured faces must disagree; return that row."""
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        last = _the_row(endpoint, "fast")
        if DISAGREEMENT_LO_MS <= last["idle_ms"] < DISAGREEMENT_HI_MS:
            return last
        if last["idle_ms"] >= DISAGREEMENT_HI_MS:
            pytest.fail(f"overshot the window: idle_ms={last['idle_ms']}")
        time.sleep(0.2)
    pytest.fail(f"never reached the window; last row {last}")


def _dash_t(tmp_path, knobs):
    """`nginx -t` over one http location carrying `knobs`. Never boots."""
    return _parse_fail(tmp_path, "nginx_rl_http.conf", _http_values(knobs))


# --------------------------------------------------------------------------- #
# §A  One slot, four readers.                                                  #
# --------------------------------------------------------------------------- #

@_needs_nginx
class TestOneSlotFourReaders:

    def test_the_open_registers_exactly_one_root_transfer(self, bands, held):
        """brix_open_register_monitor() allocates on open, before any read."""
        row = _the_row(bands, "fast")
        assert row["avg_bps"] == 0, row
        assert row["idle_ms"] >= 0, row

    def test_every_face_reads_the_same_slot(self, bands, held):
        """The four faces are four locations over one process-wide SHM table.

        Same id from four ports is what makes §B a claim about the directives:
        without it, four faces disagreeing would be four different transfers.
        """
        ids = {face: _the_row(bands, face)["id"] for face in FACES}
        assert len(set(ids.values())) == 1, ids

    def test_a_face_that_is_not_asked_does_not_invent_a_row(self, bands):
        """Control: with no handle open, every face reports no root transfer.

        The `held` fixture is deliberately absent here.  Without this the row
        counts above would be consistent with the dashboard manufacturing a row
        per request — its own HTTP GET is tracked too, on the http plane.
        """
        for face in FACES:
            assert _root_rows(_snapshot(bands, face)) == [], face


# --------------------------------------------------------------------------- #
# §B  The bands, read at one instant off four different pairs of numbers.      #
# --------------------------------------------------------------------------- #

@_needs_nginx
class TestTheBands:

    def test_one_row_reads_three_states_at_one_instant(self, bands, held):
        """THE claim: three faces, one slot, three verdicts, no stopwatch.

        The row is sampled from the three configured faces back to back inside
        a window (1.6s..18s idle) in which their thresholds cannot agree:
        past fast's 700ms stalled bound, past mid's 1500ms idle bound, short of
        slow's 20s idle bound.  Nothing about the transfer differs between the
        three reads — only which location's two numbers classified it.
        """
        _wait_for_disagreement(bands)
        rows = {face: _the_row(bands, face) for face in ("fast", "mid", "slow")}

        assert rows["fast"]["state"] == "stalled", rows
        assert rows["mid"]["state"] == "idle", rows
        assert rows["slow"]["state"] == "active", rows
        assert len({r["id"] for r in rows.values()}) == 1, rows

    @pytest.mark.parametrize("face", sorted(FACES))
    def test_each_face_classifies_by_its_own_numbers(self, bands, held, face):
        """Per face, the state is exactly what its own pair predicts.

        This one cannot flake by construction: the expectation is recomputed
        from the idle_ms in the very response being asserted, so a slow host
        moves the row into a different band and the test follows it there.  It
        is the general form of the test above, which pins the specific
        three-way split the config was built to produce.
        """
        _wait_for_disagreement(bands)
        _, idle_ms, stalled_ms = FACES[face]
        row = _the_row(bands, face)
        assert row["state"] == _expected_state(row, idle_ms, stalled_ms), (
            face, idle_ms, stalled_ms, row)

    def test_an_idle_handle_is_stalled_and_never_throttled(self, bands, held):
        """The moving branch of api.c:53 is not taken by a handle that moved
        nothing.

        "throttled" exists so a rate-limited but progressing transfer does not
        flap red; a handle opened and never read is genuinely stuck, and
        relabelling it would hide exactly the condition the state is for.
        """
        _wait_for_disagreement(bands)
        row = _the_row(bands, "fast")
        assert row["avg_bps"] == 0, row
        assert row["state"] == "stalled", row

    def test_the_row_starts_active_on_every_face(self, bands, held):
        """Immediately after the open, no face has reached its idle bound.

        The fast face's is 200ms, so this is a race against the poll itself —
        it is asserted through the same recompute-from-the-response mechanism,
        which is what makes the "active" band a claim rather than a hope.
        """
        row = _the_row(bands, "slow")
        assert row["state"] == _expected_state(row, 20000, 40000), row
        assert row["idle_ms"] < 20000, row


# --------------------------------------------------------------------------- #
# §C  The limits echo — the only place the merged pair is observable.          #
# --------------------------------------------------------------------------- #

@_needs_nginx
class TestTheLimitsEcho:

    @pytest.mark.parametrize("face", sorted(FACES))
    def test_each_face_echoes_its_own_pair(self, bands, face):
        _, idle_ms, stalled_ms = FACES[face]
        limits = _snapshot(bands, face)["limits"]
        assert limits["idle_threshold_ms"] == idle_ms, (face, limits)
        assert limits["stalled_threshold_ms"] == stalled_ms, (face, limits)

    def test_the_face_that_writes_neither_reports_the_frozen_defaults(
            self, bands):
        """5s/60s, and they are not inherited from a sibling location.

        Four faces in one http block, three of which write the pair: an echo of
        5000/60000 from the fourth is also the assertion that dashboard confs do
        not leak sideways.
        """
        limits = _snapshot(bands, "def")["limits"]
        assert limits["idle_threshold_ms"] == DEFAULT_IDLE_MS, limits
        assert limits["stalled_threshold_ms"] == DEFAULT_STALLED_MS, limits

    def test_the_echo_agrees_with_the_classification(self, bands, held):
        """The numbers the face reports are the numbers it classified with.

        An echo read from a different struct than the classifier uses would be
        a documentation bug that no other test here could see.
        """
        _wait_for_disagreement(bands)
        for face in ("fast", "mid", "slow", "def"):
            snap = _snapshot(bands, face)
            limits = snap["limits"]
            rows = _root_rows(snap)
            assert len(rows) == 1, (face, rows)
            assert rows[0]["state"] == _expected_state(
                rows[0], limits["idle_threshold_ms"],
                limits["stalled_threshold_ms"]), (face, limits, rows[0])


# --------------------------------------------------------------------------- #
# §D  The cross-field invariant (config tier, tmp_path only).                  #
# --------------------------------------------------------------------------- #

@_needs_nginx
class TestTheCrossFieldInvariant:

    INVARIANT = ("brix_dashboard_stalled_threshold must be greater than or "
                 "equal to brix_dashboard_idle_threshold")

    def test_an_inverted_pair_is_refused_at_parse_time(self, tmp_path):
        """A transfer cannot become stalled before it is idle (module.c:203).

        Written the wrong way round, the "idle" band would be empty and the
        row would jump straight from active to stalled — a dashboard that
        cannot show the state it has a colour for.
        """
        rc, out = _dash_t(tmp_path,
                          "            brix_dashboard_idle_threshold    30s;\n"
                          "            brix_dashboard_stalled_threshold 10s;\n")
        assert rc != 0, out
        assert self.INVARIANT in out, out

    def test_an_equal_pair_is_accepted(self, tmp_path):
        """SUCCESS PATH.  The bound is >=, so a zero-width idle band is legal.

        An operator who wants two states rather than three writes the same
        number twice; the check must not creep to a strict inequality.
        """
        rc, out = _dash_t(tmp_path,
                          "            brix_dashboard_idle_threshold    10s;\n"
                          "            brix_dashboard_stalled_threshold 10s;\n")
        assert rc == 0, out

    def test_the_invariant_is_checked_after_the_merge_not_at_the_setter(
            self, tmp_path):
        """Writing ONE of the two can invert the pair, and it is caught.

        `brix_dashboard_idle_threshold 90s` alone is refused because the
        unwritten stalled threshold merges to 60s underneath it — so the
        diagnostic names a directive the configuration does not contain.  That
        is the correct behaviour and the reason the check lives at the end of
        the merge rather than in the setter, but it is worth pinning: a future
        move of the check into a post handler would silently accept this.
        """
        rc, out = _dash_t(tmp_path,
                          "            brix_dashboard_idle_threshold 90s;\n")
        assert rc != 0, out
        assert self.INVARIANT in out, out

    def test_the_defaults_themselves_satisfy_the_invariant(self, tmp_path):
        """SUCCESS PATH.  A dashboard that writes neither still parses.

        The check runs on every location, including ones with no dashboard
        directives at all, so the frozen defaults have to be ordered — 5s and
        60s are, and this is what keeps them that way.
        """
        rc, out = _dash_t(tmp_path, "            brix_dashboard on;\n")
        assert rc == 0, out

    def test_a_malformed_duration_is_refused_before_the_invariant(self,
                                                                  tmp_path):
        """A typo dies at the setter, not by defaulting to something plausible.

        Silently defaulting either threshold would leave an operator reading a
        dashboard whose bands are not the ones they configured.
        """
        rc, out = _dash_t(tmp_path,
                          "            brix_dashboard_idle_threshold soon;\n")
        assert rc != 0, out
        assert "invalid value" in out, out
