"""
test_audit15j_cms_server_uto.py — the audit's LAST residual, closed.

`docs/refactor/testsuite-combinatorial-coverage-audit-2026-08-15.md` finished
tranche 9 with exactly one directive still carrying a caveat instead of a
behavioural test: `brix_cms_server_tcp_user_timeout`.  Tranche 9 had closed its
client-leg sibling by noticing that TCP_USER_TIMEOUT bounds a SYN sequence, so a
black-holed *connect* is reproducible from userspace — and re-deferred this one
with the sharper reason that the accept leg guards an already-ESTABLISHED
session, which needs "a peer whose kernel has stopped answering, and no local
userspace peer can be made to stop answering (a closed socket RSTs; a SIGSTOPped
process still ACKs from kernel context)".

Every sentence of that is true and the conclusion still does not follow.  The
peer's kernel is silenced from *outside* the peer: one `nft` DROP rule for
everything addressed to the node's socket, and its kernel never sees — so never
ACKs — a byte the manager sends.  `CAP_NET_ADMIN` inside an unprivileged network
namespace installs that rule, the same lever `_perf_netem_helpers` already uses
to synthesize a BDP link with no root.  Harness and its reasoning:
`_test_audit15j_netns_uto_helpers`.

What the accept leg actually does (`server_handler.c:338-343`): right after
accept it calls `brix_apply_tcp_deadpeer_opts(c->fd, tcp_keepalive,
tcp_user_timeout)` — "OS-level dead-peer reaping on the accepted socket, so a
silently-dropped data node is torn down by the kernel".

Isolating it from its userspace twin is the whole design of the matrix.  The
post-login idle watchdog reaps the SAME peer, and its source comment
(`server_recv_frame.c:217-222`) says so outright: it closes a node that has gone
silent for `idle_timeout_ms`, "reaps a black-holed node the ping send cannot
detect".  So every arm pins `brix_cms_server_idle_timeout 600s`, far outside the
observation window, and `brix_cms_server_interval 1` keeps a ping in flight each
second.  Inside the window the kernel is the only thing that can end the
session — the same isolation the client-leg tests get from holding
`brix_cms_send_timeout` at 30 s.

Four arms, one namespace:

  kernel   knob 2s  + DROP  -> the session is torn down (this is the feature)
  control  no knob  + DROP  -> the session survives (proves the knob is the cause)
  healthy  knob 2s  + no DROP -> the session survives (a reaper that reaps healthy
                                peers is a self-inflicted outage, not a feature)
  bareint  knob 2000 + DROP -> the session survives, because a bare int in an
                                msec slot is SECONDS, not milliseconds

That last arm is the operator foot-gun made explicit: `server.h:101` documents
the field as "ms", but `ngx_conf_set_msec_slot` reads a bare `2000` as 2000
*seconds*.  An operator who writes the number the header implies gets a knob
that will not fire this side of half an hour.
"""

import os

import pytest

from _test_phase25_ratelimit_helpers import (
    _parse_fail,
    _http_values,
    _stream_values,
)
from settings import NGINX_BIN

import _test_audit15j_netns_uto_helpers as uto

pytestmark = [
    pytest.mark.netfault,
    pytest.mark.serial,
    pytest.mark.xdist_group("lc-audit15j-uto"),
    pytest.mark.timeout(420),
]

_needs_nginx = pytest.mark.skipif(
    not os.access(NGINX_BIN, os.X_OK), reason=f"nginx not executable: {NGINX_BIN}")

# The arms are defined once and shared: one namespace, one podman launch, four
# managers.  Watch windows are the smallest that separate the claims — the knob
# fires at ~2s (measured 3.4s including the ping cadence), so 15s is ample for
# the positive arm and 8-12s is a real absence for the negative ones.
ARMS = [
    {"name": "kernel", "uto": "2s", "drop": True, "watch_s": 15.0},
    {"name": "control", "uto": None, "drop": True, "watch_s": 12.0},
    {"name": "healthy", "uto": "2s", "drop": False, "watch_s": 8.0},
    {"name": "bareint", "uto": "2000", "drop": True, "watch_s": 8.0},
]


# --------------------------------------------------------------------------- #
# Unit tier — no namespace, no nginx.  Guards the harness's own contract.      #
# --------------------------------------------------------------------------- #

def test_the_availability_probe_returns_a_reason_either_way():
    ok, reason = uto.netns_uto_available()
    assert isinstance(ok, bool)
    assert isinstance(reason, str) and reason, (
        "an unavailable harness must say why, or the gate skips silently")


def test_the_launcher_keeps_the_podman_uid_map():
    # brix force-drops a root-capable worker to nobody; a bare `unshare -Ur`
    # maps one uid, that setuid fails, and the worker exits fatal.  A silent
    # change to bare unshare would turn this gate into a permanent skip.
    assert uto._NS_LAUNCH[:3] == ["podman", "unshare", "unshare"]
    assert "-n" in uto._NS_LAUNCH


def test_every_arm_pins_the_userspace_competitor_outside_the_window(tmp_path):
    # The isolation contract: if the idle watchdog could fire inside an arm's
    # watch window, a teardown would no longer prove the kernel did it.
    conf = uto.write_conf(str(tmp_path), "iso", 41200, str(tmp_path), "2s")
    body = open(conf).read()
    assert "brix_cms_server_idle_timeout 600s;" in body
    assert "brix_cms_server_interval 1;" in body
    assert max(a["watch_s"] for a in ARMS) < 600, (
        "an arm watches longer than the idle watchdog it is isolated from")


def test_the_control_arm_config_carries_no_knob_at_all(tmp_path):
    with_knob = open(uto.write_conf(str(tmp_path), "a", 41200, str(tmp_path),
                                    "2s")).read()
    without = open(uto.write_conf(str(tmp_path), "b", 41201, str(tmp_path),
                                  None)).read()
    assert "brix_cms_server_tcp_user_timeout 2s;" in with_knob
    assert "brix_cms_server_tcp_user_timeout" not in without, (
        "the control must differ from the kernel arm in the knob and nothing "
        "else, or a survival result proves nothing")


# --------------------------------------------------------------------------- #
# Parse tier — grammar and plane, no namespace needed.                        #
# --------------------------------------------------------------------------- #

def _prefix(path):
    path.mkdir(parents=True, exist_ok=True)
    return path


def _stream_t(tmp_path, knobs):
    return _parse_fail(_prefix(tmp_path), "nginx_rl_stream.conf",
                       _stream_values(knobs, ""))


def _http_t(tmp_path, knobs):
    return _parse_fail(_prefix(tmp_path), "nginx_rl_http.conf",
                       _http_values(knobs, "", ""))


@_needs_nginx
def test_the_knob_parses_on_the_stream_plane(tmp_path):
    rc, out = _stream_t(tmp_path / "ok",
                        "brix_cms_server_tcp_user_timeout 2s;")
    assert rc == 0, f"stream-plane control failed to parse:\n{out}"


@_needs_nginx
def test_the_knob_is_refused_on_the_http_plane(tmp_path):
    rc, out = _http_t(tmp_path / "http",
                      "brix_cms_server_tcp_user_timeout 2s;")
    assert rc != 0 and "directive is not allowed here" in out, (
        "the accept leg is stream-only (server_module.c:298, "
        f"NGX_STREAM_SRV_CONF); http must refuse it:\n{out}")


@_needs_nginx
@pytest.mark.parametrize("knobs,diag", [
    ("brix_cms_server_tcp_user_timeout;", "invalid number of arguments"),
    ("brix_cms_server_tcp_user_timeout 2s 3s;", "invalid number of arguments"),
    ("brix_cms_server_tcp_user_timeout banana;", "invalid value"),
    ("brix_cms_server_tcp_user_timeout 2s;\n"
     "        brix_cms_server_tcp_user_timeout 3s;", "directive is duplicate"),
])
def test_the_knob_refuses_malformed_grammar(tmp_path, knobs, diag):
    rc, out = _stream_t(tmp_path / "bad", knobs)
    assert rc != 0 and diag in out, (
        f"expected {diag!r} for {knobs!r}, got rc={rc}:\n{out}")


# --------------------------------------------------------------------------- #
# Namespace tier — the residual itself.                                        #
# --------------------------------------------------------------------------- #

@pytest.fixture(scope="module")
def matrix(tmp_path_factory):
    """Run all four arms in ONE private namespace and share the result.

    Module-scoped because the cost is a podman launch plus four nginx boots and
    ~45s of deliberate waiting; each test below reads one arm out of it.
    """
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx not executable: {NGINX_BIN}")
    # The worker drops to nobody and must traverse every ancestor of its
    # export, so the whole run lives under /tmp rather than under a 0700
    # basetemp chain (see the harness docstring).
    import tempfile
    with tempfile.TemporaryDirectory(prefix="uto-netns-", dir="/tmp") as wd:
        res = uto.run_uto_matrix(NGINX_BIN, wd, ARMS)
    if not res.get("available"):
        pytest.skip(f"netns UTO harness unavailable: {res.get('reason')}")
    return res["arms"]


def _arm(matrix, name):
    arm = matrix[name]
    assert arm["registered"], (
        f"the {name} arm's node never reached the logged-in state, so the ping "
        f"timer never armed and the arm proves nothing:\n{arm['log_tail']}")
    return arm


def test_the_kernel_user_timeout_reaps_a_silenced_node(matrix):
    """The feature: a node whose kernel has stopped answering is torn down."""
    arm = _arm(matrix, "kernel")
    assert arm["torn_down_after"] is not None, (
        "brix_cms_server_tcp_user_timeout 2s did not end a session whose peer "
        f"stopped acknowledging for {arm['watch_s']}s — the accepted socket "
        f"never got the option (server_handler.c:342):\n{arm['log_tail']}")
    assert arm["torn_down_after"] < arm["watch_s"]


def test_the_teardown_is_the_kernels_and_not_a_userspace_deadline(matrix):
    """errno 110 on the accepted socket is the kernel's signature; a userspace
    deadline would have logged a timeout, not ETIMEDOUT from recv()."""
    arm = _arm(matrix, "kernel")
    assert arm["etimedout"], (
        "the session ended without 'Connection timed out' on the socket, so "
        "something other than TCP_USER_TIMEOUT closed it — the arm no longer "
        f"isolates the knob:\n{arm['log_tail']}")
    assert "disconnected (blacklisted" in arm["log_tail"], (
        "the reaped node was never unregistered, so locate queries would keep "
        f"routing clients at a dead server:\n{arm['log_tail']}")


def test_without_the_knob_the_same_silenced_node_survives(matrix):
    """The control: identical topology, identical black hole, no knob."""
    arm = _arm(matrix, "control")
    assert arm["torn_down_after"] is None, (
        "a session with NO tcp_user_timeout was still torn down within "
        f"{arm['watch_s']}s of the black hole — something else reaps it and "
        f"the positive arm does not isolate the knob:\n{arm['log_tail']}")


def test_the_knob_does_not_reap_a_healthy_node(matrix):
    """Security-negative: a dead-peer reaper that fires on a LIVE peer is a
    self-inflicted outage — it would evict good nodes from the cluster."""
    arm = _arm(matrix, "healthy")
    assert arm["torn_down_after"] is None, (
        "brix_cms_server_tcp_user_timeout 2s tore down a node that was "
        "answering normally; the accept leg would evict healthy servers "
        f"every 2s:\n{arm['log_tail']}")


def test_a_bare_integer_is_seconds_not_milliseconds(matrix):
    """server.h:101 documents the field as ms; the config slot reads a bare int
    as SECONDS.  `2000` is half an hour, not two seconds."""
    arm = _arm(matrix, "bareint")
    assert arm["torn_down_after"] is None, (
        "`brix_cms_server_tcp_user_timeout 2000` reaped a black-holed node "
        f"within {arm['watch_s']}s, so the bare int was read as milliseconds "
        "after all — the unit changed and every documented example that omits "
        f"a suffix now means something else:\n{arm['log_tail']}")
