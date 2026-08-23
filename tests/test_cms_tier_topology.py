"""
CMS multi-tier topology suite — assert a whole cmsd cluster wires itself up in
the correct shape and that the logs prove it.

This mirrors the "Live 4-tier cluster on xrd1":

    mgr (manager)
      └─ sub1 (sub-manager)                -> mgr
           ├─ leafA (client / data leaf)   -> sub1
           ├─ leafB (client / data leaf)   -> sub1
           └─ sub2 (sub-manager)           -> sub1
                └─ leafC (client)          -> sub2

The whole tree is stood up as ONE brix nginx master hosting all six nodes as
separate stream server blocks on 127.0.0.1 (each a distinct cmsd node identity
via ``brix_listen_port``); they connect to each other purely over the CMS wire
protocol on loopback.  No certificates or data backends are needed:

  * managers / sub-managers use ``brix_cms_server on`` (the block's handler),
  * leaf clients get a trivial ``return "";`` stream handler and only register
    upward via ``brix_cms_manager`` — role auto-derives to ``client``.

The assertions read exclusively from the error log the auto-role feature emits:

  * ``brix: cmsd role: this node is a {manager|sub-manager|client} ...``
      one proof line per node (worker-0 only).
  * ``brix: cmsd-action op=register peer=<child> dir=in ... server: <parent>``
      the parent side of every tree edge (who registered into whom).
  * ``brix: cmsd-action op=login peer=<parent> dir=out ... detail=...``
      the child side of every edge (who each node registers UP to, and whether
      brix treated it as a sub-manager (Manager bit) or a leaf/client).

So the test verifies (a) every node derived the RIGHT role, (b) every edge of
the tree is present and points the RIGHT way, (c) the single-connection gate
holds (all control-plane actions come from one worker even with N workers), and
(d) the cluster settles with no collisions/retries.

Run:
    PYTHONPATH=tests pytest tests/test_cms_tier_topology.py -v

The whole tree is one registry instance (``lc-cms-tier``) rendered from the
committed ``configs/nginx_cms_tier.conf`` template: the primary listen is the
root manager and the other five listens come from that ledger entry's ``extra``
ports.  The nginx under test must carry the CMS auto-role feature — a binary
that parses the directives but predates the feature emits no 'cmsd role:' line
at all, so the fixture skips (rather than fails) when the settle window closes
with zero role lines.
"""

import re
import time
from pathlib import Path

import pytest

from server_launcher import LifecycleHarness
from server_registry import NginxInstanceSpec

# Fixture setup launches nginx + polls for cluster settle; that easily exceeds
# the repo-default 30s per-test timeout (which is charged to the first test that
# triggers the module-scoped fixture).  Give the whole module generous headroom.
pytestmark = [pytest.mark.timeout(120),
              pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-cms-tier")]

from settings import HOST

# --------------------------------------------------------------------------- #
# Topology declaration — the single source of truth for the expected tree, and
# the contract with configs/nginx_cms_tier.conf: `port_key` names the template
# placeholder each node listens on (None = the instance's primary port, i.e. the
# root manager).  `upstream` names another node (its cmsd parent) or None.
# --------------------------------------------------------------------------- #
NODES = [
    {"name": "mgr",   "role": "manager",     "upstream": None,   "port_key": None},
    {"name": "sub1",  "role": "sub-manager", "upstream": "mgr",  "port_key": "PORT_SUB1"},
    {"name": "leafA", "role": "client",      "upstream": "sub1", "port_key": "PORT_LEAFA"},
    {"name": "leafB", "role": "client",      "upstream": "sub1", "port_key": "PORT_LEAFB"},
    {"name": "sub2",  "role": "sub-manager", "upstream": "sub1", "port_key": "PORT_SUB2"},
    {"name": "leafC", "role": "client",      "upstream": "sub2", "port_key": "PORT_LEAFC"},
]



# --------------------------------------------------------------------------- #
# Log parsing
# --------------------------------------------------------------------------- #
_ROLE_RE = re.compile(
    r"cmsd role: this node is a (?P<role>manager|sub-manager|client) "
    r"\(listen :(?P<port>\d+), upstream_manager=(?P<up>\S+)"
    r"(?: \(\+\d+ more\))?,"     # multi-manager suffix: "(+N more)"
)
_REGISTER_RE = re.compile(
    r"cmsd-action op=register peer=(?P<peer>[\d.]+:\d+) dir=in\b"
    r".*?server: (?P<server>[\d.]+:\d+)"
)
_LOGIN_RE = re.compile(
    r"cmsd-action op=login peer=(?P<peer>[\d.]+:\d+) dir=out\b"
    r".*?detail=(?P<detail>.+?)(?:, client:|$)"
)
_PID_RE = re.compile(r"\[notice\] (\d+)#(\d+):.*cmsd-action")
_OUT_PID_RE = re.compile(r"\[notice\] (\d+)#(\d+):.*cmsd-action op=\S+ .*dir=out")
_LOGIN_OUT_RE = re.compile(r"cmsd-action op=login peer=[\d.]+:\d+ dir=out")


def _parse(text):
    roles = {}                       # port -> (role, upstream_str)
    edges_in = set()                 # (child_port, parent_port) from register
    logins = set()                   # (parent_port, detail) from op=login dir=out
    action_pids = set()              # worker PIDs of ALL cmsd-action lines
    out_pids = set()                 # worker PIDs of dir=out (outbound) actions
    login_out = 0                    # count of op=login dir=out lines
    for line in text.splitlines():
        _parse_role(line, roles)
        _parse_register(line, edges_in)
        _parse_login(line, logins)
        _parse_pid(line, _PID_RE, action_pids)
        _parse_pid(line, _OUT_PID_RE, out_pids)
        login_out += int(bool(_LOGIN_OUT_RE.search(line)))
    return roles, edges_in, logins, action_pids, out_pids, login_out


def _parse_role(line, roles):
    match = _ROLE_RE.search(line)
    if match:
        roles[int(match["port"])] = (match["role"], match["up"])


def _parse_register(line, edges):
    match = _REGISTER_RE.search(line)
    if match:
        child = int(match["peer"].split(":")[1])
        parent = int(match["server"].split(":")[1])
        edges.add((child, parent))


def _parse_login(line, logins):
    match = _LOGIN_RE.search(line)
    if match:
        parent = int(match["peer"].split(":")[1])
        logins.add((parent, match["detail"].strip()))


def _parse_pid(line, pattern, pids):
    match = pattern.search(line)
    if match:
        pids.add(match.group(1))


# --------------------------------------------------------------------------- #
# Fixture: bring the whole tree up once, wait for it to settle, tear down.
# --------------------------------------------------------------------------- #
@pytest.fixture(scope="module")
def tier():
    harness = LifecycleHarness()
    try:
        yield from _tier(harness)
    finally:
        harness.close()


def _tier(harness):
    endpoint = harness.start(NginxInstanceSpec(
        name="lc-cms-tier",
        template="nginx_cms_tier.conf",
        protocol="root",
        reason="CMS 4-tier cluster: role derivation + tree edges from the log.",
    ))
    # The template's listens ARE the topology: the primary port is the root
    # manager, the rest come from the ledger entry's extra ports by node key.
    nodes_by_name = _resolved_nodes(endpoint)
    workdir = Path(endpoint.prefix) / "logs"
    logpath = workdir / "error.log"
    _wait_for_tier(logpath, len(NODES), _edge_count())
    text = logpath.read_text(errors="replace")
    parsed = _parse(text)
    # Zero role lines after a full settle window means this binary parses the
    # CMS directives but predates the auto-role feature (nothing to assert
    # against) — the old in-module probe launch expressed the same skip.
    if not parsed[0]:
        pytest.skip("nginx under test emits no 'cmsd role:' line — build one "
                    "with the CMS auto-role feature (see module docstring)")
    yield {
        "nodes": nodes_by_name,
        "log": text,
        "parsed": parsed,
        "workdir": workdir,
    }


def _resolved_nodes(endpoint):
    return {node["name"]: {**node, "port": _node_port(endpoint, node)}
            for node in NODES}


def _node_port(endpoint, node):
    if node["port_key"] is None:
        return endpoint.port
    return int(endpoint.extra_ports[node["port_key"]])


def _edge_count():
    return sum(map(lambda node: node["upstream"] is not None, NODES))


def _wait_for_tier(logpath, expected_roles, expected_edges):
    deadline = time.time() + 25
    while time.time() < deadline:
        parsed = _parse(_read_optional(logpath))
        if _tier_settled(parsed, expected_roles, expected_edges):
            return
        time.sleep(0.5)


def _read_optional(logpath):
    if logpath.exists():
        return logpath.read_text(errors="replace")
    return ""


def _tier_settled(parsed, expected_roles, expected_edges):
    return len(parsed[0]) >= expected_roles and len(parsed[1]) >= expected_edges


# --------------------------------------------------------------------------- #
# Tests
# --------------------------------------------------------------------------- #
def test_every_node_derived_its_expected_role(tier):
    """Each node logs exactly the role the topology says it should have."""
    roles = tier["parsed"][0]
    nodes = tier["nodes"]
    problems = []
    for node in NODES:
        port = nodes[node["name"]]["port"]
        got = roles.get(port)
        if got is None:
            problems.append(f"{node['name']} (:{port}) — no 'cmsd role:' line")
        elif got[0] != node["role"]:
            problems.append(
                f"{node['name']} (:{port}) — role {got[0]!r}, expected "
                f"{node['role']!r}")
    assert not problems, "role derivation mismatches:\n  " + "\n  ".join(problems)


def test_role_upstream_field_matches_topology(tier):
    """The role line's upstream_manager= names the correct parent (or none)."""
    roles = tier["parsed"][0]
    nodes = tier["nodes"]
    problems = []
    for node in NODES:
        port = nodes[node["name"]]["port"]
        _role, up = roles.get(port, (None, None))
        if node["upstream"] is None:
            expect = "none"
        else:
            expect = f"{HOST}:{nodes[node['upstream']]['port']}"
        if up != expect:
            problems.append(
                f"{node['name']} (:{port}) — upstream_manager={up!r}, "
                f"expected {expect!r}")
    assert not problems, "upstream mismatches:\n  " + "\n  ".join(problems)


def test_every_tree_edge_registered_into_correct_parent(tier):
    """For each child->parent edge, the PARENT logged an op=register for it."""
    edges_in = tier["parsed"][1]
    nodes = tier["nodes"]
    missing = []
    for node in NODES:
        if node["upstream"] is None:
            continue
        child = nodes[node["name"]]["port"]
        parent = nodes[node["upstream"]]["port"]
        if (child, parent) not in edges_in:
            missing.append(
                f"{node['name']} (:{child}) -> {node['upstream']} (:{parent})")
    assert not missing, (
        "tree edges the parent never logged as registered:\n  "
        + "\n  ".join(missing)
        + f"\n\nobserved register edges (child->parent): {sorted(edges_in)}")


def test_no_unexpected_registration_edges(tier):
    """The parent side registered ONLY the edges the topology declares."""
    edges_in = tier["parsed"][1]
    nodes = tier["nodes"]
    expected = set()
    for node in NODES:
        if node["upstream"] is not None:
            expected.add((nodes[node["name"]]["port"],
                          nodes[node["upstream"]]["port"]))
    unexpected = edges_in - expected
    assert not unexpected, (
        f"unexpected register edges (child->parent ports): {sorted(unexpected)}")


def test_each_child_logs_upward_login_with_correct_role_detail(tier):
    """Every non-root node logged op=login dir=out to its parent, and the detail
    marks it a sub-manager (Manager bit) vs a leaf/client.

    A login line names the PARENT dialed, not the child, so children that share
    a parent collapse to one (parent, detail) pair.  We therefore assert, for
    each parent, that a login line carrying the RIGHT self-classification exists
    for every distinct child role beneath it.  (Which specific child made each
    edge is pinned separately by the register lines.)"""
    logins = tier["parsed"][2]
    nodes = tier["nodes"]
    substr = {"sub-manager": "sub-manager", "client": "leaf/client"}
    problems = []
    for node in NODES:
        if node["upstream"] is None:
            continue
        parent = nodes[node["upstream"]]["port"]
        want = substr[node["role"]]
        if not any(pp == parent and want in detail for pp, detail in logins):
            problems.append(
                f"{node['name']} ({node['role']}) — no op=login dir=out to "
                f"parent :{parent} carrying {want!r}")
    assert not problems, (
        "upward-login problems:\n  " + "\n  ".join(problems)
        + f"\n\nobserved (parent_port, detail) logins: {sorted(logins)}")


def test_upstream_client_is_gated_to_a_single_worker(tier):
    """The worker-0 single-connection gate: every OUTBOUND cms-action (the
    upstream login/load) comes from one worker PID, and each node opens exactly
    ONE upstream login — not one per worker — even with multiple workers.

    (Inbound 'dir=in' registrations are handled by whichever worker accept()s
    the connection, so those legitimately spread across workers; only the
    outbound client side is gated.)"""
    _roles, _edges, _logins, action_pids, out_pids, login_out = tier["parsed"]
    assert action_pids, "no cmsd-action lines were logged at all"
    assert out_pids, "no outbound (dir=out) cms-action lines were logged"
    assert len(out_pids) == 1, (
        f"outbound cms-action lines came from {len(out_pids)} worker PIDs "
        f"{sorted(out_pids)} — the upstream CMS client is not gated to one worker")

    expected_logins = sum(1 for n in NODES if n["upstream"] is not None)  # 5
    assert login_out == expected_logins, (
        f"expected exactly {expected_logins} upstream logins (one per non-root "
        f"node), saw {login_out} — without the worker gate each of N workers "
        "would open its own upstream connection")


def test_cluster_settles_without_collisions_or_retries(tier):
    """A correctly-wired single-connection tree settles cleanly: no duplicate
    logins, no unreachable-manager retries, no heartbeat failures."""
    log = tier["log"]
    bad_markers = [
        "already logged in",
        "cannot reach cluster manager",
        "CMS load heartbeat failed",
        "CMS write handler: send_load failed",
    ]
    hits = [m for m in bad_markers if m in log]
    assert not hits, f"instability markers found in the log: {hits}"
