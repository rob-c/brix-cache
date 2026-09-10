"""
tests/test_phase115_cms_admin_socket.py — Phase-115 W8.3: `brix_cms_admin_socket`,
and the transport extraction that made it a verb table rather than a program.

WHAT W8.3 CHANGED
-----------------
§1.16 shipped one unix control socket (`brix_admin_socket`) whose accept loop,
newline framing, oversized-line refusal, `NGX_AGAIN`-safe reply flush and
per-worker path lived inside the file that also implemented the root:// session
verbs.  A cluster-plane socket was the second caller, so the transport moved out
to `src/net/admin/admin_unix.{c,h}` and both planes now contribute nothing but a
`brix_admin_verb_t[]`:

    root  (protocols/root/session/admin_socket.c) list disc msg pause cont abort
    cms   (net/cms/cms_admin.c)                   nodes drain undrain forget reset

WHY THE CLUSTER PLANE EXISTS
----------------------------
The registry helpers already backed the HTTP admin API
(`observability/dashboard/api_admin_cluster.c`).  What was missing was a way to
reach them WITHOUT the HTTP dashboard — a manager that runs no dashboard, or an
operator on the box during an incident when the HTTP plane is exactly what is
unwell, had no cluster control at all.

WHAT THIS FILE PINS, AND WHY EACH ARM IS NOT OPTIONAL
-----------------------------------------------------
success   — `nodes` lists a live two-node registry with the snapshot's own field
            names; drain/undrain move ONE node's state and leave the other alone.
error     — every refusal wording, including the two that a typo produces
            (`err bad-target`, `err bad-seconds`), because a verb that answered
            `ok` to a malformed target would report success for a node the
            operator never named.
security  — three properties the transport cannot check for itself, since it
            only ever sees the table it was handed:
              * no verb is reachable by a prefix or a short spelling;
              * the two verb tables are DISJOINT — a root verb on the cms socket
                and a cms verb on the root socket are both unknown commands;
              * the registry is byte-identical after every refused command.
            Plus the privilege boundary itself: mode 0600, which is the whole
            authorization model.

Two design choices get their own tests because each could reasonably have gone
the other way, and a future reader will otherwise "fix" them:
  * `forget` of an absent node answers `ok`, not `err not-found` — absent IS
    the state forget asks for, so it is idempotent (contrast `undrain`, where
    not-drained genuinely means the operator's premise was wrong).
  * a drain SURVIVES the heartbeat that follows it — `brix_srv_update_load()`
    refreshes an entry but never re-creates or un-drains one; only a fresh
    kYR_login clears a blacklist.

THE REGISTRY IS POPULATED THE ONLY WAY IT CAN BE
------------------------------------------------
By real CMS logins.  Two Python FakeNodes (_test_cms_parity_wave_helpers) log in
to the manager's CMS face; their advertised dPorts are ladder-owned
(NODE_A_PORT / NODE_B_PORT on `lc-p115-cmsadm-mgr`) so the `drain <host> <port>`
operands cannot name another lane's real listener.  Seeding the SHM table from
outside would test the socket against a fiction.

Run:
    TEST_SKIP_SERVER_SETUP=1 PYTHONPATH=tests pytest \
        tests/test_phase115_cms_admin_socket.py -v
"""

import os
import socket
import stat
import time
from pathlib import Path

import pytest

from _test_cms_parity_wave_helpers import FakeNode, _xrd_session
from fleet_lifecycle_ports import lifecycle_ports_for
from server_registry import NginxInstanceSpec
from settings import BIND_HOST

pytestmark = [pytest.mark.uses_lifecycle_harness,
              pytest.mark.timeout(90),
              pytest.mark.xdist_group("lc-p115-cmsadm")]

MGR = "lc-p115-cmsadm-mgr"

#: The registry stores the CMS connection's peer IP as text, so every target
#: operand is this literal — not SERVER_HOST, which may be a name.
NODE_HOST = "127.0.0.1"  # net-literal-allow: the registry key is the conn's IP

ROOT_VERBS = ("list", "disc", "msg", "pause", "cont", "abort")
CMS_VERBS = ("nodes", "drain", "undrain", "forget", "reset")

UNKNOWN = "err unknown-command\n"


# --------------------------------------------------------------------------- #
# Talking to an admin socket                                                   #
# --------------------------------------------------------------------------- #

def _body_lines(first):
    """How many body lines follow `first`.

    The grammar is either one line, or `ok <n>` and exactly n lines.  Framing
    the read this way — rather than reading until a timeout — is what makes a
    MISSING body a failure instead of a slow pass.
    """
    parts = first.split()
    if len(parts) != 2 or parts[0] != "ok":
        return 0
    return int(parts[1]) if parts[1].isdigit() else 0


class Admin:
    """One connection to an admin socket; the transport keeps it open across
    commands, and several tests depend on that (a refusal must not close it)."""

    def __init__(self, path, timeout=5):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(timeout)
        self.sock.connect(str(path))
        self.rf = self.sock.makefile("rb")

    def cmd(self, text):
        """Send one command; return the complete reply ("" when the server
        closed the connection instead of answering)."""
        self.sock.sendall(text.encode() + b"\n")
        first = self.rf.readline().decode("latin-1")
        if not first:
            return ""
        rest = [self.rf.readline().decode("latin-1")
                for _ in range(_body_lines(first))]
        return first + "".join(rest)

    def close(self):
        for f in (self.rf, self.sock):
            try:
                f.close()
            except OSError:
                pass


def _one_shot(path, payload):
    """Send raw bytes on a fresh connection; return whatever came back before
    the peer went away.

    Used for the oversized line, which is refused BY CLOSING.  The close is
    seen as a RESET rather than an orderly EOF whenever the refused bytes are
    still sitting unread in the server's receive buffer — which is exactly the
    case here — so both endings count as "went away".  What the test cares
    about is that nothing was ANSWERED, and that is the return value either
    way."""
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(5)
    try:
        sock.connect(str(path))
        sock.sendall(payload)
        out = b""
        while True:
            try:
                chunk = sock.recv(4096)
            except (socket.timeout, ConnectionResetError):
                break
            if not chunk:
                break
            out += chunk
        return out.decode("latin-1")
    finally:
        sock.close()


def _nodes(admin):
    """`nodes` -> {(host, port): {field: value}}, with the count checked."""
    reply = admin.cmd("nodes")
    head, *lines = reply.splitlines()
    assert head.startswith("ok "), f"nodes did not answer ok: {reply!r}"
    assert len(lines) == int(head.split()[1]), \
        f"header count disagrees with body: {reply!r}"
    out = {}
    for line in lines:
        target, *fields = line.split()
        host, _, port = target.rpartition(":")
        out[(host, int(port))] = dict(f.split("=", 1) for f in fields)
    return out


# --------------------------------------------------------------------------- #
# The lab                                                                      #
# --------------------------------------------------------------------------- #

class Lab:
    """A manager carrying both admin sockets, with two nodes registered."""

    def __init__(self, prefix, root_port, extra):
        self.root_sock = Path(prefix) / "tmp" / "root.sock"
        self.cms_sock = Path(prefix) / "tmp" / "cms.sock"
        self.root_port = root_port
        self.a = (NODE_HOST, extra["NODE_A_PORT"])
        self.b = (NODE_HOST, extra["NODE_B_PORT"])

    def admin(self, which="cms"):
        return Admin(self.cms_sock if which == "cms" else self.root_sock)

    @staticmethod
    def target(node):
        return f"{node[0]} {node[1]}"


def _await_paths(paths, deadline_s=8):
    deadline = time.time() + deadline_s
    while time.time() < deadline:
        if all(os.path.exists(p) for p in paths):
            return
        time.sleep(0.05)
    raise AssertionError(f"admin sockets never appeared: {paths}")


def _await_registered(lab, want, deadline_s=10):
    """Wait until both nodes' logins have reached the SHM registry."""
    deadline = time.time() + deadline_s
    seen = {}
    while time.time() < deadline:
        admin = lab.admin()
        try:
            seen = _nodes(admin)
        finally:
            admin.close()
        if all(t in seen for t in want):
            return seen
        time.sleep(0.2)
    raise AssertionError(f"nodes never registered: want {want}, saw {seen}")


@pytest.fixture()
def lab(lifecycle):
    """The two-faced manager plus two logged-in CMS nodes."""
    _port, extra = lifecycle_ports_for(MGR)
    cms_port = extra["CMS_PORT"]
    endpoint = lifecycle.start(NginxInstanceSpec(
        name=MGR,
        template="nginx_p115_cms_admin_mgr.conf",
        protocol="root",
        readiness="tcp",
        template_values={},
        reason="phase-115 W8.3 CMS admin socket over a live node registry"))

    nodes = [FakeNode(cms_port, extra["NODE_A_PORT"]),
             FakeNode(cms_port, extra["NODE_B_PORT"])]
    built = Lab(endpoint.prefix, endpoint.port, extra)
    try:
        _await_paths([built.root_sock, built.cms_sock])
        _await_registered(built, [built.a, built.b])
        yield built
    finally:
        for n in nodes:
            n.close()


# --------------------------------------------------------------------------- #
# success                                                                      #
# --------------------------------------------------------------------------- #

def test_nodes_lists_the_live_registry_with_the_snapshot_field_names(lab):
    """`nodes` reports both registered nodes, and the field NAMES are the
    snapshot struct's own — the wire and brix_srv_snapshot_entry_t cannot drift
    apart without this failing."""
    admin = lab.admin()
    try:
        listing = _nodes(admin)
    finally:
        admin.close()

    assert lab.a in listing and lab.b in listing, listing
    for target in (lab.a, lab.b):
        fields = listing[target]
        assert set(fields) == {"role", "free_mb", "util_pct", "state"}, fields
        assert fields["state"] == "up", fields
        assert fields["free_mb"].isdigit() and fields["util_pct"].isdigit()
        assert fields["role"], "role rendered empty rather than the '-' fallback"


def test_drain_moves_one_node_and_undrain_puts_it_back(lab):
    """The state an operator actually drives during an incident — and the
    property they rely on: draining A must not touch B."""
    admin = lab.admin()
    try:
        assert admin.cmd(f"drain {lab.target(lab.a)}") == "ok\n"
        listing = _nodes(admin)
        assert listing[lab.a]["state"] == "drained", listing
        assert listing[lab.b]["state"] == "up", listing

        assert admin.cmd(f"undrain {lab.target(lab.a)}") == "ok\n"
        listing = _nodes(admin)
        assert listing[lab.a]["state"] == "up", listing
        assert listing[lab.b]["state"] == "up", listing
    finally:
        admin.close()


def test_drain_survives_the_heartbeat_that_follows_it(lab):
    """DESIGN CHOICE: brix_srv_update_load() refreshes an entry but never
    re-creates or un-drains one, so only a fresh kYR_login clears a blacklist.
    A drain that a 1-second heartbeat silently lifted would be worse than no
    drain at all — the operator would believe the node was out of service."""
    admin = lab.admin()
    try:
        assert admin.cmd(f"drain {lab.target(lab.a)} 120") == "ok\n"
        time.sleep(2.5)          # brix_cms_server_interval 1 -> several beats
        listing = _nodes(admin)
        assert listing[lab.a]["state"] == "drained", listing
    finally:
        admin.close()


def test_forget_removes_the_registration(lab):
    """`forget` drops the entry outright; the node's own heartbeats do not
    bring it back, because update_load only touches entries that exist."""
    admin = lab.admin()
    try:
        assert admin.cmd(f"forget {lab.target(lab.b)}") == "ok\n"
        time.sleep(2.0)
        listing = _nodes(admin)
        assert lab.b not in listing, listing
        assert lab.a in listing, "forget removed the node it was not given"
    finally:
        admin.close()


def test_forget_of_an_absent_node_is_ok_not_not_found(lab):
    """DESIGN CHOICE, and the one place the cms table deliberately disagrees
    with itself: `forget` is idempotent because absent IS the state it asks
    for, while `undrain` answers not-found because not-drained means the
    operator's premise was wrong.  Both are asserted here so a future reader
    cannot "unify" them into one wording."""
    admin = lab.admin()
    try:
        ghost = f"{NODE_HOST} 1"
        assert admin.cmd(f"forget {ghost}") == "ok\n"
        assert admin.cmd(f"undrain {ghost}") == "err not-found\n"
    finally:
        admin.close()


# --------------------------------------------------------------------------- #
# error                                                                        #
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("command,want", [
    # a target that never registered — the premise is wrong, say so
    (f"undrain {NODE_HOST} 1", "err not-found\n"),
    (f"reset {NODE_HOST} 1", "err not-found\n"),
    # malformed targets: no port at all, non-numeric, out of range, empty host
    ("drain 127.0.0.1", "err bad-target\n"),          # net-literal-allow: operand
    ("drain 127.0.0.1 http", "err bad-target\n"),     # net-literal-allow: operand
    ("drain 127.0.0.1 70000", "err bad-target\n"),    # net-literal-allow: operand
    ("drain 127.0.0.1 0", "err bad-target\n"),        # net-literal-allow: operand
    ("undrain  1234", "err bad-target\n"),
    # a well-formed target with a bad duration is a DIFFERENT refusal, so the
    # operator learns which half of the command was wrong
    ("drain 127.0.0.1 1234 soon", "err bad-seconds\n"),   # net-literal-allow: operand
    ("drain 127.0.0.1 1234 0", "err bad-seconds\n"),      # net-literal-allow: operand
    ("drain 127.0.0.1 1234 -5", "err bad-seconds\n"),     # net-literal-allow: operand
    # not a verb at all
    ("", UNKNOWN),
    ("help", UNKNOWN),
])
def test_every_refusal_has_its_own_wording(lab, command, want):
    admin = lab.admin()
    try:
        assert admin.cmd(command) == want, command
    finally:
        admin.close()


def test_a_refusal_does_not_close_the_connection(lab):
    """The transport must stay usable after a bad command: an operator typing
    into a live socket should not have to reconnect after each typo."""
    admin = lab.admin()
    try:
        assert admin.cmd("nonsense") == UNKNOWN
        assert admin.cmd("drain nope") == "err bad-target\n"
        assert lab.a in _nodes(admin), "the connection died after a refusal"
    finally:
        admin.close()


# --------------------------------------------------------------------------- #
# security-negative                                                            #
# --------------------------------------------------------------------------- #

def test_both_admin_sockets_are_owner_only(lab):
    """Filesystem permission is the ENTIRE authorization model — there is no
    in-band auth and no verb re-checks anything, so 0600 is the boundary."""
    for path in (lab.root_sock, lab.cms_sock):
        mode = stat.S_IMODE(os.stat(path).st_mode)
        assert mode == 0o600, f"{path} is {oct(mode)}, not 0600"


@pytest.mark.parametrize("command", [
    # a bare operand verb: "drain" alone must not drain anything
    "drain", "undrain", "forget", "reset",
    # trailing space but no operand byte
    "drain ", "forget ",
    # longer spellings that share a prefix with a real verb
    "nodesx", "drainage 127.0.0.1 1234",   # net-literal-allow: operand
    # shorter spellings of a real verb
    "node", "drai", "res",
    # a leading space is not a verb
    " nodes",
])
def test_no_verb_is_reachable_by_a_prefix_or_a_short_spelling(lab, command):
    """Prefix matching would let a truncated operand mutate the wrong target,
    and would make one plane's verbs reachable from a shorter spelling of
    another's.  Every one of these must be an unknown command AND must leave
    the registry exactly as it was."""
    admin = lab.admin()
    try:
        before = _nodes(admin)
        assert admin.cmd(command) == UNKNOWN, command
        assert _nodes(admin) == before, f"{command!r} mutated the registry"
    finally:
        admin.close()


def test_an_oversized_command_line_is_refused_without_answering(lab):
    """BRIX_ADMIN_CMD_MAX is 512.  A line past it is refused by closing, with
    no reply — the buffer is never grown and never wrapped, so a long line
    cannot be split into a second, attacker-chosen command."""
    before_admin = lab.admin()
    try:
        before = _nodes(before_admin)
    finally:
        before_admin.close()

    reply = _one_shot(lab.cms_sock,
                      b"drain " + b"x" * 4096 + b" 1234\n")
    assert reply == "", f"oversized line was answered: {reply!r}"

    after_admin = lab.admin()
    try:
        assert _nodes(after_admin) == before, "the oversized line mutated state"
    finally:
        after_admin.close()


@pytest.mark.parametrize("verb", ROOT_VERBS)
def test_root_verbs_are_unknown_on_the_cms_socket(lab, verb):
    """The two tables are DISJOINT.  The shared transport cannot check this for
    itself — it only ever sees the table it was handed — so it is checked from
    outside, on both sockets."""
    admin = lab.admin("cms")
    try:
        before = _nodes(admin)
        assert admin.cmd(verb) == UNKNOWN, verb
        assert admin.cmd(f"{verb} 0123456789abcdef") == UNKNOWN, verb
        assert _nodes(admin) == before, f"root verb {verb!r} reached the registry"
    finally:
        admin.close()


@pytest.mark.parametrize("verb", CMS_VERBS)
def test_cms_verbs_are_unknown_on_the_root_socket(lab, verb):
    admin = lab.admin("root")
    try:
        assert admin.cmd(verb) == UNKNOWN, verb
        assert admin.cmd(f"{verb} {lab.target(lab.a)}") == UNKNOWN, verb
    finally:
        admin.close()

    cms = lab.admin("cms")
    try:
        listing = _nodes(cms)
        assert listing[lab.a]["state"] == "up", \
            f"cms verb {verb!r} on the root socket reached the registry anyway"
    finally:
        cms.close()


# --------------------------------------------------------------------------- #
# regression: the root plane still works after the transport extraction        #
# --------------------------------------------------------------------------- #

def test_the_root_verb_table_still_answers_after_the_extraction(lab):
    """W8.3 moved accept/framing/flush out from under these verbs.  A live
    root:// session must still appear in `list`, and the root plane's own
    refusals must be unchanged."""
    session = _xrd_session(lab.root_port)
    try:
        admin = lab.admin("root")
        try:
            reply = admin.cmd("list")
            assert reply.startswith("ok "), reply
            assert NODE_HOST in reply, \
                f"the live session is missing from list: {reply!r}"
            assert admin.cmd("disc 0123456789abcdef").startswith("err"), \
                "disc of an unknown sessid should refuse"
            assert admin.cmd("bogus") == UNKNOWN
        finally:
            admin.close()
    finally:
        session.close()
