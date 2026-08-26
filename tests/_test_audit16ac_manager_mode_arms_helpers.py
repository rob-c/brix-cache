"""`brix_manager_mode`, the flag that decides whether a node has files at all.

WHY THIS FILE EXISTS
--------------------
The audit's step-1/step-2 pass over `ngx_conf_set_flag_slot` leaves 92
directives with exactly one arm unwritten anywhere in the corpus.  This is the
last of them in the root/stream command table (`protocols/root/stream/module.c:445`)
and the one with the largest blast radius: `brix_manager_mode on` is written by
six configs, `off` by none, and the flag does not merely add a behaviour — it
DELETES one.  `brix_server_has_runtime_export()` (`core/config/runtime_server.c:25-29`)
is

    !manager_mode && !caps.supervisor && manager_map == NULL && !proxy.enable

and it gates `brix_server_setup_export()` (`:190`), so a server with the flag on
never turns its `brix_storage_backend` into an export.  The open path is the
other half: `brix_open_manager_redirect` enters `brix_open_manager_dynamic` only
under `conf->manager_mode` (`protocols/root/read/open_manager.c:191-203`), which
answers kXR_redirect out of the process-global registry.

So the arm nobody had written is the arm that says "this node keeps its files",
and it has never been measured against the arm that says the opposite.  §A reads
both over the wire, §B pins `off` and absent as the same merged value
(`server_conf_merge_cluster.c:118` merges to 0), and §C reads the export registry
itself, because "the export was never created" is not visible to a client that
is being redirected away from it.

THE FINDING — DEFECT CANDIDATE #109 (the documented override is order-dependent)
--------------------------------------------------------------------------------
`brix_cms_server on` derives manager mode for its own block
(`net/cms/server_module.c:127-146`), and the comment there promises an escape
hatch: "An explicit `brix_manager_mode off` in the same block still wins: only
flip the flag while it is UNSET so the operator can always override the
auto-derivation."  The derivation is implemented by assigning `bcf->manager_mode
= 1` — the same slot `ngx_conf_set_flag_slot` refuses to write twice.  So the
override wins only when it is written FIRST:

    brix_manager_mode off;   brix_cms_server on;    -> loads, export kept
    brix_cms_server on;      brix_manager_mode off; -> nginx: [emerg]
                                                       "brix_manager_mode"
                                                       directive is duplicate

The failing order is the one an operator writes: the override is a reaction to
the auto-derivation, so it goes after the line that caused it.  The diagnostic
names a directive that appears exactly once in the file and says nothing about
`brix_cms_server`, and no documentation of the escape hatch mentions order.
§E measures both orders, and measures that `on` after `brix_cms_server` is
refused too — the refusal is positional, not about the value.

OBSERVATION — the auto-derived block drops the export it was configured with
---------------------------------------------------------------------------
The accepted order of the same three directives (`brix_root on;
brix_storage_backend posix:/…; brix_cms_server on;`) is a block that registers no
export: the startup banner reads `export "/"` because `common.root` was never
replaced, and the census in §C has no entry for the directory.  The only notice
is "auto-enabling manager mode for this block", which is true and which does not
mention the backend it just made inert — the same notice, word for word, that a
bare `brix_cms_server on` listener with nothing to lose gets.  §D measures the
pair — AUTO against OVER, identical but for the override — from the log and from
the census, attributing each diagnostic to the block that caused it by the
config line number the notice carries.

WHAT THIS FILE DOES NOT CLAIM
-----------------------------
The redirect body's shape and the manager's registry selection belong to
`test_audit15m_stream_coresidency.py` and the `cms_mesh_lib.py` topologies; the
collapse cache in front of the same dynamic path to
`test_audit16j_root_caps_flags.py`; the dashboard's own auth combiner to
`test_audit16ab_admin_factor_arms.py`.  Each appears here only as the reading
instrument an arm is measured with.
"""

import hashlib
import hmac
import http.client
import json
import os
import time
from pathlib import Path

import pytest

from _test_conf_write_helpers import (_close, _connect, _login, _open,
                                      _open_handle, _read, _write, kXR_new,
                                      kXR_ok, kXR_open_read, kXR_open_updt)
from config_parse import nginx_t
from fleet_lifecycle_ports import LIFECYCLE_SHARED_PORTS, PARSE_PLACEHOLDER_PORT
from server_launcher import LifecycleHarness
from server_registry import NginxInstanceSpec
from settings import BIND_HOST, HOST, NGINX_BIN
# The redirect body and the flags word are read by the modules that own them.
from test_audit15m_stream_coresidency import _redirect_target
from test_protocol_flags import _get_protocol_flags

NAME = "lc-audit16ac-mgrmode"
_L = LIFECYCLE_SHARED_PORTS[NAME]
PORT = _L["port"]
OFF_PORT = _L["extra"]["OFF_PORT"]
ABS_PORT = _L["extra"]["ABS_PORT"]
CMS_PORT = _L["extra"]["CMS_PORT"]
DS_PORT = _L["extra"]["DS_PORT"]
AUTO_PORT = _L["extra"]["AUTO_PORT"]
OVER_PORT = _L["extra"]["OVER_PORT"]
HTTP_PORT = _L["extra"]["HTTP_PORT"]

PASSWORD = "audit16ac-dash-password"
CENSUS = "/brix/api/v1/vfs"

KXR_REDIRECT = 4004
KXR_ERROR = 4003

# ServerProtocolBody.flags (protocols/root/protocol/flags.h).  manager_mode's
# only wire consequence is kXR_isManager (session/protocol.c:78).
KXR_ISSERVER = 0x00000001
KXR_ISMANAGER = 0x00000002

# One distinct payload per tree: a read that differs between two arms can then
# never be explained by "the servers were looking at the same bytes".
SEED = {"mgr": b"16ac manager tree, never served\n",
        "off": b"16ac off-arm tree\n",
        "abs": b"16ac absent-arm tree\n",
        "ds": b"16ac data-server tree\n",
        "auto": b"16ac auto-derived tree\n",
        "over": b"16ac override tree\n"}

pytestmark = [pytest.mark.timeout(120),
              pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group(NAME)]


# --------------------------------------------------------------------------- #
# The instance                                                                 #
# --------------------------------------------------------------------------- #

class _Arms:
    """Seven stream servers and one dashboard in one process, addressed by port.

    The trees are held by name because §C and §F ask about the DIRECTORY (was an
    export made of it, did a file appear in it) rather than about a port.
    """

    def __init__(self, instance, trees):
        self.instance = instance
        self.trees = trees

    def errlog(self):
        """Instance prefixes are wiped at teardown, so failures quote inline."""
        log = Path(self.instance.prefix) / "logs" / "error.log"
        return log.read_text(errors="replace") if log.exists() else ""

    def tree(self, which):
        return self.trees[which]

    def canon(self, which):
        """The tree as the export registry spells it: `root_canon` is a realpath
        (`vfs_browse.c:213`), and a tmp_path can sit under a symlinked /tmp."""
        return os.path.realpath(str(self.trees[which]))


@pytest.fixture(scope="module")
def arms(tmp_path_factory):
    """MODULE-scoped, with its own harness, for the reason file 27 gives: the
    ports are fixed by the ledger, so a per-test start/stop races the OS
    releasing them.  Every cell below is a read except the two in §F that create
    a file, and those write into trees no other cell reads.
    """
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx binary not executable: {NGINX_BIN}")

    base = tmp_path_factory.mktemp("audit16ac")
    trees = {}
    for which, seed in SEED.items():
        tree = base / which
        tree.mkdir()
        (tree / "seed.bin").write_bytes(seed)
        trees[which] = tree

    harness = LifecycleHarness()
    try:
        instance = harness.start(NginxInstanceSpec(
            name=NAME,
            template="nginx_audit16ac_manager_mode_arms.conf",
            data_root=str(trees["mgr"]),
            template_values={"BIND_HOST": BIND_HOST,
                             "MGR_DATA": str(trees["mgr"]),
                             "OFF_DATA": str(trees["off"]),
                             "ABS_DATA": str(trees["abs"]),
                             "DS_DATA": str(trees["ds"]),
                             "AUTO_DATA": str(trees["auto"]),
                             "OVER_DATA": str(trees["over"]),
                             "PASSWORD": PASSWORD},
            reason="audit-16ac brix_manager_mode on/off/absent at value "
                   "granularity, plus the CMS auto-derivation override."))
        yield _Arms(instance, trees)
    finally:
        harness.close()


# --------------------------------------------------------------------------- #
# Wire helpers                                                                 #
# --------------------------------------------------------------------------- #

def _session(port):
    s = _connect(HOST, port)
    _login(s)
    return s


def _open_on(port, path="/seed.bin", options=kXR_open_read):
    """Open and return (status, body), session closed.

    The redirect sections want the OPEN verdict and nothing after it, and a
    session left open holds a worker slot for the rest of the module.
    """
    s = _session(port)
    try:
        return _open(s, path, options)
    finally:
        s.close()


def _read_back(port, path="/seed.bin", length=256):
    """Read through a fresh handle: the question is what the SERVER has."""
    s = _session(port)
    try:
        handle = _open_handle(s, path, kXR_open_read)
        status, data = _read(s, handle, 0, length)
        _close(s, handle)
        return status, data
    finally:
        s.close()


@pytest.fixture(scope="module")
def registered(arms):
    """Block until the data node has registered with the CMS listener.

    The manager's dynamic path selects out of a process-global registry that the
    data node populates through its own upward login on a `brix_cms_interval 2`
    timer, so §A's subject does not exist for the first seconds of the
    instance's life: until then the manager answers kXR_noserver
    (`open_manager.c:226-230`), which is a true statement about a different
    thing.  The readable proof that the registry is populated is a redirect.
    """
    deadline = time.time() + 30
    last = None
    while time.time() < deadline:
        last = _open_on(PORT, "/registration-probe.bin")
        if last[0] == KXR_REDIRECT:
            return arms
        time.sleep(0.5)
    pytest.fail(f"no data server registered within 30s; the manager's last open "
                f"answered {last} and every redirect cell would be reading an "
                f"empty registry.\n{arms.errlog()}")


# --------------------------------------------------------------------------- #
# HTTP helpers — the export census                                             #
# --------------------------------------------------------------------------- #

def _cookie(password=PASSWORD, stamp=None):
    """The dashboard session cookie: HMAC-SHA256(password, "<ts>") . "<ts>"."""
    stamp = int(time.time()) if stamp is None else int(stamp)
    digest = hmac.new(password.encode(), str(stamp).encode(),
                      hashlib.sha256).hexdigest()
    return f"xrd_dashboard={digest}.{stamp}"


def _get(path, cookie=None):
    headers = {"Host": "localhost"}  # net-literal-allow: vhost-selector payload the config must string-match
    if cookie is not None:
        headers["Cookie"] = cookie
    conn = http.client.HTTPConnection(HOST, HTTP_PORT, timeout=10)
    try:
        conn.request("GET", path, headers=headers)
        response = conn.getresponse()
        return response.status, response.read()
    finally:
        conn.close()


def _export_roots(arms):
    """Every export root the process registered, as the registry spells them."""
    status, body = _get(CENSUS, cookie=_cookie())
    assert status == 200, (status, body, arms.errlog())
    return [e["root"] for e in json.loads(body)["exports"]]


# --------------------------------------------------------------------------- #
# Log helpers — one config load, not the file's whole history                  #
# --------------------------------------------------------------------------- #

def _last_ready_pid(lines):
    pids = [line.split("[notice]", 1)[1].split("#", 1)[0].strip()
            for line in lines
            if "[notice]" in line and "endpoint ready" in line]
    assert pids, "no startup summary in the instance log"
    return pids[-1]


def _startup_summary(arms):
    """The startup banner of the load that produced the RUNNING master.

    An instance's error.log accumulates every config load the launcher
    performed — `nginx -t` before the start, then the start itself — so an
    absolute count over the file counts each block once per load and says
    nothing about the config.  Every line names the pid that wrote it, and the
    last pid to emit "endpoint ready" is the load the wire cells are talking
    to, so its lines are the one generation worth counting.
    """
    lines = arms.errlog().splitlines()
    last = _last_ready_pid(lines)
    return [ln for ln in lines if f"[notice] {last}#" in ln]


def _rendered_conf(arms):
    """The config the launcher rendered, as a list of lines.

    §D asks which BLOCK a per-block diagnostic came from, and the diagnostic
    names a line number in this file (`ngx_conf_log_error` appends
    " in <conf>:<line>").  Reading the file back is what turns that number into
    "the AUTO block" rather than into a number.
    """
    conf = Path(arms.instance.prefix) / "conf" / "nginx.conf"
    return conf.read_text(errors="replace").splitlines()


def _cms_server_lines(arms):
    """The 1-based line of every `brix_cms_server on;` the config writes, in the
    order the template writes them: the bare listener, AUTO, then OVER."""
    lines = [i for i, ln in enumerate(_rendered_conf(arms), start=1)
             if ln.strip().startswith("brix_cms_server")]
    assert len(lines) == 3, f"expected three brix_cms_server blocks, got {lines}"
    return lines


def _auto_derived_lines(arms):
    """The config lines the auto-derivation fired on, as a set.

    A set of LINE NUMBERS rather than a count of notices: the numbers are
    stable across the launcher's repeated loads, so this reads the config once
    however many times nginx parsed it.
    """
    marker = "auto-enabling manager mode for this block"
    return {int(ln.rsplit(":", 1)[1])
            for ln in arms.errlog().splitlines() if marker in ln}


# --------------------------------------------------------------------------- #
# §A — the two arms over the wire                                              #
# --------------------------------------------------------------------------- #

