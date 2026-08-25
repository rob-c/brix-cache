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

class TestTheArmThatDecidesWhetherANodeHasFiles:
    """MGR, OFF and ABS differ by one line and nothing else, so every difference
    below is the directive's."""

    def test_the_on_arm_redirects_instead_of_serving(self, registered):
        """The armed arm: the open never reaches a file, though the server was
        configured with a backend that has one."""
        status, body = _open_on(PORT)
        assert status == KXR_REDIRECT, (status, body, registered.errlog())

    def test_the_redirect_names_the_registered_data_server(self, registered):
        """Attribution: the redirect came out of the registry rather than out of
        a static map this config does not have."""
        status, body = _open_on(PORT)
        assert status == KXR_REDIRECT, (status, body)
        assert _redirect_target(body)[1] == DS_PORT, _redirect_target(body)

    def test_the_off_arm_serves_its_own_bytes(self, arms):
        """The arm nobody had written, doing the thing the flag suppresses."""
        status, data = _read_back(OFF_PORT)
        assert status == kXR_ok, (status, data, arms.errlog())
        assert data == SEED["off"], data

    def test_the_absent_arm_serves_its_own_bytes(self, arms):
        status, data = _read_back(ABS_PORT)
        assert status == kXR_ok, (status, data, arms.errlog())
        assert data == SEED["abs"], data

    def test_the_manager_never_serves_the_bytes_under_its_own_backend(
            self, registered):
        """The half a redirect hides: MGR's tree HAS the file, and no client can
        get it from MGR.  Without this the redirect could be read as "the file
        was missing" rather than as "the export was never made"."""
        assert (registered.tree("mgr") / "seed.bin").read_bytes() == SEED["mgr"]
        status, body = _open_on(PORT)
        assert status == KXR_REDIRECT, (status, body)
        assert SEED["mgr"] not in body

    def test_the_on_arm_advertises_the_manager_bit(self, arms):
        flags = _get_protocol_flags(HOST, PORT)
        assert flags & KXR_ISMANAGER, f"word {flags:#010x} lacks kXR_isManager"

    def test_the_off_arm_does_not(self, arms):
        flags = _get_protocol_flags(HOST, OFF_PORT)
        assert flags & KXR_ISMANAGER == 0, (
            f"word {flags:#010x} advertises kXR_isManager with the flag written "
            f"off; session/protocol.c:78 makes manager_mode its only source on a "
            f"node with no manager_map")

    def test_the_absent_arm_does_not(self, arms):
        flags = _get_protocol_flags(HOST, ABS_PORT)
        assert flags & KXR_ISMANAGER == 0, f"word {flags:#010x}"

    def test_the_off_arm_answers_a_missing_file_itself(self, arms):
        """The error arm, and the sharpest statement that `off` is not a softer
        `on`: a path the local export does not have is a local refusal, not a
        deferral to somebody who might."""
        status, body = _open_on(OFF_PORT, "/no-such-file.bin")
        assert status == KXR_ERROR, (status, body, arms.errlog())

    def test_the_on_arm_redirects_a_missing_file_too(self, registered):
        """The manager does not stat: selection is by path against the
        registry's exported prefixes, so a file nobody has is still a redirect.
        This is why the previous cell's refusal is attributable."""
        status, body = _open_on(PORT, "/no-such-file.bin")
        assert status == KXR_REDIRECT, (status, body)


# --------------------------------------------------------------------------- #
# §B — `off` and absent are one value                                          #
# --------------------------------------------------------------------------- #

class TestOffAndAbsentAreTheSameMergedValue:
    """`brix_manager_mode` merges to 0 (`server_conf_merge_cluster.c:118`), so
    the token can only ever confirm equality — which is worth measuring rather
    than assuming, because every `absent` control in this file rests on it."""

    def test_the_two_arms_advertise_the_same_word(self, arms):
        off = _get_protocol_flags(HOST, OFF_PORT)
        absent = _get_protocol_flags(HOST, ABS_PORT)
        assert off == absent, f"off {off:#010x} != absent {absent:#010x}"

    def test_both_arms_advertise_a_plain_data_server(self, arms):
        for port in (OFF_PORT, ABS_PORT):
            flags = _get_protocol_flags(HOST, port)
            assert flags & KXR_ISSERVER, f"{port}: word {flags:#010x}"

    def test_both_arms_accept_a_write_into_their_own_tree(self, arms):
        """The export exists on both, not merely the read path: `allow_write on`
        is only honoured for a server that has an export at all."""
        for which, port in (("off", OFF_PORT), ("abs", ABS_PORT)):
            payload = f"written to the {which} arm\n".encode()
            s = _session(port)
            try:
                handle = _open_handle(s, f"/{which}-written.bin",
                                      kXR_new | kXR_open_updt)
                status, body = _write(s, handle, 0, payload)
                assert status == kXR_ok, (which, status, body, arms.errlog())
                _close(s, handle)
            finally:
                s.close()
            assert (arms.tree(which) / f"{which}-written.bin").read_bytes() \
                == payload


# --------------------------------------------------------------------------- #
# §C — the export registry, where the deleted export is visible                #
# --------------------------------------------------------------------------- #

class TestTheExportCensus:
    """A redirected client cannot see whether an export was made; the VFS
    registry can.  `brix_vfs_backend_export_info()` reports every registered
    export by canonical root (`vfs_browse.c:212-214`), and the six trees are
    distinct directories, so presence in that list IS the verdict of
    `brix_server_has_runtime_export()` for the server that named it."""

    def test_the_data_server_export_is_listed(self, arms):
        """The control: the census works and the process registers exports at
        all.  Without it every absence below would be unattributable."""
        assert arms.canon("ds") in _export_roots(arms), _export_roots(arms)

    def test_the_on_arm_registers_no_export(self, arms):
        """`brix_server_has_runtime_export()` is false for a manager, so the
        configured `brix_storage_backend` never becomes an export."""
        roots = _export_roots(arms)
        assert arms.canon("mgr") not in roots, roots

    def test_the_off_arm_registers_its_export(self, arms):
        roots = _export_roots(arms)
        assert arms.canon("off") in roots, roots

    def test_the_absent_arm_registers_its_export(self, arms):
        roots = _export_roots(arms)
        assert arms.canon("abs") in roots, roots

    def test_the_two_unwritten_arms_are_indistinguishable_here_too(self, arms):
        """§B's equality, read from the other side of the process."""
        roots = _export_roots(arms)
        assert {arms.canon("off"), arms.canon("abs")} <= set(roots), roots

    def test_the_managers_banner_names_a_root_it_was_never_given(self, arms):
        """The other half of the deletion, from the startup summary
        (`postconfiguration.c:36`): `common.root` keeps its default because the
        backend was never turned into one."""
        log = arms.errlog()
        assert f'export "{arms.tree("mgr")}"' not in log, log[-4000:]
        assert "mode: cluster manager" in log, log[-4000:]


# --------------------------------------------------------------------------- #
# §D — the CMS auto-derivation and its override                                #
# --------------------------------------------------------------------------- #

class TestTheAutoDerivedManagerAndItsOverride:
    """AUTO and OVER carry the same three directives; OVER adds
    `brix_manager_mode off` FIRST.  Their own ports speak CMS (the directive's
    handler sets `cscf->handler = brix_cms_srv_handler`,
    `net/cms/server_module.c:135`), so both are read from the log and the
    census rather than over the wire.

    Every cell here reads a config LINE NUMBER or one config load's banner, not
    a count over the whole log: the launcher parses the file more than once
    (`nginx -t`, then the start), and an absolute count multiplies by however
    many times it did.
    """

    def test_the_auto_derived_block_announces_itself(self, arms):
        """The one diagnostic the derivation emits
        (`net/cms/server_module.c:141-144`), attributed to AUTO's own line."""
        auto_line = _cms_server_lines(arms)[1]
        assert auto_line in _auto_derived_lines(arms), (
            f"no auto-derivation on the AUTO block at line {auto_line}; "
            f"derived lines were {sorted(_auto_derived_lines(arms))}")

    def test_the_override_block_is_not_derived(self, arms):
        """The escape hatch, at the point where it acts: OVER writes the same
        `brix_cms_server on` and the derivation declines, because the slot it
        would write is no longer `NGX_CONF_UNSET`."""
        over_line = _cms_server_lines(arms)[2]
        assert over_line not in _auto_derived_lines(arms), (
            f"the OVER block at line {over_line} was auto-derived despite "
            f"writing brix_manager_mode off first")

    def test_the_bare_listener_is_derived_as_well(self, arms):
        """Why the derived set has two members and not one: the CMS listener
        that carries nothing but `brix_cms_server on` is derived too.  It has no
        backend to lose, which is exactly what makes AUTO the interesting one —
        the derivation cannot tell the two blocks apart."""
        listener_line = _cms_server_lines(arms)[0]
        assert _auto_derived_lines(arms) == {listener_line,
                                             _cms_server_lines(arms)[1]}, (
            f"derived lines {sorted(_auto_derived_lines(arms))} against "
            f"brix_cms_server lines {_cms_server_lines(arms)}")

    def test_the_auto_derived_block_registers_no_export(self, arms):
        """The observation this file records: the block asked for a backend, was
        told only that manager mode had been enabled, and has no export."""
        roots = _export_roots(arms)
        assert arms.canon("auto") not in roots, roots

    def test_the_override_keeps_its_export(self, arms):
        """The escape hatch's consequence — in the only order in which it can be
        written at all (§E)."""
        roots = _export_roots(arms)
        assert arms.canon("over") in roots, roots

    def test_exactly_two_blocks_report_cluster_manager_mode(self, arms):
        """MGR by directive and AUTO by derivation; OFF, ABS, DS and OVER not.
        The count is the attribution: a third would mean a block became a
        manager without either writing the flag or being told.  (The bare CMS
        listener writes no `brix_root`, so it emits no startup summary at all
        and cannot be the third.)"""
        summary = _startup_summary(arms)
        managers = [ln for ln in summary if "mode: cluster manager" in ln]
        assert len(managers) == 2, (
            f"{len(managers)} blocks report cluster manager mode in one config "
            f"load; MGR and AUTO are the two that should:\n"
            + "\n".join(summary))

    def test_the_auto_derived_block_reports_a_root_it_was_never_given(
            self, arms):
        """`common.root` keeps its default because the backend was never turned
        into an export, so two blocks in this load announce `export "/"` — MGR,
        which never named a directory it expected to serve, and AUTO, which
        did."""
        summary = _startup_summary(arms)
        rootless = [ln for ln in summary if 'export "/" ' in ln]
        assert len(rootless) == 2, "\n".join(summary)

    def test_the_override_banner_names_the_real_directory(self, arms):
        """The pair, from the log rather than the census: OVER's export root is
        its configured tree, AUTO's is nowhere in the load."""
        summary = "\n".join(_startup_summary(arms))
        assert f'export "{arms.tree("over")}"' in summary, summary
        assert f'export "{arms.tree("auto")}"' not in summary, summary


# --------------------------------------------------------------------------- #
# §E — the parse tier                                                          #
# --------------------------------------------------------------------------- #

def _parse(tmp_path, **slots):
    """`nginx -t` on the 16j scaffold with the named slots filled.

    The scaffold (`configs/nginx_audit16jparse.conf`) is reused rather than
    copied: it writes no capability or cluster directive of its own, so a
    negative about `brix_manager_mode` is never answered by a duplicate
    diagnostic the scaffold caused — the exact property the duplicate cases
    below depend on, since a duplicate is precisely what they are about.
    """
    data = tmp_path / "parse-data"
    data.mkdir(exist_ok=True)
    values = {"PORT": PARSE_PLACEHOLDER_PORT,
              "PORT2": PARSE_PLACEHOLDER_PORT + 1,
              "LOG_DIR": str(tmp_path),
              "BACKEND": f"posix:{data}",
              "KNOBS": "", "STREAM_KNOBS": "", "HTTP_KNOBS": "",
              "LOC_KNOBS": "", "OUTER": "", "EXTRA": ""}
    values.update(slots)
    result = nginx_t("nginx_audit16jparse.conf", str(tmp_path), **values)
    return result.returncode, (result.stdout or "") + (result.stderr or "")


def _diagnostics(out):
    """Only the lines nginx itself flagged: a tmp_path name can contain the
    token under test, so a substring search over the whole output would match
    the temp directory rather than a diagnostic."""
    return [ln for ln in out.splitlines()
            if any(tag in ln for tag in ("[warn]", "[error]", "[crit]",
                                         "[emerg]"))]


class TestTheParseTier:
    """Values, arity, placement — and the order dependence that is this file's
    finding."""

    @pytest.mark.parametrize("arm", ("on", "off"))
    def test_both_arms_are_accepted_in_a_stream_server(self, tmp_path, arm):
        rc, out = _parse(tmp_path, KNOBS=f"        brix_manager_mode {arm};\n")
        assert rc == 0, out

    @pytest.mark.parametrize("token", ("ON", "Off", "oFF"))
    def test_the_arms_are_case_insensitive(self, tmp_path, token):
        """`ngx_conf_set_flag_slot` compares with ngx_strcasecmp, which is what
        makes the audit's grep for `brix_manager_mode off` sound only because no
        config in the corpus spells it any other way."""
        rc, out = _parse(tmp_path, KNOBS=f"        brix_manager_mode {token};\n")
        assert rc == 0, out

    @pytest.mark.parametrize("value", ("yes", "1", "true", "disabled", ""))
    def test_a_value_outside_the_two_arms_is_refused(self, tmp_path, value):
        line = (f"        brix_manager_mode {value};\n" if value
                else "        brix_manager_mode;\n")
        rc, out = _parse(tmp_path, KNOBS=line)
        assert rc != 0, f"brix_manager_mode {value!r} was accepted: {out}"

    def test_the_directive_takes_exactly_one_argument(self, tmp_path):
        rc, out = _parse(tmp_path, KNOBS="        brix_manager_mode on off;\n")
        assert rc != 0, out
        assert "invalid number of arguments" in out, out

    def test_a_written_duplicate_is_refused(self, tmp_path):
        """The mechanism the finding rests on, stated on its own terms first."""
        rc, out = _parse(tmp_path, KNOBS=("        brix_manager_mode on;\n"
                                          "        brix_manager_mode off;\n"))
        assert rc != 0, out
        assert "duplicate" in out, out

    @pytest.mark.parametrize("slot", ("STREAM_KNOBS", "HTTP_KNOBS",
                                      "LOC_KNOBS", "OUTER"))
    def test_the_directive_is_refused_everywhere_but_a_stream_server(
            self, tmp_path, slot):
        """`NGX_STREAM_SRV_CONF` and nothing else (`stream/module.c:446`), so a
        plane for this subject is a `listen` and cannot be a location.  The
        refusal must be a placement one: `unknown directive` would mean the
        stream module was not loaded and the case measured nothing."""
        rc, out = _parse(tmp_path, **{slot: "    brix_manager_mode on;\n"})
        assert rc != 0, out
        assert "is not allowed here" in out, out
        assert "unknown directive" not in out, out

    def test_the_flag_alone_carries_no_diagnostic(self, tmp_path):
        """Silence is part of the subject: writing the arm nobody had written
        must not produce an advisory, or "never written" would have been noticed
        as noise long ago."""
        rc, out = _parse(tmp_path, KNOBS="        brix_manager_mode off;\n")
        assert rc == 0, out
        assert _diagnostics(out) == [], out


class TestTheDocumentedOverrideOnlyWorksWrittenFirst:
    """DEFECT CANDIDATE #109.  `net/cms/server_module.c:136-138` promises that
    "An explicit `brix_manager_mode off` in the same block still wins"; it wins
    only when the parser has not already reached `brix_cms_server on`, because
    the derivation writes the same slot `ngx_conf_set_flag_slot` refuses to
    write twice."""

    def test_the_override_written_first_loads(self, tmp_path):
        rc, out = _parse(tmp_path, KNOBS=("        brix_manager_mode off;\n"
                                          "        brix_cms_server on;\n"))
        assert rc == 0, out

    def test_the_override_written_after_is_a_hard_refusal(self, tmp_path):
        """The order an operator writes — the override is a reaction to the
        derivation, so it goes after the line that caused it — and the config
        does not load at all."""
        rc, out = _parse(tmp_path, KNOBS=("        brix_cms_server on;\n"
                                          "        brix_manager_mode off;\n"))
        assert rc != 0, (
            "brix_cms_server on followed by brix_manager_mode off now loads; if "
            "the derivation stopped writing the slot directly, #109 is fixed")
        assert "duplicate" in out, out

    def test_the_refusal_names_a_directive_written_once(self, tmp_path):
        """Why the finding is a defect and not a documented constraint: the
        diagnostic points at the line the operator wrote once, and never
        mentions `brix_cms_server`, which is the line that wrote it first."""
        rc, out = _parse(tmp_path, KNOBS=("        brix_cms_server on;\n"
                                          "        brix_manager_mode off;\n"))
        assert rc != 0, out
        refusal = [ln for ln in _diagnostics(out) if "duplicate" in ln]
        assert refusal, _diagnostics(out)
        assert '"brix_manager_mode" directive is duplicate' in refusal[0], \
            refusal
        assert "brix_cms_server" not in refusal[0], refusal

    def test_the_refusal_is_positional_and_not_about_the_value(self, tmp_path):
        """`on` after `brix_cms_server on` is refused identically, so this is
        not the parser objecting to an override — it cannot tell the two apart."""
        rc, out = _parse(tmp_path, KNOBS=("        brix_cms_server on;\n"
                                          "        brix_manager_mode on;\n"))
        assert rc != 0, out
        assert "duplicate" in out, out

    def test_a_block_with_no_cms_server_accepts_the_flag_in_either_place(
            self, tmp_path):
        """The bound: nothing about the flag's own position matters.  Only the
        derivation makes one order fail."""
        first = _parse(tmp_path, KNOBS=("        brix_manager_mode off;\n"
                                        "        brix_allow_write on;\n"))
        second = _parse(tmp_path, KNOBS=("        brix_allow_write on;\n"
                                         "        brix_manager_mode off;\n"))
        assert first[0] == 0, first[1]
        assert second[0] == 0, second[1]

    def test_the_derivation_does_not_reach_a_sibling_server(self, tmp_path):
        """Scope: `brix_cms_server on` writes the manager_mode slot of ITS OWN
        block, so a sibling may still write the directive freely."""
        extra = ("    server {\n"
                 f"        listen {PARSE_PLACEHOLDER_PORT + 2};\n"
                 "        brix_root on;\n"
                 "        brix_auth none;\n"
                 "        brix_manager_mode off;\n"
                 "    }\n")
        rc, out = _parse(tmp_path, KNOBS="        brix_cms_server on;\n",
                         EXTRA=extra)
        assert rc == 0, out


# --------------------------------------------------------------------------- #
# §F — security negatives                                                      #
# --------------------------------------------------------------------------- #

class TestTheManagerTouchesNoFiles:
    """The security half of "the export was never made": a node with no export
    must not be reachable as one, however the request is spelled."""

    def test_a_create_open_makes_no_file_under_the_managers_backend(
            self, registered):
        """kXR_new on the manager: the redirect happens before any path
        resolution against a local root, so the directory the config named stays
        untouched."""
        target = registered.tree("mgr") / "created-by-manager.bin"
        status, body = _open_on(PORT, "/created-by-manager.bin",
                                kXR_new | kXR_open_updt)
        assert status != kXR_ok, (status, body)
        assert not target.exists(), (
            f"{target} exists — a manager with no export wrote into the "
            f"directory its inert brix_storage_backend named")

    def test_the_off_arm_does_create_it(self, arms):
        """The control that makes the previous cell attributable: the same
        request against the same directive written `off` creates the file."""
        s = _session(OFF_PORT)
        try:
            handle = _open_handle(s, "/created-by-off.bin",
                                  kXR_new | kXR_open_updt)
            _close(s, handle)
        finally:
            s.close()
        assert (arms.tree("off") / "created-by-off.bin").exists()

    def test_a_traversal_is_not_served_by_the_manager(self, registered):
        """The manager has no root to escape from, and must not acquire one by
        being asked nicely."""
        status, body = _open_on(PORT, "/../../etc/passwd")
        assert status != kXR_ok, (status, body)
        assert b"root:x:" not in body, body

    def test_a_traversal_is_refused_by_the_off_arm(self, arms):
        """The same request against the arm that DOES have an export:
        `resolve_path()` refuses it there, so the manager's refusal above is not
        the only thing standing between a client and /etc/passwd."""
        status, body = _open_on(OFF_PORT, "/../../etc/passwd")
        assert status != kXR_ok, (status, body)
        assert b"root:x:" not in body, body


class TestTheCensusIsNotAnonymous:
    """The census is the instrument §C and §D read the registry with; an
    unauthenticated reader must not get the same list."""

    def test_no_cookie_is_refused(self, arms):
        status, _ = _get(CENSUS)
        assert status == 401, status

    def test_a_forged_cookie_is_refused(self, arms):
        status, _ = _get(CENSUS,
                         cookie=_cookie(password="not-the-dashboard-password"))
        assert status == 401, status

    def test_the_export_paths_do_not_leak_to_an_anonymous_reader(self, arms):
        """The refusal must also be silent: a 401 body that named the roots
        would hand over exactly what §C reads."""
        status, body = _get(CENSUS)
        assert status == 401, status
        for which in ("off", "abs", "ds", "over"):
            assert arms.canon(which).encode() not in body, body
