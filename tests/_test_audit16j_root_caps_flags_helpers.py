"""The five node-capability flags whose `off` arm was never written.

WHY THIS FILE EXISTS
--------------------
`ngx_conf_set_flag_slot` is the setter behind 128 directives, so the flag surface
is 256 (directive, value) pairs.  Re-running the audit's Method steps 1-2 at that
granularity leaves 92 directives with exactly ONE arm unwritten, and five of them
are one command table — `directives_caps.h`, the node's declaration of what it
IS:

    brix_metadata_only        on: nginx_meta_only.conf      off: NOWHERE
    brix_supervisor           on: nginx_supervisor.conf     off: NOWHERE
    brix_virtual_redirector   on: test_audit15b_*.py        off: NOWHERE
    brix_collapse_redir       on: nginx_collapse_redir.conf off: NOWHERE
    brix_recover_writes       on: nginx_rl_stream.conf      off: NOWHERE

All five are `NGX_STREAM_SRV_CONF | NGX_CONF_FLAG` into `caps.*`, and all five
merge to 0 (`brix_node_caps_conf_merge`, core/types/conf_structs.h:537-548), so
`off` and absent produce the same merged value.  No reading here can be a value
comparison; each arm is read as the observable its flag owns.

WHAT WAS ALREADY OWNED, AND WHAT WAS NOT
----------------------------------------
`test_protocol_flags.py` owns the whole kXR_protocol bit table for all five —
each bit asserted set on its role server and clear on a plain data server — and
this file borrows that module's own `_get_protocol_flags` rather than restating
the reading.  What the bit table cannot say is anything about the code BEHIND the
bit, and for four of the five the advertisement is the only thing anyone has ever
read:

*   `brix_supervisor` also deletes the local export
    (`brix_server_has_runtime_export`, core/config/runtime_server.c:25-29), sets
    the CMS registration role letter (net/cms/server_handler.c:310) and the
    stats role letter (net/cms/send.c:488).  The suite's only supervisor config
    writes `brix_manager_mode on` beside it, and manager_mode alone already
    makes that predicate false — so the flag's own effect has never been seen.
*   `brix_recover_writes` also arms a per-handle write journal
    (root/write/wrts_journal.c), which nothing has ever exercised.
*   `brix_collapse_redir` also gates a redirect cache
    (root/read/open_manager.c:116 and :164) reachable only under
    `brix_manager_mode`.
*   `brix_metadata_only`'s open refusal is conditional on `manager_map == NULL`
    (root/read/open_request.c:69); `test_protocol_flags.py` covers the refusal,
    nobody covered the other side of the conjunction.

THE FINDING — DEFECT CANDIDATE #83 (integrity, silent write loss)
-----------------------------------------------------------------
`brix_recover_writes on` arms a per-handle journal of committed (offset, length)
ranges.  A write whose range matches an entry is treated as a client's
post-disconnect replay: the `pwrite` is skipped and kXR_ok is returned
(root/write/write.c:120-134).  The match is on offset and length ALONE — not on
content, not on a generation the client supplied — and there is no reconnect
condition anywhere on the path.  Two consequences, both measured in §C:

1.  A legitimate client that rewrites the same range with DIFFERENT bytes on one
    open handle is answered kXR_ok and loses the second write.  The file keeps
    the first bytes; nothing is logged above debug level.
2.  The replay the journal exists to catch cannot reach it.  The journal lives
    in the open-file structure, so it dies with the handle, and the recovery path
    is a REOPEN.  A reopened handle starts with an empty journal, so the replayed
    write is executed — the double write the journal exists to prevent.

So the arm that advertises kXR_recoverWrts suppresses the writes it should keep
and executes the writes it should suppress.  §C asserts both halves and the
third mechanism that makes them worse: `kXR_sync` flushes the journal
(root/write/sync.c:92), so a client that syncs — which is what a client
establishing stable state does — loses the protection it was promised.

DEFECT CANDIDATE #84 — the collapse cache the only config for it cannot reach
----------------------------------------------------------------------------
The redirect cache `brix_collapse_redir` enables is consulted only inside
`brix_open_manager_dynamic`, which `brix_open_manager_redirect` calls only when
`conf->manager_mode` is set (root/read/open_manager.c:196-203).
`nginx_collapse_redir.conf` — the suite's only config that enables the flag —
sets a static `brix_manager_map` and NO `brix_manager_mode`, so its every open is
answered by the static-map branch (:207-215), which neither inserts into the
cache nor reads it.  The node advertises kXR_collapseRedir to clients the whole
time.  §E measures the cache working under manager_mode, and a static-map node
answering `"redirect"` and never `"redir-cache"` while advertising the bit.

DEFECT CANDIDATE #85 — `brix_virtual_redirector off` cannot clear the bit
------------------------------------------------------------------------
`kXR_attrVirtRdr` is set by `caps.virtual_redirector || (manager_map != NULL &&
cms.addr == NULL)` (session/protocol.c:81-83).  The second disjunct is how the
suite's `nginx_virtual_redir.conf` earns the bit — it never writes the directive
at all — and it means the `off` arm is not a way to say no: a static-map node
with no CMS advertises the redirector role however emphatically the config
denies it.  §D pins that, and pins that the flag remains the only route on a
node with no map, so this is an unconditional disjunct and not a broken flag.

DEFECT CANDIDATE #86 — the flag switches off a directive's syntax check
----------------------------------------------------------------------
The backend URL is parsed inside the export setup that
`brix_server_has_runtime_export()` gates, so `brix_supervisor on` does not merely
ignore `brix_storage_backend` at runtime (§B) — it stops nginx checking the
value at all.  `brix_storage_backend root://host:port/` (one trailing slash too
many) is an `nginx -t` failure on a data server, is silently accepted on a
supervisor, and is a failure again the moment the flag is written `off`.  §H
measures all three, which makes the arm the audit says nobody ever wrote the arm
that RESTORES a config-time check.

OBSERVATION — two spellings of "supervisor", neither implying the other
----------------------------------------------------------------------
`brix_supervisor` (a flag, into `caps.supervisor`) and `brix_cms_role supervisor`
(an enum token, into `cms.role`) are read by disjoint code.  The flag produces
kXR_attrSuper, removes the export and stamps a role letter; the token produces
the supervisor login Mode word and nothing else.  §G measures a node with the
token and not the flag: it keeps its export and advertises no attrSuper.
`test_audit15t_cms_role.py` owns the Mode word; the contribution here is that
the two are independent.

OBSERVATION — the merge inherits from a context the directives cannot occupy
---------------------------------------------------------------------------
`brix_node_caps_conf_merge` takes `prev` and applies parent-then-default for all
five, but every one of them is declared `NGX_STREAM_SRV_CONF` and nothing else,
so `stream{}` refuses the line and the parent slot can never hold a written
value.  The inheritance arm of that merge is unreachable, which §H measures as a
placement matrix rather than asserting from the header.

WHAT THIS FILE DOES NOT CLAIM
-----------------------------
The `on` arms' advertised bits belong to `test_protocol_flags.py`; the CMS login
Mode word and dispatch class to `test_audit15t_cms_role.py`; the
virtual-redirector role bits to `test_audit15b_virtual_redirector.py`; the mesh
registration handshake to the `cms_mesh_lib.py` topologies.  Each appears here
only as the control an `off` arm is read against.
"""

import os
import re
import time
from pathlib import Path

import pytest

from _test_conf_write_helpers import (_close, _connect, _login, _open,
                                      _open_handle, _read, _sync, _write,
                                      kXR_delete, kXR_new, kXR_ok,
                                      kXR_open_read, kXR_open_updt)
from config_parse import nginx_t
from fleet_lifecycle_ports import LIFECYCLE_SHARED_PORTS, PARSE_PLACEHOLDER_PORT
from server_registry import NginxInstanceSpec
from settings import BIND_HOST, HOST, NGINX_BIN
# The flags word and the redirect body are read by the modules that own them.
from test_audit15m_stream_coresidency import _redirect_target
from test_protocol_flags import _get_protocol_flags

pytestmark = [pytest.mark.timeout(300),
              pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-audit16j-caps")]

NAME = "lc-audit16j-caps"
_L = LIFECYCLE_SHARED_PORTS[NAME]
PORT = _L["port"]
OFF_PORT = _L["extra"]["OFF_PORT"]
SUPER_PORT = _L["extra"]["SUPER_PORT"]
WRTS_PORT = _L["extra"]["WRTS_PORT"]
MAP_PORT = _L["extra"]["MAP_PORT"]
COLLON_PORT = _L["extra"]["COLLON_PORT"]
COLLOFF_PORT = _L["extra"]["COLLOFF_PORT"]
CMS_PORT = _L["extra"]["CMS_PORT"]
DS_PORT = _L["extra"]["DS_PORT"]
ROLE_PORT = _L["extra"]["ROLE_PORT"]

# The five, in the order directives_caps.h declares them.
FLAGS = ("brix_metadata_only", "brix_supervisor", "brix_virtual_redirector",
         "brix_collapse_redir", "brix_recover_writes")

# ServerProtocolBody.flags bits (src/protocols/root/protocol/flags.h), named
# here only for the five a flag in FLAGS can set plus the two role bits two of
# them imply; test_protocol_flags.py holds the full table.
KXR_ISSERVER = 0x00000001
KXR_ISMANAGER = 0x00000002
KXR_ATTRMETA = 0x00000100
KXR_ATTRSUPER = 0x00000400
KXR_ATTRVIRTRDR = 0x00000800
KXR_RECOVERWRTS = 0x00001000
KXR_COLLAPSEREDIR = 0x00002000

# The bit each flag owns, which is what makes ONE all-five-`off` server a
# per-flag reading: the flags word is a pure OR of independent bits, so a word
# that differs from the reference names the flag whose bit moved.
OWNED_BIT = {"brix_metadata_only": KXR_ATTRMETA,
             "brix_supervisor": KXR_ATTRSUPER,
             "brix_virtual_redirector": KXR_ATTRVIRTRDR,
             "brix_collapse_redir": KXR_COLLAPSEREDIR,
             "brix_recover_writes": KXR_RECOVERWRTS}

OWNED_BITS = (KXR_ATTRMETA | KXR_ATTRSUPER | KXR_ATTRVIRTRDR
              | KXR_RECOVERWRTS | KXR_COLLAPSEREDIR)

KXR_REDIRECT = 4004

SEED = b"caps-16j-reference-payload\n"
DS_SEED = b"caps-16j-data-server-payload\n"


# --------------------------------------------------------------------------- #
# The instance                                                                 #
# --------------------------------------------------------------------------- #

class _Caps:
    """The ten-server instance, addressed by port.

    Every accessor takes a port rather than a name so a test reads as "this
    server answered this way" — the arms differ only in the directive lines the
    template writes, so the port IS the arm.
    """

    def __init__(self, endpoint, trees):
        self.endpoint = endpoint
        self.trees = trees

    def _logs(self):
        return Path(self.endpoint.prefix) / "logs"

    def errlog(self):
        """Instance prefixes are wiped at teardown, so failures quote inline."""
        log = self._logs() / "error.log"
        return log.read_text(errors="replace") if log.exists() else ""

    def access(self, which):
        """One server's brix access log, or "" before it has written a line."""
        log = self._logs() / f"{which}-access.log"
        return log.read_text(errors="replace") if log.exists() else ""

    def tree(self, which):
        return self.trees[which]


@pytest.fixture()
def caps(lifecycle, tmp_path):
    """Ten stream servers in one process, six trees seeded identically.

    The trees are seeded with the same bytes so a read that differs between two
    servers cannot be explained by their contents.  MAP_PORT, COLLON_PORT,
    COLLOFF_PORT and CMS_PORT get no tree on purpose: a manager owns no files,
    and giving one an export would let a fall-through serve locally and read as
    "the redirect did not happen" (open_manager.c:226 makes that explicit — a
    manager with an export serves the file itself).
    """
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx binary not executable: {NGINX_BIN}")

    trees = {}
    for which, seed in (("ref", SEED), ("off", SEED), ("super", SEED),
                        ("wrts", SEED), ("role", SEED), ("ds", DS_SEED)):
        tree = tmp_path / which
        tree.mkdir()
        (tree / "seed.bin").write_bytes(seed)
        trees[which] = tree

    endpoint = lifecycle.start(NginxInstanceSpec(
        name=NAME,
        template="nginx_audit16j_caps.conf",
        data_root=str(trees["ref"]),
        template_values={
            "BIND_HOST": BIND_HOST,
            "REF_DATA": str(trees["ref"]),
            "OFF_DATA": str(trees["off"]),
            "SUPER_DATA": str(trees["super"]),
            "WRTS_DATA": str(trees["wrts"]),
            "ROLE_DATA": str(trees["role"]),
            "DS_DATA": str(trees["ds"]),
        },
        reason="audit-16j the five node-capability flags at value granularity"))
    return _Caps(endpoint, trees)


# --------------------------------------------------------------------------- #
# Wire helpers — framing comes from the modules that own it                    #
# --------------------------------------------------------------------------- #

def _flags(port):
    return _get_protocol_flags(HOST, port)


def _session(port):
    """An anonymous logged-in session on one of the ten servers."""
    s = _connect(HOST, port)
    _login(s)
    return s


def _open_read(port, path="/seed.bin"):
    """Open for read and return (status, body) with the session closed.

    The redirect and refusal sections need the OPEN verdict and nothing after
    it, and a session left open holds a worker slot for the rest of the file.
    """
    s = _session(port)
    try:
        return _open(s, path, kXR_open_read)
    finally:
        s.close()


def _read_back(port, path, length):
    """Read `length` bytes of `path` through a fresh handle.

    Fresh because the question every §C case asks is what the SERVER stored, not
    what the writing handle believes it stored.
    """
    s = _session(port)
    try:
        handle = _open_handle(s, path, kXR_open_read)
        status, data = _read(s, handle, 0, length)
        _close(s, handle)
        return status, data
    finally:
        s.close()


# --------------------------------------------------------------------------- #
# §A — written-`off` against absent, for all five at once                      #
# --------------------------------------------------------------------------- #



# Shared helpers imported by sibling audit files (from test_audit16j_root_caps_flags import _parse, _diagnostics);
# kept here so the reexport makes them attributes of the main module.

def _parse(tmp_path, **slots):
    """`nginx -t` on the 16j scaffold with the named slots filled.

    Every slot defaults to empty so a case names only what it is about; the
    scaffold writes none of the five itself, so a negative about one of them is
    never answered by a duplicate diagnostic first.
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
    """Only the lines nginx itself flagged.

    A tmp_path name can contain the token under test, so a substring search over
    the whole output would match the temp directory rather than a diagnostic.
    """
    return [ln for ln in out.splitlines()
            if any(tag in ln for tag in ("[warn]", "[error]", "[crit]",
                                         "[emerg]"))]


def _open_details(caps, which, path, count, timeout=5.0):
    """The DETAIL field of every access-log line for `path` on one server.

    The line format is byte-frozen (`brix_access_format_line`,
    observability/accesslog/access_log.c:296-315): `"VERB PATH DETAIL"`.  The
    detail is where a redirect names its SOURCE, which is the only place the
    collapse cache is observable from outside the process.

    Polls for `count` lines because the log write trails the redirect that is
    already on the wire: a read that races it sees only the PREVIOUS open and
    answers a different question than the one asked.  Measured — the two-open
    cache reading below failed exactly that way once, reporting the first open's
    `registry` as the second's.  On a shortfall the list is returned short so
    the caller's own assertion reports what it saw.
    """
    pattern = r'"OPEN ' + re.escape(path) + r' ([^"]+)"'
    deadline = time.time() + timeout
    while True:
        hits = re.findall(pattern, caps.access(which))
        if len(hits) >= count or time.time() >= deadline:
            return hits
        time.sleep(0.05)
