"""Cluster-wide readdir fan-out (phase-115 W7.2b, parity-audit §7.10).

The gap the parity audit records is "xrootdfs has no multi-server fan-out".
Concretely: a CMS manager answers `kXR_dirlist` by REDIRECTING to a single
registered data server (`src/protocols/root/dirlist/handler.c:92-130` selects
one node via `brix_cms_answer_selected`), so a mount over a manager enumerates
one node's share of a directory and every file whose only replica lives
elsewhere is simply absent — a silent wrong answer, not an error. Stock XRootD
solves this client-side in `XrdFfsPosix_readdirall`; `brix_dirlist_all`
(`client/lib/fs/dirfanout.c`) is the same contract for this client, reached
from the FUSE mount with `--cluster-readdir`.

  * success   — a locate reply becomes exactly the set of data servers to ask;
                bracketed IPv6 literals survive; the union is sorted and each
                name appears once however many holders reported it
  * error     — a node that answers "not found" contributes nothing, but any
                OTHER per-node failure fails the whole call rather than
                returning a short listing the caller cannot distinguish from a
                complete one; the node table clamps instead of overflowing
  * security  — manager ('M'/'m') entries are never dialed (dialing one
                re-enters the single-node redirect this exists to bypass); a
                server-controlled reply cannot overrun a fixed buffer or leave
                a truncated hostname that would send us to the wrong host; every
                per-node connection is closed on every path

The wire behaviour needs a real multi-node CMS cluster plus a FUSE mount, which
this environment cannot provide, so the kernels are exercised directly by a C
unit (`tests/c/dirfanout_test.c`, `make -C client dirfanout`) and the wiring
around them is pinned by static guards here — the shape W7.3 established.

Run:
    PYTHONPATH=tests pytest tests/test_phase115_cluster_readdir_fanout.py -v
"""

import os
import re
import subprocess
from brix_suite.client_build import client_make
import sys

import pytest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLIENT_DIR = os.path.join(REPO, "client")
FANOUT_BIN = os.path.join(CLIENT_DIR, "bin", "dirfanout_test")

DIRFANOUT_C = os.path.join(CLIENT_DIR, "lib", "fs", "dirfanout.c")
OPS_H = os.path.join(CLIENT_DIR, "lib", "brix_ops.h")
FUSE_OPS_C = os.path.join(CLIENT_DIR, "lib", "posix", "fuse_ops.c")
XFS_META_C = os.path.join(CLIENT_DIR, "apps", "fs", "xrootdfs_meta.c")
XFS_C = os.path.join(CLIENT_DIR, "apps", "fs", "xrootdfs.c")
USAGE_C = os.path.join(CLIENT_DIR, "apps", "fs", "xrootdfs_usage.c")
MAKEFILE = os.path.join(CLIENT_DIR, "Makefile")

pytestmark = pytest.mark.timeout(300)


def _run_env():
    """Make the optional codec/krb5 libs resolvable for both link and runtime
    when the toolchain is a conda prefix; a no-op on a system build."""
    env = dict(os.environ)
    prefix = env.get("CONDA_PREFIX") or sys.prefix
    pcdir = os.path.join(prefix, "lib", "pkgconfig")
    if os.path.isdir(pcdir):
        libdir = os.path.join(prefix, "lib")
        env["LD_LIBRARY_PATH"] = libdir + os.pathsep + env.get("LD_LIBRARY_PATH", "")
        env["PKG_CONFIG_PATH"] = pcdir + os.pathsep + env.get("PKG_CONFIG_PATH", "")
    return env


@pytest.fixture(scope="module")
def fanout_bin():
    """Build only when missing — a failed link would delete a good pre-built
    binary, and this suite's static half is worth running either way."""
    out = b""
    if not os.path.exists(FANOUT_BIN):
        r = client_make(CLIENT_DIR, "dirfanout", env=_run_env(), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=600)
        out = r.stdout
    if not os.path.exists(FANOUT_BIN):
        pytest.skip("run `make -C client dirfanout`:\n"
                    f"{out.decode(errors='replace')[-800:]}")
    return FANOUT_BIN


def _read(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


_COMMENT = re.compile(r"/\*.*?\*/|//[^\n]*", re.S)


def _code(path):
    """The file with comments blanked out.

    Every guard below asks whether a source file DOES something. dirfanout.c's
    header explains at length what it must never do — skip a manager, swallow a
    failure — and a scan of the raw text would read that explanation as the
    offence it warns against. Newlines are preserved so line arithmetic holds."""
    return _COMMENT.sub(lambda m: re.sub(r"[^\n]", " ", m.group(0)),
                        _read(path))


_FUNC = re.compile(r"^([a-z_][a-z_0-9]*)\(.*?^\}", re.M | re.S)


def _functions(text):
    """{name: body} for every top-level function in a source file."""
    return {m.group(1): m.group(0) for m in _FUNC.finditer(text)}


class TestFanoutKernels:
    """The C unit binary: locate parsing, IPv6, clamping, dedup."""

    def test_the_fanout_kernel_units_all_pass(self, fanout_bin):
        """(success + error + security) every check the C harness makes, in one
        row because the binary reports them as one verdict. Its stderr is
        attached on failure so the failing check names itself."""
        p = subprocess.run([fanout_bin], env=_run_env(),
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                           timeout=120)
        assert p.returncode == 0, p.stdout.decode(errors="replace")
        text = p.stdout.decode(errors="replace")
        # The binary must actually have run its sections, not exited 0 early.
        for section in ("token selection", "IPv6 literals", "node cap",
                        "hostile reply", "dedup"):
            assert f"== {section}" in text, f"section never ran: {section}\n{text}"
        assert "FAIL" not in text, text


class TestFanoutFailurePolicy:
    """The asymmetry that makes the fan-out trustworthy."""

    def test_only_a_not_found_node_is_skipped(self):
        """(error) A node that does not hold the directory contributes nothing.
        Any other failure returns -1. If the skip predicate ever widened to
        `any error`, a dead or unauthenticated node would quietly shrink the
        listing — the exact silent-wrong-answer this feature removes."""
        fns = _functions(_code(DIRFANOUT_C))
        one = fns["dirfan_one"]
        assert "dirfan_not_found(st)" in one, \
            "dirfan_one no longer consults the not-found predicate"
        # The ONLY early success-return in the failure branch is the not-found
        # one; everything else must reach `return -1`.
        branch = one[one.index("if (rc != 0)"):]
        assert branch.count("return 0;") == 1, \
            f"more than one failure is being treated as success:\n{branch}"
        assert "return -1;" in branch

        nf = fns["dirfan_not_found"]
        assert "kXR_NotFound" in nf and "ENOENT" in nf, \
            "the not-found predicate stopped naming both not-found forms"

    def test_a_failed_node_aborts_the_whole_listing(self):
        """(error) The per-node loop must not `continue` past a failure: a
        partial union is indistinguishable from a complete one at the caller,
        so it is returned as an error instead."""
        fns = _functions(_code(DIRFANOUT_C))
        body = fns["brix_dirlist_all"]
        loop = body[body.index("for (i = 0; i < n_nodes"):]
        assert "return -1;" in loop, "a failing node no longer fails the call"
        assert "continue;" not in loop, \
            "a node failure is being skipped rather than reported"
        assert "free(acc.ents);" in loop, "the partial union is leaked on failure"

    def test_every_node_connection_is_closed_on_every_path(self):
        """(error) One dirlist per holder per readdir: a connection leaked on
        the failure path would exhaust the process's fds under a directory
        listing loop, long before anyone suspected the fan-out."""
        one = _functions(_code(DIRFANOUT_C))["dirfan_one"]
        # Exactly one close, placed after the dirlist and before every return
        # that can follow a successful connect.
        assert one.count("brix_close(&c);") == 1, \
            "the single close was duplicated or moved into a branch"
        after_close = one[one.index("brix_close(&c);"):]
        assert "brix_connect" not in after_close, \
            "a connect follows the close — some path now leaks"


class TestFanoutNeverDialsAManager:
    """The security-negative: what the fan-out refuses to talk to."""

    def test_only_data_server_entries_are_dialed(self):
        """(security) 'M'/'m' locate entries name MANAGERS. Dialing one asks it
        to redirect us to a single data server — precisely the behaviour being
        worked around — and on a multi-manager mesh it can bounce the client
        around the cluster. The token filter is the only thing preventing it."""
        code = _code(DIRFANOUT_C)
        fns = _functions(code)
        pred = fns["dirfan_is_server"]
        assert "'S'" in pred and "'s'" in pred, "the server filter lost a case"
        for manager in ("'M'", "'m'"):
            assert manager not in pred, \
                f"{manager} is accepted by the data-server filter"

        # There must be exactly ONE place nodes enter the table, and it is the
        # filtered one: a second, unfiltered path would bypass the check above.
        # Two occurrences = the definition plus its single call site.
        assert code.count("dirfan_is_server(") == 2, \
            "the server filter is defined once and applied at exactly one site"
        assert code.count("dirfan_one(") == 2, \
            "dirfan_one is defined once and called once (from the node loop)"
        loop_src = fns["brix_dirlist_all"]
        assert "dirfan_nodes_from_locate(" in loop_src, \
            "the node table no longer comes from the filtered parser"

    def test_the_endpoint_split_reuses_the_one_url_parser(self):
        """(security) A hand-rolled `host:port` split on the last colon turns
        `Sr[2001:db8::5]:1095` into a connection to some other host. The parser
        that already knows bracket syntax is used instead; the C unit proves the
        behaviour, this pins that no second splitter appears beside it."""
        parse = _functions(_code(DIRFANOUT_C))["dirfan_nodes_from_locate"]
        assert "brix_url_parse(" in parse, "the URL parser was dropped"
        for hand_rolled in ("strrchr", "strchr", "sscanf", "atoi"):
            assert hand_rolled not in parse, \
                f"{hand_rolled} suggests a second, bracket-blind host:port split"


class TestFanoutWiring:
    """A kernel nothing calls is not a feature."""

    def test_the_module_is_registered_in_the_client_build(self):
        """(error) A new client .c that is not in the Makefile compiles nowhere
        and links as an undefined symbol — or worse, silently as nothing."""
        assert "lib/fs/dirfanout.c" in _read(MAKEFILE), \
            "dirfanout.c is missing from the client source list"

    def test_the_public_entry_point_is_declared(self):
        assert "brix_dirlist_all(" in _read(OPS_H), \
            "brix_dirlist_all is not declared in brix_ops.h"
        assert "brix_dirlist_all(" in _code(FUSE_OPS_C), \
            "no FUSE op thunk reaches the fan-out"

    def test_readdir_selects_the_fanout_only_when_asked(self):
        """(success + error) Both branches must survive: the fan-out when
        --cluster-readdir is set, the single-node dirlist otherwise. A mount
        against a standalone server pays nothing, and a manager mount that
        forgot the flag keeps working (short, but working)."""
        readdir = _functions(_code(XFS_META_C))["xfs_readdir"]
        assert "g_dir_fanout" in readdir, "the flag is not consulted at readdir"
        assert "brix_fuse_op_dirlist_all" in readdir, "the fan-out op is unreachable"
        assert "brix_fuse_op_dirlist" in readdir, \
            "the single-node path was replaced rather than added to"

    def test_the_flag_is_both_parsable_and_documented(self):
        """(error) A flag the parser accepts but --help never mentions is
        shipped only to whoever read the diff."""
        assert '"--cluster-readdir"' in _code(XFS_C), \
            "--cluster-readdir is not matched by the option parser"
        assert "--cluster-readdir" in _read(USAGE_C), \
            "--cluster-readdir is absent from the usage text"
