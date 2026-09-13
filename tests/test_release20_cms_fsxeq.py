"""2.0 F17 — `brix_cms_fsxeq`: an operator program in place of a forwarded
namespace op (release-2.0 readiness register, axis (e) row F17).

    brix_cms_fsxeq {chmod|mkdir|mkpath|mv|rm|rmdir|trunc}... <program> [<arg>...]
    brix_cms_fsxeq_timeout <time>

Stock cmsd (`cms.fsxeq`) lets a site answer the namespace ops a manager
forwards down to a data node with its own program instead of the built-in
filesystem call — the way a site whose namespace lives in a database, or whose
deletes must go through an archive workflow, plugs itself in.  The program
REPLACES the op: XrdOucProg appends the op's own arguments to the configured
command line, exit 0 is success, and no op name is injected (an operator who
points several ops at one program bakes a literal argument into the line).

Pinned here:

  success   a program named for an op runs instead of the built-in leg, sees
            the op's own arguments in stock order after the configured tokens,
            and its exit 0 makes the node answer like stock cmsd — silently;
            an op the operator did NOT name still takes the built-in leg
  error     a program that exits non-zero fails the op with kYR_error; a
            program that hangs is killed at brix_cms_fsxeq_timeout and fails
            the op inside the deadline WITHOUT stalling the event loop (the
            node answers a ping while the program is still hung); the grammar
            refuses a line with no op, no program, a duplicate op or too many
            tokens
  security  a group- or world-writable program is refused at `nginx -t`; a
            manager-supplied path containing ".." never reaches the program at
            all (the lexical gate runs before the fork, because an external
            program has none of openat2's RESOLVE_BENEATH floor); a read-only
            export refuses the op before any program is forked; and the
            program inherits no worker descriptor and is handed no credential
            material — not in argv, not in its environment, not as an fd

Lab: four `lc-r20-fsxeq-*` data nodes, each dialling its own Python manager
peer (the test_cms_state_have_select harness), plus `nginx -t` for the
parse-time arms.
"""

import os
import re
import stat
import subprocess
import time

import pytest

from server_registry import NginxInstanceSpec
from ephemeral_port import free_port
from test_cms_state_have_select import (
    _ManagerPeer,
    _send_frame,
    _ping_sanity,
)
from test_cms_prepadd import _pstr, _expect_error, _expect_silence
from test_release20_frm_knobs import _inherited_fds

pytestmark = [pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-r20-fsxeq")]

_DIR = os.path.join(os.environ["TMPDIR"], "xrd_r20_fsxeq")
REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
NGINX_BIN = os.environ.get("NGINX_BIN", "/tmp/nginx-1.28.3/objs/nginx")

CMS_RR_CHMOD  = 1
CMS_RR_MKDIR  = 3
CMS_RR_MKPATH = 4
CMS_RR_MV     = 5
CMS_RR_RM     = 8
CMS_RR_RMDIR  = 9
CMS_RR_TRUNC  = 23

IDENT = "usr.1:23@cli"


# ---------------------------------------------------------------------------
# Forwarded-op payloads (rrdata.c brix_cms_rrdata_parse)
# ---------------------------------------------------------------------------

def _mode_op(mode, path):
    """fwdArgA — chmod / mkdir / mkpath / trunc: ident, mode, path.  trunc
    reuses the Mode field to carry a decimal size."""
    return _pstr(IDENT) + _pstr(mode) + _pstr(path)


def _mv_op(path, path2):
    """fwdArgB — mv: ident, path, path2."""
    return _pstr(IDENT) + _pstr(path) + _pstr(path2)


def _path_op(path):
    """fwdArgC — rm / rmdir: ident, path."""
    return _pstr(IDENT) + _pstr(path)


# ---------------------------------------------------------------------------
# The operator program
# ---------------------------------------------------------------------------

def _recorder(tmp, name, report, body="exit 0", mode=0o755, extra=""):
    """A program that records the argv it was handed and then does `body`.

    It deliberately does NOT perform the filesystem op: a test asserts the
    directory/file the built-in leg would have produced is absent, which is
    what proves the program REPLACED that leg rather than running beside it.
    """
    p = os.path.join(tmp, name)
    with open(p, "w") as f:
        f.write("#!/bin/sh\n"
                # $0 is recorded too: the pin covers argv[0], which stock
                # XrdOucProg sets to the configured program itself.
                "{ printf 'ARGV [%s]' \"$0\"\n"
                '  for a in "$@"; do printf " [%s]" "$a"; done\n'
                "  printf '\\n'\n"
                "} >> " + report + "\n" + extra + body + "\n")
    os.chmod(p, mode)
    return p


def _fd_recorder(tmp, name, report, fds, env):
    """Record argv, environment and fds without shell-redirection aliases."""
    p = os.path.join(tmp, name)
    with open(p, "w") as f:
        f.write(f'''#!/usr/bin/python3
import os
import sys

with open({report!r}, "a", encoding="utf-8") as recorded:
    recorded.write("ARGV [" + os.path.abspath(__file__) + "]" +
                   "".join(" [" + arg + "]" for arg in sys.argv[1:]) + "\\n")

entries = []
for name in os.listdir("/proc/self/fd"):
    if not name.isdigit():
        continue
    try:
        entries.append((int(name), os.readlink("/proc/self/fd/" + name)))
    except FileNotFoundError:
        pass
with open({fds!r}, "w", encoding="utf-8") as listing:
    for number, target in sorted(entries):
        listing.write(f"{{number}} -> {{target}}\\n")

with open({env!r}, "w", encoding="utf-8") as environment:
    for key, value in sorted(os.environ.items()):
        environment.write(key + "=" + value + "\\n")
''')
    os.chmod(p, 0o755)
    return p


def _nonempty(path):
    return os.path.exists(path) and os.path.getsize(path) > 0


def _wait_file(path, deadline_s=8.0):
    """The file's text once it has content, or "" if it never gets any."""
    path = str(path)
    deadline = time.time() + deadline_s
    while time.time() < deadline and not _nonempty(path):
        time.sleep(0.05)
    return open(path).read() if os.path.exists(path) else ""


def _argv_lines(report, deadline_s=8.0):
    """Every argv the program has recorded so far, newest last."""
    return [ln.strip() for ln in _wait_file(report, deadline_s).splitlines()
            if ln.startswith("ARGV")]


def _argv_tokens(line):
    return re.findall(r"\[([^\]]*)\]", line)


def _fd_is_leak(n, target, prog):
    """One `ls -l /proc/<pid>/fd` entry, judged.

    Anything above stderr is inherited worker state — listen sockets, live
    client connections, epoll instances, open log files — except the shell's
    own copy of the script it is executing.  On a stdio slot a socket or an
    epoll instance is always worker state; a pipe is too, except on stdout,
    which is this feature's own stdout capture and is expected there.
    """
    if n > 2:
        return target != prog
    if "socket:" in target or "anon_inode" in target:
        return True
    return n != 1 and "pipe:" in target


def _leaked_descriptors(fds, prog):
    return sorted(f"{n} -> {t}" for n, t in fds.items()
                  if _fd_is_leak(n, t, prog))


# ---------------------------------------------------------------------------
# Lab
# ---------------------------------------------------------------------------

_POOL = "thread_pool default threads=2 max_queue=64;"


def _start_node(lifecycle, name, extra_directives, subdir, pool=_POOL):
    """A data node dialling its own manager peer.  Returns (peer, conn, root)."""
    data_dir = os.path.join(_DIR, subdir, "data")
    os.makedirs(data_dir, exist_ok=True)
    mgr_port = free_port()
    peer = _ManagerPeer(mgr_port)
    peer.start()
    try:
        lifecycle.start(NginxInstanceSpec(
            name=name,
            template="nginx_cms_fsxeq_client.conf",
            protocol="root",
            readiness="tcp",
            data_root=data_dir,
            template_values={"MANAGER_PORT": mgr_port,
                             "THREAD_POOL": pool,
                             "EXTRA_DIRECTIVES": extra_directives},
            reason="2.0 F17 cms.fsxeq operator program for forwarded ops.",
        ))
    except Exception:
        peer.stop()
        raise
    conn = peer.wait_login()
    if conn is None:
        peer.stop()
        pytest.skip(f"nginx never dialled in to the CMS manager peer "
                    f"(err={peer._err})")
    return peer, conn, os.path.realpath(data_dir)


def _lines(*directives):
    """Whole config lines for the template's EXTRA_DIRECTIVES slot."""
    return "".join("        " + d + ";\n" for d in directives)


@pytest.fixture
def all_ops(lifecycle, tmp_path):
    """One program named for every op, plus a secret file the program must
    never see."""
    report = str(tmp_path / "argv.log")
    secret = tmp_path / "sss.keytab"
    secret.write_text("0 u:brix g:brix n:node N:1 c:1 e:0 k:S3CRET-KEYTAB-BYTES\n")
    secret.chmod(0o600)
    prog = _fd_recorder(str(tmp_path), "rec.py", report,
                        str(tmp_path / "fds.txt"), str(tmp_path / "env.txt"))
    peer, conn, root = _start_node(
        lifecycle, "lc-r20-fsxeq-all",
        _lines("brix_allow_write on",
               f"brix_sss_keytab {secret}",
               f"brix_cms_fsxeq chmod mkdir mkpath mv rm rmdir trunc {prog} --tag"),
        "all")
    try:
        yield {"conn": conn, "root": root, "report": report, "prog": prog,
               "secret": str(secret), "tmp": tmp_path}
    finally:
        peer.stop()


@pytest.fixture
def mkdir_only(lifecycle, tmp_path):
    """Only mkdir is named: every other op must still take the built-in leg."""
    report = str(tmp_path / "argv-mkdir.log")
    prog = _recorder(str(tmp_path), "mkdir_only.sh", report)
    peer, conn, root = _start_node(
        lifecycle, "lc-r20-fsxeq-one",
        _lines("brix_allow_write on", f"brix_cms_fsxeq mkdir {prog}"), "one")
    try:
        yield {"conn": conn, "root": root, "report": report}
    finally:
        peer.stop()


@pytest.fixture
def bad_programs(lifecycle, tmp_path):
    """One program, two behaviours: mkdir exits 3, rmdir hangs past the 1s
    deadline.  Both must fail the op closed, neither may touch the worker."""
    report = str(tmp_path / "argv-bad.log")
    prog = _recorder(str(tmp_path), "bad.sh", report,
                     body='case "$1" in\n'
                          '  --hang) sleep 30; exit 0 ;;\n'
                          '  *) exit 3 ;;\n'
                          'esac')
    peer, conn, root = _start_node(
        lifecycle, "lc-r20-fsxeq-bad",
        _lines("brix_allow_write on",
               "brix_cms_fsxeq_timeout 1s",
               f"brix_cms_fsxeq mkdir {prog}",
               f"brix_cms_fsxeq rmdir {prog} --hang"), "bad")
    try:
        yield {"conn": conn, "root": root, "report": report}
    finally:
        peer.stop()


@pytest.fixture
def no_pool(lifecycle, tmp_path):
    """A program is configured but the config declares no thread pool, so the
    run has nowhere to be posted.  The op must be refused, never silently
    handed back to the built-in leg."""
    report = str(tmp_path / "argv-nopool.log")
    prog = _recorder(str(tmp_path), "nopool.sh", report)
    peer, conn, root = _start_node(
        lifecycle, "lc-r20-fsxeq-nopool",
        _lines("brix_allow_write on", f"brix_cms_fsxeq mkdir {prog}"),
        "nopool", pool="")
    try:
        yield {"conn": conn, "root": root, "report": report}
    finally:
        peer.stop()


@pytest.fixture
def read_only(lifecycle, tmp_path):
    """A read-only export with a program configured: phase-105's gate must
    refuse the op BEFORE the program is forked."""
    report = str(tmp_path / "argv-ro.log")
    prog = _recorder(str(tmp_path), "ro.sh", report)
    peer, conn, root = _start_node(
        lifecycle, "lc-r20-fsxeq-ro",
        _lines("brix_allow_write off", f"brix_cms_fsxeq mkdir {prog}"), "ro")
    try:
        yield {"conn": conn, "root": root, "report": report}
    finally:
        peer.stop()


# ---------------------------------------------------------------------------
# nginx -t arms
# ---------------------------------------------------------------------------

def _nginx_t(root, srv_directives):
    (root / "logs").mkdir(exist_ok=True)
    (root / "data").mkdir(exist_ok=True)
    conf = root / "fsxeq.conf"
    conf.write_text(f"""daemon off; error_log {root}/logs/e.log info;
pid {root}/n.pid; thread_pool default threads=2;
events {{ worker_connections 64; }}
stream {{ server {{ listen unix:{root}/s.sock;
    brix_root on; brix_storage_backend posix:{root}/data; brix_auth none;
    {srv_directives}
}} }}
""")
    p = subprocess.run([NGINX_BIN, "-t", "-p", str(root), "-c", str(conf)],
                       capture_output=True, text=True, timeout=30)
    return p.returncode, p.stderr + p.stdout


# ===========================================================================
# success
# ===========================================================================

class TestFsxeqReplacesTheBuiltinLeg:

    def test_the_program_answers_the_op_and_sees_stock_argv(self, all_ops):
        """(success) every op the operator named is answered by the program,
        not by the filesystem: the reply is stock cmsd's silence, the argv is
        the configured tokens followed by the op's own arguments in stock
        order, the path is the PHYSICAL path, and nothing the built-in leg
        would have created exists on disk."""
        conn, root = all_ops["conn"], all_ops["root"]
        report, prog = all_ops["report"], all_ops["prog"]

        _send_frame(conn, 0x11, CMS_RR_MKDIR, payload=_mode_op("755", "/d1"))
        _expect_silence(conn)
        assert not os.path.exists(os.path.join(root, "d1")), \
            "the built-in mkdir ran as well — the program did not replace it"

        _send_frame(conn, 0x12, CMS_RR_TRUNC, payload=_mode_op("4096", "/f1"))
        _expect_silence(conn)
        _send_frame(conn, 0x13, CMS_RR_MV, payload=_mv_op("/a", "/b"))
        _expect_silence(conn)
        _send_frame(conn, 0x14, CMS_RR_RM, payload=_path_op("/gone"))
        _expect_silence(conn)
        _send_frame(conn, 0x15, CMS_RR_CHMOD, payload=_mode_op("640", "/c1"))
        _expect_silence(conn)

        lines = _argv_lines(report)
        assert len(lines) >= 5, f"only {len(lines)} runs recorded: {lines}"
        got = [_argv_tokens(ln) for ln in lines[:5]]
        assert got == [
            [prog, "--tag", "0755", f"{root}/d1"],
            [prog, "--tag", "4096", f"{root}/f1"],
            [prog, "--tag", f"{root}/a", f"{root}/b"],
            [prog, "--tag", f"{root}/gone"],
            [prog, "--tag", "0640", f"{root}/c1"],
        ], got
        _ping_sanity(conn)

    def test_an_unnamed_op_still_takes_the_builtin_leg(self, mkdir_only):
        """(success) the hook is per op: rmdir, which no directive names, is
        executed by the node itself — the program is never run for it."""
        conn, root = mkdir_only["conn"], mkdir_only["root"]
        victim = os.path.join(root, "doomed")
        os.makedirs(victim, exist_ok=True)

        _send_frame(conn, 0x21, CMS_RR_RMDIR, payload=_path_op("/doomed"))
        deadline = time.time() + 6.0
        while time.time() < deadline and os.path.exists(victim):
            time.sleep(0.1)
        assert not os.path.exists(victim), \
            "the built-in rmdir did not run for an op with no fsxeq program"
        _expect_silence(conn)

        # mkdir IS named, so the program takes it and no directory appears.
        _send_frame(conn, 0x22, CMS_RR_MKDIR, payload=_mode_op("755", "/made"))
        _expect_silence(conn)
        assert _argv_lines(mkdir_only["report"]), "the mkdir program never ran"
        assert not os.path.exists(os.path.join(root, "made"))
        _ping_sanity(conn)


# ===========================================================================
# error
# ===========================================================================

class TestFsxeqFailsClosed:

    def test_a_failing_program_fails_the_op(self, bad_programs):
        """(error) a non-zero exit is a failed op: kYR_error carrying the exit
        code, byte-shaped exactly like the built-in leg's failure, and the CMS
        link survives it."""
        conn = bad_programs["conn"]
        _send_frame(conn, 0x31, CMS_RR_MKDIR, payload=_mode_op("755", "/nope"))
        text = _expect_error(conn, 0x31)
        assert b"fsxeq program exited 3" in text, text
        _ping_sanity(conn)

    def test_a_hung_program_is_killed_without_stalling_the_worker(
            self, bad_programs):
        """(error) a program that never exits is SIGKILLed at
        brix_cms_fsxeq_timeout and the op fails inside the deadline — and,
        because the run is a thread-pool task, the node answers a ping while
        that program is still hung."""
        conn = bad_programs["conn"]
        started = time.time()
        _send_frame(conn, 0x32, CMS_RR_RMDIR, payload=_path_op("/hangs"))

        # The event loop is not the thing that is blocked.
        _ping_sanity(conn)
        assert time.time() - started < 3.0, \
            "the ping waited for the hung program — the event loop stalled"

        text = _expect_error(conn, 0x32, deadline_s=15.0)
        assert b"fsxeq program timed out" in text, text
        assert time.time() - started < 20.0
        _ping_sanity(conn)

    @pytest.mark.parametrize("line, needle", [
        # Two tokens, so NGX_CONF_2MORE is satisfied and the handler is the
        # one that speaks: the line names no op at all.
        ("brix_cms_fsxeq /bin/true --tag;",
         "must begin with one or more of chmod mkdir"),
        ("brix_cms_fsxeq mkdir rmdir;", "no program named after the op list"),
        ("brix_cms_fsxeq mkdir /bin/true; brix_cms_fsxeq mkdir /bin/false;",
         "already has a program"),
        ("brix_cms_fsxeq mkdir /bin/true a b c d e f g h i j k l m;",
         "at most"),
        ("brix_cms_fsxeq mkdir true;", "must be an absolute program path"),
        ("brix_cms_fsxeq mkdir;", "invalid number of arguments"),
        ("brix_cms_fsxeq_timeout soon;", "invalid value"),
    ], ids=["no-op", "no-program", "duplicate-op", "too-many-tokens",
            "relative-program", "one-argument", "bad-timeout"])
    def test_grammar_rejections(self, tmp_path, line, needle):
        """(error) every malformed line is refused at `nginx -t` with a message
        an operator can act on — never silently ignored."""
        rc, out = _nginx_t(tmp_path, line)
        assert rc != 0 and needle in out, out

    def test_the_stock_grammar_parses(self, tmp_path):
        """(success, grammar) the stock shape — several ops, a program and a
        literal disambiguating argument — is accepted."""
        rc, out = _nginx_t(tmp_path,
                           "brix_cms_fsxeq mkdir mkpath rmdir /bin/true ns; "
                           "brix_cms_fsxeq_timeout 5s;")
        assert rc == 0, out


# ===========================================================================
# security negatives
# ===========================================================================

class TestFsxeqSecurityNegatives:

    def test_group_writable_program_is_refused_at_parse_time(self, tmp_path):
        """(security-neg) the program runs with the worker's credentials, so
        one anybody else can rewrite is a privilege hand-off — refused at
        `nginx -t`, like brix_frm_stagecmd and brix_frm_purge_polprog."""
        prog = tmp_path / "loose.sh"
        prog.write_text("#!/bin/sh\nexit 0\n")
        prog.chmod(0o775)
        assert stat.S_IMODE(prog.stat().st_mode) & stat.S_IWGRP
        rc, out = _nginx_t(tmp_path, f"brix_cms_fsxeq mkdir {prog};")
        assert rc != 0 and "group- or world-writable" in out, out

    def test_a_traversal_path_never_reaches_the_program(self, all_ops):
        """(security-neg) THE property this feature could quietly lose: the
        built-in leg is confined by openat2 RESOLVE_BENEATH, an external
        program is not.  A hostile manager's ".." path is refused by the
        lexical gate in front of the fork, so the program is never even run
        with it."""
        conn, report = all_ops["conn"], all_ops["report"]
        before = len(_argv_lines(report, deadline_s=0.5))

        for streamid, path in ((0x41, "/../etc/stolen"),
                               (0x42, "/data/../../etc/stolen"),
                               (0x43, "relative/path")):
            _send_frame(conn, streamid, CMS_RR_MKDIR,
                        payload=_mode_op("755", path))
            assert b"fsxeq path denied" in _expect_error(conn, streamid)

        # mv is gated on BOTH paths.
        _send_frame(conn, 0x44, CMS_RR_MV, payload=_mv_op("/ok", "/../evil"))
        assert b"fsxeq path denied" in _expect_error(conn, 0x44)

        after = _argv_lines(report, deadline_s=1.0)
        assert len(after) == before, \
            "a refused path still reached the program:\n" + "\n".join(after)
        _ping_sanity(conn)

    def test_a_read_only_export_refuses_before_forking(self, read_only):
        """(security-neg) the phase-105 mutation gate runs FIRST: a read-only
        export answers "Read-only file system" and the operator program is
        never forked, so a program can never be the way a forbidden posture
        gets written through."""
        conn, report = read_only["conn"], read_only["report"]
        _send_frame(conn, 0x51, CMS_RR_MKDIR, payload=_mode_op("755", "/nope"))
        text = _expect_error(conn, 0x51)
        assert b"Read-only file system" in text, text
        assert not _argv_lines(report, deadline_s=1.0), \
            "the program ran on a read-only export"
        _ping_sanity(conn)

    def test_no_thread_pool_fails_the_op_closed(self, no_pool):
        """(security-neg) fail CLOSED, not open: with no thread pool there is
        nowhere to run the program, and the node must refuse the op rather
        than fall through to the built-in filesystem leg the operator replaced
        precisely so it would NOT run."""
        conn, root = no_pool["conn"], no_pool["root"]
        _send_frame(conn, 0x71, CMS_RR_MKDIR, payload=_mode_op("755", "/np"))
        text = _expect_error(conn, 0x71)
        assert b"fsxeq program not runnable" in text, text
        assert not os.path.exists(os.path.join(root, "np")), \
            "the built-in mkdir ran after the program could not be posted"
        assert not _argv_lines(no_pool["report"], deadline_s=1.0)
        _ping_sanity(conn)

    def test_the_program_inherits_no_worker_descriptor(self, all_ops):
        """(security-neg) the program runs with stdin/stdout/stderr only —
        never a worker listen socket, a live client connection, an epoll
        instance, a log descriptor or the export root fd.  A stray child
        holding a listen socket is what keeps a port bound across a restart;
        holding the root fd would hand it the confinement anchor itself."""
        conn = all_ops["conn"]
        _send_frame(conn, 0x61, CMS_RR_MKDIR, payload=_mode_op("755", "/probe"))
        _expect_silence(conn)

        listing = _wait_file(all_ops["tmp"] / "fds.txt")
        fds = _inherited_fds(listing)
        assert set(fds) >= {0, 1, 2}, listing        # a real listing

        leaked = _leaked_descriptors(fds, all_ops["prog"])
        assert not leaked, ("the fsxeq program inherited worker descriptors:\n"
                            + "\n".join(leaked))
        assert all_ops["root"] not in listing, \
            "the program inherited the export root descriptor"
        _ping_sanity(conn)

    def test_the_program_is_handed_no_credential_material(self, all_ops):
        """(security-neg) the node's SSS keytab is configured on this plane and
        must reach the program by no route at all: not its argv, not its
        environment, not an inherited descriptor."""
        conn, secret = all_ops["conn"], all_ops["secret"]
        _send_frame(conn, 0x62, CMS_RR_MKDIR, payload=_mode_op("755", "/probe2"))
        _expect_silence(conn)

        env = _wait_file(all_ops["tmp"] / "env.txt")
        listing = _wait_file(all_ops["tmp"] / "fds.txt")
        argv = _argv_lines(all_ops["report"])[-1]

        for where, text in (("environment", env), ("descriptor table", listing),
                            ("argv", argv)):
            assert secret not in text, f"the keytab PATH reached the {where}"
            assert "S3CRET-KEYTAB-BYTES" not in text, \
                f"the keytab BYTES reached the {where}"
        _ping_sanity(conn)
