"""2.0 readiness F1 (ADR-3b) — the six wired ``brix_frm_*`` engine knobs.

Until 2.0 thirteen ``brix_frm_*`` directives were accepted and ignored (ADR-3).
ADR-3b wires six of them into the stage engine and drops the other seven:

  * ``brix_frm_queue_path``   durable stage-journal directory (worker mkdir
                              0700; ``brix_frm on`` demands it, as in 1.x).
                              Replaces the env-only BRIX_STAGE_JOURNAL_DIR,
                              which stays a fallback for servers without
                              ``brix_frm on``.
  * ``brix_frm_stagecmd``     the exec MSS adapter program.  The directive
                              beats $BRIX_FRM_STAGECMD and no longer inherits
                              ``brix_prepare_command``.
  * ``brix_frm_copymax``      scheduler in-flight bound (default 8).
  * ``brix_frm_fail_retries`` dead-letter attempt cap (default 5).
  * ``brix_frm_fail_backoff`` worker-0 retry sweep re-driving FAILED journal
                              records older than the backoff (default 60s,
                              floor 1s); armed only with a durable queue_path.
  * ``brix_frm_copy_timeout`` exec child deadline (pidfd poll + SIGKILL +
                              ETIMEDOUT; default 0 = none; not applied to dread).

Static legs pin the grammar and every config-time diagnostic with ``nginx -t``
over unix sockets (no port).  Live legs drive a stagecmd script through
kXR_mkdir/rcreate on a ``tape://exec`` export, and the fail_backoff +
fail_retries pair through a dead-origin write-through export whose FAILED
record must be re-driven and dead-lettered WITHOUT a restart.  The seven
removed names are pinned as ``unknown directive`` by
test_release20_directive_surface.py.
"""

import os
import re
import struct
import subprocess
import time
from pathlib import Path

import pytest

from settings import BIND_HOST, NGINX_BIN
from lib_py.util import budget_scale
from cmdscripts.live_common import inject_nginx_load_modules, inject_nginx_runtime_paths
from brix_suite.fd_probe import (parse_identity, write_fd_probe,
                                 write_identity_probe)
from server_registry import NginxInstanceSpec
from official_interop_lib import worker_reachable

import _test_session_bind_helpers as H
from _test_release20_metrics_helpers import wait_port
from _test_xfer_wt_wire import write_file
from test_xfer_wt_journal import (BRIX_SREQ_FAILED, F_ATTEMPTS, F_DST_KEY,
                                  F_STATE, _cstr, _read_request,
                                  _scan_flush_record)

pytestmark = [pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-r20-frm-knobs")]

_SERVER = "lc-r20-frm-knobs"
TEMPLATE = "nginx_lc_r20_frm_knobs.conf"
kXR_mkdir = 3008

WIRED = ("brix_frm_queue_path", "brix_frm_stagecmd", "brix_frm_copymax",
         "brix_frm_fail_retries", "brix_frm_fail_backoff",
         "brix_frm_copy_timeout")


# --------------------------------------------------------------------------
# static legs: nginx -t over a unix socket
# --------------------------------------------------------------------------

def _server(root: Path, directives: str, tag: str = "a") -> str:
    # Prefix-relative Unix names preserve distinct servers without path limits.
    return (f"server {{ listen unix:{tag}.sock; brix_root on; "
            f"brix_storage_backend posix:{root}/data; brix_auth none; "
            f"{directives} }}")


def _nginx_t(root: Path, servers: str, main: str = ""):
    (root / "logs").mkdir(exist_ok=True)
    (root / "data").mkdir(exist_ok=True)
    conf = root / "knobs.conf"
    conf.write_text(f"""daemon off; error_log {root}/logs/e.log info;
pid {root}/n.pid; thread_pool default threads=2;
{main}
events {{ worker_connections 64; }}
stream {{ {servers} }}
""")
    inject_nginx_load_modules(conf)
    inject_nginx_runtime_paths(conf, root)
    p = subprocess.run([str(NGINX_BIN), "-t", "-p", str(root), "-c", str(conf)],
                       capture_output=True, text=True, timeout=30)
    return p.returncode, p.stderr + p.stdout


def _frm_on(root: Path) -> str:
    """The minimum a brix_frm server needs to parse: on + its journal path."""
    return f"brix_frm on; brix_frm_queue_path {root}/journal; "


def _every_knob(root: Path) -> str:
    return (_frm_on(root) +
            "brix_frm_stagecmd /bin/true; brix_frm_copymax 4; "
            "brix_frm_fail_retries 3; brix_frm_fail_backoff 5s; "
            "brix_frm_copy_timeout 30s;")


def test_every_wired_knob_parses(tmp_path):
    rc, out = _nginx_t(tmp_path, _server(tmp_path, _every_knob(tmp_path)))
    assert rc == 0, f"the ADR-3b grammar no longer parses:\n{out}"
    assert "is ignored" not in out, out


@pytest.mark.parametrize("directive,needle", [
    ("brix_frm on;", "brix_frm on requires brix_frm_queue_path"),
    ("{on} brix_frm_copymax 0;", "brix_frm_copymax must be at least 1"),
    ("{on} brix_frm_fail_retries 0;", "brix_frm_fail_retries must be at least 1"),
    ("brix_frm on; brix_frm_queue_path relative/journal;", "must be an absolute path"),
    ("{on} brix_frm_stagecmd bin/true;", "must be an absolute program path"),
    ("{on} brix_frm_copymax banana;", "invalid number"),
    ("{on} brix_frm_fail_backoff soon;", "invalid value"),
], ids=["no-queue_path", "copymax-0", "fail_retries-0", "relative-queue_path",
        "relative-stagecmd", "copymax-nan", "fail_backoff-nan"])
def test_bad_values_are_refused(tmp_path, directive, needle):
    directive = directive.format(on=_frm_on(tmp_path))
    rc, out = _nginx_t(tmp_path, _server(tmp_path, directive))
    assert rc != 0, f"{directive!r} unexpectedly accepted"
    assert needle in out, f"expected {needle!r} for {directive!r}, got:\n{out}"


def test_group_or_world_writable_stagecmd_is_refused(tmp_path):
    """Security negative: a program anyone else can rewrite must not become the
    MSS adapter the worker execs on every recall."""
    cmd = tmp_path / "loose.sh"
    cmd.write_text("#!/bin/sh\nexit 0\n")
    cmd.chmod(0o777)
    rc, out = _nginx_t(tmp_path, _server(
        tmp_path, f"{_frm_on(tmp_path)} brix_frm_stagecmd {cmd};"))
    assert rc != 0, "a world-writable stagecmd was accepted"
    assert "group- or world-writable" in out, out
    cmd.chmod(0o700)
    rc, out = _nginx_t(tmp_path, _server(
        tmp_path, f"{_frm_on(tmp_path)} brix_frm_stagecmd {cmd};"))
    assert rc == 0, f"the same program at 0700 must be accepted:\n{out}"


@pytest.mark.parametrize("a,b,needle", [
    ("brix_frm_copymax 4;", "brix_frm_copymax 5;",
     "brix_frm_copymax 5 differs from the value another brix_frm server "
     "published (4)"),
    ("brix_frm_stagecmd /bin/true;", "brix_frm_stagecmd /bin/false;",
     "brix_frm_stagecmd \"/bin/false\" differs from the value another "
     "brix_frm server published (\"/bin/true\")"),
], ids=["numeric", "string"])
def test_process_wide_knobs_must_agree_across_servers(tmp_path, a, b, needle):
    """The stage engine is process-wide: two ``brix_frm on`` servers that
    publish different values are a configuration error, never a silent
    last-writer-wins."""
    servers = (_server(tmp_path, f"{_frm_on(tmp_path)} {a}", "a")
               + _server(tmp_path, f"{_frm_on(tmp_path)} {b}", "b"))
    rc, out = _nginx_t(tmp_path, servers)
    assert rc != 0, "disagreeing process-wide knobs were accepted"
    assert needle in out, f"expected {needle!r}, got:\n{out}"
    assert "the stage engine is process-wide" in out, out


def test_agreeing_servers_publish_once(tmp_path):
    servers = (_server(tmp_path, _every_knob(tmp_path), "a")
               + _server(tmp_path, _every_knob(tmp_path), "b"))
    rc, out = _nginx_t(tmp_path, servers)
    assert rc == 0, f"two identical brix_frm servers must agree:\n{out}"


def test_knob_on_a_frm_off_server_warns_ignored(tmp_path):
    rc, out = _nginx_t(tmp_path, _server(
        tmp_path, "brix_frm_copymax 4; brix_frm_copy_timeout 2s;"))
    assert rc == 0, out
    for name in ("brix_frm_copymax", "brix_frm_copy_timeout"):
        assert f"{name} is ignored: brix_frm is off in this server" in out, out


# --------------------------------------------------------------------------
# live legs
# --------------------------------------------------------------------------

def _launch(lifecycle, backend, server_directives, main="", env=None):
    ep = lifecycle.start(NginxInstanceSpec(
        name=_SERVER,
        template=TEMPLATE,
        protocol="root",
        env=env or {},
        template_values={"BIND_HOST": BIND_HOST, "BACKEND": backend,
                         "MAIN_DIRECTIVES": main,
                         "SERVER_DIRECTIVES": server_directives},
        reason="2.0 F1 brix_frm_* engine knobs"))
    assert wait_port(ep.port), f"{_SERVER} never became connectable"
    return ep


def _error_log(ep) -> str:
    return (Path(ep.pidfile).parent / "error.log").read_text(errors="replace")


def _wait_log(ep, needle, timeout=10.0) -> str:
    deadline = time.time() + timeout
    text = ""
    while time.time() < deadline:
        text = _error_log(ep)
        if needle in text:
            return text
        time.sleep(0.2)
    raise AssertionError(f"{needle!r} never reached error.log:\n{text[-3000:]}")


def _script(tmp_path, name, cases: str) -> Path:
    s = tmp_path / name
    s.write_text("#!/bin/sh\ncase \"$1\" in\n" + cases + "  *) exit 0 ;;\nesac\n")
    s.chmod(0o755)     # exec for the de-escalated worker; never group/world-writable
    return s


def _exec_lab(lifecycle, tmp_path, stagecmd, extra="", main="", env=None):
    buffer = tmp_path / "buffer"
    ns = tmp_path / "ns"
    cache = tmp_path / "cache"
    for d in (buffer, ns, cache):
        d.mkdir(exist_ok=True)
    journal = tmp_path / "journal"          # the worker creates this leaf
    worker_reachable(buffer, ns, cache, tmp_path)
    directives = (f"brix_export {ns}; brix_cache_store posix:{cache}; "
                  "brix_cache_export /; "
                  f"brix_frm on; brix_frm_queue_path {journal}; "
                  f"brix_frm_stagecmd {stagecmd}; brix_frm_copymax 3; "
                  "brix_frm_fail_retries 2; brix_frm_fail_backoff 1s; "
                  f"{extra}")
    ep = _launch(lifecycle, f"tape://exec{buffer}", directives, main, env)
    return ep, journal


def _mkdir(sock, stream, path, mode=0o755):
    # ClientMkdirRequest: options[1] reserved[13] mode[2]; mkpath set
    body = struct.pack(">B13sH", 0x01, b"\x00" * 13, mode)
    return H._send_req(sock, stream, kXR_mkdir, body=body,
                       payload=path.encode() + b"\x00")


def _rcreate(port, path):
    H.ANON_HOST = BIND_HOST
    primary, _sessid, stream = H._establish_primary(port)
    try:
        return _mkdir(primary, stream, path)
    finally:
        primary.close()


def test_stagecmd_directive_drives_rcreate_without_the_environment(
        lifecycle, tmp_path):
    """Success: no $BRIX_FRM_STAGECMD anywhere; the directive alone selects the
    program, the worker creates queue_path, and start-up announces the
    engine-wide snapshot the six knobs produced."""
    marker = tmp_path / "rcreate.log"
    cmd = _script(tmp_path, "stagecmd.sh",
                  f"  rcreate) echo \"$1 $2\" >> {marker}; exit 0 ;;\n")
    ep, journal = _exec_lab(lifecycle, tmp_path, cmd)

    status, _ = _rcreate(ep.port, "/archive/run7")
    assert status == H.kXR_ok, f"exec rcreate failed: {status}"
    assert marker.exists() and "rcreate /archive/run7" in marker.read_text(), \
        "the directive-selected stagecmd did not receive rcreate"

    assert journal.is_dir(), "the worker did not create brix_frm_queue_path"
    log = _wait_log(ep, "stage engine: journal=")
    assert (f'stage engine: journal="{journal}" copymax=3 fail_retries=2 '
            "fail_backoff=1000 ms copy_timeout=0 ms") in log, log[-3000:]
    assert ("stage retry sweep armed (brix_frm_fail_backoff=1000 ms, "
            "brix_frm_fail_retries=2)") in log, log[-3000:]
    log = _wait_log(ep, '"exec" MSS adapter')
    assert f"(stagecmd={cmd}, copy_timeout=0 ms" in log, log[-3000:]


def test_copy_timeout_kills_a_hung_stagecmd(lifecycle, tmp_path):
    """Error: a stagecmd that never returns is killed at the deadline; the
    recall fails instead of pinning a scheduler slot forever."""
    cmd = _script(tmp_path, "hang.sh", "  rcreate) sleep 30; exit 0 ;;\n")
    ep, _journal = _exec_lab(lifecycle, tmp_path, cmd,
                             extra="brix_frm_copy_timeout 1s;")
    started = time.time()
    status, _ = _rcreate(ep.port, "/archive/hung")
    elapsed = time.time() - started
    assert status == H.kXR_error, f"a killed stagecmd must fail the mkdir: {status}"
    assert elapsed < 15, f"the deadline did not fire in time ({elapsed:.1f}s)"
    log = _wait_log(ep, "exceeded brix_frm_copy_timeout")
    # the adapter creates parents first, so the invocation that hangs (and is
    # named in the diagnostic) is `rcreate /archive`, not the leaf
    assert re.search(rf'stage command "{re.escape(str(cmd))} rcreate /archive(/hung)?" '
                     r"exceeded brix_frm_copy_timeout \(1000 ms\) and was killed",
                     log), log[-3000:]
    assert "(stagecmd=" in log and "copy_timeout=1000 ms" in log, log[-3000:]


def _proc_alive(pid: int) -> bool:
    try:
        stat = Path(f"/proc/{pid}/stat").read_text()
    except FileNotFoundError:
        return False
    return stat.rsplit(")", 1)[1].split()[0] != "Z"


def test_copy_timeout_kills_the_stage_programs_whole_process_group(
        lifecycle, tmp_path):
    """Error: the deadline kill reaches a shebang script's children too. A
    surviving grandchild keeps every descriptor it inherited open for its own
    lifetime -- before 2.0 that included the server's listen sockets, so a
    lab (or a restart) could not bind again until it died."""
    pidfile = tmp_path / "grandchild.pid"
    cmd = _script(tmp_path, "hang-tree.sh",
                  f"  rcreate) sleep 30 & echo $! > {pidfile}; wait; exit 0 ;;\n")
    # The deadline has to outlast the script's own start-up: the shell must
    # reach the line that records its child before the kill arrives, or there
    # is no pid to check. 1 s is enough on an idle host and not on a busy one
    # (seen 2026-09-17 in a lane: no pidfile, while the file passed standalone),
    # so scale it like every other wall-clock budget. Any value well under the
    # script's 30 s sleep still proves the deadline fires.
    seconds = max(1, int(round(budget_scale())))
    ep, _journal = _exec_lab(lifecycle, tmp_path, cmd,
                             extra=f"brix_frm_copy_timeout {seconds}s;")
    status, _ = _rcreate(ep.port, "/archive/tree")
    assert status == H.kXR_error, f"a killed stagecmd must fail the mkdir: {status}"
    _wait_log(ep, "exceeded brix_frm_copy_timeout")
    grandchild = int(pidfile.read_text().split()[0])
    deadline = time.time() + 5 * budget_scale()
    while _proc_alive(grandchild) and time.time() < deadline:
        time.sleep(0.1)
    assert not _proc_alive(grandchild), \
        f"the stage program's child {grandchild} outlived the deadline kill"


def test_the_stage_program_leads_its_own_session(lifecycle, tmp_path):
    """Success: the program leads its own session and process group and has
    no controlling terminal -- the property the deadline's group kill relies
    on, and what keeps its job control away from the worker's."""
    out = tmp_path / "identity.txt"
    probe = write_identity_probe(tmp_path / "identity.py")
    cmd = _script(tmp_path, "stat.sh",
                  f"  rcreate) echo $$ > {out}; {probe} >> {out}; exit 0 ;;\n")
    ep, _journal = _exec_lab(lifecycle, tmp_path, cmd)
    status, _ = _rcreate(ep.port, "/archive/session")
    assert status == H.kXR_ok, f"exec rcreate failed: {status}"
    pid, pgrp, session, tty = parse_identity(out.read_text())
    assert (pgrp, session) == (pid, pid), (pid, pgrp, session)
    assert tty == 0, "the stage program has a controlling terminal"


def _inherited_fds(listing):
    """{fd number: target} parsed out of an `ls -l /proc/<pid>/fd` listing.

    The probe runs `ls` in a child of the operator program, so `$$` is the
    program's own shell: what the listing shows is exactly what execvp() left
    open, which is the property under test.
    """
    fds = {}
    for line in listing.splitlines():
        f = line.split()
        if len(f) >= 3 and f[-2] == "->" and f[-3].isdigit():
            fds[int(f[-3])] = f[-1]
    return fds


def _server_descriptors(listing, script):
    """The `<fd> -> <target>` pairs an operator program must never hold.

    Two kinds: any descriptor above stderr -- the worker's listen sockets,
    live client connections, epoll instances, pipes and open log files all
    live there -- and a stdio slot pointing at a server object. The shell's
    own copy of the script it is executing (bash keeps it on fd 255) is not
    inherited state and does not count; neither does stderr pointing at the
    error log, which is simply the worker's stderr and is what "the program
    gets stdin/stdout/stderr" means for a daemon.
    """
    return sorted(
        f"{n} -> {t}" for n, t in _inherited_fds(listing).items()
        if (n > 2 and t != str(script))
        or (n <= 2 and any(o in t for o in ("socket:", "anon_inode", "pipe:"))))


def test_the_stage_program_inherits_no_server_descriptors(lifecycle, tmp_path):
    """Security negative: an operator program runs with stdin/stdout/stderr
    only -- never the worker's listen sockets, client connections, epoll,
    pipes or log descriptors (a listen socket is what a stray child keeps
    bound after a restart; a connection carries client traffic)."""
    fds = tmp_path / "fds.txt"
    cmd = write_fd_probe(tmp_path / "fds.py", fds)
    ep, _journal = _exec_lab(lifecycle, tmp_path, cmd)
    status, _ = _rcreate(ep.port, "/archive/fds")
    assert status == H.kXR_ok, f"exec rcreate failed: {status}"
    listing = fds.read_text()
    assert set(_inherited_fds(listing)) >= {0, 1, 2}, listing   # a real listing
    leaked = _server_descriptors(listing, cmd)
    assert not leaked, ("the stage program inherited server descriptors:\n"
                        + "\n".join(leaked))


def test_stagecmd_directive_wins_over_the_environment(lifecycle, tmp_path):
    """Security negative: an environment variable in the master's process
    environment must not redirect a configured adapter to another program."""
    env_marker = tmp_path / "from-env.log"
    conf_marker = tmp_path / "from-directive.log"
    env_cmd = _script(tmp_path, "env.sh",
                      f"  rcreate) echo \"$2\" >> {env_marker}; exit 0 ;;\n")
    conf_cmd = _script(tmp_path, "conf.sh",
                       f"  rcreate) echo \"$2\" >> {conf_marker}; exit 0 ;;\n")
    ep, _journal = _exec_lab(lifecycle, tmp_path, conf_cmd,
                             main=f"env BRIX_FRM_STAGECMD={env_cmd};",
                             env={"BRIX_FRM_STAGECMD": str(env_cmd)})
    status, _ = _rcreate(ep.port, "/archive/which")
    assert status == H.kXR_ok, status
    assert conf_marker.exists() and "/archive/which" in conf_marker.read_text()
    assert not env_marker.exists(), \
        "$BRIX_FRM_STAGECMD overrode brix_frm_stagecmd"


def _deadletter_records(journal: Path):
    d = journal / "deadletter"
    if not d.is_dir():
        return []
    out = []
    for name in sorted(os.listdir(d)):
        if name.endswith(".req"):
            rec = _read_request(str(d / name))
            if rec is not None:
                out.append(rec)
    return out


def _dead_origin_lab(lifecycle, tmp_path, journal: Path):
    """A brix_frm server whose async flush origin (root://127.0.0.1:1) is dead."""
    data = tmp_path / "data"
    stage = tmp_path / "stage"
    for d in (data, stage):
        d.mkdir(exist_ok=True)
    worker_reachable(data, stage, tmp_path)
    directives = (f"brix_export {data}; brix_stage on; "
                  f"brix_stage_store posix:{stage}; brix_stage_flush async; "
                  f"brix_frm on; brix_frm_queue_path {journal}; "
                  "brix_frm_fail_backoff 1s; brix_frm_fail_retries 2;")
    return _launch(lifecycle, "root://127.0.0.1:1", directives)  # net-literal-allow: a dead origin, never a bind address


def _wait_deadletter(journal: Path, name: str, timeout: float = 25):
    deadline = time.time() + timeout
    while time.time() < deadline:
        dead = [r for r in _deadletter_records(journal)
                if name in _cstr(r[F_DST_KEY])]
        if dead:
            return dead[0]
        time.sleep(0.3)
    return None


def _assert_dead_lettered(rec, journal: Path, name: str):
    assert rec is not None, (
        "the FAILED record was never dead-lettered by the retry sweep; "
        f"active={_scan_flush_record(str(journal), name)}")
    assert rec[F_STATE] == BRIX_SREQ_FAILED, rec[F_STATE]
    assert rec[F_ATTEMPTS] == 2, f"attempts={rec[F_ATTEMPTS]}, cap is 2"
    assert _scan_flush_record(str(journal), name) is None, \
        "a dead-lettered record must leave the active journal"


def test_fail_backoff_redrives_until_fail_retries_dead_letters(
        lifecycle, tmp_path):
    """Live journal: with a dead origin the async flush fails; the fail_backoff
    sweep re-drives the FAILED record every second WITHOUT a restart, and the
    second failed attempt (fail_retries 2) moves it to deadletter/."""
    journal = tmp_path / "journal"
    ep = _dead_origin_lab(lifecycle, tmp_path, journal)
    name = "r20_deadletter.bin"
    write_file(BIND_HOST, ep.port, f"/{name}", b"dead-origin-" + b"z" * 700)

    _assert_dead_lettered(_wait_deadletter(journal, name), journal, name)

    log = _wait_log(ep, "DEAD-LETTERED")
    assert "brix_frm_fail_retries reached while the origin stays unreachable" in log
    assert "attempts=2" in log, log[-3000:]
    assert "retry sweep - " in log and "dead-lettered/dropped" in log, log[-3000:]


def test_env_journal_fallback_never_arms_the_sweep(lifecycle, tmp_path):
    """Boundary pin: an env-only journal (no brix_frm_queue_path) keeps its
    1.x restart-only re-drive semantics — the sweep is never armed for it."""
    data = tmp_path / "data"
    stage = tmp_path / "stage"
    journal = tmp_path / "envjournal"
    for d in (data, stage, journal):
        d.mkdir(exist_ok=True)
    worker_reachable(data, stage, journal)
    directives = (f"brix_export {data}; brix_stage on; "
                  f"brix_stage_store posix:{stage}; brix_stage_flush async;")
    ep = _launch(lifecycle, "root://127.0.0.1:1", directives,  # net-literal-allow: a dead origin, never a bind address
                 main=f"env BRIX_STAGE_JOURNAL_DIR={journal};",
                 env={"BRIX_STAGE_JOURNAL_DIR": str(journal)})
    name = "r20_envonly.bin"
    write_file(BIND_HOST, ep.port, f"/{name}", b"env-only-" + b"e" * 300)
    time.sleep(3)
    log = _error_log(ep)
    assert "stage retry sweep armed" not in log, log[-3000:]
    assert not _deadletter_records(journal), "env-only journal was swept"
