"""Fleet sentinel — forensic half.

Wrap os.kill / os.killpg (inherited by every xdist worker) so that whenever a
FATAL signal is aimed at a registry nginx master, the caller's traceback and
the currently-running test's nodeid are appended to $TEST_ROOT/kill-diag.log.
This is pure forensics (it always calls the real kill afterwards, never
raises); the arbiter half in brix_suite.harness.sentinel decides whether the
fleet was actually damaged and aborts the run.  Together they turn "a test
stopped or crashed a shared fleet server" from a mysterious ConnectionRefused
cascade into a named, fail-fast bug.  On by default for a local fleet;
BRIX_FLEET_SENTINEL=0 disables both halves.

The wrapping happens at first import of this module — exactly when
tests/conftest.py used to install it inline — and, being import-cached, can
never stack a second wrapper when the conftest source is executed again (the
by-path pinning loader does exactly that).
"""

import os
import re
import signal
import subprocess
import time
import traceback

def _expression_1(low):
    return (
        "manage_test_servers" in low and ("restart" in low or " stop" in low)
    )

def _expression_2(low):
    return (
        low.split()[:1] == ["pkill"] or " pkill " in low or "killall" in low
    )

def _expression_3(low):
    return (
        "nginx" in low and "-s" in low and ("quit" in low or "stop" in low)
    )

def _expression_4(s):
    return (
        "/lc-" in s or "/tmp/" in s or "registry/main" in s
    )


_CURRENT_NODEID = [""]   # updated per-test by the sentinel setup hook


def _process_command(pid):
    try:
        with open(f"/proc/{int(pid)}/cmdline", "rb") as fh:
            return fh.read().replace(b"\0", b" ").decode("utf-8", "replace")
    except (OSError, ValueError):
        return None


def _process_kind(command):
    kinds = (("nginx: master", "nginx"), ("xrootd", "xrootd"), ("cmsd", "cmsd"))
    for marker, name in kinds:
        if marker in command:
            return name
    return None


def _server_name(pid):
    """Name a registry server process (nginx master OR xrootd/cmsd) by pid."""
    command = _process_command(pid)
    if command is None or "registry/" not in command:
        return None
    kind = _process_kind(command)
    if kind is None:
        return None
    match = re.search(r"registry/([A-Za-z0-9_.-]+)", command)
    return f"{kind}:{match.group(1) if match else '?'}"


def _log(target, sig, via):
    try:
        root = os.environ.get("TEST_ROOT", "/tmp/xrd-test")
        stamp = time.strftime("%Y-%m-%d %H:%M:%S")
        with open(os.path.join(root, "kill-diag.log"), "a") as stream:
            stream.write(f"\n=== {stamp} {via} sig={sig} target={target} "
                         f"test={_CURRENT_NODEID[0]} pid={os.getpid()} ===\n")
            stream.write("".join(traceback.format_stack()))
    except OSError:
        pass


def _trace_kill(pid, sig, *, real_kill, fatal):
    try:
        name = _server_name(pid) if int(sig) in fatal else None
        if name:
            _log(name, sig, "os.kill")
    except Exception:
        pass
    return real_kill(pid, sig)


def _group_server(pgid):
    lines = subprocess.run(
        ["pgrep", "-g", str(pgid)], capture_output=True, text=True
    ).stdout.split()
    for line in lines:
        name = _server_name(line)
        if name:
            return name
    return None


def _trace_killpg(pgid, sig, *, real_killpg, fatal):
    try:
        name = _group_server(pgid) if int(sig) in fatal else None
        if name:
            _log(f"{name}(pg{pgid})", sig, "os.killpg")
    except Exception:
        pass
    return real_killpg(pgid, sig)


def _argv_str(args):
    if isinstance(args, (list, tuple)):
        return " ".join(str(arg) for arg in args)
    return str(args)


def _nginx_stop_kind(command, lowered):
    if not _expression_3(lowered) or _expression_4(command):
        return None
    return "nginx-s-quit/stop"


def _fleet_stop_kind(command):
    lowered = command.lower()
    known = (
        ("stop-all" in lowered, "stop-all"),
        (_expression_1(lowered), "manage_test_servers-stop/restart"),
        (_expression_2(lowered), "pkill/killall"),
    )
    for matched, kind in known:
        if matched:
            return kind
    return _nginx_stop_kind(command, lowered)


def _tracing_popen_init(self, args, *extra, **kwargs):
    try:
        command = _argv_str(args)
        kind = _fleet_stop_kind(command)
        if kind:
            _log(f"FLEET-STOP[{kind}] {command[:400]}", "-", "subprocess")
    except Exception:
        pass
    type(self)._brix_base.__init__(self, args, *extra, **kwargs)


def _install_kill_tracer():
    from functools import partial

    fatal = {int(signal.SIGKILL), int(signal.SIGTERM), int(signal.SIGQUIT)}
    traced_kill = partial(_trace_kill, real_kill=os.kill, fatal=fatal)
    traced_kill.__name__ = "_kill"
    os.kill = traced_kill
    real_killpg = getattr(os, "killpg", None)
    if real_killpg is not None:
        traced_killpg = partial(_trace_killpg, real_killpg=real_killpg, fatal=fatal)
        traced_killpg.__name__ = "_killpg"
        os.killpg = traced_killpg

    real_popen = subprocess.Popen
    tracing_popen = type(
        "_TracingPopen", (real_popen,),
        {"__init__": _tracing_popen_init, "_brix_base": real_popen},
    )
    subprocess.Popen = tracing_popen


_FLEET_SENTINEL_ON = (os.environ.get("BRIX_FLEET_SENTINEL", "1") != "0"
                      and os.environ.get("TEST_SERVER_HOST") is None)
if _FLEET_SENTINEL_ON:
    _install_kill_tracer()
