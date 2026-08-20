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
import subprocess

_CURRENT_NODEID = [""]   # updated per-test by the sentinel setup hook


def _install_kill_tracer():
    import signal as _sig
    import traceback as _tb
    import re as _re
    import time as _time
    _real_kill = os.kill
    _real_killpg = getattr(os, "killpg", None)
    _fatal = {int(_sig.SIGKILL), int(_sig.SIGTERM), int(_sig.SIGQUIT)}

    def _server_name(pid):
        """Name a registry server process (nginx master OR xrootd/cmsd) by pid."""
        try:
            with open(f"/proc/{int(pid)}/cmdline", "rb") as fh:
                cmd = fh.read().replace(b"\0", b" ").decode("utf-8", "replace")
        except (OSError, ValueError):
            return None
        if "registry/" not in cmd:
            return None
        if "nginx: master" in cmd:
            kind = "nginx"
        elif "xrootd" in cmd:
            kind = "xrootd"
        elif "cmsd" in cmd:
            kind = "cmsd"
        else:
            return None
        m = _re.search(r"registry/([A-Za-z0-9_.-]+)", cmd)
        return f"{kind}:{m.group(1) if m else '?'}"

    def _log(target, sig, via):
        try:
            root = os.environ.get("TEST_ROOT", "/tmp/xrd-test")
            stamp = _time.strftime("%Y-%m-%d %H:%M:%S")
            with open(os.path.join(root, "kill-diag.log"), "a") as f:
                f.write(f"\n=== {stamp} {via} sig={sig} target={target} "
                        f"test={_CURRENT_NODEID[0]} pid={os.getpid()} ===\n")
                f.write("".join(_tb.format_stack()))
        except OSError:
            pass

    def _kill(pid, sig):
        try:
            if int(sig) in _fatal:
                n = _server_name(pid)
                if n:
                    _log(n, sig, "os.kill")
        except Exception:
            pass
        return _real_kill(pid, sig)
    os.kill = _kill

    if _real_killpg is not None:
        def _killpg(pgid, sig):
            try:
                if int(sig) in _fatal:
                    for line in subprocess.run(["pgrep", "-g", str(pgid)],
                            capture_output=True, text=True).stdout.split():
                        n = _server_name(line)
                        if n:
                            _log(f"{n}(pg{pgid})", sig, "os.killpg")
                            break
            except Exception:
                pass
            return _real_killpg(pgid, sig)
        os.killpg = _killpg

    # ---- subprocess-based fleet stops (the blind spot of os.kill wrapping) ----
    # `manage_test_servers stop-all`, a fleet `restart`, or `nginx -s quit/stop`
    # run in a CHILD process signal the masters from OUTSIDE this interpreter, so
    # the os.kill wrappers above never see them.  Wrap Popen (which run/
    # check_call/check_output all funnel through) to log fleet-scope stops with
    # the culprit test + traceback + timestamp.  Per-instance lifecycle teardown
    # (`nginx -s quit` on a registry/lc-* or /tmp/ throwaway prefix) is expected
    # and filtered out so the fleet-wide stop stands alone in the log.
    _RealPopen = subprocess.Popen

    def _argv_str(args):
        if isinstance(args, (list, tuple)):
            return " ".join(str(a) for a in args)
        return str(args)

    def _fleet_stop_kind(s):
        low = s.lower()
        if "stop-all" in low:
            return "stop-all"
        if "manage_test_servers" in low and ("restart" in low or " stop" in low):
            return "manage_test_servers-stop/restart"
        if low.split()[:1] == ["pkill"] or " pkill " in low or "killall" in low:
            return "pkill/killall"
        if "nginx" in low and "-s" in low and ("quit" in low or "stop" in low):
            # skip legitimate per-instance lifecycle/throwaway teardown
            if "/lc-" in s or "/tmp/" in s or "registry/main" in s:
                return None
            return "nginx-s-quit/stop"
        return None

    class _TracingPopen(_RealPopen):
        def __init__(self, args, *a, **kw):
            try:
                kind = _fleet_stop_kind(_argv_str(args))
                if kind:
                    _log(f"FLEET-STOP[{kind}] {_argv_str(args)[:400]}",
                         "-", "subprocess")
            except Exception:
                pass
            super().__init__(args, *a, **kw)

    subprocess.Popen = _TracingPopen


_FLEET_SENTINEL_ON = (os.environ.get("BRIX_FLEET_SENTINEL", "1") != "0"
                      and os.environ.get("TEST_SERVER_HOST") is None)
if _FLEET_SENTINEL_ON:
    _install_kill_tracer()
