"""Own a stock XRootD process and its short private Unix control directory."""

import os
import shutil
import signal
import subprocess
import tempfile

from lib_py.util import find_xrd_sec_lib


def _stock_security_layout(protocol):
    """Pair the reference security library with a plugin of its own ABI."""
    security = find_xrd_sec_lib()
    if security is None:
        return None
    plugin = security.with_name(security.name.replace("libXrdSec", "libXrdSec" + protocol, 1))
    if not plugin.is_file():
        return None
    return security, plugin.parent


def stock_gsi_layout():
    """Select the reference server's installed GSI framework/plugin pair."""
    return _stock_security_layout("gsi")


def stock_krb5_layout():
    """Select the reference server's installed Kerberos framework/plugin pair."""
    return _stock_security_layout("krb5")


def _kill_proc(p):
    """Terminate p and its whole process group (servers fork children — nginx
    workers, the stock xrootd's helpers — that survive a bare SIGTERM and would
    otherwise accumulate across themed files and exhaust the box)."""
    if not p:
        return
    try:
        pgid = os.getpgid(p.pid)
    except (ProcessLookupError, OSError):
        pgid = None
    for sig in (signal.SIGTERM, signal.SIGKILL):
        try:
            if pgid is not None:
                os.killpg(pgid, sig)
            else:
                p.send_signal(sig)
        except (ProcessLookupError, OSError):
            break
        try:
            p.wait(timeout=5)
            return
        except subprocess.TimeoutExpired:
            continue


class StockXrootdOwner:
    """Keep control state available until the exact owned process is reaped."""

    def __init__(self, reap=None):
        self._reap = _kill_proc if reap is None else reap
        self.admin = tempfile.mkdtemp(prefix="brix-off-", dir="/tmp")
        self.process = None
        self.closed = False

    def close(self):
        if self.closed:
            return
        try:
            if self.process is not None:
                self._reap(self.process)
                # _kill_proc's historical best-effort return does not guarantee
                # reap. A timeout here preserves this directory for retry.
                self.process.wait(timeout=5)
                self.process = None
            shutil.rmtree(self.admin)
            self.closed = True
        except BaseException as error:
            error.stock_server_owner = self
            raise
