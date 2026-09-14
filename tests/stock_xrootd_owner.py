"""Own a stock XRootD process and its short private Unix control directory."""

import os
import shutil
import signal
import subprocess
import tempfile


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
