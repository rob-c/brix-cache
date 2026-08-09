"""Direct Python ports for the credential-forwarding matrix live shell scenarios.

Ports ``run_fwd_brix_brix.sh`` (pairing C), ``run_fwd_brix_xrootd.sh``
(pairing A), ``run_fwd_xrootd_brix.sh`` (pairing B),
``fwd_b_token_forward_probe.sh`` (the pairing-B token evidence probe), and
``run_transparent_relay.sh``.  The :class:`ForwardHarness` below is the Python
port of the shared shell library ``tests/lib/fwd_matrix.sh`` — node spawners,
PKI/token minting, per-cell scoped teardown, and the backend-identity
assertions.  Each public scenario contains its shell script's own acceptance
sequence and PASS/FAIL/GAP/UNSUPPORTED/SKIP cell verdicts.
"""

from __future__ import annotations

import argparse
from contextlib import contextmanager
import hashlib
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import time
from typing import Iterator, NamedTuple

from cmdscripts.live_common import LiveFailure, LiveRun, REPO_ROOT
from lib_py.util import wait_tcp
from settings import BIND_HOST, CA_CERT, CA_DIR, CA_KEY, HOST, SERVER_CERT, SERVER_KEY
from ephemeral_port import free_ports

BRIX_XRDCP = REPO_ROOT / "client/bin/xrdcp"
BRIX_XRDFS = REPO_ROOT / "client/bin/xrdfs"
XROOTD_BIN = Path(os.environ.get("XROOTD_BIN", os.environ.get("BRIX_BIN", "/usr/bin/xrootd")))
SYS_XRDCP = shutil.which("xrdcp")

A_CN, B_CN, SVC_CN = "Fwd User A", "Fwd User B", "Fwd Service"
A_SUB, B_SUB = "fwd-user-a", "fwd-user-b"
TOK_AUD = "nginx-xrootd"


def _call(argv: list[str | Path], *, env_add: dict[str, str] | None = None,
          env_drop: tuple[str, ...] = (), input: str | None = None,
          stdout_to: Path | None = None, timeout: float | None = None) -> subprocess.CompletedProcess:
    """Run a command with additions to AND removals from the environment.

    ``env_drop`` matters twice over: ``NGINX`` is a reserved nginx env var
    (inherited socket fds) that must never reach a spawned nginx, and
    ``XRDC_GSI_DELEGATE`` must be truly UNSET (not empty) for the userB
    no-delegation negative control.
    """
    env = {k: v for k, v in os.environ.items() if k not in env_drop}
    env.update(env_add or {})
    out = stdout_to.open("wb") if stdout_to else subprocess.PIPE
    try:
        proc = subprocess.Popen(
            [str(a) for a in argv], env=env,
            stdin=subprocess.PIPE if input is not None else None,
            stdout=out, stderr=subprocess.PIPE,
            text=stdout_to is None,
        )
        try:
            stdout, stderr = proc.communicate(input, timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            stdout, stderr = proc.communicate()
    finally:
        if stdout_to:
            out.close()
    if not isinstance(stderr, str):
        stderr = (stderr or b"").decode(errors="replace")
    if not isinstance(stdout, str):
        stdout = ""
    return subprocess.CompletedProcess([str(a) for a in argv], proc.returncode, stdout, stderr)


def _curl_code(*args: str | Path) -> str:
    proc = _call(["curl", "-sk", "-o", os.devnull, "-w", "%{http_code}", *args], timeout=60)
    return proc.stdout.strip() or "000"


class FrontResult(NamedTuple):
    put_ok: bool
    get_ok: bool
    deny_obs: str

from split_continuation import load as _load_continuations
_load_continuations(globals(), __file__, "fwd_matrix_live_part2.py",
                    "fwd_matrix_live_part3.py", "fwd_matrix_live_part4.py")
