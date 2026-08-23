"""ARCHIVE — the flat ``tests/cli_pty.py`` as it stood before TS-5.

Kept verbatim so the move can be checked body-by-body (AST hash) rather than
taken on trust.  Nothing imports it; the live module is ``brixtest.clients.pty``.
"""

"""
CLI subprocess helpers for golden-baseline and interactive tests.

Exposed functions
-----------------
run_pipe(cmd, env=None, timeout=30) -> (exit_code, stdout_bytes, stderr_bytes)
    Run *cmd* with stdout and stderr captured via OS pipes.  Stdin is
    /dev/null so interactive prompts cannot block.

run_pty(cmd, env=None, timeout=30) -> (exit_code, stdout_bytes, stderr_bytes)
    Run *cmd* with stdout on an OS pipe and stderr attached to a PTY slave,
    so ``isatty(2)`` returns 1 on the process's stderr fd.  The caller
    drains the PTY master until EOF, which naturally occurs when the child
    exits.  A deadline guard kills the child if it hangs beyond *timeout*.
    Stdin is /dev/null.

Both signatures are pure stdlib; no third-party dependencies.
"""

import os
import select
import subprocess
import time
import pty as _pty

__all__ = ["run_pipe", "run_pty", "TIMEOUT_S"]

TIMEOUT_S = 30  # per-command hard deadline (seconds)


# ---------------------------------------------------------------------------
# run_pipe
# ---------------------------------------------------------------------------

def run_pipe(cmd, env=None, timeout=TIMEOUT_S):
    """Run a command with captured output and closed stdin."""
    result = subprocess.run(
        cmd,
        capture_output=True,
        stdin=subprocess.DEVNULL,
        env=env,
        timeout=timeout,
        check=False,
    )
    return result.returncode, result.stdout, result.stderr


# ---------------------------------------------------------------------------
# run_pty
# ---------------------------------------------------------------------------

def run_pty(cmd, env=None, timeout=TIMEOUT_S):
    """Run a command with stderr attached to a PTY slave."""
    master_fd, slave_fd = _pty.openpty()
    slave_closed = False
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=slave_fd,
            stdin=subprocess.DEVNULL,
            env=env,
        )
        os.close(slave_fd)
        slave_closed = True

        deadline = time.monotonic() + timeout
        stderr_chunks = _read_stderr(proc, master_fd, cmd, timeout, deadline)

        stdout_bytes, _ = proc.communicate(timeout=max(1, deadline - time.monotonic()))
        return proc.returncode, stdout_bytes, b"".join(stderr_chunks)

    finally:
        if not slave_closed:
            os.close(slave_fd)
        os.close(master_fd)


def _read_stderr(proc, master_fd, cmd, timeout, deadline):
    chunks = []
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            _raise_timeout(proc, cmd, timeout)
        ready, _, _ = select.select([master_fd], [], [], min(remaining, 0.5))
        if ready and not _append_chunk(master_fd, chunks):
            break
        if not ready and proc.poll() is not None:
            _drain_master(master_fd, chunks)
            break
    return chunks


def _raise_timeout(proc, cmd, timeout):
    proc.kill()
    proc.wait()
    raise subprocess.TimeoutExpired(cmd, timeout)


def _append_chunk(master_fd, chunks):
    try:
        chunk = os.read(master_fd, 4096)
    except OSError:
        return False
    if not chunk:
        return False
    chunks.append(chunk)
    return True


def _drain_master(master_fd, chunks):
    """Append all immediately available bytes from a PTY master."""
    while True:
        try:
            ready, _, _ = select.select([master_fd], [], [], 0)
            if not ready:
                break
            data = os.read(master_fd, 4096)
            if not data:
                break
            chunks.append(data)
        except OSError:
            break
