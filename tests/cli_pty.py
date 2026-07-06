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
    """Run *cmd* with stdout + stderr captured via pipes.

    What/Why/How
    ------------
    Standard subprocess capture.  Stdin is connected to /dev/null so that
    interactive tools (e.g. those that read a line from stdin before
    printing usage) see EOF immediately rather than blocking forever.

    Args:
        cmd:     Sequence of str — the command and its arguments (argv).
        env:     Mapping or None.  None inherits the caller's environment.
        timeout: Seconds before ``subprocess.TimeoutExpired`` is raised.

    Returns:
        (exit_code: int, stdout: bytes, stderr: bytes)
    """
    result = subprocess.run(
        cmd,
        capture_output=True,
        stdin=subprocess.DEVNULL,
        env=env,
        timeout=timeout,
    )
    return result.returncode, result.stdout, result.stderr


# ---------------------------------------------------------------------------
# run_pty
# ---------------------------------------------------------------------------

def run_pty(cmd, env=None, timeout=TIMEOUT_S):
    """Run *cmd* with stdout on a pipe and stderr on a PTY slave.

    What/Why/How
    ------------
    Some CLI tools detect whether stderr is a TTY (``isatty(2)``) and
    enable colour output, progress bars, or different formatting only in
    that case.  This helper allocates a PTY pair, hands the slave fd to
    the child as its stderr, and drains the master fd in a select loop
    until the child exits and the master signals EOF (EIO).

    Stdout stays a plain pipe for reliability — PTY line-discipline
    transforms (CR insertion, echo, etc.) only apply to the slave side.

    A monotonic deadline guard kills the child process if it fails to
    produce EOF within *timeout* seconds.

    Stdin is /dev/null so interactive prompts do not block.

    Args:
        cmd:     Sequence of str — the command and its arguments (argv).
        env:     Mapping or None.  None inherits the caller's environment.
        timeout: Seconds before the child is killed and TimeoutError raised.

    Returns:
        (exit_code: int, stdout: bytes, stderr: bytes)

    Raises:
        TimeoutError: if the child does not exit within *timeout* seconds.
    """
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
        # Close our copy of the slave so that when the child exits and
        # closes its slave fd, the master fd sees EOF (EIO on Linux).
        os.close(slave_fd)
        slave_closed = True

        stderr_chunks = []
        deadline = time.monotonic() + timeout

        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                proc.kill()
                proc.wait()
                raise TimeoutError(
                    f"run_pty: {cmd[0]!r} exceeded {timeout}s timeout"
                )
            ready, _, _ = select.select([master_fd], [], [], min(remaining, 0.5))
            if ready:
                try:
                    chunk = os.read(master_fd, 4096)
                except OSError:
                    # EIO: slave side closed — child has exited.
                    break
                if not chunk:
                    break
                stderr_chunks.append(chunk)
            else:
                # Timeout on select; check if the child has already exited.
                if proc.poll() is not None:
                    # Drain any bytes still buffered in the master fd.
                    _drain_master(master_fd, stderr_chunks)
                    break

        stdout_bytes, _ = proc.communicate(timeout=5)
        return proc.returncode, stdout_bytes, b"".join(stderr_chunks)

    finally:
        if not slave_closed:
            os.close(slave_fd)
        os.close(master_fd)


def _drain_master(master_fd, chunks):
    """Read all remaining bytes from *master_fd* without blocking.

    Called after the child process has exited to collect any bytes still
    buffered in the PTY master.

    Args:
        master_fd: PTY master file descriptor.
        chunks:    List to append collected bytes to (mutated in place).
    """
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
