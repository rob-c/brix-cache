"""Bounded pipe and real pseudo-terminal subprocess helpers."""

from __future__ import annotations

import contextlib
import fcntl
import os
import pty as _pty
import select
import shutil
import signal
import struct
import subprocess
import sys
import termios
import time
from typing import Optional, Union

__all__ = ["TIMEOUT_S", "run_pipe", "run_pty"]

TIMEOUT_S = 30
_MARKER = b"\n[BriXTest output truncated]\n"


class _Capture:
    """Retain the beginning and end of a bounded PTY transcript."""

    def __init__(self, limit: int) -> None:
        self.limit = limit
        available = max(0, limit - len(_MARKER))
        self.head_limit = available // 2
        self.tail_limit = available - self.head_limit
        self.complete: Optional[bytearray] = bytearray()
        self.head = bytearray()
        self.tail = bytearray()

    def feed(self, value: bytes) -> None:
        if self.complete is not None:
            self.complete.extend(value)
            if len(self.complete) <= self.limit:
                return
            payload = bytes(self.complete)
            self.head.extend(payload[:self.head_limit])
            self.tail.extend(payload[-self.tail_limit:] if self.tail_limit else b"")
            self.complete = None
            return
        if self.tail_limit:
            self.tail.extend(value)
            if len(self.tail) > self.tail_limit:
                del self.tail[:-self.tail_limit]

    def bytes(self) -> bytes:
        if self.complete is not None:
            return bytes(self.complete)
        return (bytes(self.head) + _MARKER + bytes(self.tail))[:self.limit]


def run_pipe(cmd, env=None, timeout=TIMEOUT_S):
    """Run a command with captured output and closed stdin."""
    result = subprocess.run(
        cmd, capture_output=True, stdin=subprocess.DEVNULL, env=env,
        timeout=timeout, check=False,
    )
    return result.returncode, result.stdout, result.stderr


def _window_size() -> tuple[int, int]:
    size = shutil.get_terminal_size((80, 24))
    return size.lines, size.columns


def _resize(descriptor: int, size: tuple[int, int]) -> None:
    rows, columns = size
    value = struct.pack("HHHH", rows, columns, 0, 0)
    fcntl.ioctl(descriptor, termios.TIOCSWINSZ, value)


def _disable_echo(descriptor: int) -> None:
    attributes = termios.tcgetattr(descriptor)
    attributes[3] &= ~termios.ECHO
    termios.tcsetattr(descriptor, termios.TCSANOW, attributes)


def _stream(value: bytes) -> None:
    target = getattr(sys.stdout, "buffer", sys.stdout)
    selected = value if target is not sys.stdout else value.decode("utf-8", errors="replace")
    target.write(selected)
    target.flush()


def _input_bytes(value: Optional[Union[str, bytes]]) -> bytes:
    if value is None:
        return b""
    return value if isinstance(value, bytes) else value.encode()


def _terminate(process: subprocess.Popen) -> None:
    with contextlib.suppress(OSError):
        os.killpg(process.pid, signal.SIGTERM)
    try:
        process.wait(timeout=1.0)
    except subprocess.TimeoutExpired:
        with contextlib.suppress(OSError):
            os.killpg(process.pid, signal.SIGKILL)
        process.wait()


def _sync_size(descriptor: int, previous: tuple[int, int]) -> tuple[int, int]:
    selected = _window_size()
    if selected != previous:
        _resize(descriptor, selected)
    return selected


def _read_pty(
    process: subprocess.Popen, descriptor: int, *, deadline: float,
    timeout: float, command: object, output_limit: int, stream: bool,
) -> bytes:
    capture = _Capture(output_limit)
    size = _window_size()
    while True:
        if time.monotonic() >= deadline:
            _terminate(process)
            raise subprocess.TimeoutExpired(command, timeout, output=capture.bytes())
        size = _sync_size(descriptor, size)
        ready, _, _ = select.select([descriptor], [], [], 0.1)
        if ready and not _read_chunk(descriptor, capture, stream):
            break
        if not ready and process.poll() is not None:
            _drain(descriptor, capture, stream)
            break
    return capture.bytes()


def _read_chunk(descriptor, capture, stream) -> bool:
    try:
        value = os.read(descriptor, 64 << 10)
    except OSError:
        return False
    if not value:
        return False
    capture.feed(value)
    if stream:
        _stream(value)
    return True


def _drain(descriptor, capture, stream) -> None:
    while select.select([descriptor], [], [], 0)[0]:
        if not _read_chunk(descriptor, capture, stream):
            return


def run_pty(
    cmd, env=None, timeout=TIMEOUT_S, *, input: Optional[Union[str, bytes]] = None,
    output_limit: int = 1 << 20, stream: bool = False, cwd=None,
):
    """Run with one resized PTY, bounded combined output, input, and termination."""
    master_fd, slave_fd = _pty.openpty()
    process = None
    try:
        _resize(slave_fd, _window_size())
        _disable_echo(slave_fd)
        process = subprocess.Popen(
            cmd, stdin=slave_fd, stdout=slave_fd, stderr=slave_fd, env=env, cwd=cwd,
            start_new_session=True,
        )
        os.close(slave_fd)
        slave_fd = -1
        payload = _input_bytes(input)
        if input is not None:
            with contextlib.suppress(OSError):
                if payload:
                    os.write(master_fd, payload)
                os.write(master_fd, b"\x04")
        output = _read_pty(
            process, master_fd, deadline=time.monotonic() + timeout,
            timeout=timeout, command=cmd, output_limit=output_limit, stream=stream,
        )
        process.wait(timeout=1.0)
        return process.returncode, output, b""
    finally:
        if process is not None and process.poll() is None:
            _terminate(process)
        if slave_fd >= 0:
            os.close(slave_fd)
        os.close(master_fd)
