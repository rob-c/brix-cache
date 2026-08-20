"""Shell-free subprocess convenience with durable text output capture."""

from __future__ import annotations

import dataclasses
import json
import math
import os
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Callable, Dict, Mapping, Optional, Sequence, Union

from brixtest.errors import SpecError

_TRUNCATION_MARKER = b"\n[BriXTest output truncated]\n"


class _BoundedCapture:
    """Drain an output pipe while retaining at most one declared byte budget."""

    def __init__(self, limit: int) -> None:
        self.limit = limit
        available = max(0, limit - len(_TRUNCATION_MARKER))
        self._head_limit = available // 2
        self._tail_limit = available - self._head_limit
        self._complete: Optional[bytearray] = bytearray()
        self._head = bytearray()
        self._tail = bytearray()

    def feed(self, value: bytes) -> None:
        if not value:
            return
        if self._complete is not None:
            self._complete.extend(value)
            if len(self._complete) <= self.limit:
                return
            payload = bytes(self._complete)
            self._head.extend(payload[:self._head_limit])
            if self._tail_limit:
                self._tail.extend(payload[-self._tail_limit:])
            self._complete = None
            return
        if self._tail_limit:
            self._tail.extend(value)
            if len(self._tail) > self._tail_limit:
                del self._tail[:-self._tail_limit]

    def text(self, encoding: str) -> tuple[str, bool]:
        if self._complete is not None:
            return self._complete.decode(encoding, errors="replace"), False
        payload = bytes(self._head) + _TRUNCATION_MARKER + bytes(self._tail)
        return payload[:self.limit].decode(encoding, errors="replace"), True


def _text(value: object) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value or "")


@dataclasses.dataclass(frozen=True)
class CommandResult:
    """Immutable decoded output and timing from one shell-free command."""
    argv: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str
    elapsed_seconds: float
    attempts: int = 1
    stdout_truncated: bool = False
    stderr_truncated: bool = False

    def __post_init__(self) -> None:
        if (
            isinstance(self.argv, (str, bytes))
            or not self.argv
            or not all(isinstance(part, str) and part and "\x00" not in part for part in self.argv)
        ):
            raise SpecError("command result argv", self.argv, "must be non-empty, NUL-free text")
        if isinstance(self.returncode, bool) or not isinstance(self.returncode, int):
            raise SpecError("command result returncode", self.returncode, "must be an integer")
        if not isinstance(self.stdout, str) or not isinstance(self.stderr, str):
            raise SpecError("command result output", type(self.stdout).__name__, "must be text")
        if (
            isinstance(self.elapsed_seconds, bool)
            or not isinstance(self.elapsed_seconds, (int, float))
            or not math.isfinite(float(self.elapsed_seconds))
            or self.elapsed_seconds < 0
        ):
            raise SpecError(
                "command result elapsed_seconds", self.elapsed_seconds,
                "must be a finite number >= 0",
            )
        object.__setattr__(self, "argv", tuple(self.argv))
        object.__setattr__(self, "elapsed_seconds", float(self.elapsed_seconds))
        if isinstance(self.attempts, bool) or not isinstance(self.attempts, int) or self.attempts < 1:
            raise SpecError("command result attempts", self.attempts, "must be an integer >= 1")
        if not isinstance(self.stdout_truncated, bool) or not isinstance(self.stderr_truncated, bool):
            raise SpecError("command result truncation", self, "flags must be boolean")

    @property
    def ok(self) -> bool:
        """Whether the command exited successfully."""
        return self.returncode == 0

    @property
    def output(self) -> str:
        """Standard output followed by standard error for compact diagnostics."""
        return self.stdout + self.stderr

    @property
    def args(self) -> tuple[str, ...]:
        """Standard-library-compatible alias for the executed argument vector."""
        return self.argv

    @property
    def stdout_lines(self) -> list[str]:
        """Captured standard output split into lines without terminators."""
        return self.stdout.splitlines()

    @property
    def stderr_lines(self) -> list[str]:
        """Captured standard error split into lines without terminators."""
        return self.stderr.splitlines()

    def check_returncode(self) -> None:
        """Raise ``CalledProcessError`` when the command did not succeed."""
        if not self.ok:
            raise subprocess.CalledProcessError(
                self.returncode, self.argv, output=self.stdout, stderr=self.stderr
            )

    def check(self) -> "CommandResult":
        """Raise for failure and otherwise return this result for fluent assertions."""
        self.check_returncode()
        return self

    def as_dict(self) -> Dict[str, object]:
        """Return a JSON-safe provenance record for this invocation."""
        return {
            "argv": list(self.argv), "returncode": self.returncode,
            "stdout": self.stdout, "stderr": self.stderr,
            "elapsed_seconds": self.elapsed_seconds, "ok": self.ok,
            "attempts": self.attempts,
            "stdout_truncated": self.stdout_truncated,
            "stderr_truncated": self.stderr_truncated,
        }

    def json(self) -> object:
        """Decode standard output as JSON or raise a structured specification error."""
        try:
            return json.loads(self.stdout)
        except (TypeError, ValueError) as exc:
            preview = self.stdout[:200]
            raise SpecError(
                "command stdout", preview, "must contain valid JSON",
            ) from exc


class CommandRunner:
    def __init__(
        self, archive_dir: Optional[Path], *, cwd: Path,
        observer: Optional[Callable[[float, Optional[int], str], None]] = None,
        redact: Sequence[str] = (),
    ) -> None:
        self.archive_dir = Path(archive_dir) if archive_dir is not None else None
        self.cwd = Path(cwd)
        self.observer = observer
        self.redact = tuple(redact)
        if not all(isinstance(value, str) and value for value in self.redact):
            raise SpecError("command redaction", self.redact, "must contain non-empty text")
        self._lock = threading.Lock()
        self._sequence = 0

    @staticmethod
    def _argv(command: Sequence[object]) -> tuple[str, ...]:
        if not command:
            raise SpecError("run.command", command, "needs at least one argv item")
        result = tuple(str(part) for part in command)
        if any(not part or "\x00" in part for part in result):
            raise SpecError("run.command", result, "argv entries must be non-empty and NUL-free")
        return result

    @staticmethod
    def _drain(
        pipe: object, capture: _BoundedCapture, stream: Optional[object],
        encoding: str,
    ) -> None:
        """Drain one binary subprocess pipe without retaining unbounded output."""
        try:
            while True:
                block = pipe.read(64 << 10)
                if not block:
                    return
                capture.feed(block)
                if stream is not None:
                    stream.write(block.decode(encoding, errors="replace"))
                    stream.flush()
        finally:
            pipe.close()

    @classmethod
    def _run_bounded(
        cls, argv: Sequence[str], *, cwd: Path, environment: Mapping[str, str],
        input: Optional[str], encoding: str, timeout: Optional[float],
        output_limit: int, stream: bool,
    ) -> tuple[int, str, str, bool, bool]:
        """Spawn once, drain both pipes concurrently, and enforce a deadline."""
        process = subprocess.Popen(
            argv, cwd=str(cwd), env=dict(environment),
            stdin=subprocess.PIPE if input is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=False, shell=False, start_new_session=True,
        )
        assert process.stdout is not None and process.stderr is not None
        stdout_capture = _BoundedCapture(output_limit)
        stderr_capture = _BoundedCapture(output_limit)
        stdout_thread = threading.Thread(
            target=cls._drain,
            args=(
                process.stdout, stdout_capture, sys.stdout if stream else None,
                encoding,
            ),
            name="brixtest-command-stdout", daemon=True,
        )
        stderr_thread = threading.Thread(
            target=cls._drain,
            args=(
                process.stderr, stderr_capture, sys.stderr if stream else None,
                encoding,
            ),
            name="brixtest-command-stderr", daemon=True,
        )
        stdout_thread.start()
        stderr_thread.start()
        if process.stdin is not None:
            try:
                process.stdin.write((input or "").encode(encoding, errors="replace"))
            except BrokenPipeError:
                pass
            finally:
                process.stdin.close()
        timed_out = False
        try:
            returncode = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except OSError:
                pass
            try:
                process.wait(timeout=1.0)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except OSError:
                    pass
                process.wait()
            returncode = process.returncode
        for thread in (stdout_thread, stderr_thread):
            thread.join(timeout=0.5)
        if stdout_thread.is_alive() or stderr_thread.is_alive():
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except OSError:
                pass
            for thread in (stdout_thread, stderr_thread):
                thread.join(timeout=0.5)
        stdout, stdout_truncated = stdout_capture.text(encoding)
        stderr, stderr_truncated = stderr_capture.text(encoding)
        if timed_out:
            raise subprocess.TimeoutExpired(
                tuple(argv), timeout, output=stdout, stderr=stderr,
            )
        return (
            int(returncode), stdout, stderr,
            stdout_truncated, stderr_truncated,
        )

    def run(
        self, *command: object, check: bool = True, timeout: Optional[float] = None,
        input: Optional[str] = None, env: Optional[Mapping[str, str]] = None,
        cwd: Optional[Union[str, Path]] = None,
        encoding: str = "utf-8", expected_exit_codes: Sequence[int] = (0,),
        output_limit: int = 1 << 20, mode: str = "capture", retries: int = 0,
    ) -> CommandResult:
        if len(command) == 1 and isinstance(command[0], (list, tuple)):
            argv = self._argv(command[0])
        else:
            argv = self._argv(command)
        if env is not None and (
            not isinstance(env, Mapping) or not all(
                isinstance(key, str) and isinstance(value, str) for key, value in env.items()
            )
        ):
            raise SpecError("run.command env", env, "must map strings to strings")
        if timeout is not None and (
            isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or timeout <= 0
        ):
            raise SpecError("run.command timeout", timeout, "must be > 0")
        if input is not None and not isinstance(input, str):
            raise SpecError("run.command input", type(input).__name__, "must be text")
        if not isinstance(encoding, str) or not encoding:
            raise SpecError("run.command encoding", encoding, "must be non-empty text")
        expected = tuple(expected_exit_codes)
        if not expected or not all(
            isinstance(value, int) and not isinstance(value, bool) for value in expected
        ):
            raise SpecError("run.command expected_exit_codes", expected, "must contain integers")
        if isinstance(output_limit, bool) or not isinstance(output_limit, int) or output_limit < 1:
            raise SpecError("run.command output_limit", output_limit, "must be an integer >= 1")
        if mode not in ("capture", "stream", "pty"):
            raise SpecError("run.command mode", mode, "must be capture, stream, or pty")
        if isinstance(retries, bool) or not isinstance(retries, int) or retries < 0:
            raise SpecError("run.command retries", retries, "must be an integer >= 0")
        environment = dict(os.environ)
        environment.update(dict(env or {}))
        started = time.perf_counter()
        returncode: Optional[int] = None
        error = ""
        stdout = ""
        stderr = ""
        attempts = 0
        stdout_truncated = False
        stderr_truncated = False
        try:
            while True:
                attempts += 1
                if mode == "pty":
                    if input is not None:
                        raise SpecError("run.command input", input, "is not supported in pty mode")
                    from brixtest.clients.pty import run_pty

                    returncode, raw_stdout, raw_stderr = run_pty(
                        argv, env=environment, timeout=timeout or 30.0,
                    )
                    stdout = _text(raw_stdout)
                    stderr = _text(raw_stderr)
                else:
                    (
                        returncode, stdout, stderr,
                        stdout_truncated, stderr_truncated,
                    ) = self._run_bounded(
                        argv,
                        cwd=Path(cwd) if cwd is not None else self.cwd,
                        environment=environment, input=input, encoding=encoding,
                        timeout=timeout, output_limit=output_limit,
                        stream=mode == "stream",
                    )
                if returncode in expected or attempts > retries:
                    break
            if mode == "pty":
                stdout, stdout_truncated = self._bounded(stdout, output_limit)
                stderr, stderr_truncated = self._bounded(stderr, output_limit)
            result = CommandResult(
                argv, int(returncode), stdout, stderr,
                time.perf_counter() - started, attempts,
                stdout_truncated, stderr_truncated,
            )
            if check and result.returncode not in expected:
                raise subprocess.CalledProcessError(
                    result.returncode, result.argv, output=result.stdout, stderr=result.stderr,
                )
            return result
        except (OSError, subprocess.TimeoutExpired, subprocess.CalledProcessError) as exc:
            error = type(exc).__name__
            returncode = getattr(exc, "returncode", returncode)
            stdout = _text(getattr(exc, "stdout", getattr(exc, "output", stdout)))
            stderr = _text(getattr(exc, "stderr", stderr))
            stdout_truncated = "[BriXTest output truncated]" in stdout
            stderr_truncated = "[BriXTest output truncated]" in stderr
            raise
        finally:
            elapsed = time.perf_counter() - started
            self._archive(
                argv, elapsed, returncode, error, stdout, stderr,
                attempts=attempts, mode=mode, expected=expected,
                stdout_truncated=stdout_truncated, stderr_truncated=stderr_truncated,
                max_bytes=output_limit,
            )
            if self.observer is not None:
                self.observer(elapsed, returncode, error)

    @staticmethod
    def _bounded(value: str, limit: int) -> tuple[str, bool]:
        encoded = value.encode("utf-8", errors="replace")
        if len(encoded) <= limit:
            return value, False
        marker = _TRUNCATION_MARKER
        if limit <= len(marker):
            return marker[:limit].decode("utf-8", errors="replace"), True
        available = max(0, limit - len(marker))
        head = available // 2
        tail = available - head
        selected = encoded[:head] + marker + (encoded[-tail:] if tail else b"")
        return selected.decode("utf-8", errors="replace"), True

    def _archive(
        self, argv: Sequence[str], elapsed: float, returncode: Optional[int],
        error: str, stdout: str, stderr: str,
        *, attempts: int, mode: str, expected: Sequence[int],
        stdout_truncated: bool, stderr_truncated: bool,
        max_bytes: int,
    ) -> None:
        if self.archive_dir is None:
            return
        with self._lock:
            self._sequence += 1
            stem = "%04d" % self._sequence
        self.archive_dir.mkdir(parents=True, exist_ok=True)
        archived_stdout = stdout
        archived_stderr = stderr
        for secret in self.redact:
            archived_stdout = archived_stdout.replace(secret, "[REDACTED]")
            archived_stderr = archived_stderr.replace(secret, "[REDACTED]")
        archived_stdout, _ = self._bounded(archived_stdout, max_bytes)
        archived_stderr, _ = self._bounded(archived_stderr, max_bytes)
        (self.archive_dir / (stem + ".stdout.log")).write_text(archived_stdout)
        (self.archive_dir / (stem + ".stderr.log")).write_text(archived_stderr)
        (self.archive_dir / (stem + ".json")).write_text(json.dumps({
            "argv": list(argv), "elapsed_seconds": elapsed,
            "returncode": returncode, "error": error,
            "attempts": attempts, "mode": mode,
            "expected_exit_codes": list(expected),
            "stdout_truncated": stdout_truncated,
            "stderr_truncated": stderr_truncated,
        }, indent=2, sort_keys=True) + "\n")
