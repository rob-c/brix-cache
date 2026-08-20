"""The process-worker protocol (feature F14).

Some client libraries can't live in the test process — they fork
badly, hold global state, or crash the interpreter.  The grown suite
solved this with a JSON-lines RPC to a persistent helper process; this
module is that protocol, made symmetric and typed.

Wire format, one JSON object per line, both directions::

    → {"tag": "t1", "op": "stat", "args": {"path": "/x"}}
    ← {"tag": "t1", "ok": true,  "result": {...}}
    ← {"tag": "t1", "ok": false, "error": {"type": "...", "message": "...",
                                            "stderr_tail": "..."}}

Responses may arrive in **any order** — the runner correlates on
``tag``, which is what lets one worker serve concurrent test threads.
The per-call deadline defaults from ``BRIXTEST_WORKER_TIMEOUT``
(seconds, default 90 — inherited from the grown suite's proxy-timeout
tuning).  Shutdown is TERM, then KILL after a short grace.
"""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import threading
import uuid
from typing import Any, Callable, Dict, Mapping, Optional, Sequence

from brixtest.errors import WorkerCrash, WorkerTimeout

__all__ = ["WorkerRunner", "serve", "DEFAULT_TIMEOUT"]

_ENV_TIMEOUT = "BRIXTEST_WORKER_TIMEOUT"
DEFAULT_TIMEOUT = float(os.environ.get(_ENV_TIMEOUT, "") or 90.0)
_STDERR_TAIL = 2048


class _Pending:
    __slots__ = ("event", "response")

    def __init__(self) -> None:
        self.event = threading.Event()
        self.response: Optional[Mapping[str, Any]] = None


class WorkerRunner:
    """Runner side: spawn the worker, correlate calls by tag."""

    def __init__(
        self,
        argv: Sequence[str],
        *,
        env: Optional[Mapping[str, str]] = None,
        cwd: Optional[str] = None,
    ) -> None:
        merged = dict(os.environ)
        if env:
            merged.update(env)
        self._proc = subprocess.Popen(
            list(argv),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=cwd,
            env=merged,
            text=True,
            bufsize=1,
        )
        self._pending: Dict[str, _Pending] = {}
        self._lock = threading.Lock()
        self._stderr_tail = ""
        self._reader = threading.Thread(target=self._read_loop, daemon=True)
        self._reader.start()
        self._stderr_thread = threading.Thread(target=self._stderr_loop, daemon=True)
        self._stderr_thread.start()

    # -- background readers ---------------------------------------------

    def _read_loop(self) -> None:
        assert self._proc.stdout is not None
        for line in self._proc.stdout:
            try:
                message = json.loads(line)
                tag = message["tag"]
            except (ValueError, KeyError):
                continue  # noise on stdout is not a protocol frame
            with self._lock:
                pending = self._pending.get(tag)
            if pending is not None:
                pending.response = message
                pending.event.set()
        # EOF: the worker is gone; wake every waiter so they see the crash
        with self._lock:
            waiters = list(self._pending.values())
        for pending in waiters:
            pending.event.set()

    def _stderr_loop(self) -> None:
        assert self._proc.stderr is not None
        for line in self._proc.stderr:
            self._stderr_tail = (self._stderr_tail + line)[-_STDERR_TAIL:]

    # -- calls -----------------------------------------------------------

    def call(
        self,
        op: str,
        args: Optional[Mapping[str, Any]] = None,
        *,
        timeout: float = DEFAULT_TIMEOUT,
    ) -> Any:
        tag = uuid.uuid4().hex[:12]
        pending = _Pending()
        with self._lock:
            self._pending[tag] = pending
        frame = json.dumps({"tag": tag, "op": op, "args": dict(args or {})})
        try:
            assert self._proc.stdin is not None
            self._proc.stdin.write(frame + "\n")
            self._proc.stdin.flush()
        except (OSError, ValueError):
            self._forget(tag)
            raise WorkerCrash(self._proc.poll() or -1, self._stderr_tail) from None
        if not pending.event.wait(timeout):
            self._forget(tag)
            raise WorkerTimeout(timeout, op)
        self._forget(tag)
        response = pending.response
        if response is None:  # reader hit EOF: the worker died mid-call
            raise WorkerCrash(self._proc.poll() or -1, self._stderr_tail)
        if response.get("ok"):
            return response.get("result")
        error = response.get("error") or {}
        raise RuntimeError(
            "worker op %r failed: %s: %s%s" % (
                op,
                error.get("type", "Error"),
                error.get("message", "?"),
                ("\n" + error["stderr_tail"]) if error.get("stderr_tail") else "",
            )
        )

    def _forget(self, tag: str) -> None:
        with self._lock:
            self._pending.pop(tag, None)

    # -- lifecycle -------------------------------------------------------

    def close(self, grace: float = 3.0) -> None:
        if self._proc.poll() is None:
            try:
                self._proc.terminate()
                self._proc.wait(timeout=grace)
            except subprocess.TimeoutExpired:
                self._proc.kill()
                self._proc.wait()

    def __enter__(self) -> "WorkerRunner":
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()


def serve(handlers: Mapping[str, Callable[..., Any]]) -> None:
    """Worker side: read frames from stdin, dispatch ``op`` to a handler
    called as ``handler(**args)``, answer on stdout.  Never raises out;
    every handler failure becomes an error frame.  Run this as the
    worker script's main loop."""
    try:
        # worker process only — the runner never calls serve(), so importing
        # this module never touches the test process's signal table
        signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    except (ValueError, OSError):
        pass  # not the main thread, or an exotic platform
    out_lock = threading.Lock()

    def respond(payload: Mapping[str, Any]) -> None:
        line = json.dumps(payload)
        with out_lock:
            sys.stdout.write(line + "\n")
            sys.stdout.flush()

    for raw in sys.stdin:
        try:
            frame = json.loads(raw)
            tag, op = frame["tag"], frame["op"]
            args = frame.get("args") or {}
        except (ValueError, KeyError):
            continue
        handler = handlers.get(op)
        if handler is None:
            respond({"tag": tag, "ok": False,
                     "error": {"type": "UnknownOp", "message": op, "stderr_tail": ""}})
            continue
        try:
            respond({"tag": tag, "ok": True, "result": handler(**args)})
        except Exception as exc:  # by contract: the loop survives handlers
            respond({"tag": tag, "ok": False,
                     "error": {"type": type(exc).__name__, "message": str(exc),
                               "stderr_tail": ""}})
