"""Small filesystem-backed heartbeat and cancellation control channel."""

from __future__ import annotations

import json
import os
import threading
import time
from pathlib import Path
from typing import Optional

from brixtest.helper_transport import publish

HEARTBEAT_ENV = "BRIXTEST_HELPER_HEARTBEAT"
CANCEL_ENV = "BRIXTEST_HELPER_CANCEL"


def _atomic_json(path: Path, value: object) -> None:
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(value, sort_keys=True) + "\n")
    temporary.replace(path)


class HelperHeartbeat:
    """Publish helper liveness without relying on the test worker thread."""

    def __init__(
        self, heartbeat: Path, cancellation: Path, *, interval: float = 0.25,
    ) -> None:
        self.heartbeat = Path(heartbeat)
        self.cancellation = Path(cancellation)
        self.interval = interval
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

    @classmethod
    def from_environment(cls) -> Optional["HelperHeartbeat"]:
        heartbeat = os.environ.get(HEARTBEAT_ENV, "")
        cancellation = os.environ.get(CANCEL_ENV, "")
        if not heartbeat or not cancellation:
            return None
        return cls(Path(heartbeat), Path(cancellation))

    def start(self) -> None:
        """Start one daemon publisher and emit the first heartbeat immediately."""
        if self._thread is not None:
            return
        self.heartbeat.parent.mkdir(parents=True, exist_ok=True)
        self._publish()
        self._thread = threading.Thread(
            target=self._loop, name="brixtest-helper-heartbeat", daemon=True,
        )
        self._thread.start()

    def cancelled(self) -> bool:
        """Return whether the supervising controller requested cancellation."""
        return self.cancellation.is_file()

    def close(self) -> None:
        """Stop the publisher within a short bounded wait."""
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=max(1.0, self.interval * 4))
            self._thread = None

    def _publish(self) -> None:
        payload = {
            "schema": 1, "pid": os.getpid(), "time": time.time(),
            "cancelled": self.cancelled(),
        }
        if not publish("heartbeat", payload):
            _atomic_json(self.heartbeat, payload)

    def _loop(self) -> None:
        while not self._stop.wait(self.interval):
            try:
                self._publish()
            except OSError:
                return


_HEARTBEAT: Optional[HelperHeartbeat] = None


def start_helper_heartbeat() -> None:
    """Start the process-global helper heartbeat when the channel is configured."""
    global _HEARTBEAT
    if _HEARTBEAT is not None:
        return
    _HEARTBEAT = HelperHeartbeat.from_environment()
    if _HEARTBEAT is not None:
        _HEARTBEAT.start()


def stop_helper_heartbeat() -> None:
    """Stop and clear the process-global helper heartbeat."""
    global _HEARTBEAT
    if _HEARTBEAT is not None:
        _HEARTBEAT.close()
        _HEARTBEAT = None
