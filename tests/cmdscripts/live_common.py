"""Small, explicit primitives shared by Python ports of live command scripts."""

from __future__ import annotations

from contextlib import AbstractContextManager
from pathlib import Path
import atexit
import hashlib
import os
import shutil
import signal
import subprocess
import tempfile
import time
from typing import Iterable

from cmdscripts.compile_run import REPO_ROOT
from lib_py.util import wait_tcp


class LiveFailure(RuntimeError):
    """A failed external command with its captured diagnostic output."""


_FROZEN_NGINX: Path | None = None


def freeze_nginx(src: str | Path) -> Path:
    """Return a private, immutable copy of the nginx binary.

    The shared build tree's ``objs/nginx`` can be relinked by a concurrent
    incremental build; ``exec`` of a binary during its relink window fails with
    EACCES, surfacing as a flaky ``PermissionError`` the moment a live scenario
    spawns a server.  Copy the binary once per test process to a stable path so
    every scenario spawns a frozen binary no build can disturb.  The copy is
    validated (``nginx -v``) and retried, so a binary caught mid-relink is never
    frozen in a half-written state.  Falls back to the live path if no stable
    copy can be taken.
    """
    global _FROZEN_NGINX
    if _FROZEN_NGINX is not None and _FROZEN_NGINX.exists():
        return _FROZEN_NGINX
    src = Path(src)
    if not src.exists():
        return src
    frozen = Path(tempfile.gettempdir()) / f"brix-live-nginx-{os.getpid()}" / "nginx"
    frozen.parent.mkdir(parents=True, exist_ok=True)
    for _ in range(6):
        try:
            shutil.copy2(src, frozen)
            frozen.chmod(0o755)
            if subprocess.run([str(frozen), "-v"], capture_output=True).returncode == 0:
                _FROZEN_NGINX = frozen
                atexit.register(shutil.rmtree, frozen.parent, ignore_errors=True)
                return frozen
        except OSError:
            pass  # source mid-relink (EACCES/ETXTBSY/short read) — retry
        time.sleep(0.5)
    return src


class LiveRun(AbstractContextManager["LiveRun"]):
    """Own a temporary live-test topology and every process it starts."""

    def __init__(self, label: str, nginx: str | Path | None = None) -> None:
        self.root = Path(tempfile.mkdtemp(prefix=f"{label}."))
        self.nginx = freeze_nginx(nginx or os.environ.get("NGINX_BIN", "/tmp/nginx-1.28.3/objs/nginx"))
        self.processes: list[subprocess.Popen[str]] = []
        self.pidfiles: list[Path] = []

    def __enter__(self) -> "LiveRun":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def close(self) -> None:
        for pidfile in reversed(self.pidfiles):
            try:
                os.kill(int(pidfile.read_text().strip()), signal.SIGTERM)
            except (OSError, ValueError):
                pass
        for proc in reversed(self.processes):
            if proc.poll() is None:
                proc.terminate()
        deadline = time.monotonic() + 2
        for proc in reversed(self.processes):
            remaining = max(0, deadline - time.monotonic())
            try:
                proc.wait(remaining)
            except subprocess.TimeoutExpired:
                proc.kill()
        shutil.rmtree(self.root, ignore_errors=True)

    def mkdir(self, *parts: str) -> Path:
        path = self.root.joinpath(*parts)
        path.mkdir(parents=True, exist_ok=True)
        return path

    def write(self, path: Path, text: str) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        return path

    def call(
        self,
        argv: Iterable[str | Path],
        *,
        cwd: Path | None = None,
        input: str | bytes | None = None,
        env: dict[str, str] | None = None,
        check: bool = True,
    ) -> subprocess.CompletedProcess[str]:
        command = [str(item) for item in argv]
        text = not isinstance(input, bytes)
        proc = subprocess.Popen(
            command,
            cwd=str(cwd) if cwd else None,
            env={**os.environ, **(env or {})},
            stdin=subprocess.PIPE if input is not None else None,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=text,
        )
        stdout, stderr = proc.communicate(input)
        result = subprocess.CompletedProcess(command, proc.returncode, stdout, stderr)
        if check and result.returncode:
            raise LiveFailure(f"{' '.join(command)} failed ({result.returncode}): {stderr or stdout}")
        return result

    def spawn(
        self,
        argv: Iterable[str | Path],
        *,
        cwd: Path | None = None,
        env: dict[str, str] | None = None,
    ) -> subprocess.Popen[str]:
        proc = subprocess.Popen(
            [str(item) for item in argv],
            cwd=str(cwd) if cwd else None,
            env={**os.environ, **(env or {})},
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            text=True,
        )
        self.processes.append(proc)
        return proc

    def start_nginx(self, prefix: Path, config: Path, port: int, *, timeout: float = 10) -> None:
        prefix.mkdir(parents=True, exist_ok=True)
        result = self.call([self.nginx, "-p", prefix, "-c", config], check=False)
        if result.returncode:
            raise LiveFailure(result.stderr or result.stdout or f"nginx failed to start for {config}")
        pidfile = prefix / "nginx.pid"
        self.pidfiles.append(pidfile)
        if not wait_tcp("127.0.0.1", port, timeout):
            error_log = prefix / "logs/e.log"
            detail = error_log.read_text(errors="replace") if error_log.exists() else ""
            raise LiveFailure(f"nginx was not ready on {port}: {detail}")

    def stop_nginx(self, prefix: Path) -> None:
        pidfile = prefix / "nginx.pid"
        try:
            os.kill(int(pidfile.read_text().strip()), signal.SIGTERM)
        except (OSError, ValueError):
            return
        deadline = time.monotonic() + 3
        while pidfile.exists() and time.monotonic() < deadline:
            time.sleep(0.05)

    def curl_status(self, url: str, *extra: str, timeout: int = 25) -> int:
        result = self.call(
            ["curl", "-sS", "--max-time", str(timeout), "-o", os.devnull, "-w", "%{http_code}", *extra, url],
            check=False,
        )
        return int(result.stdout.strip() or 0) if result.stdout.strip().isdigit() else 0

    def curl_bytes(self, url: str, *extra: str, timeout: int = 25) -> bytes:
        proc = subprocess.Popen(
            ["curl", "-sS", "--max-time", str(timeout), *extra, url],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        stdout, stderr = proc.communicate()
        if proc.returncode:
            raise LiveFailure(stderr.decode(errors="replace"))
        return stdout


def random_file(path: Path, size: int) -> str:
    path.write_bytes(os.urandom(size))
    return sha256(path)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def nginx_binary_from_args(argv: list[str] | None = None) -> tuple[Path | None, list[str]]:
    values = list(argv or [])
    if values and not values[0].startswith("-"):
        return Path(values.pop(0)), values
    return None, values


__all__ = ["LiveFailure", "LiveRun", "REPO_ROOT", "nginx_binary_from_args", "random_file", "sha256"]
