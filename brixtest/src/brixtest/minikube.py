"""Docker-backed Minikube target used by the CLI and Kubernetes backend."""

from __future__ import annotations

import dataclasses
import json
import os
import subprocess
import sys
from typing import Mapping, Optional, Sequence

from brixtest.errors import SpecError

__all__ = ["MinikubeConfig", "minikube_command", "minikube_status"]


def _status_is_running(value: object) -> bool:
    if not isinstance(value, Mapping):
        return False
    normalized = {str(key).lower(): str(item).lower() for key, item in value.items()}
    return all(normalized.get(name) == "running" for name in (
        "host", "kubelet", "apiserver",
    ))


@dataclasses.dataclass(frozen=True)
class MinikubeConfig:
    """Reproducible defaults for BriXTest's local Kubernetes target."""

    profile: str = "brixtest"
    driver: str = "docker"
    container_runtime: str = "docker"
    cpus: int = 2
    memory_mb: int = 4096
    server_image: str = (
        "alpine/socat@sha256:"
        "d85531a29ef5ba99dfb4717485c239307e2902d522a1bc010992a2728c92cfad"
    )

    def __post_init__(self) -> None:
        if not isinstance(self.profile, str) or not self.profile:
            raise SpecError("Minikube profile", self.profile, "must be non-empty text")
        if self.driver != "docker" or self.container_runtime != "docker":
            raise SpecError(
                "Minikube runtime", (self.driver, self.container_runtime),
                "BriXTest's supported local target uses Docker for both",
            )
        for name in ("cpus", "memory_mb"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise SpecError("Minikube %s" % name, value, "must be an integer >= 1")
        if "@sha256:" not in self.server_image:
            raise SpecError(
                "Minikube server image", self.server_image,
                "must be digest pinned",
            )

    @classmethod
    def from_environment(cls) -> "MinikubeConfig":
        """Build defaults with explicit, validated environment overrides."""
        try:
            cpus = int(os.environ.get("BRIXTEST_MINIKUBE_CPUS", "2"))
            memory = int(os.environ.get("BRIXTEST_MINIKUBE_MEMORY_MB", "4096"))
        except ValueError as exc:
            raise SpecError(
                "Minikube environment", "cpus/memory",
                "BRIXTEST_MINIKUBE_CPUS and MEMORY_MB must be integers",
            ) from exc
        return cls(
            profile=os.environ.get("BRIXTEST_MINIKUBE_PROFILE", "brixtest"),
            cpus=cpus, memory_mb=memory,
        )

    def start_argv(self) -> tuple[str, ...]:
        """Return the deterministic, Docker-only cluster start command."""
        return (
            "minikube", "start", "--profile", self.profile,
            "--driver=docker", "--container-runtime=docker",
            "--cpus=%d" % self.cpus, "--memory=%d" % self.memory_mb,
        )

    def status_argv(self) -> tuple[str, ...]:
        """Return the machine-readable cluster status command."""
        return ("minikube", "status", "--profile", self.profile, "--output=json")


def minikube_status(
    config: Optional[MinikubeConfig] = None,
) -> Mapping[str, object]:
    """Return normalized status without starting or changing a cluster."""
    selected = config or MinikubeConfig.from_environment()
    try:
        result = subprocess.run(
            list(selected.status_argv()), capture_output=True, text=True,
            timeout=15.0, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {
            "ok": False, "profile": selected.profile, "driver": selected.driver,
            "error": "%s: %s" % (type(exc).__name__, exc),
        }
    try:
        raw_details = json.loads(result.stdout or "{}")
    except ValueError:
        raw_details = {"raw": result.stdout.strip()}
    details = raw_details if isinstance(raw_details, Mapping) else {"raw": raw_details}
    running = _status_is_running(details)
    return {
        "ok": result.returncode == 0 and running,
        "running": running,
        "profile": selected.profile,
        "driver": selected.driver,
        "container_runtime": selected.container_runtime,
        "details": details,
        "error": result.stderr.strip(),
    }


def minikube_command(
    action: str, config: Optional[MinikubeConfig] = None,
    *, pytest_args: Sequence[str] = (),
) -> int:
    """Run one explicit Minikube operator action and return its exit status."""
    selected = config or MinikubeConfig.from_environment()
    if action == "start":
        try:
            return subprocess.run(list(selected.start_argv()), check=False).returncode
        except OSError as exc:
            raise SpecError(
                "Minikube start", selected.profile, "%s: %s" % (type(exc).__name__, exc),
            ) from exc
    if action == "status":
        return 0 if minikube_status(selected)["ok"] else 1
    if action == "test":
        status = minikube_status(selected)
        if not status["ok"]:
            raise SpecError(
                "Minikube test", selected.profile,
                "profile is not ready; run `brixtest minikube start` first",
            )
        try:
            loaded = subprocess.run([
                "minikube", "image", "load", "--profile", selected.profile,
                selected.server_image,
            ], check=False).returncode
        except OSError as exc:
            raise SpecError(
                "Minikube image load", selected.server_image,
                "%s: %s" % (type(exc).__name__, exc),
            ) from exc
        if loaded:
            return loaded
        env = dict(os.environ)
        env.update({
            "BRIXTEST_MINIKUBE": "1",
            "BRIXTEST_MINIKUBE_PROFILE": selected.profile,
            "BRIXTEST_BACKEND": "minikube",
        })
        argv = [
            os.environ.get("PYTHON", sys.executable), "-m", "pytest",
            *pytest_args,
        ]
        try:
            return subprocess.run(argv, env=env, check=False).returncode
        except OSError as exc:
            raise SpecError(
                "Minikube test", selected.profile, "%s: %s" % (type(exc).__name__, exc),
            ) from exc
    raise SpecError("Minikube action", action, "must be start, status, or test")
