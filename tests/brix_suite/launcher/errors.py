"""Shared exception types for the split registry launcher modules."""

from __future__ import annotations

from dataclasses import dataclass


# The launcher class is composed from three modules (start / control /
# internals).  Keeping this exception in one small module of its own is what
# lets a caller catch the public ``server_launcher.RegistryCommandFailure``
# and still catch failures raised by a method that lives in a sibling module.
@dataclass
class RegistryCommandFailure(RuntimeError):
    config_path: str
    logs_dir: str
    command: tuple[str, ...]
    returncode: int
    stdout_tail: str
    stderr_tail: str

    def __str__(self) -> str:
        return (
            f"{' '.join(self.command)} failed rc={self.returncode}\n"
            f"config: {self.config_path}\n"
            f"logs: {self.logs_dir}\n"
            f"stdout:\n{self.stdout_tail}\n"
            f"stderr:\n{self.stderr_tail}"
        )
