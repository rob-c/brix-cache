"""Single home of the launcher's structured command-failure error.

Every server_launcher shard (and server_launcher itself) must raise and catch
the SAME class: the mechanical split had duplicated it per-mixin, so
`pytest.raises(RegistryCommandFailure)` against the server_launcher copy never
matched the mixin-raised one.
"""

from dataclasses import dataclass


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
