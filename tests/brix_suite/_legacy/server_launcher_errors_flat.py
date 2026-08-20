# ARCHIVE — the pre-TS-4 flat body of ``tests/server_launcher_errors.py``, kept byte-identical so
# the "verbatim move" claim in the TS-4 decision note is checkable on disk
# rather than only in git history.  Nothing imports this; the live launcher is
# ``brix_suite.launcher``.  ``test_ci_ts4_launcher_move.py`` diffs every moved
# method against this text.
"""Shared exception types for the split registry launcher modules."""

from __future__ import annotations

from dataclasses import dataclass


# The launcher is assembled from continuation modules.  Keeping this exception
# in one small module is important: callers catching the public
# ``server_launcher.RegistryCommandFailure`` must also catch failures raised by
# methods implemented in a continuation shard.
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
