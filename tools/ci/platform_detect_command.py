"""Bounded command and optional proc-file reads for platform detection."""

import subprocess
from pathlib import Path
from typing import List, Optional


def run_command(cmd: List[str], timeout: int = 10) -> Optional[str]:
    """Return successful stdout; unavailable or timed-out probes return None."""
    try:
        result = subprocess.run(cmd, capture_output=True, text=True,
                                timeout=timeout, check=False)
        return result.stdout.strip() if result.returncode == 0 else None
    except (subprocess.SubprocessError, OSError):
        return None


def read_optional(path):
    """A missing or unreadable host information file has no observations."""
    try:
        return Path(path).read_text()
    except IOError:
        return ""
