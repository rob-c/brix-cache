"""Resolve the effective nginx worker account for test permission handoffs."""

from __future__ import annotations

import os
from pathlib import Path
import grp
import pwd
import re
import subprocess


_USER_DIRECTIVE = re.compile(
    r"^\s*user\s+([^;\s]+)(?:\s+[^;\s]+)?\s*;", re.MULTILINE
)
_BUILD_USER = re.compile(r"(?:^|\s)--user=([^\s]+)")


def _without_comments(text: str) -> str:
    return "\n".join(line.split("#", 1)[0] for line in text.splitlines())


def _compiled_user(nginx_bin: str) -> str | None:
    try:
        result = subprocess.run(
            [nginx_bin, "-V"], capture_output=True, text=True, timeout=10
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    match = _BUILD_USER.search(f"{result.stdout}\n{result.stderr}")
    return match.group(1) if match else None


def nginx_default_worker_user(nginx_bin: str) -> str:
    """Return nginx's compiled worker account, with the module fallback."""
    fallback = os.environ.get("BRIX_WORKER_USER", "nobody")
    return _compiled_user(nginx_bin) or fallback


def nginx_default_worker_group(nginx_bin: str) -> str:
    """Return the primary group of the selected worker account.

    Debian-family systems deliberately pair ``nobody`` with ``nogroup``.
    Emitting a one-argument nginx ``user`` directive makes nginx fall back to
    its compiled group name (usually ``nobody``), which need not exist.
    """
    return nginx_worker_primary_group(nginx_default_worker_user(nginx_bin))


def nginx_worker_primary_group(user: str) -> str:
    """Resolve the group for an explicit worker without changing its account."""
    fallback = os.environ.get("BRIX_WORKER_GROUP", user)
    try:
        return grp.getgrgid(pwd.getpwnam(user).pw_gid).gr_name
    except KeyError:
        return fallback


def nginx_worker_user(config_path: str, nginx_bin: str) -> str:
    """Return the account the module will preserve or de-escalate to.

    A non-root explicit nginx user is already safe and is preserved.  Explicit
    root is rejected by the module and falls back to ``BRIX_WORKER_USER``.
    When the directive is omitted, nginx's compiled ``--user`` is authoritative
    and can differ from the module development default (packaged Fedora nginx
    uses ``nginx`` while source test builds commonly use ``nobody``).
    """
    fallback = os.environ.get("BRIX_WORKER_USER", "nobody")
    try:
        text = Path(config_path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return fallback
    match = _USER_DIRECTIVE.search(_without_comments(text))
    if match:
        configured = match.group(1)
        return fallback if configured == "root" else configured
    return nginx_default_worker_user(nginx_bin)
