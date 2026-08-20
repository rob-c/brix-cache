"""Settings helpers: one precedence rule, spelled out once (contract C2).

Every tunable in BriXTest resolves **constructor argument > environment
variable > coded default**, and the environment read happens exactly
once, at construction time.  These helpers are how adapter settings
classes implement that rule without each inventing its own parsing.

``install_legacy_module`` is the migration shim machinery (charter
§10): it publishes an object under a legacy module name in
``sys.modules`` so grown ``import`` sites keep working while call
sites are moved over, and records what it installed so the shim
inventory can be printed — and eventually deleted.
"""

from __future__ import annotations

import os
import sys
import types
from typing import Dict, List, Mapping, Optional, Tuple

__all__ = [
    "env_bool",
    "env_float",
    "env_int",
    "env_str",
    "install_legacy_module",
    "installed_legacy_modules",
]

_TRUE = frozenset({"1", "true", "yes", "on"})
_FALSE = frozenset({"0", "false", "no", "off", ""})


def _environ(env: Optional[Mapping[str, str]]) -> Mapping[str, str]:
    return os.environ if env is None else env


def env_str(
    name: str,
    default: str,
    override: Optional[str] = None,
    *,
    env: Optional[Mapping[str, str]] = None,
) -> str:
    if override is not None:
        return override
    return _environ(env).get(name, default)


def env_int(
    name: str,
    default: int,
    override: Optional[int] = None,
    *,
    env: Optional[Mapping[str, str]] = None,
) -> int:
    if override is not None:
        return override
    raw = _environ(env).get(name)
    if raw is None or raw == "":
        return default
    try:
        return int(raw)
    except ValueError:
        raise ValueError(
            "environment variable %s=%r is not an integer" % (name, raw)
        ) from None


def env_float(
    name: str,
    default: float,
    override: Optional[float] = None,
    *,
    env: Optional[Mapping[str, str]] = None,
) -> float:
    if override is not None:
        return override
    raw = _environ(env).get(name)
    if raw is None or raw == "":
        return default
    try:
        return float(raw)
    except ValueError:
        raise ValueError(
            "environment variable %s=%r is not a number" % (name, raw)
        ) from None


def env_bool(
    name: str,
    default: bool,
    override: Optional[bool] = None,
    *,
    env: Optional[Mapping[str, str]] = None,
) -> bool:
    if override is not None:
        return override
    raw = _environ(env).get(name)
    if raw is None:
        return default
    lowered = raw.strip().lower()
    if lowered in _TRUE:
        return True
    if lowered in _FALSE:
        return False
    raise ValueError(
        "environment variable %s=%r is not a boolean "
        "(use one of: 1/0, true/false, yes/no, on/off)" % (name, raw)
    )


_LEGACY_INSTALLED: Dict[str, str] = {}


def install_legacy_module(name: str, namespace: Mapping[str, object]) -> types.ModuleType:
    """Publish ``namespace`` as importable module ``name`` (a migration shim).

    Returns the module object.  Idempotent for the same name; the shim
    inventory is queryable via ``installed_legacy_modules`` so the
    guard that counts remaining shims has one place to look.
    """
    module = types.ModuleType(name)
    module.__dict__.update(namespace)
    module.__dict__["__brixtest_shim__"] = True
    sys.modules[name] = module
    _LEGACY_INSTALLED[name] = ", ".join(sorted(k for k in namespace if not k.startswith("_")))
    return module


def installed_legacy_modules() -> List[Tuple[str, str]]:
    """(module name, exported names) for every shim installed this process."""
    return sorted(_LEGACY_INSTALLED.items())
