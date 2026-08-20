"""Resolve declarative config sources into semantic, checksum-backed content."""

from __future__ import annotations

import dataclasses
import hashlib
from pathlib import Path
from typing import Optional

from brixtest.design import ConfigFile
from brixtest.errors import SpecError
from brixtest.util.configtext import render_cfg


def _hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


@dataclasses.dataclass(frozen=True)
class ConfigMaterial:
    source: Optional[Path]
    source_name: str
    source_text: str
    source_sha256: str
    declared_text: str
    declared_sha256: str


def material(config: ConfigFile, source_root: Path) -> ConfigMaterial:
    """Read once and apply only user-supplied values, retaining runtime fields."""
    source = None
    if config.content is not None:
        text = config.content
        source_name = "inline-" + Path(config.destination).name
    else:
        raw = Path(str(config.path))
        source = raw.resolve() if raw.is_absolute() else (Path(source_root) / raw).resolve()
        try:
            text = source.read_text()
        except OSError as exc:
            raise SpecError("server config", str(config.path), "cannot read: %s" % exc) from exc
        source_name = source.name
    for key in config.values:
        if "{%s}" % key not in text:
            raise SpecError(
                "config.values", key, "does not name a placeholder in the source template",
            )
    declared = render_cfg(text, config.values)
    return ConfigMaterial(
        source=source, source_name=source_name, source_text=text,
        source_sha256=_hash(text), declared_text=declared,
        declared_sha256=_hash(declared),
    )


def identity(config: ConfigFile, source_root: Path) -> dict:
    item = material(config, source_root)
    return {
        "filename": config.destination,
        "runtime_template": config.template,
        "declared_sha256": item.declared_sha256,
        "bytes": len(item.declared_text.encode("utf-8")),
    }
