"""Snapshot and render each test-declared server's on-disk configuration."""

from __future__ import annotations

import dataclasses
import hashlib
import json
import shutil
from pathlib import Path
from typing import Dict, Mapping, Optional, Sequence

from brixtest.design import ConfigFile, Server
from brixtest.config.material import material
from brixtest.errors import SpecError
from brixtest.util.configtext import render_cfg_strict

__all__ = ["CapturedConfig", "ConfigStore"]


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


@dataclasses.dataclass(frozen=True)
class CapturedConfig:
    server: str
    source: Optional[Path]
    snapshot: Path
    rendered: Path
    source_sha256: str
    declared_sha256: str
    rendered_sha256: str
    template: bool
    filename: str

    @property
    def sha256(self) -> str:
        return self.rendered_sha256


class ConfigStore:
    def __init__(self, root: Path, source_root: Path) -> None:
        self.root = Path(root)
        self.source_root = Path(source_root)
        self._items: Dict[str, CapturedConfig] = {}
        self._sets: Dict[str, tuple[CapturedConfig, ...]] = {}

    def _capture_one(
        self, server: Server, config: ConfigFile, values: Mapping[str, object],
    ) -> CapturedConfig:
        selected = material(config, self.source_root)
        source = selected.source
        directory = self.root / server.name
        source_dir = directory / "source"
        rendered_dir = directory / "rendered"
        source_dir.mkdir(parents=True, exist_ok=True)
        rendered_dir.mkdir(parents=True, exist_ok=True)
        snapshot = source_dir / config.destination
        snapshot.parent.mkdir(parents=True, exist_ok=True)
        if source is None:
            snapshot.write_text(selected.source_text)
        else:
            before = (source.stat().st_size, source.stat().st_mtime_ns, _sha256(source))
            shutil.copy2(source, snapshot)
            after = (source.stat().st_size, source.stat().st_mtime_ns, _sha256(source))
            if before != after or _sha256(snapshot) != selected.source_sha256:
                raise SpecError(
                    "server %s config" % server.name, str(source),
                    "changed while being captured; retry with a stable config",
                )
        rendered = rendered_dir / config.destination
        rendered.parent.mkdir(parents=True, exist_ok=True)
        text = selected.declared_text
        if config.template:
            text = render_cfg_strict(
                text, values,
                template="%s config %s" % (
                    server.name, source or "<inline:%s>" % config.destination,
                ),
            )
        rendered.write_text(text)
        item = CapturedConfig(
            server=server.name, source=source, snapshot=snapshot, rendered=rendered,
            source_sha256=selected.source_sha256,
            declared_sha256=selected.declared_sha256,
            rendered_sha256=_sha256(rendered), template=config.template,
            filename=config.destination,
        )
        return item

    def capture_all(
        self, server: Server, values: Mapping[str, object],
    ) -> tuple[CapturedConfig, ...]:
        """Capture every declared config and retain the selected primary."""
        declarations: Sequence[ConfigFile] = server.configs.files
        targets = {
            "config_%s" % self.placeholder(item.destination):
                self.root / server.name / "rendered" / item.destination
            for item in declarations
        }
        rendered_values = dict(values)
        rendered_values.update(targets)
        captured = tuple(
            self._capture_one(server, declaration, rendered_values)
            for declaration in declarations
        )
        by_destination = {item.filename: item for item in captured}
        primary = by_destination[server.configs.primary]
        self._items[server.name] = primary
        self._sets[server.name] = captured
        self._write_manifest()
        return captured

    def capture(self, server: Server, values: Mapping[str, object]) -> CapturedConfig:
        """Capture all configs and return the primary compatibility value."""
        self.capture_all(server, values)
        return self.get(server.name)

    @staticmethod
    def placeholder(destination: str) -> str:
        """Return the stable placeholder suffix for one config destination."""
        return "".join(
            character if character.isalnum() else "_" for character in destination
        ).strip("_")

    def all(self, server: str) -> tuple[CapturedConfig, ...]:
        """Return all captured configs for one server in declaration order."""
        try:
            return self._sets[server]
        except KeyError:
            raise SpecError("server config", server, "has not been captured") from None

    def get(self, server: str) -> CapturedConfig:
        try:
            return self._items[server]
        except KeyError:
            raise SpecError("server config", server, "has not been captured") from None

    def _write_manifest(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        rows = {
            name: {
                "primary": dataclasses.asdict(self._items[name]),
                "files": [dataclasses.asdict(item) for item in values],
            }
            for name, values in sorted(self._sets.items())
        }
        (self.root / "manifest.json").write_text(
            json.dumps({"configs": rows}, indent=2, sort_keys=True, default=str) + "\n"
        )
