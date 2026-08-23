"""Resolve test artifacts by stable name instead of filesystem layout.

Preparation steps publish files under names consumed by tests and tools::

    ca_cert = fleet.artifacts.path("ca.cert")
    $ brixtest artifacts path ca.cert

The catalog file lives *inside* the artifact tree (``catalog.json``),
so the snapshot cache restores names and files as one unit: whatever
generation of the tree you hold, its names resolve to the matching files.
"""

from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

from brixtest.errors import ArtifactNotFound, SpecError

__all__ = ["ArtifactCatalog"]

_CATALOG = "catalog.json"


class ArtifactCatalog:
    def __init__(self, root: Path) -> None:
        self.root = Path(root)
        self._lock = threading.Lock()
        self.observer: Optional[Callable[[str], None]] = None

    @property
    def catalog_path(self) -> Path:
        return self.root / _CATALOG

    def _load(self) -> Dict[str, Dict[str, str]]:
        try:
            data = json.loads(self.catalog_path.read_text())
            return dict(data.get("published", {}))
        except (OSError, ValueError):
            return {}

    def _store(self, published: Dict[str, Dict[str, str]]) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        payload = {"published": published}
        self.catalog_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")

    def publish(self, name: str, path: Path, *, note: str = "") -> Path:
        """Bind ``name`` to a file or directory inside the artifact tree.
        Re-publishing the same name is fine (steps re-run); publishing a
        path outside the tree is not — the catalog must survive snapshot
        restore, which only copies the tree."""
        path = Path(path)
        try:
            rel = path.resolve().relative_to(self.root.resolve())
        except ValueError:
            raise SpecError(
                "artifact path", str(path),
                "must live inside the artifact tree %s so the snapshot "
                "cache carries name and file together" % self.root,
            ) from None
        entry = {
            "path": str(rel),
            "kind": "dir" if path.is_dir() else "file",
            "note": note,
        }
        with self._lock:
            published = self._load()
            published[name] = entry
            self._store(published)
        return path

    def path(self, name: str) -> Path:
        published = self._load()
        entry = published.get(name)
        if entry is None:
            raise ArtifactNotFound(name, sorted(published), str(self.catalog_path))
        resolved = self.root / entry["path"]
        if not resolved.exists():
            raise ArtifactNotFound(
                name + " (cataloged but missing on disk — re-run: brixtest prep)",
                sorted(published), str(self.catalog_path),
            )
        if self.observer is not None:
            self.observer(name)
        return resolved

    def read_bytes(self, name: str) -> bytes:
        return self.path(name).read_bytes()

    def read_text(self, name: str) -> str:
        return self.path(name).read_text()

    def names(self) -> List[str]:
        return sorted(self._load())

    def get(self, name: str) -> Optional[Path]:
        try:
            return self.path(name)
        except ArtifactNotFound:
            return None

    def describe(self) -> List[Tuple[str, str, str, str]]:
        """(name, kind, relative path, note) rows for the CLI table."""
        published = self._load()
        return [
            (name, published[name]["kind"], published[name]["path"],
             published[name].get("note", ""))
            for name in sorted(published)
        ]

    def __contains__(self, name: str) -> bool:
        return name in self._load()

    def __len__(self) -> int:
        return len(self._load())
