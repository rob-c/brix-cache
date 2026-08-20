"""Fleet preparation and the artifact snapshot cache (feature F6).

Prep builds everything instances need before any process starts: CA
material, rendered secrets, data trees — each an adapter-registered
``PrepStep``.  The expensive path runs once; afterwards a **snapshot**
of the artifact tree is restored instead (measured on the grown suite:
11 s cold, 0.02 s warm).

Cache honesty rules, all four inherited from the grown implementation
because they were earned there:

- a snapshot is stamped with ``_CACHE_VERSION`` and every step's
  ``stamp()``; any mismatch rejects it (ground: *stamps*),
- snapshots older than ``_TTL_SECONDS`` are rejected (ground: *ttl*),
- unreadable/incoherent metadata rejects it (ground: *corrupt*),
- a restore that fails mid-copy rejects it (ground: *copy*),

and rejection is **never fatal** — every ground falls back to the
cold build.  ``explain()`` narrates the decision for ``prep --explain``.
"""

from __future__ import annotations

import json
import shutil
import time
from pathlib import Path
from typing import Dict, List, Optional, Protocol, Sequence, Tuple

from brixtest.config.lanes import Lane
from brixtest.errors import PrepStepError
from brixtest.events import emit
from brixtest.services.artifacts import ArtifactCatalog

__all__ = ["PrepStep", "ArtifactSet", "FleetPrep"]

_CACHE_VERSION = 1
_TTL_SECONDS = 4 * 3600
_META = "snapshot-meta.json"


class PrepStep(Protocol):
    """One unit of preparation.  ``stamp()`` must change whenever the
    step's output would change (input file hashes, tool versions);
    ``build()`` populates its slice of the artifact tree."""

    name: str

    def stamp(self) -> str: ...
    def build(self, artifacts: "ArtifactSet") -> None: ...


class ArtifactSet:
    """The lane's artifact tree, handed to every step.  Steps that build
    something consumers need should ``publish`` it — the catalog is how
    tests and the CLI address artifacts by name (F16)."""

    def __init__(self, root: Path) -> None:
        self.root = Path(root)
        self.catalog = ArtifactCatalog(self.root)

    def dir(self, name: str) -> Path:
        path = self.root / name
        path.mkdir(parents=True, exist_ok=True)
        return path

    def path(self, *parts: str) -> Path:
        return self.root.joinpath(*parts)

    def publish(self, name: str, path: Path, *, note: str = "") -> Path:
        return self.catalog.publish(name, path, note=note)


class FleetPrep:
    def __init__(
        self,
        lane: Lane,
        steps: Sequence[PrepStep],
        *,
        snapshot_dir: Optional[Path] = None,
        ttl_seconds: int = _TTL_SECONDS,
    ) -> None:
        self.lane = lane
        self.steps = tuple(steps)
        self.snapshot_dir = Path(snapshot_dir) if snapshot_dir else lane.root / "prep-snapshot"
        self.ttl_seconds = ttl_seconds
        self._last_decision: List[str] = []

    # -- stamps ----------------------------------------------------------

    def _stamps(self) -> Dict[str, str]:
        return {step.name: step.stamp() for step in self.steps}

    # -- snapshot verdict ------------------------------------------------

    def _snapshot_verdict(self) -> Tuple[bool, str]:
        """(usable, reason).  Reasons name the rejection ground."""
        meta_path = self.snapshot_dir / _META
        try:
            meta = json.loads(meta_path.read_text())
            version = meta["version"]
            created = float(meta["created"])
            stamps = dict(meta["stamps"])
        except (OSError, ValueError, KeyError, TypeError) as exc:
            return False, "corrupt: %s" % exc
        if version != _CACHE_VERSION:
            return False, "stamps: cache version %r != %d" % (version, _CACHE_VERSION)
        age = time.time() - created
        if age > self.ttl_seconds:
            return False, "ttl: snapshot is %.0fs old (limit %ds)" % (age, self.ttl_seconds)
        current = self._stamps()
        if stamps != current:
            changed = sorted(
                name for name in set(stamps) | set(current)
                if stamps.get(name) != current.get(name)
            )
            return False, "stamps: changed steps %s" % ", ".join(changed)
        return True, "fresh: %.0fs old, %d step stamps match" % (age, len(current))

    # -- the run ---------------------------------------------------------

    def run(self) -> ArtifactSet:
        """Restore the snapshot if honest, else cold-build and re-snapshot."""
        self._last_decision = []
        artifacts = ArtifactSet(self.lane.artifacts_dir)
        usable, reason = self._snapshot_verdict()
        self._last_decision.append("snapshot verdict: %s" % reason)
        if usable:
            try:
                self._restore(artifacts)
                self._last_decision.append("restored snapshot")
                emit("prep.restored", data_reason=reason)
                return artifacts
            except OSError as exc:
                self._last_decision.append("copy: restore failed (%s); cold build" % exc)
        self._cold_build(artifacts)
        self._save_snapshot(artifacts)
        return artifacts

    def _restore(self, artifacts: ArtifactSet) -> None:
        payload = self.snapshot_dir / "tree"
        if artifacts.root.exists():
            shutil.rmtree(artifacts.root)
        shutil.copytree(payload, artifacts.root, symlinks=True)

    def _cold_build(self, artifacts: ArtifactSet) -> None:
        artifacts.root.mkdir(parents=True, exist_ok=True)
        for step in self.steps:
            started = time.monotonic()
            try:
                step.build(artifacts)
            except Exception as exc:
                raise PrepStepError(step.name, exc) from exc
            self._last_decision.append(
                "built %s in %.2fs" % (step.name, time.monotonic() - started)
            )
        emit("prep.built", data_steps=len(self.steps))

    def _save_snapshot(self, artifacts: ArtifactSet) -> None:
        """Best-effort: a failed save never fails the session."""
        try:
            if self.snapshot_dir.exists():
                shutil.rmtree(self.snapshot_dir)
            self.snapshot_dir.mkdir(parents=True)
            shutil.copytree(artifacts.root, self.snapshot_dir / "tree", symlinks=True)
            meta = {
                "version": _CACHE_VERSION,
                "created": time.time(),
                "stamps": self._stamps(),
            }
            (self.snapshot_dir / _META).write_text(json.dumps(meta, sort_keys=True) + "\n")
            self._last_decision.append("snapshot saved")
        except OSError as exc:
            self._last_decision.append("snapshot save skipped: %s" % exc)

    def explain(self) -> str:
        """The narrated decision from the most recent ``run()`` — or, if
        none ran yet, the verdict a run would start from."""
        if self._last_decision:
            return "\n".join(self._last_decision)
        _, reason = self._snapshot_verdict()
        return "snapshot verdict: %s (no run yet)" % reason
