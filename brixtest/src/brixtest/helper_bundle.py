"""Build deterministic, content-addressed bundles for remote pytest helpers."""

from __future__ import annotations

import dataclasses
import hashlib
import importlib.metadata
import importlib.util
import json
import os
import shutil
import stat
import zipfile
from pathlib import Path
from typing import Iterable, Mapping, Sequence

from packaging.requirements import Requirement

from brixtest.errors import SpecError

_RUNTIME_DISTRIBUTIONS = ("pytest", "pluggy")
_ROOT_CONFIGS = ("conftest.py", "pytest.ini", "pyproject.toml", "setup.cfg", "tox.ini")
_PORTABLE_SUFFIXES = frozenset({
    ".cfg", ".conf", ".crt", ".csv", ".html", ".ini", ".j2", ".jinja",
    ".json", ".key", ".md", ".pem", ".py", ".template", ".toml", ".txt",
    ".xml", ".yaml", ".yml",
})
_SKIP_DIRS = frozenset({
    ".git", ".hg", ".svn", ".mypy_cache", ".pytest_cache", ".ruff_cache",
    ".complexipy_cache", "__pycache__", "node_modules", "build", "dist", "objs",
})
_MAX_FILE = 64 << 20
_MAX_BUNDLE_INPUT = 256 << 20


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def _safe_relative(path: Path, root: Path, field: str) -> Path:
    try:
        relative = path.resolve().relative_to(root.resolve())
    except ValueError as exc:
        raise SpecError(field, str(path), "must remain under the pytest root") from exc
    if not relative.parts or any(part in ("", ".", "..") for part in relative.parts):
        raise SpecError(field, str(path), "must name a file under the pytest root")
    return relative


def _selected_test(nodeid: str, source_root: Path) -> tuple[Path, Path]:
    raw = nodeid.split("::", 1)[0]
    path = Path(raw)
    if not path.is_absolute():
        path = source_root / path
    relative = _safe_relative(path, source_root, "Kubernetes helper test")
    if not path.is_file():
        raise SpecError("Kubernetes helper test", raw, "does not name a regular file")
    return path.resolve(), relative


def _walk_regular(root: Path) -> Iterable[Path]:
    if root.is_file():
        yield root
        return
    yield from _walk_directory(root)


def _walk_directory(root: Path) -> Iterable[Path]:
    for current, directories, files in os.walk(root):
        directories[:] = _retained_directories(Path(current), directories)
        yield from _regular_named_files(Path(current), files)


def _retained_directories(parent: Path, names: Sequence[str]) -> list[str]:
    return sorted(
        name for name in names
        if name not in _SKIP_DIRS
        and not name.startswith(".")
        and not (parent / name).is_symlink()
    )


def _regular_named_files(parent: Path, names: Sequence[str]) -> Iterable[Path]:
    for name in sorted(names):
        path = parent / name
        if path.is_file() and not path.is_symlink():
            yield path


def _project_files(
    source_root: Path, test: Path, relative: Path,
    project_inputs: Sequence[Path] = (),
) -> dict[str, Path]:
    first = source_root / relative.parts[0]
    selected = first if first.is_dir() else test
    result = _workspace_files(source_root, selected)
    result.update(_portable_project_files(source_root))
    result.update(_root_config_files(source_root))
    result.update(_ancestor_conftests(source_root, test))
    result.update(_project_input_files(source_root, project_inputs))
    return result


def _project_input_files(source_root: Path, values: Sequence[Path]) -> dict[str, Path]:
    result = {}
    for value in values:
        selected = Path(value).resolve()
        relative = Path() if selected == source_root.resolve() else _safe_relative(
            selected, source_root, "native helper input",
        )
        for path in _walk_regular(selected):
            target = relative / path.relative_to(selected) if selected.is_dir() else relative
            result["workspace/%s" % target] = path
    return result


def _portable_project_files(source_root: Path) -> dict[str, Path]:
    return {
        "workspace/%s" % path.relative_to(source_root): path
        for path in _walk_regular(source_root)
        if path.suffix.lower() in _PORTABLE_SUFFIXES
    }


def _workspace_files(source_root: Path, selected: Path) -> dict[str, Path]:
    return {
        "workspace/%s" % path.relative_to(source_root): path
        for path in _walk_regular(selected)
    }


def _root_config_files(source_root: Path) -> dict[str, Path]:
    result = {}
    for name in _ROOT_CONFIGS:
        candidate = source_root / name
        if candidate.is_file() and not candidate.is_symlink():
            result["workspace/%s" % name] = candidate
    return result


def _ancestor_conftests(source_root: Path, test: Path) -> dict[str, Path]:
    result = {}
    for parent in test.parents:
        if parent == source_root.parent:
            break
        candidate = parent / "conftest.py"
        if candidate.is_file() and not candidate.is_symlink():
            result["workspace/%s" % candidate.relative_to(source_root)] = candidate
        if parent == source_root:
            break
    return result


def _module_roots(name: str) -> list[tuple[Path, str]]:
    try:
        spec = importlib.util.find_spec(name)
    except (ImportError, ModuleNotFoundError, ValueError) as exc:
        raise SpecError("Kubernetes helper module", name, "cannot be resolved") from exc
    if spec is None:
        raise SpecError("Kubernetes helper module", name, "cannot be resolved")
    if spec.submodule_search_locations:
        return [(Path(location), name.replace(".", "/")) for location in spec.submodule_search_locations]
    if spec.origin and spec.origin not in ("built-in", "frozen"):
        return [(Path(spec.origin), name.replace(".", "/") + Path(spec.origin).suffix)]
    return []


def _runtime_files(trusted_modules: Sequence[str]) -> dict[str, Path]:
    result = _module_files("brixtest")
    for name in dict.fromkeys(trusted_modules):
        result.update(_module_files(name))
    for name in _distribution_closure(_RUNTIME_DISTRIBUTIONS):
        result.update(_distribution_files(name))
    return result


def _module_files(name: str) -> dict[str, Path]:
    result = {}
    for root, relative in _module_roots(name):
        result.update(_module_root_files(root, relative))
    return result


def _module_root_files(root: Path, relative: str) -> dict[str, Path]:
    if root.is_dir():
        return {
            "opt/brixtest/python/%s" % (Path(relative) / path.relative_to(root)): path
            for path in _walk_regular(root)
        }
    if root.is_file() and not root.is_symlink():
        return {"opt/brixtest/python/%s" % relative: root}
    return {}


def _distribution_closure(names: Sequence[str]) -> tuple[str, ...]:
    selected = set()
    pending = list(names)
    while pending:
        name = pending.pop()
        if name in selected:
            continue
        selected.add(name)
        pending.extend(_required_distributions(name, selected))
    return tuple(sorted(selected))


def _required_distributions(name: str, selected: set[str]) -> list[str]:
    try:
        requirements = importlib.metadata.requires(name) or ()
    except importlib.metadata.PackageNotFoundError as exc:
        raise SpecError("Kubernetes helper dependency", name, "is not installed") from exc
    result = []
    for value in requirements:
        requirement = Requirement(value)
        enabled = requirement.marker is None or requirement.marker.evaluate({"extra": ""})
        if enabled and requirement.name not in selected:
            result.append(requirement.name)
    return result


def _distribution_files(name: str) -> dict[str, Path]:
    try:
        distribution = importlib.metadata.distribution(name)
    except importlib.metadata.PackageNotFoundError as exc:
        raise SpecError("Kubernetes helper dependency", name, "is not installed") from exc
    root = Path(distribution.locate_file("")).resolve()
    result = {}
    for item in distribution.files or ():
        _add_distribution_file(result, root, Path(distribution.locate_file(item)))
    return result


def _add_distribution_file(result: dict[str, Path], root: Path, source: Path) -> None:
    try:
        relative = source.resolve().relative_to(root)
    except ValueError:
        return
    if source.is_file() and not source.is_symlink() and source.suffix != ".pyc":
        result["opt/brixtest/python/%s" % relative] = source.resolve()


def _runtime_tools() -> dict[str, Path]:
    configured = os.environ.get("BRIXTEST_KUBECTL", "kubectl")
    selected = shutil.which(configured)
    if selected is None:
        return {}
    path = Path(selected).resolve()
    if not path.is_file() or path.is_symlink():
        return {}
    return {"opt/brixtest/bin/kubectl": path}


def _dependency_versions() -> dict[str, str]:
    names = ("brixtest", *_distribution_closure(_RUNTIME_DISTRIBUTIONS))
    return {name: _installed_version(name) for name in names}


def _installed_version(name: str) -> str:
    try:
        return importlib.metadata.version(name)
    except importlib.metadata.PackageNotFoundError:
        return "source-tree" if name == "brixtest" else "unknown"


def _validated_files(files: Mapping[str, Path]) -> tuple[list[dict[str, object]], int]:
    rows = []
    total = 0
    for target, source in sorted(files.items()):
        size = source.stat().st_size
        if size > _MAX_FILE:
            raise SpecError("Kubernetes helper bundle file", str(source), "exceeds 64 MiB")
        total += size
        if total > _MAX_BUNDLE_INPUT:
            raise SpecError("Kubernetes helper bundle", total, "exceeds 256 MiB")
        rows.append({
            "path": target, "source": str(source), "bytes": size,
            "sha256": _sha256_bytes(source.read_bytes()),
            "mode": stat.S_IMODE(source.stat().st_mode),
        })
    return rows, total


def _fingerprint(rows: Sequence[Mapping[str, object]], dependencies: Mapping[str, str]) -> str:
    content = [{key: row[key] for key in ("path", "bytes", "sha256", "mode")} for row in rows]
    encoded = json.dumps(
        {"schema": 1, "files": content, "dependencies": dependencies},
        sort_keys=True, separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _write_zip(path: Path, rows: Sequence[Mapping[str, object]], manifest: bytes) -> None:
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
        for row in rows:
            info = zipfile.ZipInfo(str(row["path"]), date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = (int(row["mode"]) & 0xFFFF) << 16
            archive.writestr(info, Path(str(row["source"])).read_bytes())
        info = zipfile.ZipInfo("opt/brixtest/bundle.json", date_time=(1980, 1, 1, 0, 0, 0))
        info.compress_type = zipfile.ZIP_DEFLATED
        info.external_attr = 0o600 << 16
        archive.writestr(info, manifest)


@dataclasses.dataclass(frozen=True)
class HelperBundle:
    """One immutable remote-helper bundle and its dependency identity."""

    path: Path
    fingerprint: str
    sha256: str
    file_count: int
    input_bytes: int
    dependencies: Mapping[str, str]

    def as_dict(self) -> dict[str, object]:
        """Return JSON-safe bundle provenance."""
        return {
            "path": str(self.path), "fingerprint": self.fingerprint,
            "sha256": self.sha256,
            "file_count": self.file_count, "input_bytes": self.input_bytes,
            "dependencies": dict(self.dependencies),
        }


def build_helper_bundle(
    source_root: Path, nodeid: str, destination: Path, *,
    trusted_modules: Sequence[str] = (), project_inputs: Sequence[Path] = (),
) -> HelperBundle:
    """Build a deterministic bundle for exactly one remotely collected item."""
    source_root = Path(source_root).resolve()
    test, relative = _selected_test(nodeid, source_root)
    files = _project_files(source_root, test, relative, project_inputs)
    files.update(_runtime_files(trusted_modules))
    files.update(_runtime_tools())
    rows, total = _validated_files(files)
    dependencies = _dependency_versions()
    fingerprint = _fingerprint(rows, dependencies)
    destination.mkdir(parents=True, exist_ok=True)
    path = destination / ("helper-bundle-%s.zip" % fingerprint)
    manifest = json.dumps({
        "schema": 1, "fingerprint": fingerprint,
        "dependencies": dependencies,
        "files": [{key: row[key] for key in ("path", "bytes", "sha256", "mode")} for row in rows],
    }, indent=2, sort_keys=True).encode("utf-8") + b"\n"
    if not path.exists():
        _write_zip(path, rows, manifest)
        path.chmod(0o600)
    return HelperBundle(
        path, fingerprint, _sha256_path(path), len(rows), total, dependencies,
    )


def archive_helper_bundle(identity: Mapping[str, object], session_dir: Path) -> dict[str, object]:
    """Retain a verified remote-helper bundle in the session object store."""
    source = Path(str(identity.get("path", "")))
    expected = str(identity.get("sha256", ""))
    if not source.is_file() or source.is_symlink() or _sha256_path(source) != expected:
        raise SpecError(
            "Kubernetes helper bundle archive", str(source),
            "must remain a regular file with its recorded SHA-256",
        )
    target = Path(session_dir) / "objects" / "sha256" / expected[:2] / expected
    target.parent.mkdir(parents=True, exist_ok=True)
    if not target.exists():
        temporary = target.with_name(".%s.%d" % (target.name, os.getpid()))
        shutil.copyfile(source, temporary)
        temporary.replace(target)
        target.chmod(0o600)
    result = dict(identity)
    result.pop("path", None)
    result["object"] = str(target.relative_to(session_dir))
    result["size"] = target.stat().st_size
    return result


__all__ = ["HelperBundle", "archive_helper_bundle", "build_helper_bundle"]
