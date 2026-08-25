"""Content-addressed OCI images built from immutable binary captures."""

from __future__ import annotations

import dataclasses
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
from pathlib import Path
from typing import Mapping, Sequence

from brixtest.errors import SpecError
from brixtest.planning.capabilities import backend_capabilities
from brixtest.runtime.binaries import CapturedBinary
from brixtest.util.immutable import freeze_mapping

_INTERPRETER = re.compile(r"Requesting program interpreter:\s*([^\]]+)")
_REGISTRY = re.compile(
    r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?(?::[0-9]{1,5})?"
    r"(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*"
)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def _safe_name(value: str) -> str:
    selected = "".join(
        char if char.isalnum() or char == "-" else "-"
        for char in value.lower().replace("_", "-")
    )[:48].strip("-")
    if not selected:
        raise SpecError("generated image name", value, "must contain alphanumeric text")
    return selected


def _fingerprint(binaries: Sequence[CapturedBinary], base_image: str) -> str:
    rows = [{
        "name": item.name, "sha256": item.sha256,
        "libraries": dict(getattr(item, "_library_sha256", {})),
        "runtime_files": dict(getattr(item, "_runtime_file_sha256", {})),
    } for item in sorted(binaries, key=lambda value: value.name)]
    encoded = json.dumps(
        {"schema": 1, "base_image": base_image, "binaries": rows},
        sort_keys=True, separators=(",", ":"),
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


def _interpreter(executable: Path) -> str:
    tool = shutil.which("readelf")
    if tool is None:
        return ""
    result = subprocess.run(
        [tool, "-l", str(executable)], capture_output=True, text=True,
        timeout=10.0, check=False,
    )
    match = _INTERPRETER.search(result.stdout) if result.returncode == 0 else None
    return match.group(1).strip() if match is not None else ""


def _copy(source: Path, destination: Path, mode: int) -> dict[str, object]:
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        return _existing_copy(source, destination, mode)
    shutil.copyfile(source, destination)
    destination.chmod(mode)
    os.utime(destination, (0, 0))
    return {
        "path": "/" + str(destination).split("/rootfs/", 1)[-1],
        "bytes": destination.stat().st_size, "sha256": _sha256(destination),
        "mode": oct(mode),
    }


def _existing_copy(source: Path, destination: Path, mode: int) -> dict[str, object]:
    expected_mode = stat.S_IMODE(destination.stat().st_mode)
    if _sha256(source) != _sha256(destination) or expected_mode != mode:
        raise SpecError(
            "generated image path", "/" + str(destination).split("/rootfs/", 1)[-1],
            "is supplied by conflicting captured inputs",
        )
    return {
        "path": "/" + str(destination).split("/rootfs/", 1)[-1],
        "bytes": destination.stat().st_size, "sha256": _sha256(destination),
        "mode": oct(mode),
    }


def _library_by_name(binary: CapturedBinary) -> dict[str, Path]:
    return {path.name: path for path in binary.libraries}


def _stage_binary(rootfs: Path, binary: CapturedBinary) -> tuple[list[dict], str]:
    if re.fullmatch(r"[a-z][a-z0-9_-]*", binary.name) is None:
        raise SpecError(
            "generated image binary", binary.name,
            "must be a safe BriXTest binary name",
        )
    destination = rootfs / "opt" / "brixtest" / "bin" / binary.name
    files = [_copy(binary.path, destination, 0o755)]
    libraries = _library_by_name(binary)
    for name, source in sorted(libraries.items()):
        target = rootfs / "opt" / "brixtest" / "lib" / name
        files.append(_copy(source, target, 0o755))
    interpreter = _interpreter(binary.path)
    if interpreter:
        source = libraries.get(Path(interpreter).name)
        if source is None:
            raise SpecError(
                "binary image interpreter", interpreter,
                "was not captured; enable transitive library discovery",
            )
        files.append(_copy(source, rootfs / interpreter.lstrip("/"), 0o755))
    for image_path, source in sorted(binary.runtime_files.items()):
        mode = stat.S_IMODE(source.stat().st_mode) & 0o777
        files.append(_copy(source, rootfs / image_path.lstrip("/"), mode))
    return files, "/opt/brixtest/bin/%s" % binary.name


def _dockerfile(base_image: str) -> str:
    if base_image and re.fullmatch(r"[^@\s]+@sha256:[0-9a-fA-F]{64}", base_image) is None:
        raise SpecError(
            "generated image base", base_image,
            "must be empty or a digest-pinned image",
        )
    base = base_image or "scratch"
    return (
        "FROM %s\nCOPY rootfs/ /\n"
        "ENV LD_LIBRARY_PATH=/opt/brixtest/lib\n"
    ) % base


def _registry(value: str) -> str:
    if value and _REGISTRY.fullmatch(value) is None:
        raise SpecError(
            "generated image registry", value,
            "must be a registry host with an optional repository prefix",
        )
    return value


def _inspect(value: str) -> tuple[str, tuple[str, ...], object]:
    try:
        payload = json.loads(value)
        item = payload[0]
        image_id = str(item["Id"])
        layers = tuple(str(row) for row in item.get("RootFS", {}).get("Layers", ()))
    except (IndexError, KeyError, TypeError, ValueError) as exc:
        raise SpecError("generated OCI image", "inspect", "returned invalid JSON") from exc
    return image_id, layers, payload


@dataclasses.dataclass(frozen=True)
class GeneratedImage:
    """One run-owned image plus its generated command paths and provenance."""

    tag: str
    image_id: str
    fingerprint: str
    paths: Mapping[str, str]
    layers: Sequence[str]
    files: Sequence[Mapping[str, object]]
    context: Path
    base_image: str = ""
    tool_versions: Mapping[str, str] = dataclasses.field(default_factory=dict)
    delivery: str = "minikube-load"

    def __post_init__(self) -> None:
        object.__setattr__(self, "paths", freeze_mapping(self.paths))
        object.__setattr__(self, "layers", tuple(self.layers))
        object.__setattr__(self, "files", tuple(freeze_mapping(row) for row in self.files))
        object.__setattr__(self, "tool_versions", freeze_mapping(self.tool_versions))

    def as_dict(self) -> dict[str, object]:
        """Return JSON-safe image, layer, file, and command provenance."""
        return {
            "tag": self.tag, "image_id": self.image_id,
            "fingerprint": self.fingerprint, "paths": dict(self.paths),
            "layers": list(self.layers), "files": [dict(row) for row in self.files],
            "context": str(self.context), "base_image": self.base_image,
            "tool_versions": dict(self.tool_versions), "delivery": self.delivery,
        }


class OCIImageStore:
    """Build and load immutable per-run images through bounded commands."""

    brixtest_api_version = 1
    brixtest_capabilities = tuple(sorted(
        backend_capabilities("oci", "image"),
    ))

    def __init__(self, owner, profile: str, *, registry: str = "") -> None:
        self.owner = owner
        self.profile = profile
        self.registry = _registry(registry)
        self.root = owner.root / "runtime" / "images"
        self._items: dict[str, GeneratedImage] = {}

    def build(
        self, name: str, binaries: Sequence[CapturedBinary], *, base_image: str = "",
    ) -> GeneratedImage:
        fingerprint = _fingerprint(binaries, base_image)
        held = self._items.get(fingerprint)
        if held is not None:
            return held
        context = self.root / fingerprint
        rootfs = context / "rootfs"
        rootfs.mkdir(parents=True, exist_ok=False)
        files, paths = self._stage(rootfs, binaries)
        (context / "Dockerfile").write_text(_dockerfile(base_image))
        repository = self.registry or "brixtest.local"
        tag = "%s/%s:sha256-%s" % (repository, _safe_name(name), fingerprint)
        self.owner.commands.run(
            "docker", "build", "--pull=false", "--network=none",
            "--tag", tag, str(context), timeout=300.0,
        )
        inspected = self.owner.commands.run(
            "docker", "image", "inspect", tag, timeout=30.0,
        )
        image_id, layers, inspect_payload = _inspect(inspected.stdout)
        self._publish_image(tag)
        tool_versions = self._tool_versions()
        item = GeneratedImage(
            tag, image_id, fingerprint, paths, layers, files, context,
            base_image, tool_versions,
            delivery="registry-push" if self.registry else "minikube-load",
        )
        self._items[fingerprint] = item
        self._publish(name, item, inspect_payload)
        return item

    def _publish_image(self, tag: str) -> None:
        if self.registry:
            self.owner.commands.run("docker", "push", tag, timeout=300.0)
            return
        self.owner.commands.run(
            "minikube", "--profile", self.profile, "image", "load", tag,
            timeout=300.0,
        )

    def _tool_versions(self) -> dict[str, str]:
        docker = self.owner.commands.run(
            "docker", "version", "--format={{json .Client.Version}}", timeout=30.0,
        )
        versions = {"docker": docker.stdout.strip()}
        if self.registry:
            return versions
        minikube = self.owner.commands.run(
            "minikube", "version", "--output=json", timeout=30.0,
        )
        versions["minikube"] = minikube.stdout.strip()
        return versions

    @staticmethod
    def _stage(
        rootfs: Path, binaries: Sequence[CapturedBinary],
    ) -> tuple[list[dict], dict[str, str]]:
        files = []
        paths = {}
        for binary in sorted(binaries, key=lambda item: item.name):
            staged, path = _stage_binary(rootfs, binary)
            files.extend(staged)
            paths[binary.name] = path
        return files, paths

    def _publish(self, name: str, item: GeneratedImage, inspect_payload: object) -> None:
        payload = item.as_dict()
        self.owner.evidence.event("generated-oci-image", {"server": name, **payload})
        self.owner.evidence.attach_json(
            "image-%s.json" % name,
            {**payload, "inspect": inspect_payload, "sbom": payload["files"]},
            role="image-provenance",
            description="generated OCI image manifest, layers, and file SBOM",
        )
