"""Config, binary, artifact, and readiness declarations."""

from __future__ import annotations

import dataclasses
import re
from pathlib import Path
from typing import Mapping, Optional, Sequence, Tuple, Union

from brixtest.errors import SpecError
from brixtest.resources import Reference, artifact_ref, binary_ref
from brixtest.util.immutable import freeze_mapping

KiB = 1 << 10
MiB = 1 << 20
GiB = 1 << 30
KB = 1_000
MB = 1_000_000
GB = 1_000_000_000

_NAME = re.compile(r"^[a-z][a-z0-9_-]*$")
_PLACEHOLDER_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_ENV_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_ARTIFACT_KINDS = frozenset({"noise", "file", "text"})


def _name(value: str, field: str) -> str:
    if not isinstance(value, str) or not _NAME.match(value):
        raise SpecError(
            field, value,
            "must start with a lowercase letter and contain [a-z0-9_-] only",
        )
    return value


def _argv(value: Sequence[object], field: str) -> Tuple[object, ...]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence) or not value:
        raise SpecError(field, value, "must be a non-empty argv sequence")
    for part in value:
        if not isinstance(part, (str, Binary, Reference)):
            raise SpecError(
                field, part,
                "argv entries must be strings, Binary declarations, or typed references",
            )
    return tuple(value)


def _string_mapping(value: Mapping[str, object], field: str) -> Mapping[str, object]:
    valid = isinstance(value, Mapping) and all(
        isinstance(key, str)
        and _ENV_NAME.fullmatch(key) is not None
        and isinstance(item, (str, Reference))
        and "\0" not in str(item)
        for key, item in value.items()
    )
    if not valid:
        raise SpecError(
            field, value,
            "must map portable environment names to NUL-free text or typed references",
        )
    return freeze_mapping(value)


def _config_values_valid(values: Mapping[str, object]) -> bool:
    allowed = (str, int, float, bool, Path, Reference)
    for key, value in values.items():
        if not isinstance(key, str) or _PLACEHOLDER_NAME.fullmatch(key) is None:
            return False
        if not isinstance(value, allowed):
            return False
    return True


def _library_paths_valid(values: object) -> bool:
    if isinstance(values, (str, bytes)) or not isinstance(values, Sequence):
        return False
    return all(isinstance(path, (str, Path)) for path in values)


def _artifact_options_valid(values: object) -> bool:
    if not isinstance(values, Mapping):
        return False
    return all(isinstance(key, str) and bool(key) for key in values)


def _artifact_filename(declaration: "Artifact") -> str:
    if declaration.filename:
        filename = declaration.filename
    elif declaration.kind == "file":
        filename = Path(str(declaration.source)).name
    else:
        filename = declaration.name + ".bin"
    if not isinstance(filename, str) or not filename or Path(filename).name != filename:
        raise SpecError("artifact.filename", filename, "must be a non-empty basename")
    return filename


def _validate_config_source(declaration: "ConfigFile") -> None:
    if (declaration.path is None) == (declaration.content is None):
        raise SpecError(
            "server config", declaration.path,
            "needs exactly one of an on-disk path or text content",
        )
    if declaration.path is not None:
        if not isinstance(declaration.path, (str, Path)):
            raise SpecError("config.path", declaration.path, "must be a string or path")
        if not str(declaration.path):
            raise SpecError("config.path", declaration.path, "must not be empty")
    if declaration.content is not None and not isinstance(declaration.content, str):
        raise SpecError("config.content", declaration.content, "must be text")


def _validate_config_destination(value: object) -> None:
    if not isinstance(value, str):
        raise SpecError("config.destination", value, "must be text")
    destination = Path(value)
    if not value or destination.is_absolute() or ".." in destination.parts:
        raise SpecError("config.destination", value, "must be a confined relative path")

@dataclasses.dataclass(frozen=True)
class ConfigFile:
    """Immutable server-config content or a lazily loaded on-disk source."""

    path: Optional[Union[str, Path]] = None
    template: bool = True
    destination: str = "server.conf"
    content: Optional[str] = None
    values: Mapping[str, object] = dataclasses.field(default_factory=dict)

    def __post_init__(self) -> None:
        _validate_config_source(self)
        _validate_config_destination(self.destination)
        if not _config_values_valid(self.values):
            raise SpecError(
                "config.values", self.values,
                "keys must be valid {placeholder_name} identifiers and values must be plain data",
            )
        object.__setattr__(self, "values", freeze_mapping(self.values))

    @property
    def filename(self) -> str:
        """The relative filename BriXTest will give the captured config."""
        return self.destination


@dataclasses.dataclass(frozen=True)
class ConfigTemplate:
    """A lazy on-disk template completed with declaration-time values."""

    path: Union[str, Path]

    def __post_init__(self) -> None:
        if not isinstance(self.path, (str, Path)) or not str(self.path):
            raise SpecError("config template", self.path, "path must not be empty")

    def fill(self, *, filename: str = "server.conf", **values: object) -> ConfigFile:
        """Bind author values while leaving runtime placeholders unresolved."""
        return ConfigFile(
            path=self.path, template=True, destination=filename, values=values,
        )


def load_template(path: Union[str, Path]) -> ConfigTemplate:
    """Declare a template without reading or executing anything at collection."""
    return ConfigTemplate(path)


def server_config(
    content: str, filename: str = "server.conf", *, template: bool = True,
) -> ConfigFile:
    """Pass complete text content and its desired filename to BriXTest."""
    return ConfigFile(
        path=None, content=content, template=template, destination=filename,
    )


def template_config(
    path: Union[str, Path], *, destination: str = "server.conf",
    values: Optional[Mapping[str, object]] = None,
) -> ConfigFile:
    """Declare an on-disk config template with optional author-owned values."""
    return ConfigFile(
        path=path, template=True, destination=destination, values=dict(values or {}),
    )


def static_config(
    path: Union[str, Path], *, destination: str = "server.conf"
) -> ConfigFile:
    """Declare an on-disk config that must be captured without rendering."""
    return ConfigFile(path=path, template=False, destination=destination)


@dataclasses.dataclass(frozen=True)
class ConfigSet:
    """An ordered set of captured server configs with one command-line primary."""

    files: Sequence[ConfigFile]
    primary: str = ""

    def __post_init__(self) -> None:
        selected = _config_files(self.files)
        destinations = _config_destinations(selected)
        primary = _primary_destination(self.primary, destinations)
        object.__setattr__(self, "files", selected)
        object.__setattr__(self, "primary", primary)

    @property
    def primary_file(self) -> ConfigFile:
        """Return the config used by the conventional ``{config}`` placeholder."""
        return self.get(self.primary)

    def get(self, destination: str) -> ConfigFile:
        """Resolve one config declaration by its captured destination path."""
        for item in self.files:
            if item.destination == destination:
                return item
        raise SpecError(
            "config destination", destination,
            "known: %s" % ", ".join(item.destination for item in self.files),
        )


def _config_files(value: object) -> tuple[ConfigFile, ...]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        raise SpecError("configs.files", value, "must be a ConfigFile sequence")
    selected = tuple(value)
    if not selected or not all(isinstance(item, ConfigFile) for item in selected):
        raise SpecError("configs.files", selected, "must contain at least one ConfigFile")
    return selected


def _config_destinations(selected: Sequence[ConfigFile]) -> list[str]:
    destinations = [item.destination for item in selected]
    if len(set(destinations)) != len(destinations):
        raise SpecError("configs.files", destinations, "destinations must be unique")
    return destinations


def _primary_destination(primary: str, destinations: Sequence[str]) -> str:
    selected = primary or destinations[0]
    if selected not in destinations:
        raise SpecError("configs.primary", selected, "must name a declared destination")
    return selected


def configs(*files: ConfigFile, primary: str = "") -> ConfigSet:
    """Group one or more server configs and optionally select the primary file."""
    return ConfigSet(files, primary)


def _validate_binary_source(declaration: "Binary") -> None:
    _optional_path(declaration.path, "binary.path")
    _optional_text(declaration.image, "binary.image")
    _optional_text(declaration.image_path, "binary.image_path")
    if declaration.path is None and not (declaration.image and declaration.image_path):
        raise SpecError(
            "binary", declaration.name, "needs a local path or an image plus image_path",
        )


def _optional_path(value: object, field: str) -> None:
    if value is not None and not isinstance(value, (str, Path)):
        raise SpecError(field, value, "must be a string or path")


def _optional_text(value: object, field: str) -> None:
    if value is not None and not isinstance(value, str):
        raise SpecError(field, value, "must be text")


def _validate_binary_policy(declaration: "Binary") -> None:
    if not isinstance(declaration.discover_libraries, bool):
        raise SpecError(
            "binary.discover_libraries", declaration.discover_libraries, "must be boolean",
        )
    if bool(declaration.image) != bool(declaration.image_path):
        raise SpecError(
            "binary.image", declaration.image,
            "image and image_path must be supplied together",
        )


@dataclasses.dataclass(frozen=True)
class Binary:
    """A local executable snapshot and its immutable Kubernetes equivalent."""

    name: str
    path: Optional[Union[str, Path]] = None
    libraries: Sequence[Union[str, Path]] = ()
    discover_libraries: bool = True
    image: Optional[str] = None
    image_path: Optional[str] = None

    def ref(self, *, directory: bool = False) -> Reference:
        """Reference this binary's immutable captured path at runtime."""
        return binary_ref(self, directory=directory)

    def __post_init__(self) -> None:
        _name(self.name, "binary.name")
        _validate_binary_source(self)
        _validate_binary_policy(self)
        if not _library_paths_valid(self.libraries):
            raise SpecError("binary.libraries", self.libraries, "must contain strings or paths")
        object.__setattr__(self, "libraries", tuple(self.libraries))


def binary(
    name: str,
    path: Optional[Union[str, Path]] = None,
    *,
    libraries: Sequence[Union[str, Path]] = (),
    discover_libraries: bool = True,
    image: Optional[str] = None,
    image_path: Optional[str] = None,
) -> Binary:
    """Declare an executable snapshot and optional Kubernetes image identity."""
    return Binary(
        name=name, path=path, libraries=libraries,
        discover_libraries=discover_libraries,
        image=image, image_path=image_path,
    )


def _validate_artifact_payload(declaration: "Artifact") -> None:
    _validate_noise_artifact(declaration)
    _validate_artifact_seed(declaration)
    _validate_file_artifact(declaration)
    _validate_text_artifact(declaration)


def _validate_noise_artifact(declaration: "Artifact") -> None:
    if declaration.kind == "noise" and not _nonnegative_integer(declaration.size):
        raise SpecError("artifact.size", declaration.size, "must be an integer >= 0")


def _validate_artifact_seed(declaration: "Artifact") -> None:
    if not _integer(declaration.seed):
        raise SpecError("artifact.seed", declaration.seed, "must be an integer")


def _validate_file_artifact(declaration: "Artifact") -> None:
    if declaration.kind == "file" and declaration.source is None:
        raise SpecError(
            "artifact.source", declaration.source, "is required for file artifacts",
        )


def _validate_text_artifact(declaration: "Artifact") -> None:
    if declaration.kind == "text" and not isinstance(declaration.text, str):
        raise SpecError("artifact.text", declaration.text, "must be a string")


def _integer(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _nonnegative_integer(value: object) -> bool:
    return _integer(value) and value >= 0


@dataclasses.dataclass(frozen=True)
class Artifact:
    """A deterministic or copied input published by name into one run."""

    name: str
    kind: str
    size: int = 0
    seed: int = 0
    source: Optional[Union[str, Path]] = None
    text: str = ""
    filename: str = ""
    options: Mapping[str, object] = dataclasses.field(default_factory=dict)

    def ref(self, *, directory: bool = False) -> Reference:
        """Reference this artifact's materialized path at runtime."""
        return artifact_ref(self, directory=directory)

    def __post_init__(self) -> None:
        _name(self.name, "artifact.name")
        _name(self.kind, "artifact.kind")
        _validate_artifact_payload(self)
        if not _artifact_options_valid(self.options):
            raise SpecError("artifact.options", self.options, "must map non-empty text keys")
        if self.kind in _ARTIFACT_KINDS and self.options:
            raise SpecError(
                "artifact.options", self.options,
                "built-in artifacts use their named declaration fields",
            )
        object.__setattr__(self, "options", freeze_mapping(self.options))
        object.__setattr__(self, "filename", _artifact_filename(self))


def artifact(
    name: str, kind: str, *, filename: str = "", **options: object,
) -> Artifact:
    """Declare an artifact materialized by a versioned provider extension."""
    if kind in _ARTIFACT_KINDS:
        raise SpecError(
            "artifact kind", kind,
            "use noise(), file_artifact(), or text_artifact() for built-in inputs",
        )
    return Artifact(
        name=name, kind=kind, filename=filename or name + ".bin", options=options,
    )


def noise(name: str, *, size: int, seed: int = 0, filename: str = "") -> Artifact:
    """Declare deterministic high-entropy bytes generated inside the run."""
    return Artifact(name=name, kind="noise", size=size, seed=seed, filename=filename)


def file_artifact(
    name: str, path: Union[str, Path], *, filename: str = ""
) -> Artifact:
    """Declare a file that BriXTest copies and hashes before test execution."""
    return Artifact(name=name, kind="file", source=path, filename=filename)


def text_artifact(name: str, text: str, *, filename: str = "") -> Artifact:
    """Declare a small UTF-8 text artifact materialized inside the run."""
    return Artifact(name=name, kind="text", text=text, filename=filename or name + ".txt")


@dataclasses.dataclass(frozen=True)
class Readiness:
    """A server startup probe using a named port or immediate readiness."""
    kind: str = "tcp"
    port: str = "primary"
    timeout: float = 10.0

    def __post_init__(self) -> None:
        _validate_readiness_kind(self.kind)
        _validate_readiness_port(self.port)
        _validate_readiness_timeout(self.timeout)


def _validate_readiness_kind(value: object) -> None:
    if not isinstance(value, str) or value not in ("tcp", "none"):
        raise SpecError("readiness.kind", value, "must be tcp or none")


def _validate_readiness_port(value: object) -> None:
    if not isinstance(value, str) or not value:
        raise SpecError("readiness.port", value, "must be a non-empty port role")


def _validate_readiness_timeout(value: object) -> None:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value <= 0:
        raise SpecError("readiness.timeout", value, "must be > 0")


def tcp(port: str = "primary", *, timeout: float = 10.0) -> Readiness:
    """Wait until a named TCP port accepts connections."""
    return Readiness(kind="tcp", port=port, timeout=timeout)


def immediate() -> Readiness:
    """Treat a successfully spawned process as ready without probing it."""
    return Readiness(kind="none")
