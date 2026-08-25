"""Isolation selection and stable replay arguments for the pytest adapter."""

from __future__ import annotations

from pathlib import Path
from typing import Mapping, Optional

from brixtest.errors import SpecError
from brixtest.isolation import Isolation, docker, kubernetes, nsenter, podman, process, runc


def _profile_bundle(values: dict, profile: Mapping[str, object]) -> None:
    bundle = values.get("bundle")
    profile_path = profile.get("_path")
    if bundle and not Path(str(bundle)).is_absolute() and profile_path:
        values["bundle"] = Path(str(profile_path)).parent / str(bundle)


def _profile_isolation(profile, definition) -> Optional[Isolation]:
    profile_isolation = profile.get("isolation") if isinstance(profile, Mapping) else None
    if not isinstance(profile_isolation, Mapping):
        return None
    try:
        values = dict(profile_isolation)
        _profile_bundle(values, profile)
        return Isolation(**values).resolved(definition.source.parent)
    except TypeError as exc:
        raise SpecError(
            "suite profile.isolation", profile_isolation,
            "contains unknown constructor fields: %s" % exc,
        ) from exc


def _require_isolation_kind(config, definition) -> Isolation:
    related = (
        config.getoption("--brixtest-isolation-image"),
        config.getoption("--brixtest-nsenter-target"),
        config.getoption("--brixtest-nsenter-namespace"),
        config.getoption("--brixtest-runc-bundle"),
        config.getoption("--brixtest-isolation-arg"),
        config.getoption("--brixtest-allow-mutable-image"),
        config.getoption("--brixtest-container-python") != "python3",
        config.getoption("--brixtest-kubernetes-context"),
        config.getoption("--brixtest-kubernetes-namespace"),
        config.getoption("--brixtest-kubernetes-service-account"),
    )
    if any(related):
        raise SpecError(
            "isolation override", related,
            "runtime-specific options require --brixtest-isolation",
        )
    return definition.isolation.resolved(definition.source.parent)


def _validate_isolation_image(kind: str, values: Mapping[str, object]) -> None:
    container = kind in ("docker", "podman", "kubernetes")
    if values["image"] and not container:
        raise SpecError(
            "isolation.image", values["image"],
            "is valid only for docker, podman, or kubernetes",
        )
    if values["mutable"] and not container:
        raise SpecError(
            "mutable image opt-out", kind, "is valid only for docker or podman",
        )


def _validate_nsenter_options(kind: str, values: Mapping[str, object]) -> None:
    if (values["target"] or values["namespaces"]) and kind != "nsenter":
        raise SpecError("nsenter options", kind, "require --brixtest-isolation=nsenter")


def _validate_runc_options(kind: str, values: Mapping[str, object]) -> None:
    if values["bundle"] and kind != "runc":
        raise SpecError(
            "runc bundle", values["bundle"], "requires --brixtest-isolation=runc",
        )


def _validate_extra_options(kind: str, values: Mapping[str, object]) -> None:
    if values["extra"] and kind not in ("docker", "podman", "runc"):
        raise SpecError(
            "isolation arguments", values["extra"],
            "are valid only for container runtimes",
        )


def _validate_kubernetes_options(kind: str, values: Mapping[str, object]) -> None:
    selected = (values["context"], values["namespace"], values["service_account"])
    if any(selected) and kind != "kubernetes":
        raise SpecError(
            "Kubernetes isolation options", selected,
            "require --brixtest-isolation=kubernetes",
        )


def _isolation_values(config, kind: str) -> dict:
    values = {
        "extra": tuple(config.getoption("--brixtest-isolation-arg")),
        "python": config.getoption("--brixtest-container-python"),
        "image": config.getoption("--brixtest-isolation-image"),
        "target": config.getoption("--brixtest-nsenter-target"),
        "namespaces": config.getoption("--brixtest-nsenter-namespace"),
        "bundle": config.getoption("--brixtest-runc-bundle"),
        "mutable": config.getoption("--brixtest-allow-mutable-image"),
        "context": config.getoption("--brixtest-kubernetes-context") or "",
        "namespace": config.getoption("--brixtest-kubernetes-namespace") or "",
        "service_account": config.getoption("--brixtest-kubernetes-service-account") or "",
    }
    _validate_isolation_image(kind, values)
    _validate_nsenter_options(kind, values)
    _validate_runc_options(kind, values)
    _validate_extra_options(kind, values)
    _validate_kubernetes_options(kind, values)
    return values


def _container_runtime(kind: str, values: Mapping[str, object]) -> Isolation:
    factory = docker if kind == "docker" else podman
    return factory(
        values["image"] or "",
        python=values["python"],
        extra_args=values["extra"],
        allow_mutable=values["mutable"],
    )


def _runc_runtime(values: Mapping[str, object], definition) -> Isolation:
    if not values["bundle"]:
        raise SpecError(
            "isolation.bundle", values["bundle"],
            "--brixtest-runc-bundle is required",
        )
    return runc(
        Path(values["bundle"]),
        python=values["python"],
        extra_args=values["extra"],
    ).resolved(definition.source.parent)


def _selected_runtime(kind: str, values: Mapping[str, object], definition) -> Isolation:
    if kind == "process":
        return process()
    if kind == "nsenter":
        namespaces = values["namespaces"] or (
            "mount", "uts", "ipc", "net", "pid", "cgroup",
        )
        return nsenter(values["target"] or 0, namespaces=tuple(namespaces))
    if kind in ("docker", "podman"):
        return _container_runtime(kind, values)
    if kind == "kubernetes":
        return kubernetes(
            values["image"] or "", python=values["python"],
            context=values["context"], namespace=values["namespace"] or "default",
            service_account=values["service_account"] or "default",
        )
    return _runc_runtime(values, definition)


def selected_isolation(config, definition) -> Isolation:
    kind = config.getoption("--brixtest-isolation") or config.getini("brixtest_isolation")
    profile = getattr(config, "_brixtest_profile", {})
    if kind:
        return _selected_runtime(kind, _isolation_values(config, kind), definition)
    selected = _profile_isolation(profile, definition)
    if selected is not None:
        return selected
    return _require_isolation_kind(config, definition)


def _append_option(args: list[str], option: str, value: object) -> None:
    if value:
        args.extend((option, str(value)))


def _append_profile(args: list[str], profile: object) -> None:
    if isinstance(profile, Mapping) and profile.get("_path"):
        args.extend(("--brixtest-profile", str(profile["_path"])))


def _append_repeated_options(config, args: list[str]) -> None:
    for option in (
        "--brixtest-binary", "--brixtest-env", "--brixtest-server-env",
        "--brixtest-client-env", "--brixtest-helper-plugin", "--brixtest-safe-import",
    ):
        for value in config.getoption(option):
            args.extend((option, value))


def replay_options(config, isolation: Isolation) -> list[str]:
    """Return stable, non-secret pytest arguments for a repeatable case run."""
    args = [
        "-p", "brixtest.pytest_plugin", "-x", "--tb=long",
        "--brixtest-helper-log-max-bytes",
        str(config.getoption("--brixtest-helper-log-max-bytes")),
    ]
    _append_option(args, "--brixtest-backend", config.getoption("--brixtest-backend"))
    runs = config.getoption("--brixtest-runs")
    _append_option(args, "--brixtest-runs", Path(runs).resolve() if runs else None)
    _append_profile(args, getattr(config, "_brixtest_profile", {}))
    _append_option(args, "--brixtest-sanitizer", config.getoption("--brixtest-sanitizer"))
    args.extend(isolation.cli_args())
    _append_repeated_options(config, args)
    return args
