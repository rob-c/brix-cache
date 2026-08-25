"""Translate a declared identity into process and OCI launcher arguments."""

from __future__ import annotations

import shutil
import os
import sys
from pathlib import Path
from typing import Optional, Sequence

from brixtest._design_managed import Identity
from brixtest.errors import SpecError
from brixtest.runtime.linux_identity import linux_capabilities
from brixtest.runtime.identity_nss import write_nss_files


def process_identity_argv(
    identity: Optional[Identity], command: Sequence[str],
) -> tuple[str, ...]:
    """Wrap a direct process with an explicit least-privilege identity."""
    if identity is None:
        return tuple(command)
    _reject_remote_authorization("process", identity)
    if shutil.which("setpriv") is None:
        raise SpecError("process identity", identity.name, "requires the setpriv executable")
    argv = ["setpriv", "--no-new-privs"]
    argv.extend(_setpriv_capabilities(identity))
    argv.extend(_setpriv_ids(identity))
    argv.extend(command)
    return _process_user_namespace(identity, argv)


def _process_user_namespace(identity: Identity, command: Sequence[str]) -> tuple[str, ...]:
    requested = identity.user_namespace or identity.uid_map or identity.gid_map
    if not requested:
        return tuple(command)
    _require_user_namespace_tools(identity)
    uid, gid, uid_rows, gid_rows = _process_identity_maps(identity)
    argv = _user_namespace_prefix(identity, uid, gid)
    argv.extend(_id_map_argv("--uid-map", uid_rows))
    argv.extend(_id_map_argv("--gid-map", gid_rows))
    argv.extend(("--", *command))
    return tuple(argv)


def _require_user_namespace_tools(identity: Identity) -> None:
    for executable in ("newuidmap", "newgidmap"):
        if shutil.which(executable) is None:
            raise SpecError(
                "identity %s user namespace" % identity.name, executable,
                "requires newuidmap and newgidmap",
            )


def _process_identity_maps(identity: Identity) -> tuple:
    uid = _selected_id(identity.uid)
    gid = _selected_id(identity.gid)
    uid_rows = _selected_map(identity.uid_map, uid, os.getuid())
    gid_rows = _selected_map(identity.gid_map, gid, os.getgid())
    return uid, gid, uid_rows, gid_rows


def _selected_id(value: Optional[int]) -> int:
    return 0 if value is None else value


def _selected_map(rows, inside: int, outside: int) -> tuple:
    return tuple(rows) if rows else ((inside, outside, 1),)


def _user_namespace_prefix(identity: Identity, uid: int, gid: int) -> list[str]:
    argv = [sys.executable, "-m", "brixtest.runtime.userns_exec"]
    argv.extend(("--uid", str(uid), "--gid", str(gid)))
    for group in identity.groups:
        argv.extend(("--group", str(group)))
    return argv


def container_identity_argv(
    runtime: str, identity: Optional[Identity], state: Path,
) -> tuple[str, ...]:
    """Return Docker-compatible flags for one declared OCI identity."""
    if identity is None:
        return ()
    _reject_remote_authorization(runtime, identity)
    argv = ["--cap-drop", "ALL"]
    for capability in linux_capabilities(identity.capabilities):
        argv.extend(("--cap-add", capability))
    argv.extend(_container_ids(identity))
    argv.extend(_container_user_namespace(runtime, identity))
    argv.extend(_container_nss_argv(state, identity))
    return tuple(argv)


def _reject_remote_authorization(runtime: str, identity: Identity) -> None:
    if identity.service_account or identity.permissions:
        raise SpecError(
            "identity %s authorization" % identity.name, runtime,
            "ServiceAccount and RBAC permissions require Kubernetes",
        )


def _reject_user_namespace(runtime: str, identity: Identity) -> None:
    if identity.user_namespace or identity.uid_map or identity.gid_map:
        raise SpecError(
            "identity %s user namespace" % identity.name, runtime,
            "is supported by process and Podman launchers only",
        )


def _setpriv_capabilities(identity: Identity) -> list[str]:
    selected = ["+%s" % value.lower() for value in linux_capabilities(identity.capabilities)]
    value = ",".join(("-all", *selected))
    return ["--bounding-set", value, "--inh-caps", value, "--ambient-caps", value]


def _setpriv_ids(identity: Identity) -> list[str]:
    argv = _optional_id_argv("--reuid", identity.uid)
    argv.extend(_optional_id_argv("--regid", identity.gid))
    argv.extend(_setpriv_groups(identity))
    return argv


def _optional_id_argv(option: str, value: Optional[int]) -> list[str]:
    return [option, str(value)] if value is not None else []


def _setpriv_groups(identity: Identity) -> list[str]:
    if identity.groups:
        return ["--groups", ",".join(str(value) for value in identity.groups)]
    return ["--clear-groups"] if identity.gid is not None else []


def _container_ids(identity: Identity) -> list[str]:
    if identity.gid is not None and identity.uid is None:
        raise SpecError(
            "identity %s gid" % identity.name, identity.gid,
            "OCI identity requires uid when gid is declared",
        )
    argv = []
    if identity.uid is not None:
        user = str(identity.uid)
        if identity.gid is not None:
            user = "%s:%s" % (user, identity.gid)
        argv.extend(("--user", user))
    for group in identity.groups:
        argv.extend(("--group-add", str(group)))
    return argv


def _container_user_namespace(runtime: str, identity: Identity) -> list[str]:
    requested = identity.user_namespace or identity.uid_map or identity.gid_map
    if not requested:
        return []
    if runtime != "podman":
        _reject_user_namespace(runtime, identity)
    argv = ["--userns", "private"]
    argv.extend(_id_map_argv("--uidmap", identity.uid_map))
    argv.extend(_id_map_argv("--gidmap", identity.gid_map))
    return argv


def _id_map_argv(option: str, mappings: Sequence[tuple[int, int, int]]) -> list[str]:
    argv = []
    for container_id, host_id, length in mappings:
        argv.extend((option, "%d:%d:%d" % (container_id, host_id, length)))
    return argv


def _container_nss_argv(state: Path, identity: Identity) -> list[str]:
    files = write_nss_files(state, identity)
    if files is None:
        return []
    argv = []
    for name, path in sorted(files.items()):
        argv.extend(("--volume", "%s:/etc/%s:ro" % (path, name)))
    return argv


__all__ = ["container_identity_argv", "process_identity_argv"]
