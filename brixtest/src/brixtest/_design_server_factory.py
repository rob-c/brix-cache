"""Normalization helpers for the author-facing server factory."""

from __future__ import annotations

from typing import Mapping, Optional, Sequence, Union

from brixtest._design_inputs import Binary, ConfigFile, ConfigSet, _string_mapping
from brixtest.errors import SpecError
from brixtest.resources import Command, Endpoint, Execution


def _server_command_policy_supported(value: Command) -> bool:
    return not any((
        value.input is not None,
        value.encoding != "utf-8",
        value.timeout != 30.0,
        tuple(value.expected_exit_codes) != (0,),
        value.output_limit != 1 << 20,
        value.mode != "capture",
        value.retries != 0,
    ))


def _select_server_binary(
    name: str, command: Optional[Sequence[object]], binary: Optional[Binary],
    args: Sequence[object],
) -> Optional[Sequence[object]]:
    if binary is None:
        if args:
            raise SpecError("server args", args, "requires server(binary=...)")
        return command
    if command is not None:
        raise SpecError("server command", name, "use command or binary+args, not both")
    if not isinstance(binary, Binary):
        raise SpecError("server binary", binary, "must be a Binary declaration")
    if isinstance(args, (str, bytes)) or not isinstance(args, Sequence):
        raise SpecError("server args", args, "must be an argv sequence, not text")
    return (binary, *tuple(args))


def _selected_execution(
    name: str, command: object, execution: Optional[Execution],
) -> object:
    if execution is None:
        return command
    if command is not None:
        raise SpecError("server execution", name, "use execution or command, not both")
    if not isinstance(execution, Command):
        raise SpecError("server execution", execution, "must be an Execution declaration")
    return execution


def _command_fields(
    name: str, command: Command, env: Optional[Mapping[str, object]], cwd: str,
) -> tuple[Sequence[object], Mapping[str, object], str]:
    if not _server_command_policy_supported(command):
        raise SpecError(
            "server command policy", name,
            "server Command declarations support argv/env/cwd; use Probe, Lifecycle, and LogPolicy for server execution policy",
        )
    combined_env = dict(command.env)
    combined_env.update(_string_mapping({} if env is None else env, "server.env"))
    return command.argv, combined_env, cwd or command.cwd


def _server_command(
    name: str, command: Optional[Union[Sequence[object], Command]],
    execution: Optional[Execution], binary: Optional[Binary], args: Sequence[object],
    env: Optional[Mapping[str, object]], cwd: str,
) -> tuple[Sequence[object], Mapping[str, object], str]:
    command = _selected_execution(name, command, execution)
    if isinstance(command, Command):
        command, env, cwd = _command_fields(name, command, env, cwd)
    command = _select_server_binary(name, command, binary, args)
    if command is None:
        raise SpecError("server command", command, "is required")
    return command, {} if env is None else env, cwd


def _declared_config_set(
    configs: Union[Sequence[ConfigFile], ConfigSet], config: Optional[ConfigFile],
) -> Optional[ConfigSet]:
    if isinstance(configs, ConfigSet):
        return configs
    if not configs:
        return None
    primary = config.destination if config else ""
    return ConfigSet(tuple(configs), primary)


def _primary_config(
    name: str, config: Optional[ConfigFile], selected: Optional[ConfigSet],
    metadata: Optional[Mapping[str, object]],
) -> tuple[ConfigFile, ConfigSet, Mapping[str, object]]:
    if config is not None:
        return config, selected, {} if metadata is None else metadata
    if selected is not None:
        return selected.primary_file, selected, {} if metadata is None else metadata
    config = ConfigFile(content="", destination="%s.conf" % name, template=False)
    updated = dict(metadata or {})
    updated.setdefault("brixtest.synthetic_config", True)
    return config, ConfigSet((config,), config.destination), updated


def _include_primary(config: ConfigFile, selected: ConfigSet) -> ConfigSet:
    if config in selected.files:
        return selected
    return ConfigSet((config, *selected.files), config.destination)


def _server_configuration(
    name: str, config: Optional[ConfigFile],
    configs: Union[Sequence[ConfigFile], ConfigSet],
    metadata: Optional[Mapping[str, object]],
) -> tuple[ConfigFile, ConfigSet, Mapping[str, object]]:
    selected = _declared_config_set(configs, config)
    config, selected, metadata = _primary_config(name, config, selected, metadata)
    selected = selected or ConfigSet((config,), config.destination)
    return config, _include_primary(config, selected), metadata


def _server_port_map(
    ports: Union[Sequence[str], Mapping[str, Optional[int]]],
    endpoints: Sequence[Endpoint],
) -> Mapping[str, Optional[int]]:
    if _uses_endpoint_ports(ports, endpoints):
        return {item.name: item.port for item in endpoints}
    if isinstance(ports, Mapping):
        return dict(ports)
    if isinstance(ports, (str, bytes)) or not isinstance(ports, Sequence):
        raise SpecError("server.ports", ports, "must be a role sequence, not text")
    return dict.fromkeys(ports)


def _uses_endpoint_ports(ports: object, endpoints: Sequence[Endpoint]) -> bool:
    if not endpoints or isinstance(ports, Mapping):
        return False
    return tuple(ports) == ("primary",)
