"""Client and reusable tool declarations."""

from __future__ import annotations

import dataclasses
from pathlib import Path
from typing import Mapping, Optional, Sequence, Union, overload

from brixtest._design_inputs import Binary, _argv, _name, _string_mapping
from brixtest.errors import SpecError
from brixtest.resources import Command, Execution, LogPolicy, Mount, Placement
from brixtest.util.immutable import freeze_mapping


def _positive_timeout(value: object) -> bool:
    return not isinstance(value, bool) and isinstance(value, (int, float)) and value > 0


def _confined_cwd(value: object) -> bool:
    if not isinstance(value, str):
        return False
    path = Path(value)
    return not path.is_absolute() and ".." not in path.parts


def _validate_client_identity(declaration: "Client") -> None:
    _name(declaration.name, "client.name")
    if not _positive_timeout(declaration.timeout):
        raise SpecError("client.timeout", declaration.timeout, "must be > 0")
    if not all(isinstance(item, Binary) for item in declaration.binaries):
        raise SpecError(
            "client.binaries", declaration.binaries, "must contain Binary declarations"
        )
    if not _confined_cwd(declaration.cwd):
        raise SpecError("client.cwd", declaration.cwd, "must be a confined relative path")
    if declaration.input is not None and not isinstance(declaration.input, str):
        raise SpecError("client.input", declaration.input, "must be text or None")


def _validate_client_policy(declaration: "Client") -> tuple[int, ...]:
    exits = tuple(declaration.expected_exit_codes)
    if not _valid_exit_codes(exits):
        raise SpecError("client.expected_exit_codes", exits, "must contain integer statuses")
    if not _bounded_integer(declaration.output_limit, minimum=1):
        raise SpecError("client.output_limit", declaration.output_limit, "must be an integer >= 1")
    if declaration.mode not in ("capture", "stream", "pty"):
        raise SpecError("client.mode", declaration.mode, "must be capture, stream, or pty")
    if not _bounded_integer(declaration.retries, minimum=0):
        raise SpecError("client.retries", declaration.retries, "must be an integer >= 0")
    if not _valid_encoding(declaration.encoding):
        raise SpecError("client.encoding", declaration.encoding, "must be non-empty text")
    return exits


def _valid_exit_codes(exits) -> bool:
    return bool(exits) and all(_exit_code(value) for value in exits)


def _valid_encoding(value: object) -> bool:
    return isinstance(value, str) and bool(value)


def _exit_code(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _bounded_integer(value: object, *, minimum: int) -> bool:
    return _exit_code(value) and value >= minimum


def _validate_client_resources(declaration: "Client") -> None:
    if not all(isinstance(item, Mount) for item in declaration.mounts):
        raise SpecError("client.mounts", declaration.mounts, "must contain Mount declarations")
    if not isinstance(declaration.logs, LogPolicy):
        raise SpecError("client.logs", declaration.logs, "must be a LogPolicy declaration")
    if not isinstance(declaration.placement, Placement):
        raise SpecError(
            "client.placement", declaration.placement, "must be a Placement declaration"
        )
    if not isinstance(declaration.metadata, Mapping):
        raise SpecError("client.metadata", declaration.metadata, "must be a mapping")

@dataclasses.dataclass(frozen=True)
class Client:
    """A reusable, named, shell-free client command declaration."""
    name: str
    command: Sequence[object]
    env: Mapping[str, object] = dataclasses.field(default_factory=dict)
    timeout: float = 30.0
    binaries: Sequence[Binary] = ()
    cwd: str = ""
    input: Optional[str] = None
    expected_exit_codes: Sequence[int] = (0,)
    output_limit: int = 1 << 20
    mode: str = "capture"
    retries: int = 0
    encoding: str = "utf-8"
    mounts: Sequence[Mount] = ()
    logs: LogPolicy = dataclasses.field(default_factory=LogPolicy)
    placement: Placement = dataclasses.field(default_factory=Placement)
    metadata: Mapping[str, object] = dataclasses.field(default_factory=dict)

    @property
    def execution(self) -> Execution:
        """Canonical reusable execution policy represented by this client."""
        return Execution(
            self.command, env=self.env, cwd=self.cwd, input=self.input,
            encoding=self.encoding, timeout=self.timeout,
            expected_exit_codes=self.expected_exit_codes,
            output_limit=self.output_limit, mode=self.mode, retries=self.retries,
        )

    @property
    def resource_kind(self) -> str:
        """Stable author-model discriminator used by tooling and diagnostics."""
        return "client"

    def __post_init__(self) -> None:
        _validate_client_identity(self)
        object.__setattr__(self, "command", _argv(self.command, "client.command"))
        object.__setattr__(self, "env", _string_mapping(self.env, "client.env"))
        object.__setattr__(self, "binaries", tuple(self.binaries))
        object.__setattr__(self, "expected_exit_codes", _validate_client_policy(self))
        _validate_client_resources(self)
        object.__setattr__(self, "mounts", tuple(self.mounts))
        object.__setattr__(self, "metadata", freeze_mapping(self.metadata))


def _client_command(
    name: str, command: Optional[Union[Sequence[object], Command]],
    execution: Optional[Execution], binary: Optional[Binary], args: Sequence[object],
) -> tuple[Sequence[object], Optional[Command]]:
    command = _execution_command(name, command, execution)
    defaults = command if isinstance(command, Command) else None
    selected = defaults.argv if defaults is not None else command
    selected = _binary_command(name, selected, binary, args)
    if selected is None:
        raise SpecError("client command", selected, "is required")
    return selected, defaults


def _execution_command(
    name: str, command: Optional[Union[Sequence[object], Command]],
    execution: Optional[Execution],
) -> Optional[Union[Sequence[object], Command]]:
    if execution is not None:
        if command is not None:
            raise SpecError("client execution", name, "use execution or command, not both")
        if not isinstance(execution, Command):
            raise SpecError("client execution", execution, "must be an Execution declaration")
        return execution
    return command


def _binary_command(
    name: str, selected: Optional[Sequence[object]], binary: Optional[Binary],
    args: Sequence[object],
) -> Optional[Sequence[object]]:
    if binary is not None:
        if selected is not None:
            raise SpecError("client command", name, "use command or binary+args, not both")
        if not isinstance(binary, Binary):
            raise SpecError("client binary", binary, "must be a Binary declaration")
        if isinstance(args, (str, bytes)) or not isinstance(args, Sequence):
            raise SpecError("client args", args, "must be an argv sequence, not text")
        selected = (binary, *tuple(args))
    elif args:
        raise SpecError("client args", args, "requires client(binary=...)")
    return selected


def _client_policy(defaults: Optional[Command], **selected: object) -> dict[str, object]:
    values = dict(selected)
    if defaults is None:
        return values
    combined_env = dict(defaults.env)
    combined_env.update(_string_mapping(values["env"], "client.env"))
    values["env"] = combined_env
    values["cwd"] = _inherited(values["cwd"], "", defaults.cwd)
    values["input"] = _inherited(values["input"], None, defaults.input)
    values["timeout"] = _inherited(values["timeout"], 30.0, defaults.timeout)
    values["expected_exit_codes"] = _inherited(
        tuple(values["expected_exit_codes"]), (0,), defaults.expected_exit_codes,
    )
    values["output_limit"] = _inherited(
        values["output_limit"], 1 << 20, defaults.output_limit,
    )
    values["mode"] = _inherited(values["mode"], "capture", defaults.mode)
    values["retries"] = _inherited(values["retries"], 0, defaults.retries)
    values["encoding"] = _inherited(values["encoding"], "utf-8", defaults.encoding)
    return values


def _inherited(value, untouched, inherited):
    return inherited if value == untouched else value


@overload
def client(
    name: str, *, execution: Execution, env: Optional[Mapping[str, object]] = None,
    timeout: float = 30.0, binaries: Sequence[Binary] = (), cwd: str = "",
    input: Optional[str] = None, expected_exit_codes: Sequence[int] = (0,),
    output_limit: int = 1 << 20, mode: str = "capture", retries: int = 0,
    encoding: str = "utf-8", mounts: Sequence[Mount] = (),
    logs: Optional[LogPolicy] = None,
    placement: Optional[Placement] = None,
    metadata: Optional[Mapping[str, object]] = None,
) -> Client: ...


@overload
def client(
    name: str, *, binary: Binary, args: Sequence[object] = (),
    env: Optional[Mapping[str, object]] = None, timeout: float = 30.0,
    binaries: Sequence[Binary] = (), cwd: str = "", input: Optional[str] = None,
    expected_exit_codes: Sequence[int] = (0,), output_limit: int = 1 << 20,
    mode: str = "capture", retries: int = 0, encoding: str = "utf-8",
    mounts: Sequence[Mount] = (), logs: Optional[LogPolicy] = None,
    placement: Optional[Placement] = None,
    metadata: Optional[Mapping[str, object]] = None,
) -> Client: ...


@overload
def client(
    name: str, *, command: Union[Sequence[object], Command],
    env: Optional[Mapping[str, object]] = None, timeout: float = 30.0,
    binaries: Sequence[Binary] = (), cwd: str = "", input: Optional[str] = None,
    expected_exit_codes: Sequence[int] = (0,), output_limit: int = 1 << 20,
    mode: str = "capture", retries: int = 0, encoding: str = "utf-8",
    mounts: Sequence[Mount] = (), logs: Optional[LogPolicy] = None,
    placement: Optional[Placement] = None,
    metadata: Optional[Mapping[str, object]] = None,
) -> Client: ...


def client(
    name: str,
    *,
    command: Optional[Union[Sequence[object], Command]] = None,
    execution: Optional[Execution] = None,
    binary: Optional[Binary] = None,
    args: Sequence[object] = (),
    env: Optional[Mapping[str, object]] = None,
    timeout: float = 30.0,
    binaries: Sequence[Binary] = (),
    cwd: str = "",
    input: Optional[str] = None,
    expected_exit_codes: Sequence[int] = (0,),
    output_limit: int = 1 << 20,
    mode: str = "capture",
    retries: int = 0,
    encoding: str = "utf-8",
    mounts: Sequence[Mount] = (),
    logs: Optional[LogPolicy] = None,
    placement: Optional[Placement] = None,
    metadata: Optional[Mapping[str, object]] = None,
) -> Client:
    """Declare a named client using either ``command`` or ``binary`` + ``args``."""
    command, command_defaults = _client_command(name, command, execution, binary, args)
    policy = _client_policy(
        command_defaults, env={} if env is None else env, cwd=cwd, input=input,
        timeout=timeout, expected_exit_codes=expected_exit_codes,
        output_limit=output_limit, mode=mode, retries=retries, encoding=encoding,
    )
    return Client(
        name=name, command=command,
        env=_string_mapping(policy["env"], "client.env"), timeout=policy["timeout"],
        binaries=binaries, cwd=policy["cwd"], input=policy["input"],
        expected_exit_codes=policy["expected_exit_codes"],
        output_limit=policy["output_limit"], mode=policy["mode"],
        retries=policy["retries"], encoding=policy["encoding"],
        mounts=mounts,
        logs=LogPolicy() if logs is None else logs,
        placement=Placement() if placement is None else placement,
        metadata={} if metadata is None else metadata,
    )


@dataclasses.dataclass(frozen=True)
class Tool(Client):
    """First-class named test tool; a semantic specialization of Client."""

    @property
    def resource_kind(self) -> str:
        """Identify this declaration as an invocable tool rather than an actor."""
        return "tool"


@overload
def tool(
    name: str, *, execution: Execution, env: Optional[Mapping[str, object]] = None,
    timeout: float = 30.0, binaries: Sequence[Binary] = (), cwd: str = "",
    input: Optional[str] = None, expected_exit_codes: Sequence[int] = (0,),
    output_limit: int = 1 << 20, mode: str = "capture", retries: int = 0,
    encoding: str = "utf-8", mounts: Sequence[Mount] = (),
    logs: Optional[LogPolicy] = None,
    placement: Optional[Placement] = None,
    metadata: Optional[Mapping[str, object]] = None,
) -> Tool: ...


@overload
def tool(
    name: str, *, binary: Binary, args: Sequence[object] = (),
    env: Optional[Mapping[str, object]] = None, timeout: float = 30.0,
    binaries: Sequence[Binary] = (), cwd: str = "", input: Optional[str] = None,
    expected_exit_codes: Sequence[int] = (0,), output_limit: int = 1 << 20,
    mode: str = "capture", retries: int = 0, encoding: str = "utf-8",
    mounts: Sequence[Mount] = (), logs: Optional[LogPolicy] = None,
    placement: Optional[Placement] = None,
    metadata: Optional[Mapping[str, object]] = None,
) -> Tool: ...


@overload
def tool(
    name: str, *, command: Union[Sequence[object], Command],
    env: Optional[Mapping[str, object]] = None, timeout: float = 30.0,
    binaries: Sequence[Binary] = (), cwd: str = "", input: Optional[str] = None,
    expected_exit_codes: Sequence[int] = (0,), output_limit: int = 1 << 20,
    mode: str = "capture", retries: int = 0, encoding: str = "utf-8",
    mounts: Sequence[Mount] = (), logs: Optional[LogPolicy] = None,
    placement: Optional[Placement] = None,
    metadata: Optional[Mapping[str, object]] = None,
) -> Tool: ...


def tool(
    name: str,
    *,
    execution: Optional[Execution] = None,
    command: Optional[Union[Sequence[object], Command]] = None,
    binary: Optional[Binary] = None,
    args: Sequence[object] = (),
    env: Optional[Mapping[str, object]] = None,
    timeout: float = 30.0,
    binaries: Sequence[Binary] = (),
    cwd: str = "",
    input: Optional[str] = None,
    expected_exit_codes: Sequence[int] = (0,),
    output_limit: int = 1 << 20,
    mode: str = "capture",
    retries: int = 0,
    encoding: str = "utf-8",
    mounts: Sequence[Mount] = (),
    logs: Optional[LogPolicy] = None,
    placement: Optional[Placement] = None,
    metadata: Optional[Mapping[str, object]] = None,
) -> Tool:
    """Declare a named tool with the same execution guarantees as a client."""
    declared = client(
        name, execution=execution, command=command, binary=binary, args=args,
        env=env, timeout=timeout, binaries=binaries, cwd=cwd, input=input,
        expected_exit_codes=expected_exit_codes, output_limit=output_limit,
        mode=mode, retries=retries, encoding=encoding, mounts=mounts,
        logs=logs, placement=placement, metadata=metadata,
    )
    return Tool(**{
        field.name: getattr(declared, field.name) for field in dataclasses.fields(Client)
    })
