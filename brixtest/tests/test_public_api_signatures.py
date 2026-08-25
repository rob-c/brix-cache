"""Exhaustive contracts for BriXTest's stable test-author API."""

import dataclasses
import hashlib
import inspect
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

import brixtest
from brixtest import (  # noqa: F401 -- importing every public type is the contract
    Artifact,
    ArtifactProviderContext,
    AuthRecipe,
    BackendContext,
    Binary,
    BriXTestError,
    CapturedBinary,
    CaseDefinition,
    CaseManager,
    CaseRunError,
    Client,
    CollectorSpec,
    CommandResult,
    ConfigFile,
    ConfigTemplate,
    ConfiguredClient,
    ConfiguredTool,
    Credential,
    ExtensionRegistry,
    HelperProcessError,
    HostMapping,
    Isolation,
    KerberosAuth,
    MaterializedArtifact,
    MaterializedAuth,
    MaterializedCredential,
    MetricRecorder,
    MetricSample,
    MetricTimer,
    Readiness,
    Run,
    Server,
    Service,
    SpecError,
    TemplateError,
    TLSAuth,
    TokenAuth,
    ToolExecutionContext,
    ToolExecutionRequest,
    VOMSAuth,
)
from brixtest._api import (
    PUBLIC_CALL_SHAPES,
    PUBLIC_CLASS_CALL_SHAPES,
    PUBLIC_EXPORTS,
    PUBLIC_MEMBER_CALL_SHAPES,
    PUBLIC_METHODS,
    PUBLIC_PROPERTIES,
)

_VALUE_EXPORTS = {"GB", "GiB", "KB", "KiB", "MB", "MiB", "__version__"}

_PUBLIC_METHODS = {
    getattr(brixtest, name): set(members)
    for name, members in PUBLIC_METHODS.items()
}


def _visible_methods(value):
    return {
        name for name, member in inspect.getmembers(value)
        if not name.startswith("_")
        and name not in {"add_note", "with_traceback"}
        and (callable(member) or isinstance(member, property))
    }


def _call_shape(value, strip_owner=False):
    parameters = _visible_parameters(value, strip_owner)
    result = [_parameter_label(parameter) for parameter in parameters]
    boundary = _keyword_boundary(parameters)
    if boundary is not None:
        result.insert(boundary, "*")
    return tuple(result)


def _visible_parameters(value, strip_owner):
    return [
        parameter for parameter in inspect.signature(value).parameters.values()
        if not strip_owner or parameter.name not in ("self", "cls")
    ]


def _parameter_label(parameter):
    if parameter.kind is inspect.Parameter.VAR_POSITIONAL:
        return "*" + parameter.name
    if parameter.kind is inspect.Parameter.VAR_KEYWORD:
        return "**" + parameter.name
    suffix = "?" if parameter.default is not inspect.Parameter.empty else ""
    return parameter.name + suffix


def _keyword_boundary(parameters):
    if any(parameter.kind is inspect.Parameter.VAR_POSITIONAL for parameter in parameters):
        return None
    return next(
        (index for index, parameter in enumerate(parameters)
         if parameter.kind is inspect.Parameter.KEYWORD_ONLY),
        None,
    )



def test_every_public_method_and_property_has_individual_help_text():
    for owner_name, names in PUBLIC_METHODS.items():
        owner = getattr(brixtest, owner_name)
        for name in names:
            member = inspect.getattr_static(owner, name)
            value = member.fget if isinstance(member, property) else member
            assert inspect.getdoc(value), owner_name + "." + name


def test_public_mapping_fields_are_recursively_immutable_and_serializable(tmp_path):
    raw_env = {"MODE": "test"}
    raw_ports = {"http": None}
    server = brixtest.server(
        "origin", command=["server"], config=brixtest.server_config("x"),
        ports=raw_ports, env=raw_env,
    )
    client = brixtest.client("reader", command=["reader"], env=raw_env)
    token = brixtest.token_auth(claims={"roles": ["reader"], "nested": {"level": 1}})
    collector = brixtest.collector("custom", nested={"items": [1, 2]})
    sample = MetricRecorder().gauge("queue.depth", 2, labels={"role": "reader"})
    service = Service(
        "origin", "127.0.0.1", {"primary": 43123}, tmp_path / "config",
        tmp_path / "log", tmp_path, config_artifact={"checksums": {"sha256": "a" * 64}},
    )
    auth = MaterializedAuth(
        "token", "token", tmp_path, {"token": tmp_path / "token"},
        {"TOKEN": "test"}, {"TOKEN": "server"}, {"TOKEN": "client"},
        {"audiences": ["storage"]},
    )

    raw_env["MODE"] = "changed"
    raw_ports["admin"] = None
    assert server.env == {"MODE": "test"} and client.env == {"MODE": "test"}
    assert set(server.ports) == {"http"}

    mappings = (
        server.ports, server.env, client.env, token.claims, collector.options,
        sample.labels, service.ports, service.config_artifact, auth.files,
        auth.test_env, auth.metadata,
    )
    for mapping in mappings:
        with pytest.raises(TypeError, match="immutable mapping"):
            mapping.update({"new": "value"})
    assert token.claims["roles"] == ("reader",)
    assert token.claims["nested"]["level"] == 1
    assert collector.options["nested"]["items"] == (1, 2)
    for value in (server, client, token, collector, sample, service, auth):
        assert isinstance(hash(value), int)
    json.dumps(dataclasses.asdict(server), default=str)
    json.dumps(dataclasses.asdict(token), default=str)


def _public_api_callables():
    callables = [
        getattr(brixtest, name) for name in PUBLIC_EXPORTS
        if inspect.isfunction(getattr(brixtest, name))
    ]
    for owner, names in _PUBLIC_METHODS.items():
        for name in names:
            member = inspect.getattr_static(owner, name)
            callables.append(member.fget if isinstance(member, property) else member)
    return callables


def _assert_annotated(value) -> None:
    empty = inspect.Signature.empty
    signature = inspect.signature(value)
    assert signature.return_annotation is not empty, value
    assert all(
        parameter.annotation is not empty
        for parameter in signature.parameters.values()
        if parameter.name not in ("self", "cls")
    ), value


def _assert_constructor_annotated(value) -> None:
    empty = inspect.Signature.empty
    signature = inspect.signature(value)
    assert all(
        parameter.annotation is not empty for parameter in signature.parameters.values()
    ), value


def test_every_public_function_method_and_property_is_fully_annotated():
    for value in _public_api_callables():
        _assert_annotated(value)

    for name in PUBLIC_EXPORTS:
        value = getattr(brixtest, name)
        if inspect.isclass(value):
            _assert_constructor_annotated(value)


def test_every_public_factory_and_helper_has_a_locked_call_shape():
    public_functions = {
        name: getattr(brixtest, name) for name in PUBLIC_EXPORTS
        if inspect.isfunction(getattr(brixtest, name))
    }
    assert set(PUBLIC_CALL_SHAPES) == set(public_functions)
    assert {
        name: _call_shape(value) for name, value in public_functions.items()
    } == PUBLIC_CALL_SHAPES


def test_every_public_class_constructor_and_member_has_a_locked_call_shape():
    public_classes = {
        name: getattr(brixtest, name) for name in PUBLIC_METHODS
    }
    assert {
        name: _call_shape(value) for name, value in public_classes.items()
    } == PUBLIC_CLASS_CALL_SHAPES
    actual_members, actual_properties = _member_shapes(public_classes)
    assert (actual_members, actual_properties) == (
        PUBLIC_MEMBER_CALL_SHAPES, PUBLIC_PROPERTIES,
    )


def _member_shapes(public_classes):
    actual_members = {}
    actual_properties = {}
    for owner_name, member_names in PUBLIC_METHODS.items():
        owner = public_classes[owner_name]
        members, properties = _owner_shapes(owner_name, owner, member_names)
        actual_members.update(members)
        if properties:
            actual_properties[owner_name] = tuple(properties)
    return actual_members, actual_properties


def _owner_shapes(owner_name, owner, member_names):
    members = {}
    properties = []
    for member_name in member_names:
        member = inspect.getattr_static(owner, member_name)
        if isinstance(member, property):
            properties.append(member_name)
            member = member.fget
        members[owner_name + "." + member_name] = _call_shape(member, strip_owner=True)
    return members, properties


@pytest.mark.parametrize("statement", [
    "from brixtest.clients import ConfiguredClient; from brixtest.runtime import Run",
    "from brixtest.runtime.commands import CommandResult; from brixtest.clients import ClientSpec",
    "from brixtest.cli.main import main; from brixtest import CommandResult",
])
def test_public_packages_are_import_order_independent(statement):
    result = subprocess.run(
        [sys.executable, "-c", statement], capture_output=True, text=True,
        timeout=10, check=False,
    )
    assert result.returncode == 0, result.stderr


def test_top_level_error_taxonomy_is_structured_and_brand_consistent():
    error = SpecError("server.port", 0, "must be positive")
    assert isinstance(error, BriXTestError)
    assert error.details() == {
        "field": "server.port", "value": 0, "rule": "must be positive",
    }
    assert isinstance(TemplateError("x", ["port"]), BriXTestError)
    assert isinstance(CaseRunError("node", "setup", "boom"), BriXTestError)
    assert isinstance(HelperProcessError("node", timeout=1), BriXTestError)


def test_config_declarations_have_consistent_filename_and_content_semantics(tmp_path):
    inline = brixtest.server_config("listen={port}\n", filename="service.conf")
    assert isinstance(inline, ConfigFile)
    assert inline.filename == inline.destination == "service.conf"
    assert inline.content == "listen={port}\n" and inline.path is None
    template = brixtest.load_template(tmp_path / "service.in")
    completed = template.fill(filename="service.conf", mode="strict")
    assert isinstance(template, ConfigTemplate)
    assert completed.path == tmp_path / "service.in"
    assert completed.values == {"mode": "strict"}
    assert brixtest.template_config("x.in").template is True
    assert brixtest.static_config("x.conf").template is False


def test_artifact_factories_and_materialized_io_are_uniform(tmp_path):
    source = tmp_path / "source.bin"
    source.write_bytes(b"payload")
    declarations = (
        brixtest.noise("random", size=8, seed=2),
        brixtest.file_artifact("copied", source),
        brixtest.text_artifact("message", "hello"),
    )
    assert [item.kind for item in declarations] == ["noise", "file", "text"]
    materialized = MaterializedArtifact(
        "copied", source, 7, hashlib.sha256(b"payload").hexdigest(), "file",
    )
    assert os.fspath(materialized) == str(source)
    assert materialized.read_text() == "payload"
    assert materialized.read_bytes() == b"payload"
    assert json.loads(json.dumps(materialized.as_dict()))["sha256"] \
        == hashlib.sha256(b"payload").hexdigest()
    assert materialized.verify()
    with materialized.open("rb") as handle:
        assert handle.read() == b"payload"
    document = tmp_path / "document.json"
    document.write_text('{"answer": 42}')
    json_artifact = MaterializedArtifact(
        "document", document, document.stat().st_size,
        hashlib.sha256(document.read_bytes()).hexdigest(), "text",
    )
    assert json_artifact.read_json() == {"answer": 42}
    document.write_text("changed")
    assert not json_artifact.verify()
    with pytest.raises(SpecError, match="valid encoded JSON"):
        json_artifact.read_json()


def test_binary_declarations_and_captures_are_path_friendly(tmp_path):
    declaration = brixtest.binary(
        "python", sys.executable, libraries=["libexample.so"], discover_libraries=False,
    )
    assert declaration.name == "python" and declaration.libraries == ("libexample.so",)
    captured = CapturedBinary(
        "python", Path(sys.executable), tmp_path,
        hashlib.sha256(Path(sys.executable).read_bytes()).hexdigest(), (),
        source=Path(sys.executable),
    )
    assert os.fspath(captured) == sys.executable
    assert json.loads(json.dumps(captured.as_dict()))["name"] == "python"
    assert captured.verify()


def test_server_and_client_share_binary_plus_args_or_command_contract():
    executable = brixtest.binary("python", sys.executable, discover_libraries=False)
    config = brixtest.server_config("port={port}\n")
    server = brixtest.server(
        "origin", binary=executable, args=["-m", "http.server", "{port}"],
        config=config,
    )
    client = brixtest.client(
        "reader", binary=executable, args=["-c", "print('ok')"], timeout=4,
    )
    assert server.command[0] is executable and client.command[0] is executable
    assert client.timeout == 4
    with pytest.raises(SpecError, match=r"command or binary\+args"):
        brixtest.client("bad", command=["x"], binary=executable)
    with pytest.raises(SpecError, match="requires client"):
        brixtest.client("bad", args=["x"])
    with pytest.raises(SpecError, match="is required"):
        brixtest.client("bad")


@pytest.mark.parametrize("operation,field", [
    (lambda: brixtest.server(
        "bad", command=["x"], config=brixtest.server_config("x"), ports="http",
    ), "server.ports"),
    (lambda: brixtest.client("bad", command=["x"], env=[("NAME", 1)]), "client.env"),
    (lambda: brixtest.binary("bad", "/bin/true", libraries="lib.so"), "binary.libraries"),
    (lambda: brixtest.credential("bad", "x", targets="test"), "credential.targets"),
    (lambda: brixtest.host_mapping("bad", "host.test", aliases="alias.test"), "host.aliases"),
    (lambda: brixtest.tls_auth(aliases="alias.test"), "tls.aliases"),
    (lambda: brixtest.token_auth(scopes="read:/"), "token.scopes"),
    (lambda: brixtest.voms_auth(fqans="/brixtest/Role=NULL"), "voms.fqans"),
    (lambda: brixtest.prometheus("http://metrics", allow="requests"), "prometheus.allow"),
    (brixtest.structured_logs, "structured log paths"),
    (lambda: brixtest.server_config("x", filename=3), "config.destination"),
    (lambda: brixtest.Binary("bad", "/bin/true", discover_libraries=1), "discover_libraries"),
    (lambda: brixtest.client("bad", binary=brixtest.binary("x", "/bin/true"), args=3), "client args"),
    (lambda: brixtest.server(
        "bad", binary=brixtest.binary("x", "/bin/true"), args=3,
        config=brixtest.server_config("x"),
    ), "server args"),
    (lambda: brixtest.credential("bad", "x", env=3), "credential.env"),
    (lambda: brixtest.credential("bad", "x", targets=3), "credential.targets"),
    (lambda: brixtest.token_auth(claims=[]), "token.claims"),
    (lambda: brixtest.issue_token(
        secret="x", issuer="https://issuer.test", audience="a", subject="s",
        scopes="read:/",
    ), "token.scopes"),
    (lambda: brixtest.issue_token(
        secret="x", issuer="https://issuer.test", audience="a", subject="s",
        claims=[],
    ), "token.claims"),
    (lambda: brixtest.collector("custom", interval="soon"), "collector interval"),
    (lambda: brixtest.CollectorSpec([], "name"), "collector kind"),
    (lambda: brixtest.docker(3), "isolation.image"),
    (lambda: brixtest.kubernetes(3), "isolation.image"),
    (lambda: brixtest.nsenter("pid"), "target_pid"),
    (lambda: brixtest.runc(3), "isolation.bundle"),
])
def test_public_factories_turn_common_python_shape_mistakes_into_spec_errors(
    operation, field,
):
    with pytest.raises(SpecError, match=field):
        operation()


@pytest.mark.parametrize("operation,field", [
    (lambda: MaterializedArtifact("x", Path("x"), 0, "bad", "text"), "artifact.sha256"),
    (lambda: CapturedBinary("x", Path("x"), Path(), "", ()), "binary.sha256"),
    (lambda: MaterializedCredential(
        "x", Path("x"), "a" * 64, "text", "x", None, "path", 3,
    ), "credential.targets"),
    (lambda: MaterializedAuth("x", "token", None, {}, {}, {}, {}, {}), "auth.root"),
    (lambda: MetricSample("metric", 1, "", "gauge", {}, -1), "at_seconds"),
])
def test_public_returned_value_constructors_also_use_structured_errors(operation, field):
    with pytest.raises(SpecError, match=field):
        operation()
