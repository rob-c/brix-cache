"""Exhaustive contracts for BriXTest's stable test-author API."""

import dataclasses
import ast
import hashlib
import inspect
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

import brixtest
from brixtest import (  # noqa: F401 -- importing every public type is the contract
    BriXTestError,
    Artifact,
    ArtifactProviderContext,
    AuthRecipe,
    BackendContext,
    Binary,
    CapturedBinary,
    CaseManager,
    CaseDefinition,
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
    ToolExecutionContext,
    ToolExecutionRequest,
    TLSAuth,
    TokenAuth,
    VOMSAuth,
)
from brixtest._api import (
    PUBLIC_ATTRIBUTES,
    PUBLIC_CALL_SHAPES,
    PUBLIC_CLASS_CALL_SHAPES,
    PUBLIC_EXPORTS,
    PUBLIC_GROUPS,
    PUBLIC_MEMBER_CALL_SHAPES,
    PUBLIC_METHODS,
    PUBLIC_PROPERTIES,
)
from brixtest.clients.configured import ClientSpec
from brixtest.pytest_options import (
    INTERNAL_PYTEST_OPTIONS,
    PUBLIC_PYTEST_FIXTURES,
    PUBLIC_PYTEST_HOOKS,
    PUBLIC_PYTEST_INI,
    PUBLIC_PYTEST_MARKERS,
    PUBLIC_PYTEST_OPTIONS,
    pytest_addoption,
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
    result = []
    keyword_boundary = False
    for parameter in inspect.signature(value).parameters.values():
        if strip_owner and parameter.name in ("self", "cls"):
            continue
        if parameter.kind is inspect.Parameter.VAR_POSITIONAL:
            result.append("*" + parameter.name)
            keyword_boundary = True
            continue
        if parameter.kind is inspect.Parameter.VAR_KEYWORD:
            result.append("**" + parameter.name)
            continue
        if parameter.kind is inspect.Parameter.KEYWORD_ONLY and not keyword_boundary:
            result.append("*")
            keyword_boundary = True
        suffix = "?" if parameter.default is not inspect.Parameter.empty else ""
        result.append(parameter.name + suffix)
    return tuple(result)


def test_public_manifest_is_unique_sorted_and_exactly_matches_star_import():
    assert set(brixtest.__all__) == {"__version__", *PUBLIC_EXPORTS}
    assert brixtest.__all__ == ["__version__", *sorted(PUBLIC_EXPORTS)]
    assert len(PUBLIC_EXPORTS) == sum(len(group) for group in PUBLIC_GROUPS.values())
    assert all(PUBLIC_GROUPS.values())
    assert brixtest.__version__ == "0.15.0"


def test_typed_package_facade_exactly_reexports_the_runtime_contract():
    stub = Path(brixtest.__file__).with_name("__init__.pyi")
    tree = ast.parse(stub.read_text(), filename=str(stub))
    names = {
        alias.asname or alias.name
        for node in tree.body if isinstance(node, ast.ImportFrom)
        for alias in node.names
    }
    assert names == set(PUBLIC_EXPORTS)
    assert stub.with_name("py.typed").is_file()


def test_api_contract_is_complete_immutable_and_json_compatible():
    contract = brixtest.api_contract()
    encoded = json.loads(json.dumps(contract))
    assert encoded["schema_version"] == 2
    assert encoded["package"] == "brixtest"
    assert encoded["version"] == brixtest.__version__

    symbols = {row["name"]: row for row in contract["symbols"]}
    assert set(symbols) == set(brixtest.__all__)
    assert tuple(symbols) == tuple(brixtest.__all__)
    assert symbols["__version__"]["kind"] == "constant"
    assert symbols["api_contract"]["call_shape"] == ()
    assert symbols["Run"]["call_shape"] == PUBLIC_CLASS_CALL_SHAPES["Run"]
    assert symbols["Run"]["attributes"] == PUBLIC_ATTRIBUTES["Run"]
    assert symbols["Run"]["members"] == PUBLIC_METHODS["Run"]
    assert symbols["Run"]["properties"] == PUBLIC_PROPERTIES["Run"]
    assert symbols["Run"]["member_call_shapes"]["command"] \
        == PUBLIC_MEMBER_CALL_SHAPES["Run.command"]
    assert {
        name for names in contract["groups"].values() for name in names
    } == set(brixtest.__all__)
    assert set(contract["pytest"]["options"]) == PUBLIC_PYTEST_OPTIONS
    assert set(contract["pytest"]["fixtures"]) == PUBLIC_PYTEST_FIXTURES
    assert set(contract["pytest"]["markers"]) == PUBLIC_PYTEST_MARKERS
    assert set(contract["pytest"]["ini"]) == PUBLIC_PYTEST_INI
    assert set(contract["pytest"]["hooks"]) == PUBLIC_PYTEST_HOOKS

    with pytest.raises(TypeError, match="immutable mapping"):
        contract["version"] = "changed"
    with pytest.raises(TypeError, match="immutable mapping"):
        contract["symbols"][0]["name"] = "changed"


def test_api_contract_class_and_function_details_match_canonical_manifests():
    symbols = {row["name"]: row for row in brixtest.api_contract()["symbols"]}
    assert {
        name: tuple(row["call_shape"])
        for name, row in symbols.items()
        if row["kind"] == "function"
    } == PUBLIC_CALL_SHAPES
    assert {
        name: tuple(row["members"])
        for name, row in symbols.items()
        if row["kind"] == "class"
    } == PUBLIC_METHODS
    assert {
        name: tuple(row["call_shape"])
        for name, row in symbols.items()
        if row["kind"] == "class"
    } == PUBLIC_CLASS_CALL_SHAPES
    assert {
        "%s.%s" % (name, member): tuple(shape)
        for name, row in symbols.items()
        for member, shape in row["member_call_shapes"].items()
    } == PUBLIC_MEMBER_CALL_SHAPES
    assert {
        name: tuple(row["properties"])
        for name, row in symbols.items()
        if row["properties"]
    } == PUBLIC_PROPERTIES
    assert {
        name: tuple(row["attributes"])
        for name, row in symbols.items()
        if row["kind"] == "class"
    } == PUBLIC_ATTRIBUTES


def test_api_cli_browses_the_same_contract_in_human_and_json_forms():
    command = [sys.executable, "-m", "brixtest", "api"]
    human = subprocess.run(
        command, capture_output=True, text=True, timeout=10, check=False,
    )
    assert human.returncode == 0, human.stderr
    assert "BriXTest 0.15.0 public API" in human.stdout
    assert "api_contract()" in human.stdout and "Run" in human.stdout
    assert "fixtures: brixtest_metrics, metrics, run" in human.stdout

    machine = subprocess.run(
        [*command, "--json"], capture_output=True, text=True, timeout=10,
        check=False,
    )
    assert machine.returncode == 0, machine.stderr
    payload = json.loads(machine.stdout)
    assert payload["version"] == "0.15.0"
    assert {row["name"] for row in payload["symbols"]} == set(brixtest.__all__)


def test_api_cli_can_focus_on_a_group_or_exact_symbol():
    grouped = subprocess.run(
        [sys.executable, "-m", "brixtest", "api", "--group", "runtime", "--json"],
        capture_output=True, text=True, timeout=10, check=False,
    )
    payload = json.loads(grouped.stdout)
    assert grouped.returncode == 0
    assert {row["group"] for row in payload["symbols"]} == {"runtime"}
    assert set(payload["groups"]) == {"runtime"}

    exact = subprocess.run(
        [sys.executable, "-m", "brixtest", "api", "Run"],
        capture_output=True, text=True, timeout=10, check=False,
    )
    assert exact.returncode == 0 and "members:" in exact.stdout
    missing = subprocess.run(
        [sys.executable, "-m", "brixtest", "api", "NotPublic"],
        capture_output=True, text=True, timeout=10, check=False,
    )
    assert missing.returncode == 2 and "no public API symbol" in missing.stderr


def test_reference_table_covers_every_public_name_exactly_once():
    reference = Path(__file__).resolve().parents[1] / "docs" / "api-reference.md"
    text = reference.read_text().partition("<!-- PUBLIC-API:START -->")[2].partition(
        "<!-- PUBLIC-API:END -->"
    )[0]
    documented = re.findall(r"^\| `([^`]+)` \|", text, flags=re.MULTILINE)
    assert len(documented) == len(set(documented))
    assert set(documented) == set(brixtest.__all__)


def test_pytest_option_fixture_and_marker_manifests_cover_the_plugin_surface():
    options = set()
    ini = set()

    class Group:
        def addoption(self, *names, **metadata):
            options.update(name for name in names if name.startswith("--"))

    class Parser:
        def addini(self, name, help, default=""):
            ini.add(name)

        def getgroup(self, name):
            assert name == "brixtest"
            return Group()

    pytest_addoption(Parser())
    assert options == PUBLIC_PYTEST_OPTIONS | INTERNAL_PYTEST_OPTIONS
    assert ini == PUBLIC_PYTEST_INI
    assert PUBLIC_PYTEST_FIXTURES == {"run", "metrics", "brixtest_metrics"}
    assert PUBLIC_PYTEST_MARKERS == {"brixtest", "brixtest_budget"}
    assert PUBLIC_PYTEST_INI == {
        "brixtest_backend", "brixtest_isolation", "brixtest_runs",
        "brixtest_helper_plugins", "brixtest_safe_imports", "brixtest_profile",
    }
    assert PUBLIC_PYTEST_HOOKS == {
        "pytest_brixtest_plan", "pytest_brixtest_helper_plugins",
        "pytest_brixtest_result", "pytest_brixtest_server_ready",
        "pytest_brixtest_server_stopped", "pytest_brixtest_tool_result",
        "pytest_brixtest_artifact_materialized",
    }


@pytest.mark.parametrize("name,module", sorted(PUBLIC_EXPORTS.items()))
def test_every_public_name_lazily_resolves_from_its_manifest_module(name, module):
    value = getattr(brixtest, name)
    assert value is getattr(__import__(module, fromlist=[name]), name)
    assert getattr(brixtest, name) is value


@pytest.mark.parametrize("name", sorted(set(PUBLIC_EXPORTS) - _VALUE_EXPORTS))
def test_every_public_callable_or_type_has_help_text(name):
    assert inspect.getdoc(getattr(brixtest, name)), name


@pytest.mark.parametrize("value,expected", [
    (brixtest.KB, 1_000), (brixtest.MB, 1_000_000),
    (brixtest.GB, 1_000_000_000), (brixtest.KiB, 1 << 10),
    (brixtest.MiB, 1 << 20), (brixtest.GiB, 1 << 30),
])
def test_public_size_constants_are_unambiguous(value, expected):
    assert value == expected


@pytest.mark.parametrize("public_type,expected", _PUBLIC_METHODS.items())
def test_user_facing_value_objects_have_an_explicit_stable_method_surface(
    public_type, expected,
):
    assert _visible_methods(public_type) == expected


def test_method_contract_covers_every_public_class():
    public_class_names = {
        name for name in PUBLIC_EXPORTS
        if inspect.isclass(getattr(brixtest, name))
    }
    assert set(PUBLIC_METHODS) == public_class_names
    assert set(_PUBLIC_METHODS) == {
        getattr(brixtest, name) for name in public_class_names
    }


def test_every_public_dataclass_value_is_structurally_immutable():
    public_dataclasses = {
        getattr(brixtest, name) for name in PUBLIC_EXPORTS
        if inspect.isclass(getattr(brixtest, name))
        and dataclasses.is_dataclass(getattr(brixtest, name))
    }
    assert public_dataclasses
    assert all(value.__dataclass_params__.frozen for value in public_dataclasses)


def test_public_dataclass_fields_exactly_match_the_readable_attribute_contract():
    public_dataclasses = {
        name: getattr(brixtest, name) for name in PUBLIC_ATTRIBUTES
        if dataclasses.is_dataclass(getattr(brixtest, name))
    }
    assert public_dataclasses
    assert {
        name: tuple(field.name for field in dataclasses.fields(value))
        for name, value in public_dataclasses.items()
    } == {
        name: PUBLIC_ATTRIBUTES[name] for name in public_dataclasses
    }


def test_non_dataclass_objects_exactly_match_the_readable_attribute_contract(tmp_path):
    def body(run):
        return None

    definition = brixtest.get_case(brixtest.case(observe=[])(body))
    recorder = MetricRecorder()
    objects = {
        "BriXTestError": BriXTestError("message"),
        "CaseManager": CaseManager(definition, "contract::case", root=tmp_path / "run"),
        "CaseRunError": CaseRunError("node", "setup", "cause"),
        "ConfiguredClient": ConfiguredClient(
            ClientSpec("client", (sys.executable, "--version")), {},
        ),
        "ConfiguredTool": ConfiguredTool(
            ClientSpec("tool", (sys.executable, "--version")), {},
        ),
        "ExtensionRegistry": ExtensionRegistry(),
        "HelperProcessError": HelperProcessError("node", returncode=1),
        "MetricRecorder": recorder,
        "MetricTimer": recorder.timer("contract.timer"),
        "Run": Run(SimpleNamespace(
            root=tmp_path, workspace=tmp_path / "workspace",
            backend_name="local", metrics=recorder,
        )),
        "BackendContext": BackendContext(SimpleNamespace(
            definition=definition, nodeid="contract::case", root=tmp_path,
            workspace=tmp_path / "workspace", backend_name="local",
            metrics=recorder, evidence=SimpleNamespace(), _services={},
        )),
        "SpecError": SpecError("field", "value", "rule"),
        "TemplateError": TemplateError("template", ("field",)),
    }
    non_dataclasses = {
        name for name in PUBLIC_ATTRIBUTES
        if not dataclasses.is_dataclass(getattr(brixtest, name))
    }
    assert set(objects) == non_dataclasses
    assert {
        name: tuple(key for key in vars(value) if not key.startswith("_"))
        for name, value in objects.items()
    } == {
        name: PUBLIC_ATTRIBUTES[name] for name in objects
    }


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


def test_every_public_function_method_and_property_is_fully_annotated():
    empty = inspect.Signature.empty
    callables = [
        getattr(brixtest, name) for name in PUBLIC_EXPORTS
        if inspect.isfunction(getattr(brixtest, name))
    ]
    for owner, names in _PUBLIC_METHODS.items():
        for name in names:
            member = inspect.getattr_static(owner, name)
            callables.append(member.fget if isinstance(member, property) else member)
    for value in callables:
        signature = inspect.signature(value)
        assert signature.return_annotation is not empty, value
        assert all(
            parameter.annotation is not empty
            for parameter in signature.parameters.values()
            if parameter.name not in ("self", "cls")
        ), value

    for name in PUBLIC_EXPORTS:
        value = getattr(brixtest, name)
        if not inspect.isclass(value):
            continue
        signature = inspect.signature(value)
        assert all(
            parameter.annotation is not empty
            for parameter in signature.parameters.values()
        ), value


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
    actual_members = {}
    actual_properties = {}
    for owner_name, member_names in PUBLIC_METHODS.items():
        owner = public_classes[owner_name]
        properties = []
        for member_name in member_names:
            member = inspect.getattr_static(owner, member_name)
            if isinstance(member, property):
                properties.append(member_name)
                member = member.fget
            actual_members[owner_name + "." + member_name] = _call_shape(
                member, strip_owner=True,
            )
        if properties:
            actual_properties[owner_name] = tuple(properties)
    assert actual_members == PUBLIC_MEMBER_CALL_SHAPES
    assert actual_properties == PUBLIC_PROPERTIES


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
    (lambda: brixtest.structured_logs(), "structured log paths"),
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
    (lambda: CapturedBinary("x", Path("x"), Path("."), "", ()), "binary.sha256"),
    (lambda: MaterializedCredential(
        "x", Path("x"), "a" * 64, "text", "x", None, "path", 3,
    ), "credential.targets"),
    (lambda: MaterializedAuth("x", "token", None, {}, {}, {}, {}, {}), "auth.root"),
    (lambda: MetricSample("metric", 1, "", "gauge", {}, -1), "at_seconds"),
])
def test_public_returned_value_constructors_also_use_structured_errors(operation, field):
    with pytest.raises(SpecError, match=field):
        operation()


def test_case_decorator_produces_a_complete_immutable_definition():
    def body(run):
        return None

    decorated = brixtest.case(
        trials=2, warmup=1, backend="local", isolation=brixtest.process(),
        timeout=9, keep="always", observe=[],
    )(body)
    definition = brixtest.get_case(decorated)
    assert brixtest.is_case(decorated) and not brixtest.is_case(body.__name__)
    assert isinstance(definition, brixtest.CaseDefinition)
    assert (definition.trials, definition.warmup, definition.timeout) == (2, 1, 9)
    assert definition.backend == "local" and definition.keep == "always"
    assert definition.resource_names == {
        "servers": (), "clients": (), "artifacts": (), "binaries": (),
        "credentials": (), "auth": (), "hosts": (), "observe": (),
    }
    assert json.loads(json.dumps(definition.as_dict()))["backend"] == "local"
    with pytest.raises(dataclasses.FrozenInstanceError):
        definition.timeout = 1
    with pytest.raises(SpecError, match="case.trials"):
        dataclasses.replace(definition, trials=0)
    with pytest.raises(SpecError, match="decorated"):
        brixtest.get_case(lambda: None)


def test_readiness_and_service_cover_endpoint_config_and_log_access(tmp_path):
    config = tmp_path / "origin.conf"
    log = tmp_path / "origin.log"
    config.write_text("listen 43123\n")
    log.write_text("ready\n")
    service = Service(
        "origin", "127.0.0.1", {"http": 43123, "primary": 43123},
        config, log, tmp_path,
    )
    assert brixtest.tcp("http", timeout=3).kind == "tcp"
    assert brixtest.immediate().kind == "none"
    assert service.port("http") == 43123
    assert service.address("http") == ("127.0.0.1", 43123)
    assert service.url(role="http", path="status") == "http://127.0.0.1:43123/status"
    assert service.read_config() == "listen 43123\n"
    assert service.read_log() == "ready\n"
    assert json.loads(json.dumps(service.as_dict()))["ports"]["http"] == 43123
    assert dataclasses.replace(service, host="::1").url(path="health") \
        == "http://[::1]:43123/health"
    with pytest.raises(SpecError, match="declares"):
        service.port("missing")
    with pytest.raises(SpecError, match="URI scheme"):
        service.url("not a scheme")
    with pytest.raises(SpecError, match="TCP port"):
        dataclasses.replace(service, ports={"primary": 0})


def test_command_result_has_standard_and_fluent_output_helpers():
    result = CommandResult(("tool",), 0, "a\nb\n", "warn\n", 0.1)
    assert result.ok and result.args == ("tool",)
    assert result.output == "a\nb\nwarn\n"
    assert result.stdout_lines == ["a", "b"] and result.stderr_lines == ["warn"]
    assert json.loads(json.dumps(result.as_dict()))["ok"] is True
    assert CommandResult(("tool",), 0, '{"ok": true}', "", 0).json() == {"ok": True}
    with pytest.raises(SpecError, match="valid JSON"):
        result.json()
    assert result.check() is result and result.check_returncode() is None
    failed = CommandResult(("tool",), 7, "", "bad", 0.1)
    with pytest.raises(subprocess.CalledProcessError) as raised:
        failed.check()
    assert raised.value.stderr == "bad"
    for values in (
        ((), 0, "", "", 0), (("tool",), True, "", "", 0),
        (("tool",), 0, b"bytes", "", 0), (("tool",), 0, "", "", -1),
    ):
        with pytest.raises(SpecError):
            CommandResult(*values)


def test_configured_client_exposes_identity_timeout_command_and_text_output(tmp_path):
    client = ConfiguredClient(ClientSpec(
        "reader", (sys.executable, "-c", "print('hello')"), cwd=str(tmp_path), timeout=5,
    ), {})
    assert client.name == "reader" and client.timeout == 5
    assert client.command[0] == sys.executable
    result = client.run()
    assert isinstance(result, CommandResult) and result.stdout == "hello\n"
    assert client.cwd == tmp_path
    assert json.loads(json.dumps(client.as_dict()))["name"] == "reader"
    with pytest.raises(SpecError, match="timeout"):
        client.run(timeout=0)
    with pytest.raises(SpecError, match="must map strings"):
        client.run(env={"BAD": 1})
    with pytest.raises(SpecError, match="NUL-free"):
        client.run("bad\x00arg")


def test_metrics_cover_every_numeric_operation_timer_tags_snapshot_and_sink():
    events = []
    metrics = MetricRecorder(lambda event, row: events.append((event, dict(row))))
    gauge = metrics.gauge("queue.depth", 3, unit="items")
    metrics.count("requests", labels={"route": "read"})
    metrics.observe("latency", 0.2, unit="s")
    with metrics.timer("operation") as timer:
        pass
    metrics.tag("build", "asan")
    snapshot = metrics.snapshot()
    assert gauge.as_dict()["kind"] == "gauge"
    assert timer.elapsed >= 0 and len(snapshot["samples"]) == 4
    assert snapshot["tags"] == {"build": "asan"}
    replayed = []
    metrics.set_sink(lambda event, row: replayed.append(event), replay=True)
    assert replayed.count("metric") == 4 and replayed.count("tag") == 1
    assert {event for event, _ in events} == {"metric", "tag"}


def test_isolation_factories_cover_every_supported_backend(tmp_path):
    digest = "registry.test/brixtest@sha256:" + "a" * 64
    values = (
        brixtest.process(), brixtest.nsenter(12, namespaces=("mount", "net")),
        brixtest.docker(digest), brixtest.podman(digest), brixtest.runc(tmp_path),
    )
    assert [item.kind for item in values] == [
        "process", "nsenter", "docker", "podman", "runc",
    ]
    assert all(isinstance(item, brixtest.Isolation) for item in values)
    assert "--brixtest-isolation" in values[0].cli_args()


def test_credential_factories_and_materialized_io_cover_all_public_forms(tmp_path):
    payload = brixtest.text_artifact("payload", "content")
    values = (
        brixtest.credential("plain", "secret"),
        brixtest.checksum_credential("checksum", payload),
        brixtest.signed_credential("signed", "scope", secret="key"),
    )
    assert [item.kind for item in values] == ["text", "checksum", "signed"]
    path = tmp_path / "credential"
    path.write_text("secret")
    materialized = MaterializedCredential(
        "plain", path, hashlib.sha256(b"secret").hexdigest(), "text",
        "credentials/plain", "TOKEN", "content",
        ("test",),
    )
    assert os.fspath(materialized) == str(path)
    assert materialized.content == materialized.read_text() == "secret"
    assert materialized.read_bytes() == b"secret"
    assert "secret" not in json.dumps(materialized.as_dict())
    assert materialized.verify()
    with materialized.open("r") as handle:
        assert handle.read() == "secret"
    path.write_text("tampered")
    assert not materialized.verify()


def test_auth_recipe_token_and_materialized_surfaces_are_complete(tmp_path):
    recipes = (
        brixtest.token_auth(), brixtest.tls_auth(), brixtest.voms_auth(),
        brixtest.kerberos_auth(),
    )
    assert [item.kind for item in recipes] == ["token", "tls", "voms", "kerberos"]
    token = brixtest.issue_token(
        secret="secret", issuer="https://issuer.test", audience="storage",
        subject="user", scopes=("read:/",), now=100, lifetime=50,
    )
    header, payload = brixtest.decode_token(token)
    assert header["alg"] == "HS256" and payload["scope"] == "read:/"
    assert brixtest.verify_token(
        token, secret="secret", issuer="https://issuer.test", audience="storage", now=101,
    )["sub"] == "user"
    token_path = tmp_path / "token"
    token_path.write_text(token)
    auth = MaterializedAuth(
        "token", "token", tmp_path, {"token": token_path},
        {"TOKEN": "test"}, {"TOKEN": "server"}, {"TOKEN": "client"}, {},
    )
    assert auth.path("token") == token_path
    assert auth.environment() == {"TOKEN": "test"}
    assert auth.environment("server") == {"TOKEN": "server"}
    serialized = json.dumps(auth.as_dict())
    assert '\"TOKEN\": \"test\"' not in serialized and "TOKEN" in serialized
    with pytest.raises(SpecError, match="must be test"):
        auth.environment("other")


def test_direct_token_api_rejects_claim_override_and_untyped_time_values():
    common = {
        "secret": "secret", "issuer": "https://issuer.test", "audience": "storage",
        "subject": "user", "now": 100,
    }
    with pytest.raises(SpecError, match="cannot override"):
        brixtest.issue_token(**common, claims={"exp": 999})
    with pytest.raises(SpecError, match="positive integer"):
        brixtest.issue_token(**common, lifetime=0)
    with pytest.raises(SpecError, match="JSON serializable"):
        brixtest.issue_token(**common, claims={"custom": object()})
    token = brixtest.issue_token(**common)
    with pytest.raises(SpecError, match="integer timestamp"):
        brixtest.verify_token(token, secret="secret", now=True)


def test_network_and_collector_factories_cover_every_public_kind():
    host = brixtest.host_mapping(
        "origin", "Origin.Test.", aliases=("Alias.Test.",), address="127.0.0.8",
    )
    assert host.hostnames == ("origin.test", "alias.test")
    collectors = (
        brixtest.process_tree(interval=0.1),
        brixtest.prometheus("{server_origin_url}/metrics", allow=("requests",)),
        brixtest.structured_logs("runtime/*.jsonl"),
        brixtest.kubernetes_events(),
        brixtest.collector("custom", option="value"),
    )
    assert [item.kind for item in collectors] == [
        "process", "prometheus", "structured-logs", "kubernetes", "plugin",
    ]
    assert all(isinstance(item, brixtest.CollectorSpec) for item in collectors)


def test_run_facade_delegates_every_resource_and_evidence_convenience(tmp_path):
    artifact_path = tmp_path / "artifact.txt"
    artifact_path.write_text('{"message": "hello"}')
    artifact = MaterializedArtifact(
        "message", artifact_path, artifact_path.stat().st_size,
        hashlib.sha256(artifact_path.read_bytes()).hexdigest(), "text",
    )
    binary = CapturedBinary("tool", Path(sys.executable), tmp_path, "b" * 64, ())
    credential_path = tmp_path / "credential"
    credential_path.write_text("proof")
    credential = MaterializedCredential(
        "proof", credential_path, "c" * 64, "text", "proof", None, "path", ("test",),
    )
    auth = MaterializedAuth("auth", "token", tmp_path, {}, {}, {}, {}, {})
    service = Service(
        "origin", "127.0.0.1", {"primary": 43123}, artifact_path,
        artifact_path, tmp_path,
    )
    client = ConfiguredClient(ClientSpec("reader", (sys.executable, "--version")), {})
    configured_tool = ConfiguredTool(
        ClientSpec("inspect", (sys.executable, "--version")), {},
    )
    calls = []

    class Commands:
        def run(self, *argv, **options):
            calls.append((argv, options))
            return CommandResult(tuple(str(item) for item in argv), 0, "ok", "", 0)

    class Store:
        def __init__(self, value):
            self.value = value
            self._items = {value.name: value}
            self._captured = self._items

        def get(self, name):
            calls.append(("get", name))
            return self.value

    class Evidence:
        def __init__(self):
            self.spans = SimpleNamespace(span=lambda name, **attrs: (name, attrs))

        def attach(self, path, **metadata):
            return {"path": path, **metadata}

        def attach_text(self, name, text, **metadata):
            return {"name": name, "text": text, **metadata}

        def attach_json(self, name, value, **metadata):
            return {"name": name, "value": value, **metadata}

    manager = SimpleNamespace(
        root=tmp_path, workspace=tmp_path, backend_name="local", metrics=MetricRecorder(),
        commands=Commands(), artifact_store=Store(artifact), binary_store=Store(binary),
        _services={"origin": service},
        _clients={"reader": client, "inspect": configured_tool},
        service=lambda name: service,
        client=lambda name: {
            "reader": client, "inspect": configured_tool,
        }[name],
        security=SimpleNamespace(
            credential=lambda name: credential, auth_stack=lambda name: auth,
            resolve=lambda hostname: "127.0.0.8", reverse=lambda address: "origin.test",
            credentials=SimpleNamespace(_items={"proof": credential}),
            auth=SimpleNamespace(_items={"auth": auth}),
        ),
        evidence=Evidence(),
    )
    run = Run(manager)
    assert run.command("tool", check=False).stdout == "ok"
    assert run.execute(brixtest.execution("tool", "--version")).stdout == "ok"
    assert run.server("origin") is service and run.client("reader") is client
    assert run.tool("inspect") is configured_tool
    with pytest.warns(DeprecationWarning, match="run.execute"):
        assert run.tool(brixtest.execution("tool"), check=False).stdout == "ok"
    with pytest.warns(DeprecationWarning, match="compatibility path"):
        assert run.tool("reader") is client
    assert run.artifact("message") is artifact
    assert run.artifact_text("message") == '{"message": "hello"}'
    assert run.artifact_bytes("message") == b'{"message": "hello"}'
    assert run.artifact_json("message") == {"message": "hello"}
    assert run.artifact_file("message") == run.artifact_path("message") == artifact_path
    with run.open_artifact("message", "r") as handle:
        assert handle.read() == '{"message": "hello"}'
    assert run.binary("tool") is binary
    assert run.credential("proof") is credential and run.auth("auth") is auth
    assert run.resolve("origin.test") == "127.0.0.8"
    assert run.reverse("127.0.0.8") == "origin.test"
    assert run.attach_text("x", "text")["text"] == "text"
    assert run.attach_json("x", {"ok": True})["value"] == {"ok": True}
    assert run.attach(artifact_path, role="output")["role"] == "output"
    assert run.step("transfer", bytes=5) == ("transfer", {"bytes": 5})
    assert set(run.servers) == {"origin"}
    assert set(run.clients) == {"reader", "inspect"} and set(run.tools) == {"inspect"}
    assert set(run.artifacts) == {"message"} and set(run.binaries) == {"tool"}
    assert set(run.credentials) == {"proof"} and set(run.auth_stacks) == {"auth"}
    assert json.loads(json.dumps(run.as_dict()))["backend"] == "local"
    snapshot = run.servers
    snapshot.clear()
    assert set(run.servers) == {"origin"}
    for operation in (
        lambda: run.server([]), lambda: run.client(None), lambda: run.artifact(3),
        lambda: run.binary({}), lambda: run.credential(object()), lambda: run.auth(()),
        lambda: run.resolve(None), lambda: run.reverse(""),
    ):
        with pytest.raises(SpecError):
            operation()
