"""Exhaustive contracts for BriXTest's stable test-author API."""

import ast
import dataclasses
import inspect
import json
import re
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

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
    ServiceFilesystem,
    SpecError,
    TemplateError,
    TLSAuth,
    TokenAuth,
    ToolExecutionContext,
    ToolExecutionRequest,
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
    _assert_contract_header(encoded)
    symbols = {row["name"]: row for row in contract["symbols"]}
    _assert_symbol_contract(symbols)
    _assert_framework_contract(contract)
    with pytest.raises(TypeError, match="immutable mapping"):
        contract["version"] = "changed"


def _assert_contract_header(encoded):
    assert (
        encoded["schema_version"], encoded["package"], encoded["version"],
    ) == (2, "brixtest", brixtest.__version__)


def _assert_symbol_contract(symbols):
    observed = (
        set(symbols), tuple(symbols), symbols["__version__"]["kind"],
        symbols["api_contract"]["call_shape"], symbols["Run"]["call_shape"],
        symbols["Run"]["attributes"], symbols["Run"]["members"],
        symbols["Run"]["properties"],
        symbols["Run"]["member_call_shapes"]["command"],
    )
    expected = (
        set(brixtest.__all__), tuple(brixtest.__all__), "constant", (),
        PUBLIC_CLASS_CALL_SHAPES["Run"], PUBLIC_ATTRIBUTES["Run"],
        PUBLIC_METHODS["Run"], PUBLIC_PROPERTIES["Run"],
        PUBLIC_MEMBER_CALL_SHAPES["Run.command"],
    )
    assert observed == expected


def _assert_framework_contract(contract):
    grouped = {
        name for names in contract["groups"].values() for name in names
    }
    pytest_contract = contract["pytest"]
    observed = (
        grouped, set(pytest_contract["options"]), set(pytest_contract["fixtures"]),
        set(pytest_contract["markers"]), set(pytest_contract["ini"]),
        set(pytest_contract["hooks"]),
    )
    expected = (
        set(brixtest.__all__), PUBLIC_PYTEST_OPTIONS, PUBLIC_PYTEST_FIXTURES,
        PUBLIC_PYTEST_MARKERS, PUBLIC_PYTEST_INI, PUBLIC_PYTEST_HOOKS,
    )
    assert observed == expected
    with pytest.raises(TypeError, match="immutable mapping"):
        contract["symbols"][0]["name"] = "changed"


def _contract_shapes(symbols):
    return {
        name: tuple(row["call_shape"])
        for name, row in symbols.items()
        if row["kind"] == "function"
    }


def _contract_members(symbols):
    return {
        name: tuple(row["members"])
        for name, row in symbols.items()
        if row["kind"] == "class"
    }


def _contract_class_shapes(symbols):
    return {
        name: tuple(row["call_shape"])
        for name, row in symbols.items()
        if row["kind"] == "class"
    }


def _contract_member_shapes(symbols):
    return {
        "%s.%s" % (name, member): tuple(shape)
        for name, row in symbols.items()
        for member, shape in row["member_call_shapes"].items()
    }


def _contract_properties(symbols):
    return {
        name: tuple(row["properties"])
        for name, row in symbols.items()
        if row["properties"]
    }


def _contract_attributes(symbols):
    return {
        name: tuple(row["attributes"])
        for name, row in symbols.items()
        if row["kind"] == "class"
    }


def test_api_contract_class_and_function_details_match_canonical_manifests():
    symbols = {row["name"]: row for row in brixtest.api_contract()["symbols"]}
    assert _contract_shapes(symbols) == PUBLIC_CALL_SHAPES
    assert _contract_members(symbols) == PUBLIC_METHODS
    assert _contract_class_shapes(symbols) == PUBLIC_CLASS_CALL_SHAPES
    assert _contract_member_shapes(symbols) == PUBLIC_MEMBER_CALL_SHAPES
    assert _contract_properties(symbols) == PUBLIC_PROPERTIES
    assert _contract_attributes(symbols) == PUBLIC_ATTRIBUTES


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
    assert {"run", "metrics", "brixtest_metrics"} == PUBLIC_PYTEST_FIXTURES
    assert {"brixtest", "brixtest_budget"} == PUBLIC_PYTEST_MARKERS
    assert {
        "brixtest_backend", "brixtest_isolation", "brixtest_runs",
        "brixtest_helper_plugins", "brixtest_safe_imports", "brixtest_profile",
    } == PUBLIC_PYTEST_INI
    assert {
        "pytest_brixtest_plan", "pytest_brixtest_helper_plugins",
        "pytest_brixtest_result", "pytest_brixtest_server_ready",
        "pytest_brixtest_server_stopped", "pytest_brixtest_tool_result",
        "pytest_brixtest_artifact_materialized",
    } == PUBLIC_PYTEST_HOOKS


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
    assert (bool(public_dataclasses), _all_frozen(public_dataclasses)) == (True, True)


def _all_frozen(values):
    return all(value.__dataclass_params__.frozen for value in values)


def test_public_dataclass_fields_exactly_match_the_readable_attribute_contract():
    public_dataclasses = {
        name: getattr(brixtest, name) for name in PUBLIC_ATTRIBUTES
        if dataclasses.is_dataclass(getattr(brixtest, name))
    }
    assert public_dataclasses
    assert _dataclass_fields(public_dataclasses) == _expected_attributes(public_dataclasses)


def _dataclass_fields(values):
    return {
        name: tuple(field.name for field in dataclasses.fields(value))
        for name, value in values.items()
    }


def _expected_attributes(values):
    return {name: PUBLIC_ATTRIBUTES[name] for name in values}


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
        "ServiceFilesystem": ServiceFilesystem(SimpleNamespace()),
        "BackendContext": BackendContext(SimpleNamespace(
            definition=definition, nodeid="contract::case", root=tmp_path,
            workspace=tmp_path / "workspace", backend_name="local",
            metrics=recorder, evidence=SimpleNamespace(), _services={},
        )),
        "SpecError": SpecError("field", "value", "rule"),
        "TemplateError": TemplateError("template", ("field",)),
    }
    assert set(objects) == _non_dataclass_names()
    assert _object_attributes(objects) == _expected_attributes(objects)


def _non_dataclass_names():
    return {
        name for name in PUBLIC_ATTRIBUTES
        if not dataclasses.is_dataclass(getattr(brixtest, name))
    }


def _object_attributes(objects):
    return {
        name: tuple(key for key in vars(value) if not key.startswith("_"))
        for name, value in objects.items()
    }
