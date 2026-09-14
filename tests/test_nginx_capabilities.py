"""Selected-build capability metadata, with no nginx or real nm execution."""

import ast
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

import pytest

from brix_suite import nginx_capabilities as subject


@pytest.fixture
def selected(monkeypatch, tmp_path):
    binary = tmp_path / "nginx"
    binary.write_bytes(b"\x7fELF")
    modules, calls, outputs = [], [], {}

    def probe(argv, **kwargs):
        assert argv[:2] == ["nm", "-P"]
        assert kwargs == {"capture_output": True, "text": True, "timeout": 10}
        key = (Path(argv[-1]), tuple(argv[2:-1]))
        calls.append(key)
        output = outputs.get(key, "")
        if isinstance(output, BaseException):
            raise output
        if isinstance(output, tuple):
            return SimpleNamespace(returncode=output[0], stdout=output[1], stderr=output[2])
        return SimpleNamespace(returncode=0, stdout=output, stderr="")

    monkeypatch.setitem(sys.modules, "brix_suite.nginx_tools", SimpleNamespace(
        _nginx_bin=lambda: str(binary)))
    monkeypatch.setitem(sys.modules, "cmdscripts.live_common", SimpleNamespace(
        _configured_nginx_modules=lambda: list(modules)))
    monkeypatch.setattr(subject.subprocess, "run", probe)
    return SimpleNamespace(binary=binary, modules=modules, calls=calls,
                           outputs=outputs, directory=tmp_path)


def _module(case, name="selected.so", magic=b"\x7fELF"):
    path = case.directory / name
    path.write_bytes(magic)
    case.modules.append(str(path))
    return path


@pytest.mark.parametrize("symbol", ["brix_acc_access", "brix_baq_enqueue",
                                   "brix_baq_reconcile", "brix_chkpoint_recover_root"])
def test_static_executable_defined_symbol_is_available(selected, symbol):
    selected.outputs[selected.binary, ()] = f"{symbol} T abc 10\n"
    assert subject.nginx_has_symbol(symbol)
    assert selected.calls == [(selected.binary, ())]


def test_dynamic_table_of_only_configured_module_enables_capability(selected):
    module = _module(selected)
    selected.outputs[module, ("-D",)] = "brix_acc_access T 1 10\n"
    assert subject.nginx_has_symbol("brix_acc_access")
    assert selected.calls == [(selected.binary, ()), (selected.binary, ("-D",)),
                              (module, ()), (module, ("-D",))]


@pytest.mark.parametrize("magic", [b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe",
                                 b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe",
                                 b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca",
                                 b"\xca\xfe\xba\xbf", b"\xbf\xba\xfe\xca"])
def test_macho_c_prefix_uses_only_portable_symbol_table(selected, magic):
    selected.binary.write_bytes(magic)
    selected.outputs[selected.binary, ()] = "_brix_acc_access T 1 10\n"
    assert subject.nginx_has_symbol("brix_acc_access")
    assert selected.calls == [(selected.binary, ())]
    selected.calls.clear()
    selected.outputs[selected.binary, ()] = ""
    assert not subject.nginx_has_symbol("brix_acc_access")
    assert selected.calls == [(selected.binary, ())]


@pytest.mark.parametrize("row", ["brix_acc_access U", "brix_acc_access U 0",
                               "brix_acc_access w", "brix_acc_access v 0",
                               "brix_acc_access ? 0", "brix_acc_access T invalid",
                               "brix_acc_access TT 1", "brix_acc_access_extra T 1",
                               "prefix_brix_acc_access T 1", "_brix_acc_access T 1"])
def test_undefined_malformed_or_substring_symbols_do_not_enable(selected, row):
    selected.outputs[selected.binary, ()] = row
    selected.outputs[selected.binary, ("-D",)] = row
    assert not subject.nginx_has_symbol("brix_acc_access")


def test_unconfigured_object_cannot_enable_capability(selected):
    unrelated = selected.directory / "old-unselected.so"
    unrelated.write_bytes(b"\x7fELF")
    selected.outputs[unrelated, ()] = "brix_acc_access T 1\n"
    assert not subject.nginx_has_symbol("brix_acc_access")
    assert all(path == selected.binary for path, _mode in selected.calls)


def test_missing_binary_cannot_borrow_capability_from_a_module(selected):
    module = _module(selected)
    selected.outputs[module, ()] = "brix_acc_access T 1\n"
    selected.binary.unlink()
    assert not subject.nginx_has_symbol("brix_acc_access")
    assert selected.calls == []


def test_missing_configured_module_is_an_inspection_error(selected):
    module = _module(selected)
    module.unlink()
    with pytest.raises(RuntimeError, match="Cannot inspect selected nginx object"):
        subject.nginx_has_symbol("brix_acc_access")


@pytest.mark.parametrize("error", [FileNotFoundError("nm missing"),
                                 subprocess.TimeoutExpired("nm", 10)])
def test_probe_exception_is_propagated_as_an_error_not_skip_or_success(selected, error):
    selected.outputs[selected.binary, ()] = error
    with pytest.raises(RuntimeError, match="Cannot inspect selected nginx object") as raised:
        subject.nginx_has_symbol("brix_acc_access")
    assert raised.value.__cause__ is error


@pytest.mark.parametrize("dynamic_result", [(1, "brix_acc_access T 1", "broken metadata"),
                                           (0, "", "")])
def test_failed_probe_output_cannot_be_misreported_as_present_or_absent(selected, dynamic_result):
    selected.outputs[selected.binary, ()] = (1, "brix_acc_access T 1", "broken metadata")
    selected.outputs[selected.binary, ("-D",)] = dynamic_result
    with pytest.raises(RuntimeError, match="broken metadata"):
        subject.nginx_has_symbol("brix_acc_access")


def test_successful_dynamic_fallback_can_prove_a_defined_symbol(selected):
    selected.outputs[selected.binary, ()] = (1, "", "regular table unavailable")
    selected.outputs[selected.binary, ("-D",)] = "brix_acc_access T 1\n"
    assert subject.nginx_has_symbol("brix_acc_access")


def _source_function(filename, name):
    source = Path(__file__).with_name(filename)
    tree = ast.parse(source.read_text())
    function = next(node for node in tree.body
                    if isinstance(node, ast.FunctionDef) and node.name == name)
    return source, function


@pytest.mark.parametrize("filename,symbol", [
    ("test_acc_residual.py", "brix_acc_access"),
    ("test_backend_async_root.py", "brix_baq_enqueue"),
    ("test_backend_async_webdav.py", "brix_baq_enqueue"),
    ("test_backend_async_s3.py", "brix_baq_enqueue"),
    ("test_backend_async_reboot.py", "brix_baq_reconcile"),
    ("test_chkpoint_recover_export.py", "brix_chkpoint_recover_root"),
])
def test_existing_gate_propagates_shared_capability_result(filename, symbol):
    source, gate = _source_function(filename, "_have_nginx")
    calls = []
    namespace = {"nginx_has_symbol": lambda name: calls.append(name) or False}
    exec(compile(ast.Module(body=[gate], type_ignores=[]), str(source), "exec"), namespace)
    assert namespace["_have_nginx"]() is False
    assert calls == [symbol]


def test_acc_fixture_uses_selected_capability_before_creating_an_instance(tmp_path):
    source, fixture = _source_function("test_acc.py", "acc_server")
    calls = []
    namespace = {"pytest": pytest, "_have_tools": lambda: True,
                 "nginx_has_symbol": lambda name: calls.append(name) or False}
    exec(compile(ast.Module(body=[fixture], type_ignores=[]), str(source), "exec"), namespace)
    with pytest.raises(pytest.skip.Exception, match="selected nginx build lacks the xrdacc engine"):
        namespace["acc_server"].__wrapped__(None, tmp_path)
    assert calls == ["brix_acc_access"]
    assert list(tmp_path.iterdir()) == []
