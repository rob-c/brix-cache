"""VOMS native drivers must preserve the selected archive's external SDK."""

import subprocess
import os

import pytest

import test_credinfo_voms_unit as unit
import _test_voms_corner_helpers as corner


def _make_result(monkeypatch, returncode=0):
    result = subprocess.CompletedProcess([], returncode,
        'ALL_CFLAGS := -Ilib -I"/selected sdk/include" -DBRIX_HAVE_LIBURING\n'
        'LDLIBS := -L/unselected/sdk -luring\n', "fixture build failure")
    monkeypatch.setattr(unit, "client_make", lambda *args, **kwargs: result)


def test_voms_native_driver_keeps_selected_sdk_runtime_paths(monkeypatch):
    """Static consumers get link search paths and rpaths from canonical metadata."""
    _make_result(monkeypatch)
    flags = ["-L/selected/sdk", "-Wl,-rpath,/selected/sdk", "-luring", "-pthread"]
    monkeypatch.setattr(unit, "client_static_dependency_flags", lambda _: flags)
    cflags, ldlibs = unit._client_make_flags()
    assert "-I/selected sdk/include" in cflags
    assert ldlibs == flags
    assert "-L/unselected/sdk" not in ldlibs


def test_voms_native_driver_propagates_metadata_errors(monkeypatch):
    """A broken external SDK is a failure, not a silently reduced feature set."""
    _make_result(monkeypatch)

    def broken(_):
        raise subprocess.CalledProcessError(1, ["pkg-config"], stderr="bad SDK")

    monkeypatch.setattr(unit, "client_static_dependency_flags", broken)
    with pytest.raises(subprocess.CalledProcessError):
        unit._client_make_flags()


def test_failed_make_cannot_supply_plausible_but_untrusted_flags(monkeypatch):
    """Never compile against partial output from a failed build-graph query."""
    _make_result(monkeypatch, returncode=2)
    with pytest.raises(subprocess.CalledProcessError):
        unit._client_make_flags()


def test_voms_corner_harness_includes_the_real_crypto_compatibility_owner(monkeypatch):
    """OpenSSL 1/3 identity rendering has a shared src header on every host."""
    commands = []
    monkeypatch.setattr(corner, 'openssl_compile_args', lambda arguments: arguments)
    monkeypatch.setattr(corner, '_run', lambda arguments: commands.append(arguments))
    assert corner.build_harness('/fixture/verdict') == '/fixture/verdict'
    command = commands[0]
    assert command[command.index('-I') + 1] == os.path.join(corner.REPO, 'shared')
    assert os.path.join(corner.REPO, 'src') in command
    assert '-lcrypto' in command


def test_voms_corner_harness_compile_errors_are_never_skipped(monkeypatch):
    """A missing compatibility header is an error, not absent VOMS coverage."""
    def broken(arguments):
        raise subprocess.CalledProcessError(1, arguments, stderr='missing name_compat.h')

    monkeypatch.setattr(corner, '_run', broken)
    with pytest.raises(subprocess.CalledProcessError):
        corner.build_harness('/fixture/verdict')


def test_voms_corner_harness_output_path_remains_a_literal_argument(monkeypatch):
    """Security-negative: the compile wrapper never evaluates output path syntax."""
    commands = []
    monkeypatch.setattr(corner, 'openssl_compile_args', lambda arguments: arguments)
    monkeypatch.setattr(corner, '_run', lambda arguments: commands.append(arguments))
    output = '/fixture space/verdict; echo SHOULD_NOT_EXECUTE'
    corner.build_harness(output)
    assert commands[0][-2:] == ['-o', output]
