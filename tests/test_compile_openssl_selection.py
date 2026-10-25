"""Standalone C tests must honor the selected parallel or keg-only OpenSSL SDK."""

import subprocess

import pytest

from cmdscripts import compile_run


def test_selected_sdk_supplies_headers_and_libraries_together(monkeypatch):
    monkeypatch.setattr(compile_run.shutil, "which", lambda _: "/bin/pkg-config")
    monkeypatch.setattr(compile_run, "run", lambda args: subprocess.CompletedProcess(
        args, 0, '-I/sdk/include -L/sdk/lib -lssl -lcrypto\n', ""))
    assert compile_run.openssl_compile_args(["unit.c", "-lcrypto", "-lz"]) == [
        "unit.c", "-lz", "-I/sdk/include", "-L/sdk/lib", "-lssl", "-lcrypto"]


def test_missing_metadata_preserves_the_compile_dependency(monkeypatch):
    monkeypatch.setattr(compile_run.shutil, "which", lambda _: "/bin/pkg-config")
    monkeypatch.setattr(compile_run, "run", lambda args: subprocess.CompletedProcess(
        args, 1, "", "no package"))
    assert compile_run.openssl_compile_args(["unit.c", "-lcrypto"]) == ["unit.c", "-lcrypto"]


def test_non_crypto_unit_cannot_gain_an_unrequested_dependency(monkeypatch):
    def forbidden(*args):
        raise AssertionError("unrelated unit must not query or link OpenSSL")
    monkeypatch.setattr(compile_run, "run", forbidden)
    assert compile_run.openssl_compile_args(["unit.c", "-lm"]) == ["unit.c", "-lm"]


@pytest.mark.parametrize("library,package", [
    ("-lsqlite3", "sqlite3"), ("-lzstd", "libzstd"), ("-lcurl", "libcurl"),
    ("-ljansson", "jansson"), ("-lxml2", "libxml-2.0"), ("-llz4", "liblz4"),
    ("-lepoll-shim", "epoll-shim"),
])
def test_native_dependency_headers_and_libraries_share_the_selected_sdk(
        monkeypatch, library, package):
    queried = []

    def probe(arguments):
        queried.append(arguments)
        return subprocess.CompletedProcess(arguments, 0,
            '-I"/native sdk/include" -L"/native sdk/lib" ' + library, "")

    monkeypatch.setattr(compile_run.shutil, "which", lambda _: "/bin/pkg-config")
    monkeypatch.setattr(compile_run, "run", probe)
    assert compile_run.library_compile_args(["unit.c", library]) == [
        "unit.c", "-I/native sdk/include", "-L/native sdk/lib", library]
    assert queried == [["pkg-config", "--cflags", "--libs", package]]


@pytest.mark.parametrize("code,flags", [(1, ""), (0, "")])
def test_failed_or_empty_metadata_cannot_remove_a_required_library(monkeypatch, code, flags):
    monkeypatch.setattr(compile_run.shutil, "which", lambda _: "/bin/pkg-config")
    monkeypatch.setattr(compile_run, "run", lambda args: subprocess.CompletedProcess(
        args, code, flags, "unusable metadata"))
    assert compile_run.library_compile_args(["unit.c", "-lsqlite3"]) == ["unit.c", "-lsqlite3"]


def test_system_unit_cannot_gain_unrequested_external_dependencies(monkeypatch):
    def forbidden(*args):
        raise AssertionError("a system-only unit must not select external SDKs")

    monkeypatch.setattr(compile_run, "run", forbidden)
    assert compile_run.library_compile_args(["unit.c", "-lm"]) == ["unit.c", "-lm"]


@pytest.mark.parametrize("host,source,required", [
    ("freebsd15", "client/probe.c", True), ("freebsd15", "src/probe.c", False),
    ("darwin", "client/probe.c", False), ("linux", "client/probe.c", False),
])
def test_client_shim_requirement_is_native_and_does_not_leak_to_other_hosts(
        host, source, required):
    arguments = compile_run._client_platform_args([source], host)
    assert ("-lepoll-shim" in arguments) == required
