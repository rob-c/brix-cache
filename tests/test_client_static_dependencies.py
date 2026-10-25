"""In-tree consumers use the same selected external SDKs as installed clients."""

import subprocess

import pytest

from lib_py import client_toolchain as toolchain
from cmdscripts import brixcvmfs_live as cvmfs
from cmdscripts import compile_run
from cmdscripts import pblock_live as pblock
from types import SimpleNamespace


def test_static_metadata_preserves_sdk_runtime_paths_and_pthread(monkeypatch, tmp_path):
    calls = []
    monkeypatch.setattr(toolchain, "client_make", lambda *args, **kwargs:
                        subprocess.CompletedProcess(args, 0))

    def query(command, **kwargs):
        calls.append((command, kwargs))
        return subprocess.CompletedProcess(command, 0,
            f"-L{tmp_path} -lbrix -lxrdproto -lbrix -L/opt/sdk/lib -luring "
            "-pthread -Wl,-rpath,/opt/sdk/lib")

    monkeypatch.setattr(toolchain.subprocess, "run", query)
    assert toolchain.client_static_dependency_flags(tmp_path) == [
        "-L/opt/sdk/lib", "-luring", "-pthread", "-Wl,-rpath,/opt/sdk/lib"]
    assert "--define-variable=libdir=" + str(tmp_path) in calls[0][0]


def test_failed_metadata_build_cannot_be_treated_as_optional(monkeypatch, tmp_path):
    monkeypatch.setattr(toolchain, "client_make", lambda *args, **kwargs:
                        subprocess.CompletedProcess(args, 1, "", "bad SDK"))
    with pytest.raises(subprocess.CalledProcessError):
        toolchain.client_static_dependency_flags(tmp_path)


def test_failed_pkgconfig_query_cannot_silently_drop_dependencies(monkeypatch, tmp_path):
    monkeypatch.setattr(toolchain, "client_make", lambda *args, **kwargs:
                        subprocess.CompletedProcess(args, 0))

    def broken(command, **kwargs):
        assert kwargs["check"] is True
        raise subprocess.CalledProcessError(1, command, stderr="missing metadata")

    monkeypatch.setattr(toolchain.subprocess, "run", broken)
    with pytest.raises(subprocess.CalledProcessError):
        toolchain.client_static_dependency_flags(tmp_path)


@pytest.mark.parametrize("flags,expected", [
    ('-L"/selected/sdk with space/lib" -Wl,-rpath,/selected/sdk/lib',
     ["-L/selected/sdk with space/lib", "-Wl,-rpath,/selected/sdk/lib"]),
    ("-Wl,-z,relro -Wl,-z,now", ["-Wl,-z,relro", "-Wl,-z,now"]),
    ("", []),
])
def test_live_consumers_keep_explicit_link_flags_before_system_search_paths(
        monkeypatch, tmp_path, flags, expected):
    calls = []
    monkeypatch.setenv("LDFLAGS", flags)
    monkeypatch.setattr(compile_run, "openssl_compile_args", list)
    monkeypatch.setattr(cvmfs, "_gcov_flags", lambda _: [])
    run = SimpleNamespace(call=lambda command, **kwargs: calls.append(command))
    output = tmp_path / "consumer"
    assert cvmfs._gcc(run, output, ["input.c", "-L/usr/lib", "-luring"]) == output
    assert calls == [["gcc", *expected, "input.c", "-L/usr/lib", "-luring", "-o", output]]


@pytest.mark.parametrize('returncode', [0, 1])
def test_pblock_benchmark_uses_the_archives_selected_dependency_graph(
        monkeypatch, tmp_path, returncode):
    """Use recorded SDK/runtime flags; build failure must remain a failure."""
    calls = []
    flags = ['-L/selected/lib', '-luring', '-Wl,-rpath,/selected/lib']
    monkeypatch.setattr(pblock, 'client_static_dependency_flags', lambda _: flags)
    monkeypatch.setattr(pblock, '_gcov_flags', lambda _: [])

    def call(command, **kwargs):
        calls.append(command)
        return SimpleNamespace(returncode=returncode, stderr='native link failed')

    run = SimpleNamespace(root=tmp_path, call=call)
    if returncode:
        with pytest.raises(pblock.LiveFailure, match='native link failed'):
            pblock._build_meta_bench(run)
    else:
        assert pblock._build_meta_bench(run) == tmp_path / 'pblock_meta_bench'
    command = calls[0]
    index = command.index(flags[0])
    assert command[index:index + len(flags)] == flags
    assert command.count('-luring') == 1


def test_pblock_benchmark_does_not_hide_failed_dependency_discovery(monkeypatch, tmp_path):
    """Missing SDK metadata cannot fall back to an incompatible system library."""
    def missing(_):
        raise subprocess.CalledProcessError(1, ['pkg-config'])

    monkeypatch.setattr(pblock, 'client_static_dependency_flags', missing)
    run = SimpleNamespace(root=tmp_path, call=lambda *args, **kwargs: pytest.fail('must not compile'))
    with pytest.raises(subprocess.CalledProcessError):
        pblock._build_meta_bench(run)


def test_cli_hint_probe_links_only_the_archives_selected_dependencies(monkeypatch):
    """Success: FreeBSD may not acquire an unbuilt Linux io_uring dependency."""
    import _test_cli_hints_helpers as hints

    selected = ['-L/selected/lib', '-lcrypto', '-pthread', '-Wl,-rpath,/selected/lib']
    monkeypatch.setattr(hints, 'client_static_dependency_flags', lambda _: selected)
    assert hints._probe_link_libraries() == selected
    assert '-luring' not in hints._probe_link_libraries()


def test_cli_hint_probe_link_failure_is_not_a_skip(monkeypatch, tmp_path):
    """Error: a real compilation failure must stay visible in full-suite totals."""
    import _test_cli_hints_helpers as hints

    monkeypatch.setattr(hints, '_require_suggest_inputs', lambda *args: None)
    monkeypatch.setattr(hints, '_probe_link_libraries', lambda: [])
    monkeypatch.setattr(hints.subprocess, 'run', lambda *args, **options:
                        subprocess.CompletedProcess(args, 1, '', 'missing native dependency'))
    with pytest.raises(AssertionError, match='missing native dependency'):
        hints._compile_suggest_probe(tmp_path)


def test_cli_hint_probe_never_falls_back_after_metadata_failure(monkeypatch):
    """Security-negative: never link against an unrelated implicit SDK graph."""
    import _test_cli_hints_helpers as hints

    def missing(_):
        raise subprocess.CalledProcessError(1, ['pkg-config'], stderr='unselected SDK')

    monkeypatch.setattr(hints, 'client_static_dependency_flags', missing)
    with pytest.raises(subprocess.CalledProcessError):
        hints._probe_link_libraries()


@pytest.mark.parametrize('adapter', [[], ['src/platform/freebsd/xattr_wrapper.c']])
def test_standalone_cvmfs_links_native_xattr_owner_once(monkeypatch, adapter):
    monkeypatch.setattr(cvmfs, 'client_pal_host_sources', lambda *args: ['client-pal.c'])
    monkeypatch.setattr(cvmfs, 'pal_xattr_sources', lambda: adapter)
    sources = list(adapter)
    defines, archives, libraries = cvmfs._link_dependencies(None, [], sources)
    assert defines == ['-DXRDPROTO_NO_NGX'] and archives == libraries == []
    assert sources.count('client-pal.c') == 1
    assert sources.count('src/platform/freebsd/xattr_wrapper.c') == len(adapter)


def test_umbrella_keeps_xattr_owner_in_its_archive_not_a_duplicate_body(monkeypatch):
    expected = (['archive-mode'], ['client.a'], ['sdk-lib'])
    monkeypatch.setattr(cvmfs, '_prepare_umbrella_dependencies', lambda *args: expected)
    monkeypatch.setattr(cvmfs, 'pal_xattr_sources', lambda: pytest.fail('duplicate PAL owner'))
    assert cvmfs._link_dependencies(['client/apps/fs/brixmount.c'], [], []) == expected


def test_standalone_xattr_dependency_failure_is_not_silently_omitted(monkeypatch):
    def missing():
        raise RuntimeError('injected native adapter lookup failure')

    monkeypatch.setattr(cvmfs, 'pal_xattr_sources', missing)
    with pytest.raises(RuntimeError, match='native adapter lookup failure'):
        cvmfs._link_dependencies(None, [], [])


@pytest.mark.parametrize('sources,expected', [
    ([], []),
    (['src/platform/freebsd/xattr_wrapper.c'], ['selected-host/xattr_wrapper.o']),
])
def test_object_xattr_closure_uses_the_source_owners_native_addon(monkeypatch, tmp_path,
                                                              sources, expected):
    """Source- and object-linked tools cannot disagree about the required PAL."""
    monkeypatch.setattr(compile_run, 'pal_xattr_sources', lambda: sources)
    monkeypatch.setattr(compile_run, 'pal_host_addon', lambda name: f'selected-host/{name}.o')
    assert compile_run.pal_xattr_addons(tmp_path) == [tmp_path / path for path in expected]


def test_object_xattr_discovery_failure_is_not_a_libc_fallback(monkeypatch, tmp_path):
    """An unknown adapter selection remains a build error, never reduced coverage."""
    def missing():
        raise RuntimeError('native xattr selection failed')

    monkeypatch.setattr(compile_run, 'pal_xattr_sources', missing)
    with pytest.raises(RuntimeError, match='native xattr selection failed'):
        compile_run.pal_xattr_addons(tmp_path)


@pytest.mark.parametrize('library,package', [
    ('-lbrotlienc', 'libbrotlienc'), ('-lbrotlidec', 'libbrotlidec'),
    ('-lbrotlicommon', 'libbrotlicommon'), ('-l:liblz4.so.1', 'liblz4'),
])
def test_codec_units_select_headers_and_link_flags_from_one_sdk(monkeypatch, library, package):
    calls = []
    monkeypatch.setattr(compile_run.shutil, 'which', lambda _: '/usr/local/bin/pkg-config')

    def query(arguments):
        calls.append(arguments)
        return subprocess.CompletedProcess(arguments, 0, '-I/selected/include -L/selected/lib -lcodec')

    monkeypatch.setattr(compile_run, 'run', query)
    flags = compile_run.library_compile_args([library])
    assert calls == [['pkg-config', '--cflags', '--libs', package]]
    assert flags == ['-I/selected/include', '-L/selected/lib', '-lcodec']


def test_missing_codec_metadata_keeps_the_link_requirement(monkeypatch):
    monkeypatch.setattr(compile_run.shutil, 'which', lambda _: '/usr/local/bin/pkg-config')
    monkeypatch.setattr(compile_run, 'run', lambda args:
                        subprocess.CompletedProcess(args, 1, '', 'missing SDK'))
    assert compile_run.library_compile_args(['input.c', '-lbrotlienc']) == ['input.c', '-lbrotlienc']


def test_object_unit_compiler_failure_is_preserved_with_selected_sdk(monkeypatch):
    from cmdscripts import c_regression_units as units

    monkeypatch.setattr(units, 'library_compile_args', lambda args: [*args, '-L/selected/lib'])
    failure = subprocess.CompletedProcess(['cc'], 1, '', 'bad selected SDK')
    monkeypatch.setattr(units, 'run', lambda args, **kw: failure)
    assert units._cc(['-lcodec']) is failure


@pytest.mark.parametrize('host,names,expected', [
    ('darwin', ['posix_wrapper'], ['-framework', 'Security']),
    ('darwin', ['storage_wrapper'], []), ('freebsd', ['posix_wrapper'], []),
    ('linux', ['posix_wrapper'], []),
])
def test_platform_source_unit_declares_only_its_native_link_dependencies(
        monkeypatch, host, names, expected):
    monkeypatch.setattr(compile_run, 'platform_host_name', lambda: host)
    assert compile_run.pal_host_libraries(*names) == expected


@pytest.mark.parametrize('host,expected', [
    ('linux', ['shared/cvmfs/platform/platform.c']),
    ('freebsd', ['shared/cvmfs/platform/platform.c']), ('darwin', []), ('windows', []),
])
def test_module_platform_owns_shared_descriptor_symbols_once(monkeypatch, host, expected):
    monkeypatch.setattr(compile_run, 'platform_host_name', lambda: host)
    assert compile_run.module_shared_platform_sources() == expected
