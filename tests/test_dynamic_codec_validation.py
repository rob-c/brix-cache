"""Dynamic builds check native dependencies and load the actual module set."""

import subprocess

import pytest

from cmdscripts import operator_build as build


@pytest.fixture(params=["darwin", "linux"])
def validation(monkeypatch, tmp_path, request):
    monkeypatch.setattr(build.sys, "platform", request.param)
    objects = tmp_path / "objs"
    objects.mkdir()
    for name in ("ngx_stream_module.so", "ngx_stream_brix_module.so",
                 "ngx_http_brix_xrdhttp_filter_module.so", "nginx"):
        (objects / name).touch()
    state = {"inspect_rc": 0, "load_rc": 0, "ldd_rc": 0,
             "dependencies": "libz.so.1 libz.1.dylib libzstd liblzma libbrotlienc libbrotlidec libbz2 liblz4"}
    calls = []

    def run(argv, **_kwargs):
        calls.append(argv)
        if argv[0] in ("readelf", "otool"):
            return subprocess.CompletedProcess(argv, state["inspect_rc"], state["dependencies"], "")
        if argv[0] == "ldd":
            return subprocess.CompletedProcess(argv, state["ldd_rc"], "", "")
        return subprocess.CompletedProcess(argv, state["load_rc"], "", "load failed")

    monkeypatch.setattr(build, "run", run)
    return tmp_path, state, calls


def test_complete_dependencies_are_actually_loaded(validation):
    root, _state, calls = validation
    assert build._validate_dynamic(root) is None
    assert calls[-1][0] == str(root / "objs/nginx") and "-t" in calls[-1]


def test_failed_dependency_inspection_is_not_a_pass(validation):
    root, state, calls = validation
    state["inspect_rc"] = 1
    result = build._validate_dynamic(root)
    assert result is not None and not result[0]
    assert len(calls) == 1


def test_missing_lz4_cannot_pass_the_codec_gate(validation):
    root, state, _calls = validation
    state["dependencies"] = state["dependencies"].replace("liblz4", "")
    result = build._validate_dynamic(root)
    assert result is not None and not result[0] and "liblz4" in result[1]


def test_a_missing_filter_module_is_rejected(validation):
    root, _state, _calls = validation
    (root / "objs/ngx_http_brix_xrdhttp_filter_module.so").unlink()
    result = build._validate_dynamic(root)
    assert result is not None and not result[0] and "module missing" in result[1]


def test_unresolved_load_is_not_an_unavailable_feature_skip(validation):
    root, state, _calls = validation
    state["load_rc"] = 1
    result = build._validate_dynamic(root)
    assert result is not None and not result[0] and "load failed" in result[1]


def test_drop_matrix_uses_the_shared_native_sdk_selector(monkeypatch):
    import test_compression_build_matrix as matrix

    monkeypatch.delenv('BRIX_LZ4_CFLAGS', raising=False)
    monkeypatch.delenv('BRIX_LZ4_LIBS', raising=False)
    calls = []
    monkeypatch.setattr(matrix, 'library_compile_args',
                        lambda args: calls.append(args) or ['-I/selected/include', *args])
    assert matrix._codec_link_flags('brotli', ['-lbrotlienc']) == [
        '-I/selected/include', '-lbrotlienc']
    assert calls == [['-lbrotlienc']]


@pytest.mark.parametrize('message', ['missing header', 'undefined symbol', 'syntax error'])
def test_drop_probe_compile_errors_cannot_become_skips(monkeypatch, tmp_path, message):
    import test_compression_build_matrix as matrix

    monkeypatch.setattr(matrix, '_require_source', lambda *args: None)
    monkeypatch.setattr(matrix, '_drop_build_inputs', lambda *args: (['cc'], ['-lz'], []))
    monkeypatch.setattr(matrix.subprocess, 'run', lambda args, **kwargs:
                        subprocess.CompletedProcess(args, 1, '', message))
    with pytest.raises(pytest.fail.Exception, match=message):
        matrix.test_codec_per_codec_drop_independence(tmp_path, 'zstd')


def test_explicit_lz4_selection_never_borrows_a_foreign_prefix(monkeypatch):
    import test_compression_build_matrix as matrix

    monkeypatch.setenv('BRIX_LZ4_CFLAGS', '-I"/chosen sdk/include"')
    monkeypatch.delenv('BRIX_LZ4_LIBS', raising=False)

    def foreign(_arguments):
        pytest.fail('explicit LZ4 selection must not query another SDK')

    monkeypatch.setattr(matrix, 'library_compile_args', foreign)
    assert matrix._codec_link_flags('lz4', ['/chosen/liblz4.a']) == [
        '-I/chosen sdk/include', '/chosen/liblz4.a']
