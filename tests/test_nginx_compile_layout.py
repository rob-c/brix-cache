"""Compile tests must run against the selected SDK on every build layout."""

import pytest
import subprocess
from types import SimpleNamespace

from lib_py import nginx_build
from lib_py.nginx_build import configured_compile_layout, native_test_link_flags


@pytest.mark.parametrize("style", ["cmake", "source", "objects"])
def test_supported_layouts_keep_relative_includes_in_the_source_tree(tmp_path, style):
    """CMake, Nix SDK, and Homebrew objects expose usable compile metadata."""
    source = tmp_path / "nginx-src"
    source.mkdir()
    build = tmp_path
    if style == "cmake":
        makefile, cwd = build / "modules/Makefile", source
    else:
        makefile, cwd = source / "objs/Makefile", source
        build = source if style == "source" else source / "objs"
    makefile.parent.mkdir(exist_ok=True)
    makefile.touch()
    environment = {"BRIX_NGINX_BUILD_DIR": str(build), "TEST_NGINX_SRC": str(source)}
    assert configured_compile_layout(tmp_path, environment) == (makefile, cwd)


def test_source_only_override_can_select_a_complete_sdk(tmp_path):
    """The existing source override suffices without a CMake build variable."""
    makefile = tmp_path / "objs/Makefile"
    makefile.parent.mkdir()
    makefile.touch()
    assert configured_compile_layout(tmp_path, {"NGX_SRC": str(tmp_path)}) == (makefile, tmp_path)


def test_explicit_missing_build_cannot_fall_back_to_an_unrelated_sdk(tmp_path):
    """Security-negative: never manufacture evidence from another build."""
    makefile = tmp_path / "objs/Makefile"
    makefile.parent.mkdir()
    makefile.touch()
    environment = {"BRIX_NGINX_BUILD_DIR": str(tmp_path / "missing"),
                   "TEST_NGINX_SRC": str(tmp_path)}
    assert configured_compile_layout(tmp_path, environment) is None


def test_missing_compiler_working_directory_is_not_accepted(tmp_path):
    """A partial CMake SDK must report its missing source directory."""
    makefile = tmp_path / "modules/Makefile"
    makefile.parent.mkdir()
    makefile.touch()
    assert configured_compile_layout(tmp_path, {"BRIX_NGINX_BUILD_DIR": str(tmp_path)}) is None


def test_darwin_linker_operations_retain_dead_strip_and_the_clock_substitute():
    assert native_test_link_flags(["-Wl,--gc-sections", "-Wl,--wrap=time"], "darwin") == [
        "-Wl,-dead_strip", "-Dtime=__wrap_time"]


def test_linux_linker_operations_are_unchanged():
    flags = ["-Wl,--gc-sections", "-Wl,--wrap=time"]
    assert native_test_link_flags(flags, "linux") == flags


def test_unsupported_linker_interposition_is_not_silently_removed():
    flags = ["-Wl,--wrap=socket", "-lcrypto"]
    assert native_test_link_flags(flags, "darwin") == flags


def test_selected_dependency_keeps_headers_libraries_and_runtime_together(monkeypatch):
    outputs = {"--cflags": "-I/selected/include", "--libs": "-L/selected/lib -luring"}
    monkeypatch.setattr(nginx_build.subprocess, "run", lambda command, **options:
                        SimpleNamespace(stdout=outputs[command[1]]))
    assert nginx_build.selected_native_dependency("liburing") == (
        ["-I/selected/include"],
        ["-L/selected/lib", "-luring", "-Wl,-rpath,/selected/lib"])


def test_failed_dependency_selection_cannot_fall_back_to_system_headers(monkeypatch):
    def failed(command, **options):
        raise subprocess.CalledProcessError(1, command)

    monkeypatch.setattr(nginx_build.subprocess, "run", failed)
    with pytest.raises(subprocess.CalledProcessError):
        nginx_build.native_test_sdk_flags(["-luring"])


def test_unrelated_native_units_do_not_discover_an_optional_sdk(monkeypatch):
    def unexpected(name):
        pytest.fail('unrelated unit tried to resolve ' + name)

    monkeypatch.setattr(nginx_build, "selected_native_dependency", unexpected)
    assert nginx_build.native_test_sdk_flags(["-lm"]) == ([], ["-lm"])


def _configured_sdk_makefile(root, cflags):
    """Model generated compiler metadata rather than an installed header tree."""
    makefile = root / 'Makefile'
    makefile.write_text('CC = cc\nCFLAGS = ' + cflags + '\nALL_INCS = -Isrc/core\n')
    return makefile


def test_object_units_keep_selected_sdk_dependency_includes(tmp_path, monkeypatch):
    """Success: PCRE and other keg/prefix headers follow the configured SDK."""
    from cmdscripts import object_unit_layout as layout

    sdk = tmp_path / 'modules'
    sdk.mkdir()
    source = tmp_path / 'nginx-src'
    source.mkdir()
    _configured_sdk_makefile(sdk, '-O2 -I"/selected sdk/include" -isystem deps/include')
    monkeypatch.setattr(layout, 'OBJS', sdk)
    monkeypatch.setattr(layout, 'NGX_SRC', source)
    assert layout._inc('/unit/include') == (
        '-I', '/unit/include', '-I', '/selected sdk/include',
        '-isystem', str(source / 'deps/include'))


def test_incomplete_sdk_compile_metadata_is_an_error(tmp_path):
    """Error: a partial SDK cannot look like a complete native compile graph."""
    makefile = tmp_path / 'Makefile'
    makefile.write_text('CC = cc\nALL_INCS = -Isrc/core\n')
    with pytest.raises(ValueError, match='Missing CFLAGS'):
        nginx_build.configured_dependency_includes(makefile, tmp_path)


@pytest.mark.parametrize('flags', ['-O2 -I', '-isystem -DSECURITY_CHECK=0'])
def test_malformed_sdk_include_cannot_consume_the_next_option(tmp_path, flags):
    """Security-negative: do not reinterpret an option as an include path."""
    makefile = _configured_sdk_makefile(tmp_path, flags)
    with pytest.raises(ValueError, match='Missing include path'):
        nginx_build.configured_dependency_includes(makefile, tmp_path)


def test_unit_instrumentation_is_not_replaced_by_sdk_build_options(tmp_path):
    """Only dependency include operands transfer; sanitizers remain caller-owned."""
    makefile = _configured_sdk_makefile(tmp_path, '-O3 -fno-sanitize=all -I/selected/include')
    assert nginx_build.configured_dependency_includes(makefile, tmp_path) == [
        '-I', '/selected/include']


def test_missing_explicit_dependency_metadata_never_borrows_another_sdk(tmp_path):
    """An unrelated Makefile in the working directory is never a fallback."""
    _configured_sdk_makefile(tmp_path, '-I/foreign/include')
    assert nginx_build.configured_dependency_includes(tmp_path / 'missing/Makefile',
                                                     tmp_path) == []


def _completion_unit_sdk(tmp_path, monkeypatch, case):
    """Prepare only selected SDK metadata, including deliberately broken variants."""
    source, objects = tmp_path / 'nginx-src', tmp_path / 'modules'
    objects.mkdir()
    (objects / 'ngx_auto_config.h').touch()
    flags = '-O2 -I"/selected sdk/include"' if case == 'success' else '-isystem -DNO_CHECKS=1'
    makefile = _configured_sdk_makefile(objects, flags)
    if case == 'incomplete':
        makefile.write_text('CC = cc\nALL_INCS = -Isrc/core\n')
    monkeypatch.setenv('TEST_NGINX_SRC', str(source))
    monkeypatch.setenv('TEST_NGINX_BUILD_DIR', str(objects))
    return source


def _completion_include_function(consumer, source, monkeypatch):
    """Select the consumer without adding alternative header-discovery logic."""
    import importlib

    selected = importlib.import_module(consumer)
    if consumer == 'test_cache_registry_state':
        monkeypatch.setattr(selected, 'NGINX_SOURCE', source)
    name = {'test_cache_registry_state': '_include_flags',
            'test_pgwrite_completion': '_nginx_include_flags'}[consumer]
    return getattr(selected, name)


@pytest.mark.parametrize('consumer', ['test_cache_registry_state', 'test_pgwrite_completion'])
@pytest.mark.parametrize('case', ['success', 'incomplete', 'malformed'])
def test_production_completion_units_use_their_exact_sdk_dependencies(tmp_path, monkeypatch, consumer, case):
    """Retain prefix headers, reject partial SDKs, and never consume options as paths."""
    source = _completion_unit_sdk(tmp_path, monkeypatch, case)
    include_flags = _completion_include_function(consumer, source, monkeypatch)
    if case == 'success':
        assert include_flags()[-2:] == ['-I', '/selected sdk/include']
    else:
        with pytest.raises(ValueError, match='Missing'):
            include_flags()


@pytest.mark.parametrize('style', ['cmake', 'source'])
def test_regression_objects_follow_the_selected_generated_sdk(tmp_path, monkeypatch, style):
    """Object lookup and compile headers must refer to the exact same SDK."""
    from cmdscripts import c_regression_units as units

    source = tmp_path / 'nginx-src'
    source.mkdir()
    objects = tmp_path / 'modules' if style == 'cmake' else source / 'objs'
    target = objects / 'addon/posix/sd_posix_ns.o'
    target.parent.mkdir(parents=True)
    target.touch()
    monkeypatch.setenv('TEST_NGINX_OBJS', str(objects))
    assert units._need_obj(source, 'objs/addon/posix/sd_posix_ns.o') == target
    assert units._find_obj(source, 'sd_posix_ns.o') == target


def test_missing_selected_object_cannot_borrow_a_source_tree_object(tmp_path, monkeypatch):
    """Security-negative: another SDK's object cannot manufacture a pass."""
    from cmdscripts import c_regression_units as units

    foreign = tmp_path / 'objs/addon/posix/sd_posix_ns.o'
    foreign.parent.mkdir(parents=True)
    foreign.touch()
    monkeypatch.setenv('TEST_NGINX_OBJS', str(tmp_path / 'missing'))
    assert isinstance(units._need_obj(tmp_path, 'objs/addon/posix/sd_posix_ns.o'), str)
    assert units._find_obj(tmp_path, 'sd_posix_ns.o') is None


def test_object_unit_feature_layout_matches_the_selected_sdk(tmp_path, monkeypatch):
    """Conditional metrics fields must match the actual object ABI, not defaults."""
    from cmdscripts import c_regression_units as units

    selected = tmp_path / 'modules'
    selected.mkdir()
    (selected / 'Makefile').write_text('CFLAGS = -DBRIX_HAVE_CEPH=1 -DBRIX_HAVE_ZSTD=1\n')
    monkeypatch.setenv('TEST_NGINX_OBJS', str(selected))
    assert units._brix_have_defines(tmp_path) == ['-DBRIX_HAVE_CEPH=1', '-DBRIX_HAVE_ZSTD=1']


def test_absent_feature_metadata_cannot_borrow_a_foreign_source_tree(tmp_path, monkeypatch):
    """An unselected source tree's feature flags must not change a unit's ABI."""
    from cmdscripts import c_regression_units as units

    foreign = tmp_path / 'objs'
    foreign.mkdir()
    (foreign / 'Makefile').write_text('CFLAGS = -DBRIX_HAVE_FOREIGN=1\n')
    monkeypatch.setenv('TEST_NGINX_OBJS', str(tmp_path / 'missing'))
    assert units._brix_have_defines(tmp_path) == []


@pytest.mark.parametrize('ok,message,exception', [
    (True, 'ALL PASS', None),
    (False, 'compile failed', AssertionError),
    (True, 'SKIP: selected object is absent', pytest.skip.Exception),
])
def test_regression_reporting_cannot_count_an_unbuilt_unit_as_passed(
        monkeypatch, tmp_path, ok, message, exception):
    """Successful execution, real failure and unavailability remain distinct."""
    import test_c_regression_units as suite

    monkeypatch.setattr(suite, 'run_checks', lambda *args: [(ok, message)])
    if exception is None:
        suite.test_c_regression_shell_port(tmp_path, 'probe')
    else:
        with pytest.raises(exception):
            suite.test_c_regression_shell_port(tmp_path, 'probe')


def test_dependency_flags_preserve_quoted_paths_and_never_inject_shell(monkeypatch):
    calls = []

    def selected(command, **options):
        calls.append((command, options))
        return SimpleNamespace(stdout='-I"/selected/sdk include"' if command[1] ==
                               "--cflags" else '-L"/selected/sdk lib" -luring')

    monkeypatch.setattr(nginx_build.subprocess, "run", selected)
    includes, libraries = nginx_build.selected_native_dependency("liburing")
    assert includes == ["-I/selected/sdk include"]
    assert libraries[-1] == "-Wl,-rpath,/selected/sdk lib"
    assert all(options.get("shell") is not True for _, options in calls)


@pytest.mark.parametrize("variable", ["TEST_NGINX_SRC", "NGX_SRC", "NGINX_SRC"])
def test_dns_units_honor_each_supported_explicit_sdk(monkeypatch, tmp_path, variable):
    from cmdscripts import c_regression_units as units
    for name in ("TEST_NGINX_SRC", "NGX_SRC", "NGINX_SRC"):
        monkeypatch.delenv(name, raising=False)
    # An explicitly missing source must not silently select a different SDK.
    selected = tmp_path / "missing-sdk"
    monkeypatch.setenv(variable, str(selected))
    assert units._default_nginx_source() == selected


@pytest.mark.parametrize("style", ["split", "missing", "conflicting"])
def test_regression_units_keep_explicit_generated_headers_authoritative(
        monkeypatch, tmp_path, style):
    """Selected split headers win; absent SDKs cannot borrow unrelated headers."""
    from cmdscripts import c_regression_units as units
    source = tmp_path / "nginx-src"
    selected = tmp_path / "modules"
    if style != "missing":
        selected.mkdir()
        (selected / "ngx_auto_headers.h").touch()
    if style == "conflicting":
        (source / "objs").mkdir(parents=True)
        (source / "objs/ngx_auto_headers.h").touch()
    monkeypatch.setenv("TEST_NGINX_OBJS", str(selected))
    assert units._nginx_generated_include(source) == selected
