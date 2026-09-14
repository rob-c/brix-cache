"""The PAL source guard proves ownership and real configured bodies, not runtime support."""

import importlib
from pathlib import Path

import pytest


@pytest.fixture()
def pal(monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / 'tools/ci'))
    return importlib.import_module('check_pal_seam')


def _bodies(names):
    return ''.join(f'int {name}(void) {{ return 0; }}\n' for name in names)


def _write(root, relative, body):
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body)
    return path


@pytest.fixture()
def tree(tmp_path, pal):
    for directory in ('src', 'shared', 'client'):
        (tmp_path / directory).mkdir()
    runtime = 'src/platform/platform_runtime.c'
    _write(tmp_path, runtime, _bodies(pal.COMMON_API[:3]))
    _write(tmp_path, 'src/platform/platform_api.h', '#include "platform_api_endian.h"\n')
    _write(tmp_path, 'src/platform/platform_api_endian.h', _bodies(pal.INLINE_API))
    parts = ['brix_shared_platform_srcs=""\n']
    for index, host in enumerate(pal.HOSTS):
        branch = 'if' if index == 0 else 'elif'
        source = f'src/platform/{host}/wrapper.c'
        _write(tmp_path, source, _bodies(pal.COMMON_API[3:]))
        parts.append(f'{branch} [ "$BRIX_PLATFORM_{host.upper()}" = "1" ]; then\n')
        parts.append(f'    brix_platform_srcs="$ngx_addon_dir/{source}"\n')
    parts.append('fi\n')
    parts.append(f'ngx_module_srcs="$ngx_addon_dir/{runtime} '
                 '$brix_shared_platform_srcs $brix_platform_srcs"\n')
    _write(tmp_path, 'config', ''.join(parts))
    return tmp_path


def _check(pal, tree):
    checker = pal.PALChecker(tree)
    checker.scan()
    checker.check_pal_implementation()
    return checker


def test_configured_common_bodies_and_public_consumer_pass(pal, tree):
    _write(tree, 'src/protocols/demo.c',
           '#include "platform/platform_api.h"\n'
           'int demo(void) { return brix_plat_random(0, 0); }\n')
    assert _check(pal, tree).violations == []
    assert pal.main(['--directory', str(tree / 'src'), '--check-implementation']) == 0


@pytest.mark.parametrize('body', [
    '/* int brix_plat_random(void) { return 0; } */',
    'const char *text = "int brix_plat_random(void) { return 0; }";',
    'int brix_plat_random(void);',
    'void demo(void) { if (brix_plat_random()) { return; } }',
    '#define brix_plat_random(x) { x; }',
])
def test_nondefinitions_cannot_satisfy_a_missing_api(pal, tree, body):
    path = tree / 'src/platform/linux/wrapper.c'
    path.write_text(path.read_text().replace(_bodies(['brix_plat_random']), body))
    findings = _check(pal, tree).violations
    assert any('linux: brix_plat_random requires one actual definition; found 0' in f
               for f in findings)


def test_duplicate_common_body_is_rejected(pal, tree):
    path = tree / 'src/platform/linux/wrapper.c'
    path.write_text(path.read_text() + _bodies(['brix_plat_random']))
    assert any('brix_plat_random requires one actual definition; found 2' in f
               for f in _check(pal, tree).violations)


@pytest.mark.parametrize('name', ['brix_plat_random', 'brix_platform_event_init'])
def test_consumer_cannot_own_either_pal_api_family(pal, tree, name):
    _write(tree, 'src/protocols/src/platform_fake/handler.c', _bodies([name]))
    assert any(f'PAL definition {name} outside its implementation owner' in f
               for f in _check(pal, tree).violations)


@pytest.mark.parametrize('target', [
    'platform/linux/posix_wrapper.h',
    'platform/platform_api_file.h',
    '../platform/darwin/cpu_cache.h',
    '../platform/linux/../platform_api_file.h',
])
def test_private_header_paths_cannot_bypass_public_umbrella(pal, tree, target):
    _write(tree, 'src/protocols/demo.c', f'#include "{target}"\n')
    assert any('private PAL header' in f for f in _check(pal, tree).violations)


def test_comments_strings_and_portable_network_conversions_are_valid(pal, tree):
    _write(tree, 'src/protocols/demo.c',
           '/* #include "platform/linux/internal.h"\n'
           'int brix_plat_random(void) { } */\n'
           'const char *text = "/* not a comment */ brix_plat_random() { }";\n'
           'int demo(int word) { return htonl(word); }\n')
    assert _check(pal, tree).violations == []


def test_host_selection_cannot_use_foreign_source(pal, tree):
    config = tree / 'config'
    config.write_text(config.read_text().replace('linux/wrapper.c', 'darwin/wrapper.c'))
    assert any('linux: foreign or unsupported PAL source owner' in f
               for f in _check(pal, tree).violations)


def test_unbuilt_source_comment_cannot_satisfy_build_selection(pal, tree):
    config = tree / 'config'
    config.write_text(config.read_text().replace(
        'brix_platform_srcs="$ngx_addon_dir/src/platform/linux/wrapper.c"',
        'brix_platform_srcs=""\n# $ngx_addon_dir/src/platform/linux/wrapper.c'))
    assert any('linux: empty PAL source selection' in f
               for f in _check(pal, tree).violations)


def test_unit_translation_unit_cannot_supply_common_api(pal, tree):
    original = tree / 'src/platform/linux/wrapper.c'
    _write(tree, 'src/platform/linux/wrapper_unittest.c', original.read_text())
    config = tree / 'config'
    config.write_text(config.read_text().replace('linux/wrapper.c', 'linux/wrapper_unittest.c'))
    assert any('linux: foreign or unsupported PAL source owner' in f
               for f in _check(pal, tree).violations)


def test_missing_module_source_expansion_is_rejected(pal, tree):
    config = tree / 'config'
    config.write_text(config.read_text().replace('$brix_shared_platform_srcs ', ''))
    assert any('consumer omits $brix_shared_platform_srcs' in f
               for f in _check(pal, tree).violations)


def test_inline_api_body_is_required(pal, tree):
    _write(tree, 'src/platform/platform_api_endian.h', '')
    assert any('public inline API: brix_plat_htobe64' in f
               for f in _check(pal, tree).violations)


def test_unreferenced_inline_header_cannot_satisfy_public_api(pal, tree):
    _write(tree, 'src/platform/platform_api.h', '// #include "platform_api_endian.h"\n')
    assert any('umbrella does not include common endian API' in f
               for f in _check(pal, tree).violations)


def test_private_header_diagnostic_preserves_source_line(pal):
    body = '/* explanation\n */\n\n#include "platform/linux/private.h"\n'
    assert pal.include_targets(body) == [(4, 'platform/linux/private.h')]


def test_missing_production_tree_fails_closed(pal, tree):
    (tree / 'client').rmdir()
    assert any('missing production directory' in f for f in _check(pal, tree).violations)


def test_unreadable_selected_source_fails_closed(pal, tree, monkeypatch):
    read_text = Path.read_text

    def denied(path, *args, **kwargs):
        if path == tree / 'src/platform/linux/wrapper.c':
            raise PermissionError('fixture read failure')
        return read_text(path, *args, **kwargs)

    monkeypatch.setattr(Path, 'read_text', denied)
    assert any('fixture read failure' in f for f in _check(pal, tree).violations)


def test_scan_ignores_build_tree_even_when_ancestor_is_named_src(pal, tree):
    _write(tree, 'build/src/protocols/demo.c', _bodies(['brix_plat_random']))
    assert _check(pal, tree).violations == []


def test_definition_parser_handles_function_pointer_parameters(pal):
    body = 'int brix_platform_event_init(void (*callback)(int)) { return 0; }'
    assert pal.definitions(body) == [('brix_platform_event_init', 1)]
