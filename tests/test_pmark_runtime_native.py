"""Named SciTags rules and collector callbacks preserve fail-open behavior."""

import json
import subprocess

import pytest

from test_nginx_native_contract import server_native_compile  # noqa: F401


@pytest.fixture(scope='module')
def pmark_runtime(server_native_compile, tmp_path_factory):
    binary = server_native_compile('pmark-runtime', 'tests/c/pmark_runtime_native_test.c',
        ['-Wl,--wrap=' + name for name in ('ngx_array_create', 'ngx_array_push',
                                          'ngx_pcalloc', 'brix_dns_resolve')])
    root = tmp_path_factory.mktemp('pmark-registry')
    registry = root / 'defs.json'
    registry.write_text(json.dumps({'experiments': [
        {'expName': name, 'expId': number, 'activities': [
            {'activityName': name, 'activityId': number}
            for name, number in [('default', 2), ('role', 3), ('user', 4)]]}
        for name, number in [('alpha', 1), ('beta', 2), ('gamma', 3)]]}))
    def run(mode='normal', spec='collector.invalid:1234', path='/data/file',
            vo='', user='', cgi='', expected=0, registry_path=None):
        result = subprocess.run([str(binary), mode, str(registry_path or registry),
            spec, path, vo, user, cgi, str(expected)], capture_output=True, text=True, timeout=10)
        assert result.returncode == 0, result.stdout + result.stderr
        return dict(item.split('=') for item in result.stdout.splitlines()[-1].split()), result.stdout
    return run, root


@pytest.mark.parametrize('mode', ['normal', 'deferred'])
@pytest.mark.parametrize('spec,host,port', [('collector.invalid', 'collector.invalid', 10514),
    ('collector.invalid:1', 'collector.invalid', 1), ('collector.invalid:65535', 'collector.invalid', 65535),
    ('[2001:db8::8]:1234', '2001:db8::8', 1234),
    ('[2001:db8::8]', '2001:db8::8', 10514)])
def test_collectors_resolve_once_and_append_after_callback(pmark_runtime, mode, spec, host, port):
    result, output = pmark_runtime[0](mode, spec)
    assert result['dest'] == result['calls'] == result['ok'] == '1'
    assert f'dns={host} port={port}' in output


@pytest.mark.parametrize('spec', ['', 'x' * 256, 'collector.invalid:0',
                                  'collector.invalid:65536', 'collector.invalid:bad', 'origin'])
def test_invalid_or_per_flow_destination_never_reaches_dns(pmark_runtime, spec):
    result, _ = pmark_runtime[0](spec=spec)
    assert result['dest'] == result['calls'] == '0' and result['ok'] == '1'


@pytest.mark.parametrize('mode', ['dns-start', 'dns-error', 'dns-empty', 'dest-push'])
def test_collector_failure_leaves_marking_available(pmark_runtime, mode):
    result, _ = pmark_runtime[0](mode)
    assert result['dest'] == '0' and result['ok'] == '1'


@pytest.mark.parametrize('mode', ['disabled', 'exp-create', 'act-create', 'dest-create',
                                 'exp-push', 'act-push', 'dns-alloc'])
def test_allocation_or_disabled_runtime_is_cached_as_unavailable(pmark_runtime, mode):
    result, _ = pmark_runtime[0](mode, expected=-5)
    assert result['ready'] == '1' and result['ok'] == '0'


@pytest.mark.parametrize('path,vo,user,cgi,experiment,activity', [
    ('/data/file', 'atlas,/atlas/Role=production', 'alice', '', 2, 4),
    ('/data/file', 'atlas,/atlas/Role=production', '', '', 2, 3),
    ('/data/file', '/atlas/Role=production/Capability=NULL', '', '', 2, 3),
    ('/data/file', '/atlas/Role=' + 'a' * 128, '', '', 2, 2),
    ('/data/file', '/atlas/Role=', '', '', 2, 2),
    ('/data/file', '', '', '', 2, 2), ('/other', 'x,atlas,y', '', '', 3, 1),
    ('/other', 'notatlas', '', '', 1, 1),
    ('/data/file', 'atlas', 'alice', 'scitag.flow=325', 5, 5),
    ('/data/file', '', '', 'scitag.flow=invalid', 2, 2),
])
def test_mapping_priority_and_invalid_override_fallback(pmark_runtime, path, vo, user, cgi, experiment, activity):
    result, _ = pmark_runtime[0](path=path, vo=vo, user=user, cgi=cgi)
    assert result['mapped'] == '0'
    assert (int(result['exp']), int(result['act'])) == (experiment, activity)


@pytest.mark.parametrize('content', ['{', '{}', '{"experiments": []}'])
def test_bad_registry_disables_names_without_failing_runtime(pmark_runtime, content):
    run, root = pmark_runtime
    bad = root / 'invalid.json'; bad.write_text(content)
    result, _ = run(registry_path=bad)
    assert result['runtime'] == '0' and result['mapped'] == '-5'
    assert result['exp'] == result['act'] == '0'
