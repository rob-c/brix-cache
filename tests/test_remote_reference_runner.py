"""External-oracle mode is explicit, independently sourced and never native-green."""
import argparse
import base64
import json
import os
import stat
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
import xml.etree.ElementTree as ET

import pytest

from tools.ci import remote_reference as runner
from tools.ci import remote_reference_checks as checks
from tools.ci import remote_reference_target as target
from tools.ci import remote_reference_policy as policy


@pytest.mark.parametrize('value', ['root://localhost:12345/', 'roots://localhost:12345//'])  # net-literal-allow: offline URL grammar corpus
def test_external_endpoint_accepts_only_an_explicit_bare_lab_endpoint(value):
    assert runner.endpoint(value) == value.rstrip('/')


def test_oracle_xattr_inspection_preserves_exact_bytes_on_the_opened_inode(tmp_path, monkeypatch):
    """Read metadata from the confined descriptor, not a second path lookup."""
    path = tmp_path / 'space ; plain'
    path.write_bytes(b'data')
    value = b'\x00\xff\n'

    def names(descriptor):
        assert os.fstat(descriptor).st_ino == path.stat().st_ino
        return ['user.sample', 'security.unrelated']

    monkeypatch.setattr(os, 'listxattr', names)
    monkeypatch.setattr(os, 'getxattr', lambda fd, name: value)
    assert policy.fixture_xattrs(tmp_path, path) == {'user.sample': base64.b64encode(value).decode()}


@pytest.mark.parametrize('kind', ['outside', 'parent', 'leaf-link', 'directory-link'])
def test_oracle_inspection_never_follows_namespace_escapes(tmp_path, monkeypatch, kind):
    """Foreign names and symlinked leaves/ancestors fail before xattr inspection."""
    root = tmp_path / 'root'
    root.mkdir()
    foreign = tmp_path / 'private'
    foreign.mkdir()
    (foreign / 'key').write_bytes(b'never inspect')
    (root / 'leaf').symlink_to(foreign / 'key')
    (root / 'ancestor').symlink_to(foreign, target_is_directory=True)
    paths = {'outside': foreign / 'key', 'parent': root / '../private/key',
             'leaf-link': root / 'leaf', 'directory-link': root / 'ancestor/key'}
    monkeypatch.setattr(os, 'listxattr', lambda fd: pytest.fail('escaped descriptor inspected'))
    with pytest.raises((ValueError, OSError)):
        policy.fixture_xattrs(root, paths[kind])


def test_oracle_inspection_refuses_a_fifo_without_blocking(tmp_path):
    """A fixture path cannot turn the bounded metadata request into a stream read."""
    path = tmp_path / 'fifo'
    os.mkfifo(path)
    with pytest.raises(ValueError, match='plain file or directory'):
        policy.fixture_xattrs(tmp_path, path)


@pytest.mark.parametrize('count,size', [(1025, 1), (1, 65537), (17, 65536)])
def test_oracle_inspection_enforces_count_value_and_total_bounds(tmp_path, monkeypatch, count, size):
    """Independent bounds prevent oversized reference metadata from filling frames."""
    path = tmp_path / 'file'
    path.touch()
    monkeypatch.setattr(os, 'listxattr', lambda fd: ['user.' + str(n) for n in range(count)])
    monkeypatch.setattr(os, 'getxattr', lambda fd, name: b'x' * size)
    with pytest.raises(ValueError, match='exceeds'):
        policy.fixture_xattrs(tmp_path, path)


def test_explicit_remote_metadata_failure_never_falls_back_to_local_or_skips(tmp_path, monkeypatch):
    """A selected oracle inspection is authoritative even when its process fails."""
    from lib_py.reference_host import reference_disk_xattrs

    monkeypatch.setenv('TEST_REFERENCE_SHARED_ROOT', str(tmp_path))
    monkeypatch.setenv('TEST_REFERENCE_FIXTURE_COMMAND', '["/selected/inspector"]')

    def failed(*args, **kwargs):
        raise subprocess.CalledProcessError(125, args[0])

    monkeypatch.setattr(subprocess, 'run', failed)
    with pytest.raises(subprocess.CalledProcessError):
        reference_disk_xattrs(tmp_path / 'file')


def test_oracle_metadata_route_leaves_native_brix_inspection_unchanged(tmp_path, monkeypatch):
    """Only shared-reference paths are remote; independent ZFS paths stay native."""
    from lib_py.reference_host import reference_disk_xattrs

    monkeypatch.delenv('TEST_REFERENCE_FIXTURE_COMMAND', raising=False)
    assert reference_disk_xattrs(tmp_path / 'native') is None
    monkeypatch.setenv('TEST_REFERENCE_FIXTURE_COMMAND', '["/selected/inspector"]')
    monkeypatch.setenv('TEST_REFERENCE_SHARED_ROOT', str(tmp_path / 'shared'))
    assert reference_disk_xattrs(tmp_path / 'native') is None


def test_oracle_metadata_route_decodes_binary_values_exactly(tmp_path, monkeypatch):
    """Read-only remote inspection returns real binary values, including empties."""
    from lib_py.reference_host import reference_disk_xattrs

    monkeypatch.setenv('TEST_REFERENCE_FIXTURE_COMMAND', '["/selected/inspector"]')
    monkeypatch.setenv('TEST_REFERENCE_SHARED_ROOT', str(tmp_path))
    output = json.dumps({'user.a': 'AP8=', 'user.empty': ''}).encode()
    monkeypatch.setattr(subprocess, 'run', lambda *a, **kw: SimpleNamespace(stdout=output))
    assert reference_disk_xattrs(tmp_path / 'file') == {'user.a': b'\x00\xff', 'user.empty': b''}


def test_fixture_inspector_requires_the_existing_independent_namespace_proof(tmp_path):
    """The metadata route cannot bypass the same shared-fixture lease as a CLI."""
    from tools.ci import remote_reference_transport

    with pytest.raises(ValueError, match='shared fixtures'):
        remote_reference_transport._command(dict(kind='fixture'),
            SimpleNamespace(shared_fixture_proof=None), None)


@pytest.mark.parametrize('kind', ['file', 'directory', 'fifo'])
def test_oracle_stat_observes_actual_size_and_allocation_without_reading(tmp_path, kind):
    path = tmp_path / kind
    if kind == 'directory':
        path.mkdir()
    elif kind == 'fifo':
        os.mkfifo(path)
    else:
        with path.open('wb') as stream:
            stream.write(b'AB')
            stream.truncate(16 * 1024 * 1024)
    actual = path.stat()
    assert policy.fixture_stat(tmp_path, path) == {
        name: getattr(actual, name) for name in ('st_mode', 'st_size', 'st_blocks')}


@pytest.mark.parametrize('kind', ['outside', 'parent', 'link'])
def test_oracle_stat_rejects_foreign_or_linked_names(tmp_path, kind):
    root = tmp_path / 'root'
    root.mkdir()
    private = tmp_path / 'private'
    private.touch()
    (root / 'link').symlink_to(private)
    path = {'outside': private, 'parent': root / '../private', 'link': root / 'link'}[kind]
    with pytest.raises((OSError, ValueError)):
        policy.fixture_stat(root, path)


def test_fifo_fixture_creation_is_exclusive_and_preserves_existing_contents(tmp_path):
    path = tmp_path / 'fifo'
    assert policy.fixture_mkfifo(tmp_path, path, 0o600) == {'created': True}
    assert stat.S_ISFIFO(path.stat().st_mode)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    existing = tmp_path / 'existing'
    existing.write_bytes(b'unchanged')
    with pytest.raises(FileExistsError):
        policy.fixture_mkfifo(tmp_path, existing, 0o600)
    assert existing.read_bytes() == b'unchanged'


@pytest.mark.parametrize('kind', ['outside', 'parent', 'link', 'setuid', 'negative'])
def test_fifo_fixture_creation_cannot_escape_or_add_special_permissions(tmp_path, kind):
    root, foreign = tmp_path / 'root', tmp_path / 'foreign'
    root.mkdir()
    foreign.mkdir()
    (root / 'link').symlink_to(foreign, target_is_directory=True)
    paths = {'outside': foreign / 'new', 'parent': root / '../foreign/new',
             'link': root / 'link/new', 'setuid': root / 'new', 'negative': root / 'new'}
    mode = {'setuid': 0o4600, 'negative': -1}.get(kind, 0o600)
    with pytest.raises((OSError, ValueError)):
        policy.fixture_mkfifo(root, paths[kind], mode)
    assert not list(foreign.iterdir())
    assert not (root / 'new').exists()


def test_read_only_inspection_cannot_invoke_fixture_creation(tmp_path):
    args = SimpleNamespace(fixture_root=tmp_path, client_python=sys.executable)
    with pytest.raises(ValueError):
        policy.fixture_command(dict(argv=['mkfifo', str(tmp_path / 'new')]), args)
    from tools.ci import remote_reference_transport

    with pytest.raises(ValueError, match='shared fixtures'):
        remote_reference_transport._command(dict(kind='fixture-create'),
            SimpleNamespace(shared_fixture_proof=None), None)
    assert not (tmp_path / 'new').exists()


@pytest.mark.parametrize('operation', ['stat', 'fifo'])
def test_fixed_fixture_commands_execute_without_a_shell_or_caller_code(tmp_path, operation):
    args = SimpleNamespace(fixture_root=tmp_path, client_python=sys.executable)
    path = tmp_path / 'space ; $(not-a-command)'
    if operation == 'stat':
        path.write_bytes(b'plain')
        command = policy.fixture_command(dict(argv=['stat', str(path)]), args)
    else:
        command = policy.fixture_create_command(dict(argv=[str(path), str(0o600)]), args)
    result = subprocess.run(command, check=True, capture_output=True, timeout=5,
                            cwd=tmp_path, env={**os.environ, 'PYTHONPATH': ''})
    record = json.loads(result.stdout)
    assert record['st_size'] == 5 if operation == 'stat' else record == {'created': True}


def test_native_metadata_and_fifo_paths_need_no_remote_route(tmp_path, monkeypatch):
    from lib_py.reference_host import reference_disk_stat, reference_mkfifo

    monkeypatch.delenv('TEST_REFERENCE_FIXTURE_COMMAND', raising=False)
    monkeypatch.delenv('TEST_REFERENCE_FIFO_COMMAND', raising=False)
    path = tmp_path / 'fifo'
    reference_mkfifo(path, 0o600)
    assert reference_disk_stat(path) == path.stat()
    with pytest.raises(FileExistsError):
        reference_mkfifo(path, 0o600)


@pytest.mark.parametrize('operation,relative,mode', [
    ('mkfifo', 'outside', 0o600), ('mkfifo', 'root/new', 0o4600),
    ('exec', 'root/new', 0o600),
], ids=['outside', 'privileged-mode', 'unknown-command'])
def test_fixture_script_rejects_invalid_requests_from_private_cwd(tmp_path, operation,
                                                                relative, mode):
    root = tmp_path / 'root'
    root.mkdir()
    destination = tmp_path / relative
    result = subprocess.run(
        [sys.executable, policy.__file__, operation, str(root), str(destination), str(mode)],
        cwd=tmp_path, env={**os.environ, 'PYTHONPATH': ''}, capture_output=True, timeout=5)
    assert result.returncode != 0
    assert not destination.exists()


@pytest.mark.parametrize('values', [dict(st_mode=0o40755, st_size=4096, st_blocks=8),
    dict(st_mode=0o40755, st_size=-1, st_blocks=8),
    dict(st_mode=0o40755, st_size=4096),
    dict(st_mode=0o40755, st_size=True, st_blocks=8)])
def test_reference_stat_validates_exact_remote_fields(tmp_path, monkeypatch, values):
    from lib_py.reference_host import reference_disk_stat

    monkeypatch.setenv('TEST_REFERENCE_FIXTURE_COMMAND', '["/selected/inspector"]')
    monkeypatch.setenv('TEST_REFERENCE_SHARED_ROOT', str(tmp_path))
    calls = []

    def run(argv, **kwargs):
        calls.append(argv)
        return SimpleNamespace(stdout=json.dumps(values).encode())

    monkeypatch.setattr(subprocess, 'run', run)
    if len(values) == 3 and type(values['st_size']) is int and values['st_size'] >= 0:
        assert reference_disk_stat(tmp_path / 'file').st_size == 4096
    else:
        with pytest.raises(ValueError, match='stat fields'):
            reference_disk_stat(tmp_path / 'file')
    assert calls == [['/selected/inspector', 'stat', str(tmp_path / 'file')]]


@pytest.mark.parametrize('kind', ['correct-directories', 'wrong-wire-size', 'file', 'parent'])
def test_directory_size_comparison_uses_each_actual_filesystem_not_a_magic_size(tmp_path, monkeypatch, kind):
    from lib_py import reference_host

    observed = []

    def backing(path):
        observed.append(path)
        return SimpleNamespace(st_size=2 if path.parts[-2] == 'our' else 4096,
            st_mode=stat.S_IFREG if kind == 'file' else stat.S_IFDIR)

    monkeypatch.setattr(reference_host, 'reference_disk_stat', backing)
    pair = dict(our_data=str(tmp_path / 'our'), off_data=str(tmp_path / 'off'))
    if kind == 'correct-directories':
        reference_host.assert_backing_size_parity(pair, '/dir', 2, 4096)
        assert len(observed) == 2
    elif kind == 'parent':
        with pytest.raises(ValueError, match='confined'):
            reference_host.assert_backing_size_parity(pair, '/../private', 2, 4096)
        assert not observed
    else:
        with pytest.raises(AssertionError):
            reference_host.assert_backing_size_parity(pair, '/dir', 3 if kind == 'wrong-wire-size' else 2, 4096)


@pytest.mark.parametrize('kind', ['directories', 'wrong-size', 'file'])
def test_gfal_listing_retains_actual_directory_and_strict_file_sizes(tmp_path, monkeypatch, kind):
    import test_conf_gfal_ops as gfal
    from lib_py import reference_host

    pair = dict(our_data=str(tmp_path / 'our'), off_data=str(tmp_path / 'off'))
    ours = 3 if kind == 'wrong-size' else 2
    listing = lambda size: f'drwxrwxrwx 0 0 0 {size} Jun 24 14:04 dir\n'
    monkeypatch.setattr(gfal, '_both', lambda *args: (
        (0, listing(ours), ''), (0, listing(4096), '')))
    monkeypatch.setattr(reference_host, 'reference_disk_stat', lambda path: SimpleNamespace(
        st_size=2 if path.parts[-2] == 'our' else 4096,
        st_mode=stat.S_IFREG if kind == 'file' else stat.S_IFDIR))
    if kind == 'directories':
        gfal.test_ls_long_names_and_sizes(pair, '')
    else:
        with pytest.raises(AssertionError):
            gfal.test_ls_long_names_and_sizes(pair, '')


@pytest.mark.parametrize('value', [
    'https://localhost:12345/', 'root://localhost/', 'root://localhost:99999/',  # net-literal-allow: offline URL grammar corpus
    'root://user:secret@localhost:12345/', 'root://localhost:12345/?authz=secret',  # net-literal-allow: credential smuggling corpus
    'root://localhost:12345/#secret', 'root://localhost:12345/private',  # net-literal-allow: namespace smuggling corpus
    'root://localhost:12345/../', 'root://localhost:12345/\n',  # net-literal-allow: traversal and newline corpus
])
def test_endpoint_cannot_smuggle_credentials_or_an_operator_namespace(value):
    with pytest.raises(argparse.ArgumentTypeError):
        runner.endpoint(value)


def test_reports_keep_failures_errors_and_external_identity_separate(tmp_path):
    outcomes = [dict(name=name, outcome=outcome, detail='diagnostic', seconds=0.1)
                for name, outcome in [('a', 'passed'), ('b', 'failed'), ('c', 'errors')]]
    assert not runner.write_reports(tmp_path, dict(profile='anonymous'), outcomes)
    summary = json.loads((tmp_path / 'summary.json').read_text())
    assert summary['native_full_suite'] is False
    assert summary['counts'] == dict(tests=3, passed=1, failed=1, errors=1, skipped=0)
    root = ET.parse(tmp_path / 'results.xml').getroot()
    assert len(root.findall('./testcase/failure')) == 1
    assert len(root.findall('./testcase/error')) == 1


def test_optimized_python_cannot_disable_the_validation_assertions():
    result = subprocess.run([sys.executable, '-O', '-m', 'tools.ci.remote_reference', '--help'],
                            cwd=Path(__file__).resolve().parents[1], capture_output=True,
                            text=True, timeout=15)
    assert result.returncode == 2
    assert 'assertions must be enabled' in result.stderr


def _native_evidence():
    return dict(schema_version=1, mode='external-reference-target', native_full_suite=False,
        root='/private-lab', server=dict(system='FreeBSD', uid=2101,
            artifacts={'nginx': '0' * 64, 'module': '1' * 64}),
        fixture=dict(size=1234, sha256='2' * 64))


def test_valid_native_evidence_keeps_the_actual_server_identity(tmp_path):
    evidence = _native_evidence()
    path = tmp_path / 'evidence.json'
    path.write_text(json.dumps(evidence))
    assert runner.server_evidence(path) == evidence


@pytest.mark.parametrize('field,value', [
    ('native_full_suite', True), ('server', dict(system='FreeBSD', uid=0)),
    ('fixture', dict(size=1234, sha256='not-a-digest')), ('padding', 'x' * 65536),
])
def test_native_evidence_is_bounded_and_cannot_claim_a_full_suite_pass(tmp_path, field, value):
    evidence = _native_evidence()
    evidence[field] = value
    path = tmp_path / 'evidence.json'
    path.write_text(json.dumps(evidence))
    with pytest.raises((AssertionError, ValueError)):
        runner.server_evidence(path)


@pytest.mark.parametrize('outcome,error', [('passed', None), ('failed', AssertionError),
                                          ('errors', RuntimeError)])
def test_case_verdict_does_not_turn_transport_errors_into_passes(outcome, error):
    def check():
        if error:
            raise error('kept visible')

    result = checks.execute_case('contract', check)
    assert result['outcome'] == outcome


@pytest.fixture
def reference_tools(tmp_path, monkeypatch):
    paths = [tmp_path / name for name in ('xrdcp', 'xrdfs')]
    for path in paths:
        path.write_bytes(b'unit fixture, not an executable oracle')
        path.chmod(0o700)
    args = SimpleNamespace(xrdcp=paths[0], xrdfs=paths[1],
                           client_python=Path('/selected/python'), timeout=10)
    monkeypatch.setattr('lib_py.util.linked_libraries', lambda *args, **kwargs: 'libXrdCl.6.dylib')
    monkeypatch.setattr(runner, '_bindings_provenance', lambda *args: dict(version='6.2.0'))
    monkeypatch.setattr(runner.subprocess, 'run', lambda *args, **kwargs:
                        SimpleNamespace(stdout='v6.2.0', stderr=''))
    return args


def test_independent_reference_provenance_records_both_cli_artifacts(reference_tools, tmp_path):
    result = runner.official_provenance(reference_tools, tmp_path)
    assert set(result['tools']) == {'xrdcp', 'xrdfs'}
    assert all(len(info['sha256']) == 64 for info in result['tools'].values())


def test_brix_cannot_be_substituted_for_an_external_oracle(reference_tools, tmp_path, monkeypatch):
    monkeypatch.setattr('lib_py.util.linked_libraries', lambda *args, **kwargs: 'libbrix.so libssl.so')
    with pytest.raises(AssertionError, match='independent XrdCl'):
        runner.official_provenance(reference_tools, tmp_path)


def test_operator_credentials_and_tls_downgrade_overrides_cannot_leak_into_the_reference(monkeypatch):
    monkeypatch.setattr(runner.os, 'environ', dict(runner.os.environ))
    names = ('X509_USER_PROXY', 'XrdSecGSICERT', 'BEARER_TOKEN', 'BEARER_TOKEN_FILE',
             'SCITOKENS_FILE', 'XRD_SECPROTOCOL')
    for name in names:
        monkeypatch.setenv(name, 'operator-credential')
    monkeypatch.setenv('XRD_NOTLSOK', '1')
    monkeypatch.setenv('XRD_TLSNODATA', '1')
    monkeypatch.setenv('BRIX_REFERENCE_TEST_UNRELATED', 'retained')
    runner._isolate_credentials()
    assert not set(names) & runner.os.environ.keys()
    assert runner.os.environ['XRD_NOTLSOK'] == runner.os.environ['XRD_TLSNODATA'] == '0'
    assert runner.os.environ['BRIX_REFERENCE_TEST_UNRELATED'] == 'retained'


def test_failed_linkage_inspection_is_not_a_reference_pass(reference_tools, tmp_path, monkeypatch):
    def failed(*args, **kwargs):
        raise OSError('inspector failed')

    monkeypatch.setattr('lib_py.util.linked_libraries', failed)
    with pytest.raises(OSError):
        runner.official_provenance(reference_tools, tmp_path)


def test_cli_and_bindings_must_describe_the_same_reference_version(reference_tools, tmp_path, monkeypatch):
    monkeypatch.setattr(runner, '_bindings_provenance', lambda *args: dict(version='5.9.2'))
    with pytest.raises(AssertionError, match='versions do not match'):
        runner.official_provenance(reference_tools, tmp_path)


def test_cleanup_never_removes_a_namespace_it_failed_to_create(tmp_path):
    calls = []
    context = object.__new__(checks.ReferenceContext)
    context.created = False
    context.fs = SimpleNamespace(rmdir=lambda path: calls.append(path))
    context.cleanup()
    assert calls == []


@pytest.mark.parametrize('ok,errno,passes', [(False, 3010, True), (True, 0, False),
                                           (False, 0, False), (False, 3011, False)])
def test_a_transport_failure_is_not_proof_of_access_control(ok, errno, passes):
    status = SimpleNamespace(ok=ok, errno=errno)
    if passes:
        checks.require_refusal(status, (3010,))
    else:
        with pytest.raises(AssertionError):
            checks.require_refusal(status, (3010,))


@pytest.mark.parametrize('mapping', [True, False])
@pytest.mark.parametrize('ok', [True, False])
def test_attribute_transport_success_does_not_hide_a_per_attribute_failure(ok, mapping):
    status = {'ok': ok} if mapping else SimpleNamespace(ok=ok)
    result = (SimpleNamespace(ok=True), [('user.test', status)])
    if ok:
        checks._xattr_mutation(result)
    else:
        with pytest.raises(AssertionError):
            checks._xattr_mutation(result)


@pytest.mark.parametrize('records,passes', [
    ([('a', 'one', {'ok': True}), ('b', '', {'ok': True})], True),
    ([('a', 'one', {'ok': True}), ('a', '', {'ok': True})], False),
    ([('a', 'one', {'ok': True})], False),
    ([('a', 'one', {'ok': True}), ('b', '', {'ok': False})], False),
    ([('U.a', 'one', {'ok': True}), ('b', '', {'ok': True})], False),
])
def test_external_attribute_batch_requires_every_exact_value_and_status(records, passes):
    if passes:
        checks._assert_attribute_values(records, {'a': 'one', 'b': ''})
        checks._xattr_mutation((SimpleNamespace(ok=True), records), ['a', 'b'])
    else:
        with pytest.raises(AssertionError):
            checks._assert_attribute_values(records, {'a': 'one', 'b': ''})
        with pytest.raises(AssertionError):
            checks._xattr_mutation((SimpleNamespace(ok=True), records), ['a', 'b'])


@pytest.mark.parametrize('code,message,passes', [
    (204, '[FATAL] Auth failed: No protocols left to try', True),
    (204, 'unrelated client failure', False), (110, 'TLS error', False),
])
def test_missing_credentials_require_an_explicit_authentication_failure(code, message, passes):
    status = SimpleNamespace(ok=False, errno=0, code=code, message=message)
    if passes:
        checks._authentication_refused(status)
    else:
        with pytest.raises(AssertionError):
            checks._authentication_refused(status)


@pytest.mark.parametrize('verdict', ['refused', 'accepted', 'transport-error'])
def test_tls_protocol_negative_is_fresh_and_always_restores_the_valid_client(monkeypatch, verdict):
    shutdowns, reopened = [], []
    monkeypatch.setenv('XrdSecPROTOCOL', 'gsi')
    monkeypatch.setattr('brix_suite.clients.xrdcl.worker_link._shutdown_worker',
                        lambda: shutdowns.append('shutdown'))

    class Handle:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def open(self, *args):
            assert runner.os.environ['XrdSecPROTOCOL'] == 'unix'
            if verdict == 'transport-error':
                raise TimeoutError('not an authentication rejection')
            return SimpleNamespace(ok=verdict == 'accepted', errno=0, code=204,
                                   message='[FATAL] Auth failed'), None

    context = SimpleNamespace(args=SimpleNamespace(url='roots://localhost:12345'),  # net-literal-allow: mock-only rejected-auth oracle
        client=SimpleNamespace(File=Handle, FileSystem=lambda url: reopened.append(url)),
        url=lambda path: 'roots://localhost:12345/' + path)  # net-literal-allow: mock-only rejected-auth oracle
    if verdict == 'refused':
        checks.disallowed_auth_protocol(context)
    else:
        with pytest.raises((AssertionError, TimeoutError)):
            checks.disallowed_auth_protocol(context)
    assert runner.os.environ['XrdSecPROTOCOL'] == 'gsi'
    assert shutdowns == ['shutdown', 'shutdown']
    assert reopened == ['roots://localhost:12345']  # net-literal-allow: mock-only rejected-auth oracle


def test_native_target_requires_an_ordinary_account(tmp_path, monkeypatch):
    monkeypatch.setattr(target.os, 'geteuid', lambda: 0)
    with pytest.raises(SystemExit):
        target._arguments(['--build-dir', str(tmp_path), '--scratch-base', str(tmp_path)])


@pytest.mark.parametrize('seconds', ['0', '1801'])
def test_native_target_cannot_leave_an_unbounded_lease(tmp_path, monkeypatch, seconds):
    monkeypatch.setattr(target.os, 'geteuid', lambda: 1000)
    with pytest.raises(SystemExit):
        target._arguments(['--build-dir', str(tmp_path), '--scratch-base', str(tmp_path),
                           '--lease-seconds', seconds])


def test_native_target_profiles_preserve_auth_and_readonly_policy(tmp_path, monkeypatch):
    monkeypatch.setattr('ephemeral_port.free_port', lambda host: 12345)
    specs = dict(target._specs(tmp_path, True))
    assert set(specs) == {'anonymous', 'readonly', 'gsi', 'gsi-tls'}
    assert 'brix_allow_write off;' in specs['readonly'].template_values['TLS_LINES']
    assert specs['gsi'].template_values['AUTH'] == specs['gsi-tls'].template_values['AUTH'] == 'gsi'
    assert 'brix_tls on;' in specs['gsi-tls'].template_values['TLS_LINES']
    assert all(spec.template_values['BIND_HOST'] == '127.0.0.1' for spec in specs.values())  # net-literal-allow: loopback-only fixture policy, no dial


@pytest.mark.parametrize('tamper', ['none', 'fixture', 'outside'])
def test_target_retains_native_integrity_evidence_without_hiding_tampering(tmp_path, monkeypatch, tamper):
    monkeypatch.setattr('ephemeral_port.free_port', lambda host: 12345)
    list(target._specs(tmp_path, False))
    digest = target._digest(tmp_path / 'data/reference.bin')
    if tamper != 'none':
        path = tmp_path / ('data/reference.bin' if tamper == 'fixture' else 'outside-sentinel')
        path.write_bytes(b'tampered')
    target._final_evidence(tmp_path, {'fixture': {'sha256': digest}})
    record = json.loads((tmp_path / 'final.json').read_text())
    assert record['reference_fixture_unchanged'] == (tamper != 'fixture')
    assert record['outside_sentinel_unchanged'] == (tamper != 'outside')
    assert record['remaining_test_namespaces'] == []
    assert record['native_full_suite'] is False
