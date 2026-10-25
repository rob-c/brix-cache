"""Native confinement and owned-helper lifetime; no success-shaped emulation."""
import subprocess
import json
from types import SimpleNamespace
from pathlib import Path

import pytest

from cmdscripts.compile_run import compile_binary, pal_host_sources, platform_host_name
from test_platform_linux_native import native_compile


@pytest.mark.parametrize('status,content,accepted', [
    (200, b'mapped\x00\xff', True), (503, b'mapped\x00\xff', False),
    (200, b'wrong backend or identity', False),
])
def test_broker_readiness_requires_real_success_and_exact_backend_bytes(status, content, accepted):
    """Do not mistake a live listener, error response or another object for ready."""
    from impersonation_gridmap_helpers import assert_mapped_read_ready

    response = SimpleNamespace(status_code=status, content=content)
    if accepted:
        assert_mapped_read_ready(response, b'mapped\x00\xff')
    else:
        with pytest.raises(AssertionError):
            assert_mapped_read_ready(response, b'mapped\x00\xff')


@pytest.fixture(scope='module')
def credential_match_probe(native_compile):
    """Exercise production complete-identity matching, including duplicate gids."""
    return native_compile('fixed-credential-match', r'''
#include "auth/impersonate/broker_internal.h"
#include "auth/impersonate/broker_fixed.h"
#include <assert.h>
int main(int argc, char **argv)
{
    assert(argc == 2);
    brix_idmap_creds_t left = {.uid=1701, .gid=1701, .ngroups=2, .groups={1701,1702}};
    brix_idmap_creds_t right = left;
    int expected = 0;
    if (strcmp(argv[1], "same") == 0) { expected = 1; }
    if (strcmp(argv[1], "order") == 0) {
        right.groups[0] = 1702; right.groups[1] = 1701; expected = 1;
    }
    if (strcmp(argv[1], "uid") == 0) { right.uid++; }
    if (strcmp(argv[1], "gid") == 0) { right.gid++; }
    if (strcmp(argv[1], "added") == 0) {
        right.groups[2] = 1703; right.ngroups++;
    }
    if (strcmp(argv[1], "removed") == 0) { right.ngroups--; }
    if (strcmp(argv[1], "duplicate") == 0) { left.groups[1] = 1701; }
    if (strcmp(argv[1], "invalid") == 0) { left.ngroups = -1; }
    assert(brix_imp_fixed_creds_equal(&left, &right) == expected);
    assert(brix_imp_fixed_creds_equal(&right, &left) == expected);
    return 0;
}
''', ['src/auth/impersonate/broker_fixed.c'],
        ['-ffunction-sections', '-fdata-sections', '-Wl,--gc-sections'])


@pytest.mark.parametrize('case', ['same', 'order', 'uid', 'gid', 'added',
                                 'removed', 'duplicate', 'invalid'])
def test_complete_credentials_cannot_lend_foreign_groups(credential_match_probe, case):
    """Exact matching accepts reordered sets, not extra or repeated privileges."""
    result = subprocess.run([str(credential_match_probe), case], capture_output=True,
                            text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.fixture(scope='module')
def local_codec_probe(native_compile):
    """Compile the shared production socket writer, not a transport model."""
    return native_compile('fixed-local-codec', r'''
#include "auth/impersonate/broker_internal.h"
#include "auth/impersonate/client_internal.h"
#include <assert.h>
#include <signal.h>
int main(int argc, char **argv)
{
    int pair[2];
    char output[4];
    assert(argc == 2);
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
    signal(SIGPIPE, SIG_DFL);
    if (strcmp(argv[1], "closed") == 0) {
        close(pair[1]);
        assert(imp_write_full(pair[0], "brix", 4) == -1);
        assert(errno == EPIPE || errno == ECONNRESET);
    } else if (strcmp(argv[1], "empty") == 0) {
        assert(imp_write_full(pair[0], NULL, 0) == 0);
        struct pollfd probe = {.fd=pair[1], .events=POLLIN};
        assert(poll(&probe, 1, 0) == 0);
        close(pair[1]);
    } else {
        assert(imp_write_full(pair[0], "brix", 4) == 0);
        assert(read(pair[1], output, 4) == 4 && memcmp(output, "brix", 4) == 0);
        close(pair[1]);
    }
    close(pair[0]);
    return 0;
}
''', ['src/auth/impersonate/client.c'],
        ['-ffunction-sections', '-fdata-sections', '-Wl,--gc-sections'])


@pytest.mark.parametrize('case', ['success', 'closed', 'empty'])
def test_helper_channel_writes_are_bounded_and_sigpipe_safe(local_codec_probe, case):
    """A dropped private peer cannot terminate the serving supervisor."""
    result = subprocess.run([str(local_codec_probe), case], capture_output=True,
                            text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.fixture(scope='module')
def sandbox_probe(tmp_path_factory):
    """Link the actual host primitive, not a model of Capsicum semantics."""
    output = tmp_path_factory.mktemp('identity-sandbox') / 'probe'
    libraries = [] if platform_host_name() == 'darwin' else ['-lcrypt']
    result = compile_binary(output, ['-std=gnu11', '-Wall', '-Wextra', '-Werror',
        '-D_GNU_SOURCE', '-Isrc', 'tests/c/fixed_identity_sandbox.c',
        *pal_host_sources('priv_wrapper'), *libraries])
    assert result.returncode == 0, result.stdout + result.stderr
    return output


@pytest.mark.parametrize('mode', ['confine', 'lifetime'])
def test_native_confinement_and_owned_lifetime(sandbox_probe, tmp_path, mode):
    """Usable relative I/O cannot grant ambient paths, exec or saved root."""
    selected = mode if platform_host_name() == 'freebsd' else 'unsupported'
    result = subprocess.run([str(sandbox_probe), selected, str(tmp_path)],
                            capture_output=True, text=True, timeout=15)
    assert result.returncode == 0, result.stdout + result.stderr
    assert not (tmp_path.parent / 'outside').exists()
    if selected == 'confine':
        assert (tmp_path / 'probe').read_bytes() == b'brix'


@pytest.mark.parametrize('protocol,network', [
    ('UDS', False), ('UDD', False), ('UDQ', False),
    ('TCP', True), ('UDP', True), ('unknown', True),
])
def test_native_descriptor_report_distinguishes_unix_and_network(monkeypatch, protocol, network):
    """Record sockets are local IPC, never an inherited TCP listener."""
    from lib_py import process_host

    row = dict(fd=3, fd_type='socket', protocol=protocol, path='-')
    monkeypatch.setattr(process_host, 'native_process_record', lambda *args:
                        dict(files=[dict(fd='cwd'), row]))
    target = process_host.native_descriptor_targets(123)[3]
    assert target.startswith('network:') is network


def test_native_process_report_requires_the_exact_pid(monkeypatch):
    """A malformed or wrong-owner report cannot become an empty authority list."""
    from lib_py import process_host

    payload = {'procstat': {'files': {'123': {'process_id': 124, 'files': []}}}}
    monkeypatch.setattr(process_host.subprocess, 'run', lambda *args, **kwargs:
                        SimpleNamespace(stdout=json.dumps(payload)))
    with pytest.raises(RuntimeError, match='invalid native process report'):
        process_host.native_descriptor_targets(123)


@pytest.mark.parametrize('descriptor', [-1, 'unknown', True])
def test_native_descriptor_report_refuses_invalid_handles(monkeypatch, descriptor):
    """Unknown descriptor data must fail, not hide potentially retained authority."""
    from lib_py import process_host

    monkeypatch.setattr(process_host, 'native_process_record', lambda *args:
                        dict(files=[dict(fd=descriptor)]))
    with pytest.raises(RuntimeError, match='invalid native descriptor number'):
        process_host.native_descriptor_targets(123)


def _pblock_account_commands(monkeypatch, host, fail_create=False):
    """Record actual fixture argv; never execute account tools in a unit test."""
    import subprocess
    import test_pblock_group_multiuser as module
    from lib_py import account_host

    commands = []

    def run(command, **options):
        commands.append(command)
        if fail_create and options.get('check'):
            raise subprocess.CalledProcessError(73, command)
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(account_host, 'sys', SimpleNamespace(platform=host))
    monkeypatch.setattr(module, 'subprocess', SimpleNamespace(run=run))
    return module, commands


@pytest.mark.parametrize('host', ['freebsd15', 'linux'])
def test_pblock_accounts_use_native_tools_and_exact_fixture_identities(monkeypatch, host):
    """The complete create/cleanup catalogue preserves every reserved uid/gid."""
    from lib_py import account_host

    module, commands = _pblock_account_commands(monkeypatch, host)
    module._provision_accounts()
    assert len(commands) == 10
    assert commands[5:7] == [account_host.group_add(name, gid)
                             for name, gid in module.GROUPS.items()]
    assert commands[7:] == [account_host.user_add(name, uid, group, module.nologin_shell())
                            for name, uid, group, _logical in module.USERS.values()]


def test_pblock_account_creation_failure_cannot_fall_back_or_alias_ids(monkeypatch):
    """A refused explicit group never becomes a different account or retry."""
    import subprocess

    module, commands = _pblock_account_commands(monkeypatch, 'freebsd15', True)
    with pytest.raises(subprocess.CalledProcessError) as failure:
        module._provision_accounts()
    assert failure.value.returncode == 73
    assert len(commands) == 6
    assert all('-o' not in command for command in commands)


def test_pblock_account_cleanup_never_recurses_into_home_directories(monkeypatch):
    """Delete only the explicit fixture identities, never an attached home tree."""
    from lib_py import account_host

    module, commands = _pblock_account_commands(monkeypatch, 'freebsd15')
    module._reap_accounts()
    assert commands == [account_host.user_delete(name) for name, *_ in module.USERS.values()] + [
        account_host.group_delete(name) for name in module.GROUPS]
    assert all('-r' not in command for command in commands)


@pytest.mark.parametrize('gid,group', [(0, 'root'), (0, 'wheel'), (80, 'admin')])
def test_pblock_root_worker_keeps_the_native_primary_group(monkeypatch, tmp_path, gid, group):
    """A root subject stays root without assuming Linux's root group spelling."""
    import test_pblock_privilege_drop as module

    requested, specifications = [], []
    monkeypatch.setattr(module, 'pwd', SimpleNamespace(getpwnam=lambda user:
                        SimpleNamespace(pw_gid=gid)))

    def lookup(selected):
        requested.append(selected)
        return SimpleNamespace(gr_name=group)

    monkeypatch.setattr(module, 'grp', SimpleNamespace(getgrgid=lookup))
    (tmp_path / 'tmp').mkdir()
    endpoint = SimpleNamespace(port=12345, prefix=str(tmp_path))
    harness = SimpleNamespace(start=lambda spec: specifications.append(spec) or endpoint)
    module._start(harness, 'native-root', str(tmp_path / 'export'))
    assert requested == [gid]
    assert specifications[0].template_values['ROOT_GROUP'] == group
    template = Path(__file__).parent / 'configs/nginx_pblock_privdrop_webdav.conf'
    assert 'user root {ROOT_GROUP};' in template.read_text()


def test_pblock_missing_native_root_group_refuses_before_launch(monkeypatch):
    """An unresolved account group cannot become a default worker identity."""
    import test_pblock_privilege_drop as module

    def missing(_gid):
        raise KeyError('native primary group missing')

    launched = []
    monkeypatch.setattr(module, 'grp', SimpleNamespace(getgrgid=missing))
    with pytest.raises(KeyError, match='native primary group missing'):
        module._start(SimpleNamespace(start=launched.append), 'missing', '/unused')
    assert launched == []


@pytest.mark.parametrize('fault', ['none', 'real-uid', 'saved-uid', 'effective-gid',
                                  'saved-gid', 'unknown-worker'])
def test_pblock_identity_proof_cannot_be_satisfied_by_parent_group(monkeypatch, tmp_path, fault):
    """Inspect actual saved credentials even when file ownership looks safe."""
    import test_pblock_privilege_drop as module

    uids, gids = [module.NOBODY_UID] * 3, [module.NOBODY_GID] * 3
    changes = {'real-uid': (uids, 0), 'saved-uid': (uids, 2),
               'effective-gid': (gids, 1), 'saved-gid': (gids, 2)}
    if fault in changes:
        values, index = changes[fault]
        values[index] = 0
    worker = SimpleNamespace(pid=123, uids=lambda: tuple(uids), gids=lambda: tuple(gids))
    master = SimpleNamespace(children=lambda: [worker])
    monkeypatch.setattr(module, 'psutil', SimpleNamespace(Process=lambda pid: master))
    title = b'helper' if fault == 'unknown-worker' else b'nginx: worker process'
    monkeypatch.setattr(module, 'process_cmdline', lambda pid: title)
    (tmp_path / 'logs').mkdir()
    (tmp_path / 'logs/nginx.pid').write_text('100')
    if fault == 'none':
        module._assert_worker_identity(tmp_path)
        return
    with pytest.raises(AssertionError):
        module._assert_worker_identity(tmp_path)


@pytest.mark.parametrize('text,expected', [('enabled\n', True), ('disabled\n', False)])
def test_native_nnp_query_uses_only_the_selected_process(monkeypatch, text, expected):
    from lib_py import process_host

    calls = []

    def run(command, **options):
        calls.append((command, options))
        return SimpleNamespace(stdout=text)

    monkeypatch.setattr(process_host.subprocess, 'run', run)
    assert process_host.native_no_new_privileges(123) is expected
    assert calls == [(['/usr/bin/proccontrol', '-m', 'nonewprivs', '-q', '-p', '123'],
                      dict(check=True, capture_output=True, text=True, timeout=10))]


@pytest.mark.parametrize('pid', [0, -1, True, '123'])
def test_native_nnp_query_refuses_invalid_identity_before_spawn(monkeypatch, pid):
    from lib_py import process_host

    calls = []
    monkeypatch.setattr(process_host.subprocess, 'run', lambda *args, **kwargs: calls.append(args))
    with pytest.raises(ValueError, match='invalid native process identity'):
        process_host.native_no_new_privileges(pid)
    assert calls == []


@pytest.mark.parametrize('failure', ['empty', 'unknown', 'failed', 'timeout'])
def test_native_nnp_query_cannot_attest_unknown_or_failed_inspection(monkeypatch, failure):
    from lib_py import process_host

    errors = dict(failed=subprocess.CalledProcessError(1, 'proccontrol'),
                  timeout=subprocess.TimeoutExpired('proccontrol', 10))

    def run(*_args, **_options):
        if failure in errors:
            raise errors[failure]
        return SimpleNamespace(stdout='' if failure == 'empty' else 'maybe enabled')

    monkeypatch.setattr(process_host.subprocess, 'run', run)
    with pytest.raises((RuntimeError, subprocess.SubprocessError)):
        process_host.native_no_new_privileges(123)


def _worker_evidence(host):
    account = SimpleNamespace(pw_uid=1701, pw_gid=1702)
    if host == 'freebsd':
        credentials = dict(ruid=1701, uid=1701, svuid=1701, rgid=1702, group=1702,
                           svgid=1702, groups=[1702])
        return account, dict(credentials=credentials, no_new_privileges=True)
    status = dict(Uid='1701 1701 1701 1701', Gid='1702 1702 1702 1702',
                  Groups='1702', NoNewPrivs='1')
    status.update({key: '0000000000000000' for key in
                   ('CapEff', 'CapPrm', 'CapBnd', 'CapInh', 'CapAmb')})
    return account, status


def _fault_worker_evidence(status, host, fault):
    if host == 'freebsd':
        record = status['credentials']
        if fault in ('uid', 'saved-uid', 'gid', 'saved-gid'):
            record[dict(uid='uid', **{'saved-uid': 'svuid', 'gid': 'group',
                                     'saved-gid': 'svgid'})[fault]] = 0
        elif fault == 'groups':
            record['groups'].append(0)
        elif fault == 'nnp':
            status['no_new_privileges'] = False
        return
    slot = {'uid': 'Uid', 'saved-uid': 'Uid', 'gid': 'Gid', 'saved-gid': 'Gid'}
    if fault in slot:
        values = status[slot[fault]].split()
        values[2 if fault.startswith('saved') else 1] = '0'
        status[slot[fault]] = ' '.join(values)
    elif fault == 'groups':
        status['Groups'] += ' 0'
    elif fault == 'nnp':
        status['NoNewPrivs'] = '0'


@pytest.mark.parametrize('host', ['freebsd', 'linux'])
@pytest.mark.parametrize('fault', ['none', 'uid', 'saved-uid', 'gid', 'saved-gid', 'groups', 'nnp'])
def test_worker_proof_checks_complete_native_identity_and_nnp(host, fault):
    import test_worker_deescalation_root as module

    account, status = _worker_evidence(host)
    _fault_worker_evidence(status, host, fault)
    if fault == 'none':
        module._assert_confined(status, account)
        return
    with pytest.raises(AssertionError):
        module._assert_confined(status, account)


@pytest.mark.parametrize('field', ['CapEff', 'CapPrm', 'CapBnd', 'CapInh', 'CapAmb'])
def test_linux_worker_proof_still_rejects_each_retained_capability_set(field):
    import test_worker_deescalation_root as module

    account, status = _worker_evidence('linux')
    status[field] = '00000000000000c0'
    with pytest.raises(AssertionError):
        module._assert_confined(status, account)


@pytest.mark.parametrize('fault', ['none', 'foreign-worker', 'no-workers', 'inspection-error'])
def test_worker_proof_inspects_every_worker_and_never_accepts_unknown(monkeypatch, fault):
    import test_worker_deescalation_root as module

    account, status = _worker_evidence('freebsd')
    _bad_account, bad_status = _worker_evidence('freebsd')
    bad_status['credentials']['svuid'] = 0
    workers = [] if fault == 'no-workers' else [status]
    if fault == 'foreign-worker':
        workers.append(bad_status)

    def inspect(_prefix):
        if fault == 'inspection-error':
            raise RuntimeError('unreadable native identity')
        return workers

    monkeypatch.setattr(module, '_worker_statuses', inspect)
    if fault == 'none':
        module._assert_workers_confined('/unused', account)
        return
    with pytest.raises((AssertionError, RuntimeError)):
        module._assert_workers_confined('/unused', account)
