"""Offline contracts for safe, portable stock-GSI fixture listeners."""
import ast
import ipaddress
import os
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace
from settings import HOST
import pytest


SOURCE = Path(__file__).with_name("test_native_gsi_interop.py")


def _readiness(connect):
    tree = ast.parse(SOURCE.read_text())
    helper = next(node for node in tree.body if isinstance(node, ast.FunctionDef)
                  and node.name == "_listener_ready")
    namespace = {"HOST": HOST,
                 "socket": SimpleNamespace(create_connection=connect),
                 "time": SimpleNamespace(sleep=lambda _: None)}
    exec(compile(ast.Module(body=[helper], type_ignores=[]), str(SOURCE), "exec"),
         namespace)
    return namespace["_listener_ready"]


def test_readiness_probes_the_reserved_port():
    calls = []

    def connect(address, timeout):
        calls.append((address, timeout))
        return nullcontext()

    assert _readiness(connect)(12345, SimpleNamespace(poll=lambda: None))
    assert calls == [((HOST, 12345), 0.2)]


def test_refused_listener_is_bounded():
    calls = []

    def refused(address, timeout):
        calls.append(address)
        raise ConnectionRefusedError()

    assert not _readiness(refused)(12345, SimpleNamespace(poll=lambda: None))
    assert calls == [(HOST, 12345)] * 50


@pytest.mark.parametrize('states,probes', [([1], 0), ([None, 1], 1)])
def test_exited_gsi_owner_cannot_be_replaced_by_a_foreign_listener(states, probes):
    calls = []
    status = iter(states)
    def connect(address, timeout):
        calls.append((address, timeout))
        return nullcontext()
    assert not _readiness(connect)(12345, SimpleNamespace(poll=lambda: next(status)))
    assert calls == [((HOST, 12345), 0.2)] * probes


@pytest.mark.parametrize('ready', [True, False])
def test_installed_gsi_reference_startup_failure_is_not_a_skip(ready):
    tree = ast.parse(SOURCE.read_text())
    helper = next(node for node in tree.body if isinstance(node, ast.FunctionDef)
                  and node.name == '_guard_gsi_server_6')
    namespace = {'pytest': pytest}
    exec(compile(ast.Module(body=[helper], type_ignores=[]), str(SOURCE), 'exec'), namespace)
    guard = namespace[helper.name]
    if ready:
        guard(True)
        return
    with pytest.raises(pytest.fail.Exception, match='installed stock xrootd GSI'):
        guard(False)


@pytest.mark.parametrize('host,family', [('127.0.0.1', 'v4'), ('::1', 'v6')])  # net-literal-allow: numeric address-family selection corpus, no network connection
def test_gsi_reference_command_matches_the_probed_address_family(host, family):
    from lib_py.reference_host import reference_listener_args
    tree = ast.parse(SOURCE.read_text())
    assignment = next(node for node in ast.walk(tree)
                      if isinstance(node, ast.Assign) and any(
                          isinstance(target, ast.Name) and target.id == 'argv'
                          for target in node.targets))
    namespace = dict(HOST=host, reference_listener_args=reference_listener_args,
                     cfg=Path('/fixture/config'), base=Path('/fixture'))
    command = eval(compile(ast.Expression(assignment.value), str(SOURCE), 'eval'), namespace)
    assert command == ['xrootd', '-I', family, '-c', '/fixture/config',
                       '-l', '/fixture/x.log', '-n', 'gsitest']


def test_fixture_cannot_kill_an_unrelated_listener():
    text = SOURCE.read_text()
    assert "port = free_port()" in text
    assert "fuser" not in text
    assert "ss -tln" not in text
    assert "PORT = 21094" not in text


def _gridftp_ready(probe):
    source = SOURCE.with_name('test_gridftp_delegate_xrootd.py')
    tree = ast.parse(source.read_text())
    helper = next(node for node in tree.body if isinstance(node, ast.FunctionDef)
                  and node.name == '_require_reference_ready')
    namespace = {'BIND_HOST': HOST, 'wait_tcp': probe, 'pytest': pytest}
    exec(compile(ast.Module(body=[helper], type_ignores=[]), str(source), 'exec'), namespace)
    assert 'ss -tln' not in source.read_text()
    return namespace['_require_reference_ready']


def _assert_gridftp_outcome(probe, server, ready):
    if ready:
        _gridftp_ready(probe)(server)
        return
    with pytest.raises(pytest.fail.Exception, match='reference log'):
        _gridftp_ready(probe)(server)


@pytest.mark.parametrize('alive,listening,expected_probes,expected_stops', [(True, True, 1, 0),
                                                                         (True, False, 1, 1),
                                                                         (False, True, 0, 1)])
def test_gridftp_readiness_accepts_only_a_live_owned_reference(alive, listening, expected_probes, expected_stops):
    """A foreign listener cannot bless an exited owned daemon or get killed."""
    probes, stopped = [], []
    def probe(host, port, timeout):
        probes.append((host, port, timeout))
        return listening
    server = SimpleNamespace(port=12345, _proc=SimpleNamespace(poll=lambda: None if alive else 1),
                             stop=lambda: stopped.append('owned'), log_text=lambda: 'reference log')
    _assert_gridftp_outcome(probe, server, expected_stops == 0)
    assert stopped == ['owned'] * expected_stops
    assert probes == [(HOST, 12345, 6.0)] * expected_probes


@pytest.mark.parametrize('host,family', [('127.0.0.1', 'v4'), ('::1', 'v6'),  # net-literal-allow: numeric address-family selection corpus, no network connection
                                       ('not-a-numeric-fixture-host', None)])
def test_gridftp_reference_listener_family_is_explicit(host, family):
    source = SOURCE.with_name('test_gridftp_delegate_xrootd.py')
    tree = ast.parse(source.read_text())
    helper = next(node for node in tree.body if isinstance(node, ast.FunctionDef)
                  and node.name == '_reference_command')
    namespace = {'BIND_HOST': host, 'ipaddress': ipaddress}
    exec(compile(ast.Module(body=[helper], type_ignores=[]), str(source), 'exec'), namespace)
    command = namespace['_reference_command']
    if family is None:
        with pytest.raises(ValueError):
            command('/fixture/config', '/fixture/log')
        return
    assert command('/fixture/config', '/fixture/log') == [
        'xrootd', '-I', family, '-c', '/fixture/config', '-l', '/fixture/log']


def _upstream_reader(**namespace):
    source = SOURCE.with_name('test_gridftp_delegate_xrootd.py')
    tree = ast.parse(source.read_text())
    helper = next(node for node in tree.body if isinstance(node, ast.FunctionDef)
                  and node.name == '_upstream_bytes')
    namespace.setdefault('os', os)
    exec(compile(ast.Module(body=[helper], type_ignores=[]), str(source), 'exec'), namespace)
    return namespace['_upstream_bytes']


def test_upstream_observer_preserves_exact_bytes(tmp_path):
    (tmp_path / 'object').write_bytes(b'payload')
    assert _upstream_reader()(SimpleNamespace(data=str(tmp_path)), 'object', 7) == b'payload'


def test_upstream_observer_preserves_missing_object(tmp_path):
    assert _upstream_reader()(SimpleNamespace(data=str(tmp_path)), 'absent', 7) is None


@pytest.mark.parametrize('actual_size', [6, 1 << 44], ids=['short', 'hostile-sparse-size'])
def test_upstream_observer_refuses_wrong_size_before_read(tmp_path, actual_size):
    """A malformed reference offset must fail, never allocate a sparse extent."""
    (tmp_path / 'object').touch()
    def forbidden(_size):
        raise AssertionError('read was attempted before size validation')
    handle = SimpleNamespace(fileno=lambda: 123, read=forbidden)
    operating_system = SimpleNamespace(path=os.path,
                                      fstat=lambda _fd: SimpleNamespace(st_size=actual_size))
    reader = _upstream_reader(os=operating_system, open=lambda *_args: nullcontext(handle))
    with pytest.raises(AssertionError, match='upstream object size differs'):
        reader(SimpleNamespace(data=str(tmp_path)), 'object', 7)


@pytest.mark.parametrize('change', ['exact', 'short', 'oversized'])
def test_roundtrip_checks_upstream_size_before_download(tmp_path, change):
    """A corrupt reference extent must fail before the client streams it."""
    source = SOURCE.with_name('test_gridftp_delegate_xrootd.py')
    tree = ast.parse(source.read_text())
    test = next(node for node in tree.body if isinstance(node, ast.FunctionDef)
                and node.name == 'test_stored_object_round_trips_back_through_the_gateway')
    calls = []
    upstream = tmp_path / 'rt.bin'
    def transfer(src, dst):
        calls.append((src, dst))
        if src.startswith('file://'):
            payload = Path(src.removeprefix('file://')).read_bytes()
            delta = {'exact': 0, 'short': -1, 'oversized': 1}[change]
            upstream.write_bytes((payload + b'x')[:len(payload) + delta])
        else:
            Path(dst.removeprefix('file://')).write_bytes(upstream.read_bytes())
        return SimpleNamespace(returncode=0, stderr='')
    namespace = dict(os=os, SERVER_HOST=HOST, _guc=transfer, _upstream_bytes=_upstream_reader())
    exec(compile(ast.Module(body=[test], type_ignores=[]), str(source), 'exec'), namespace)
    invoke = lambda: namespace[test.name](SimpleNamespace(port=12345),
                                          SimpleNamespace(data=str(tmp_path)), tmp_path)
    _assert_roundtrip_observation(invoke, change)
    assert len(calls) == {'exact': 2, 'short': 1, 'oversized': 1}[change]


def _assert_roundtrip_observation(invoke, change):
    if change == 'exact':
        invoke()
        return
    with pytest.raises(AssertionError, match='upstream object size differs'):
        invoke()


def _resilience_helper(name, **namespace):
    return _reference_helper('test_official_xrootd_resilience.py', name, **namespace)


def _reference_helper(filename, name, **namespace):
    source = SOURCE.with_name(filename)
    tree = ast.parse(source.read_text())
    helper = next(node for node in tree.body if isinstance(node, ast.FunctionDef)
                  and node.name == name)
    exec(compile(ast.Module(body=[helper], type_ignores=[]), str(source), 'exec'), namespace)
    return namespace[name]


@pytest.mark.parametrize('states,ready,probes,success', [
    ([None], True, 1, True), ([None], False, 50, False),
    ([1], True, 0, False), ([None, 1], True, 1, False)])
def test_resilience_reference_requires_a_live_owned_listener(states, ready, probes, success):
    observed = []
    def probe(port):
        observed.append(port)
        return ready
    def poll():
        return states.pop(0) if len(states) > 1 else states[0]
    process = SimpleNamespace(poll=poll, returncode=1)
    require = _resilience_helper('_require_reference_listener', _port_up=probe,
                                 pytest=pytest, time=SimpleNamespace(sleep=lambda _: None))
    if success:
        require(process, 12345)
    else:
        with pytest.raises(pytest.fail.Exception, match='installed xrootd'):
            require(process, 12345)
    assert observed == [12345] * probes


@pytest.mark.parametrize('host,family', [('127.0.0.1', 'v4'), ('::1', 'v6')])  # net-literal-allow: numeric address-family selection corpus, no network connection
def test_resilience_reference_uses_scoped_family_transport_and_process_group(tmp_path, host, family):
    from lib_py.reference_host import reference_listener_args, reference_transport_directives
    calls = []
    def spawn(argv, **options):
        calls.append((argv, options))
        return 'owned process'
    start = _resilience_helper('_start_reference', XROOTD='/fixture/xrootd', HOST=host,
        reference_listener_args=reference_listener_args,
        reference_transport_directives=lambda: reference_transport_directives('freebsd'),
        os=SimpleNamespace(geteuid=lambda: 2101),
        subprocess=SimpleNamespace(Popen=spawn, DEVNULL=-3))
    admin = tmp_path / 'short-owned-admin'
    assert start(tmp_path, admin, 12345) == 'owned process'
    argv, options = calls.pop()
    assert argv == ['/fixture/xrootd', '-I', family, '-c', str(tmp_path / 'xrootd.cfg'),
                    '-l', str(tmp_path / 'xrootd.log')]
    assert options == dict(stdout=-3, stderr=-3, start_new_session=True)
    config = (tmp_path / 'xrootd.cfg').read_text()
    assert f'all.adminpath {admin}\nall.pidpath {admin}\n' in config
    assert 'xrootd.async nosf\n' in config


def test_root_reference_preserves_private_control_permissions(tmp_path):
    from lib_py.reference_host import reference_listener_args
    root = tmp_path / 'export'
    root.mkdir()
    admin = tmp_path / 'owned-admin'
    admin.mkdir(mode=0o700)
    calls, ownership = [], []
    start = _resilience_helper('_start_reference', XROOTD='/fixture/xrootd', HOST=HOST,
        reference_listener_args=reference_listener_args,
        reference_transport_directives=lambda: '',
        os=SimpleNamespace(geteuid=lambda: 0, environ={'REF_RUNAS_USER': 'fixture-user'}),
        shutil=SimpleNamespace(chown=lambda path, user: ownership.append((path, user))),
        subprocess=SimpleNamespace(Popen=lambda argv, **_options: argv, DEVNULL=-3,
            run=lambda argv, **_options: calls.append(argv)))
    argv = start(root, admin, 12345)
    assert argv[-2:] == ['-R', 'fixture-user']
    assert ownership == [(admin, 'fixture-user')]
    assert calls == [['chmod', '-R', 'a+rwX', str(root)]]
    assert admin.stat().st_mode & 0o777 == 0o700


@pytest.mark.parametrize('filename', ['test_tpc_gsi_outbound.py',
    'test_krb5_xrootd_interop.py', 'test_krb5_cache_origin_e2e.py'])
@pytest.mark.parametrize('host,family', [('127.0.0.1', 'v4'), ('::1', 'v6')])  # net-literal-allow: numeric address-family selection corpus, no network connection
def test_auth_reference_launchers_pin_the_probed_address_family(filename, host, family):
    """All real GSI/Kerberos reference launchers share numeric family selection."""
    from lib_py.reference_host import reference_listener_args
    source = SOURCE.with_name(filename)
    expression = next(node for node in ast.walk(ast.parse(source.read_text()))
                      if _contains_reference_family(node))
    namespace = dict(HOST=host, reference_listener_args=reference_listener_args,
        xrootd='xrootd', cfg=Path('/fixture/config'), config=Path('/fixture/config'),
        log_path=Path('/fixture/log'), paths={'logs': Path('/fixture')})
    command = eval(compile(ast.Expression(expression), str(source), 'eval'), namespace)
    assert command[:5] == ['xrootd', '-I', family, '-c', '/fixture/config']


def _contains_reference_family(node):
    return isinstance(node, ast.List) and any(_is_reference_family(item) for item in node.elts)


def _is_reference_family(item):
    return (isinstance(item, ast.Starred) and isinstance(item.value, ast.Call)
            and isinstance(item.value.func, ast.Name)
            and item.value.func.id == 'reference_listener_args')


@pytest.mark.parametrize('status,listening,ready,probes', [
    (None, True, True, 1), (None, False, False, 1), (1, True, False, 0)])
def test_tpc_reference_startup_never_skips_or_accepts_an_exited_owner(
        monkeypatch, status, listening, ready, probes):
    """Installed TPC source failures are visible and cannot borrow a foreign port."""
    from lib_py.reference_host import reference_listener_ready
    from lib_py import util
    owner, calls = SimpleNamespace(), []
    monkeypatch.setattr(util, 'wait_tcp', lambda host, port, timeout: calls.append(port) or listening)
    process = SimpleNamespace(poll=lambda: status)
    start = _reference_helper('test_tpc_gsi_outbound.py', '_start_gsi_source',
        HOST=HOST, reference_listener_args=lambda _host: ['-I', 'v4'],
        _gsi_source_argv=lambda _base, _paths, argv: argv,
        subprocess=SimpleNamespace(Popen=lambda *_args, **_options: process, DEVNULL=-3),
        reference_listener_ready=reference_listener_ready, pytest=pytest)
    invoke = lambda: start(Path('/fixture'), {'logs': Path('/fixture')},
                           Path('/fixture/config'), 12345, owner)
    _assert_installed_start(invoke, ready)
    assert owner.process is process
    assert calls == [12345] * probes


@pytest.mark.parametrize('status,listening,ready,probes,retirements', [
    (None, True, True, 1, []), (None, False, False, 1, ['process', 'directory']),
    (1, True, False, 0, ['process', 'directory'])])
def test_kerberos_origin_failed_start_retires_only_its_owned_resources(
        monkeypatch, status, listening, ready, probes, retirements):
    """A failure before fixture yield still reaps its daemon and control directory."""
    from lib_py.reference_host import reference_listener_ready
    from lib_py import util
    process, retired, calls = SimpleNamespace(poll=lambda: status), [], []
    monkeypatch.setattr(util, 'wait_tcp', lambda host, port, timeout: calls.append(port) or listening)
    start = _reference_helper('test_krb5_cache_origin_e2e.py', '_start_ready_origin',
        _start_origin=lambda _path: (process, 12345, 'log', 'data', '/owned-control'),
        reference_listener_ready=reference_listener_ready,
        _origin_log_tail=lambda _log: 'owned reference log',
        _stop_origin=lambda owned: retired.append(('process', owned)),
        shutil=SimpleNamespace(rmtree=lambda path: retired.append(('directory', path))),
        HOST=HOST, time=SimpleNamespace(time=lambda: 0), pytest=pytest)
    _assert_installed_start(lambda: start('/fixture'), ready)
    assert [kind for kind, _value in retired] == retirements
    for kind, value in retired:
        assert value == {'process': process, 'directory': '/owned-control'}[kind]
    assert calls == [12345] * probes


def _assert_installed_start(invoke, ready):
    if ready:
        invoke()
        return
    with pytest.raises(pytest.fail.Exception, match='installed'):
        invoke()


@pytest.mark.parametrize('after,expected', [(None, True), (1, False)])
def test_shared_reference_readiness_rechecks_the_owner_after_tcp(monkeypatch, after, expected):
    """A dying child plus an unrelated listening socket must still be refused."""
    from lib_py.reference_host import reference_listener_ready
    from lib_py import util
    calls, states = [], iter([None, after])
    monkeypatch.setattr(util, 'wait_tcp', lambda host, port, timeout: calls.append(port) or True)
    process = SimpleNamespace(poll=lambda: next(states))
    assert reference_listener_ready(process, HOST, 12345, timeout=6) is expected
    assert calls == [12345]
