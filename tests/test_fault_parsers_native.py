"""Fault-injection parser output is bounded and preserves wire bytes exactly."""

import ipaddress
import json
from pathlib import Path
import struct
import subprocess

import pytest

from brix_suite.client_build import client_make, client_run
from test_xrd_dispatch_native import private_link_command


# pytest-timeout includes module-fixture setup in the first case. The two
# bounded build commands can each take 120 seconds on an instrumented SDK;
# retain the separate ten-second deadline for every parser invocation.
pytestmark = pytest.mark.timeout(300)


@pytest.fixture(scope='module')
def fault_parser(tmp_path_factory):
    root = Path(__file__).resolve().parents[1]
    output = tmp_path_factory.mktemp('fault-parsers')
    binary = output / 'brix-fault-proxy'
    plan = client_make(root / 'client', '-n', 'brix-fault-proxy', f'BINDIR={output}',
                       capture_output=True, text=True, timeout=120)
    assert plan.returncode == 0, plan.stdout + plan.stderr
    command = private_link_command(plan.stdout.replace('\\\n', ' '), binary)
    command += ['-Dmain=brix_fault_unused_main', str(root / 'tests/c/fault_parsers_native_test.c')]
    if '--coverage' in command:
        command.append('-O0')
    result = client_run(root / 'client', command, cwd=root / 'client',
                        capture_output=True, text=True, timeout=120)
    assert result.returncode == 0, result.stdout + result.stderr
    def invoke(operation, value, other='', capacity=4096, expected=0):
        result = subprocess.run([str(binary), operation, str(capacity), value, other, str(expected)],
                                capture_output=True, timeout=10)
        assert result.returncode == 0, result.stderr.decode(errors='replace')
        return result.stdout, result.stderr.decode()
    return invoke


@pytest.mark.parametrize('token,decoded', [('hex:', b''), ('hex:00aAfF19', b'\x00\xaa\xff\x19'),
    (r'str:a\r\n\t\0\\\x41\q', b'a\r\n\t\0\\Aq'), ('literal', b'literal'), ('str:slash\\', b'slash\\')])
def test_payload_decoding_preserves_embedded_bytes(fault_parser, token, decoded):
    output, _observed = fault_parser('payload', token, expected=len(decoded))
    assert output == decoded


@pytest.mark.parametrize('token', ['<null>', 'hex:0', 'hex:gg', 'str:\\x', 'str:\\x1', 'str:\\xZZ'])
def test_invalid_payload_is_refused(fault_parser, token):
    fault_parser('payload', token, expected=-1)


@pytest.mark.parametrize('token', ['hex:aabb', 'str:ab', 'ab'])
@pytest.mark.parametrize('capacity', [0, 1])
def test_payload_cannot_overrun_capacity(fault_parser, token, capacity):
    fault_parser('payload', token, capacity=capacity, expected=-1)


@pytest.mark.parametrize('mode,full', [('plain', b'abab!'), ('inject', b'prefixabab!'),
    ('rewrite', b'XYZXYZ!'), ('drop', b''), ('repeat', b'aabbaabb!!')])
@pytest.mark.parametrize('capacity', [0, 1, 4, 20])
def test_mutation_output_truncates_at_capacity(fault_parser, mode, full, capacity):
    expected = full[:capacity]
    output, stats = fault_parser('mutate', mode, capacity=capacity, expected=len(expected))
    assert output == expected
    if mode == 'drop':
        assert 'drop=5' in stats
    if mode == 'rewrite':
        assert 'replace=2' in stats


@pytest.mark.parametrize('source,dest,family', [('192.0.2.1', '192.0.2.2', 4),
                                            ('2001:db8::1', '2001:db8::2', 6)])
@pytest.mark.parametrize('version', [1, 2])
def test_proxy_header_preserves_addresses_and_port_boundaries(fault_parser, source, dest, family, version):
    source_spec, dest_spec = f'{source}:1', f'{dest}:65535'
    if family == 6:
        source_spec, dest_spec = f'[{source}]:1', f'[{dest}]:65535'
    expected = proxy_header(version, source, dest, family)
    output, _observed = fault_parser(f'v{version}', source_spec, dest_spec, expected=len(expected))
    assert output == expected


def proxy_header(version, source, dest, family):
    if version == 1:
        return f'PROXY TCP{family} {source} {dest} 1 65535\r\n'.encode()
    addresses = ipaddress.ip_address(source).packed + ipaddress.ip_address(dest).packed
    payload = addresses + struct.pack('!HH', 1, 65535)
    return b'\r\n\r\n\0\r\nQUIT\n' + bytes([0x21, 0x11 if family == 4 else 0x21]) + struct.pack('!H', len(payload)) + payload


@pytest.mark.parametrize('source', ['<null>', 'missing', ':1', '192.0.2.1:', '192.0.2.1:0',
    '192.0.2.1:65536', '[2001:db8::1]:1', '[broken:1', '[]:1', '[2001:db8::1]1',
    'not-an-ip:1', 'x' * 80 + ':1', '[' + 'x' * 80 + ']:1'])
@pytest.mark.parametrize('version', [1, 2])
def test_invalid_or_mixed_family_proxy_headers_are_refused(fault_parser, source, version):
    fault_parser(f'v{version}', source, '192.0.2.2:2', expected=-1)


@pytest.mark.parametrize('version', [1, 2])
@pytest.mark.parametrize('capacity', [0, 1, 27])
def test_proxy_header_requires_space_for_complete_record(fault_parser, version, capacity):
    fault_parser(f'v{version}', '192.0.2.1:1', '192.0.2.2:2', capacity=capacity, expected=-1)


@pytest.mark.parametrize('value', ['ascii', '\x01\b\f\n\r\t/\\"', 'é', '€', 'Aé€'])
def test_json_decodes_bmp_and_standard_escapes(fault_parser, value):
    output, _observed = fault_parser('get', json.dumps({'key': value}), 'key', expected=1)
    assert output == value.encode()


@pytest.mark.parametrize('value', ['"abcdef"', '"\\n"', '"\\u0041"', '"\\u00e9"', '"\\u20ac"'])
@pytest.mark.parametrize('capacity', [1, 2])
def test_json_string_refuses_insufficient_utf8_capacity(fault_parser, value, capacity):
    decoded = json.loads(value).encode()
    expected = 1 if len(decoded) < capacity else -1
    output, _observed = fault_parser('get', '{"key":' + value + '}', 'key', capacity, expected)
    if expected == 1:
        assert output == decoded


@pytest.mark.parametrize('value', ['5242880', '0.02', 'true', 'null', '-123'])
def test_bare_json_tokens_preserve_spelling(fault_parser, value):
    output, _observed = fault_parser('get', '{"ignored":"key", "key":' + value + ' \t}', 'key', expected=1)
    assert output == value.encode()


@pytest.mark.parametrize('value', ['[]', '{no}', '{"key" 1}', '{"key":}', '{"key":"unterminated}',
    '{"key":"\\q"}', '{"key":"\\uXX00"}', '{"key":"\\u12"}', '{"other":"\\q","key":1}',
    '{"other":1 junk', '{"' + 'k' * 64 + '":1,"key":2}'])
def test_malformed_json_is_refused(fault_parser, value):
    fault_parser('get', value, 'key', expected=-1)


@pytest.mark.parametrize('value', ['{}', '{"other":1}', '{"other":"text"}'])
def test_absent_key_is_distinct_from_malformed(fault_parser, value):
    output, _observed = fault_parser('get', value, 'key')
    assert output == b''


@pytest.mark.parametrize('value,expected', [({'cmd': 'clear'}, b'clear'),
    ({'cmd': 'latency', 'args': '9 up'}, b'latency 9 up')])
def test_json_command_projection_preserves_arguments(fault_parser, value, expected):
    output, _observed = fault_parser('verb', json.dumps(value))
    assert output == expected


@pytest.mark.parametrize('value', ['{}', '{"cmd":""}', '{"cmd":5}', '{"cmd":"clear","args":3}'])
def test_invalid_json_commands_are_rejected(fault_parser, value):
    fault_parser('verb', value, expected=-1)


def test_projected_command_cannot_overrun_output(fault_parser):
    fault_parser('verb', '{"cmd":"clear"}', capacity=3, expected=-1)
