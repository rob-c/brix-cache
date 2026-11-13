"""Diagnostic JSON extraction remains bounded through escapes and nested data."""

import json
from pathlib import Path
import shutil
import subprocess

import pytest


@pytest.fixture(scope='module', params=['plain', 'sanitized'])
def json_binary(tmp_path_factory, request):
    """Compile the real libc-only scanner, with a separate sanitizer consumer."""
    compiler = shutil.which('cc')
    if compiler is None:
        pytest.skip('C compiler required')
    root = Path(__file__).resolve().parents[1]
    binary = tmp_path_factory.mktemp('json-min') / request.param
    flags = (['-fsanitize=address,undefined', '-fno-sanitize-recover=all']
             if request.param == 'sanitized' else [])
    result = subprocess.run([compiler, '-O1', '-g', '-Wall', '-Wextra', '-Werror',
        '-I' + str(root / 'src'), *flags,
        str(root / 'tests/c/json_min_native_test.c'),
        str(root / 'src/core/compat/json_min.c'), '-o', str(binary)],
        capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stdout + result.stderr
    return binary


def extract(binary, document, key='key', capacity=128, mode='normal'):
    """Keep the exact buffer, including embedded NULs and untouched tail bytes."""
    result = subprocess.run([str(binary), document, key, str(capacity), mode],
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr
    status, data = result.stdout.strip().split(':')
    return int(status), bytes.fromhex(data)


@pytest.mark.parametrize('value', ['', 'ordinary', '"\\/\b\f\n\r\t',
    '\x00after-nul', '\u007f\u0080\u07ff\u0800\uffff', '\U00010000\U0010ffff'])
@pytest.mark.parametrize('capacity', [1, 2, 3, 4, 8, 128])
def test_decoded_strings_match_python_with_bounded_output(json_binary, value, capacity):
    """ASCII, BMP and surrogate pairs preserve bytes within explicit truncation."""
    status, buffer = extract(json_binary, json.dumps({'key': value}), capacity=capacity)
    expected = value.encode()[:capacity - 1] + b'\0'
    assert status == 1
    assert buffer.startswith(expected)


@pytest.mark.parametrize('literal', ['true', 'false', 'null', '-12', '1.25e+10'])
@pytest.mark.parametrize('capacity', [1, 3, 128])
def test_scalar_tokens_are_raw_and_terminated(json_binary, literal, capacity):
    status, buffer = extract(json_binary, '{"key":' + literal + '}', capacity=capacity)
    assert status == 1
    assert buffer.startswith(literal.encode()[:capacity - 1] + b'\0')


@pytest.mark.parametrize('prefix', [
    {'ignored': 'quoted "key": "impostor"'},
    {'ignored': {'key': 'nested', 'array': ['[{}]', {'k': 'v'}]}},
    {'ignored': [True, None, ['escaped \\ \u1234 \U00010000']]},
    {'ignored': 12345},
])
def test_only_top_level_member_matches(json_binary, prefix):
    document = json.dumps({**prefix, 'key': 'top-level'})
    status, buffer = extract(json_binary, document)
    assert status == 1 and buffer.startswith(b'top-level\0')


@pytest.mark.parametrize('document', [
    '', ' ', '[]', 'false', '{}', '{', '{wrong:1}', '{"key"', '{"key" 1}',
    '{"key":', '{"key":"', '{"key":"\\', '{"key":"\\q"}',
    '{"key":"\\u"}', '{"key":"\\u123"}', '{"key":"\\u12g4"}',
    '{"wrong":"\\q","key":1}', '{"wrong":[1,2',
    '{"wrong":["\\q"],"key":1}', '{"wrong":{"key":1}}',
    '{"key":[]}', '{"key":{}}',
])
def test_missing_malformed_and_container_values_are_not_flat_strings(json_binary,
                                                                   document):
    assert extract(json_binary, document)[0] == 0


@pytest.mark.parametrize('mode', ['null-json', 'null-key', 'null-output'])
def test_null_arguments_do_not_write_output(json_binary, mode):
    status, buffer = extract(json_binary, '{"key":"value"}', mode=mode)
    assert status == 0 and buffer == b'\xa5' * 128


def test_zero_capacity_does_not_write_output(json_binary):
    assert extract(json_binary, '{"key":"value"}', capacity=0) == (0, b'')


@pytest.mark.parametrize('length', [127, 128, 129, 1024, 4096])
def test_oversized_keys_never_escape_bounded_key_buffer(json_binary, length):
    """Matching long keys must not compare beyond the scanner's private buffer."""
    key = 'k' * length
    status, buffer = extract(json_binary, json.dumps({key: 'value'}), key)
    assert status == (1 if length < 128 else 0)
    if status:
        assert buffer.startswith(b'value\0')


def test_skipped_oversized_key_does_not_hide_later_member(json_binary):
    document = json.dumps({'k' * 4096: ['nested'], 'key': 'later'})
    status, buffer = extract(json_binary, document)
    assert status == 1 and buffer.startswith(b'later\0')


@pytest.mark.parametrize('escape,expected', [
    ('\\uD800', '\ufffd'), ('\\uD800x', '\ufffdx'),
    ('\\uD800\\u0041', '\ufffdA'), ('\\u006b', 'k'),
])
def test_escape_boundaries_are_explicit(json_binary, escape, expected):
    status, buffer = extract(json_binary, '{"key":"' + escape + '"}')
    assert status == 1 and buffer.startswith(expected.encode() + b'\0')
