"""Check Linux ARM64 vector kernels against independent scalar oracles."""

from functools import reduce
import operator
from pathlib import Path
import platform
import subprocess
import sys
import zlib

import pytest

from test_platform_linux_native import native_compile  # noqa: F401

pytestmark = pytest.mark.skipif(
    sys.platform != 'linux' or platform.machine() not in ('aarch64', 'arm64'),
    reason='native Linux ARM64 checksum kernels')


@pytest.fixture(scope='module', params=['baseline', 'crc'])
def checksum_binary(native_compile, request):
    """Compile software and optional CRC instruction paths from production C."""
    if request.param == 'crc' and 'crc32' not in Path('/proc/cpuinfo').read_text():
        pytest.skip('CPU does not advertise ARM CRC32 instructions')
    root = Path(__file__).resolve().parents[1]
    architecture = 'armv8-a+crc' if request.param == 'crc' else 'armv8-a'
    return native_compile('arm64-checksum-' + request.param,
        (root / 'tests/c/arm64_checksum_native_test.c').read_text(),
        ['src/platform/linux/checksum_neon.c', 'src/platform/linux/arm64_crypto.c',
         'src/core/compat/crc32c.c', 'src/core/compat/crc32c_hw.c'],
        ['-march=' + architecture])


def raw_crc(data, seed):
    """Independent reflected Castagnoli recurrence, without final complement."""
    crc = seed & 0xffffffff
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ (0x82f63b78 if crc & 1 else 0)
    return crc


def fletcher(data):
    """Fletcher's two sequential modulo-255 sums."""
    first, second = 0, 0
    for byte in data:
        first = (first + byte) % 255
        second = (second + first) % 255
    return (second << 8) | first


def expected_checksum(name, data, seed):
    """Use standard Adler and independent numeric definitions for every family."""
    words = [int.from_bytes(data[index:index + 8], 'little')
             for index in range(0, len(data), 8)]
    oracles = {
        'adler': lambda: zlib.adler32(data, seed),
        'fletcher': lambda: fletcher(data),
        'xor': lambda: reduce(operator.xor, words, seed),
        'copy-crc': lambda: raw_crc(data, seed ^ 0xffffffff) ^ 0xffffffff,
        'byte-sum': lambda: sum(data) & 0xffffffff,
        'raw-crc': lambda: raw_crc(data, seed),
        'dispatch-crc': lambda: raw_crc(data, seed),
        'word-sum': lambda: sum(words) & 0xffffffffffffffff,
    }
    return oracles[name]()


def invoke(binary, operation, length=0, seed=0):
    """Surface native assertion failures and guard-page faults directly."""
    result = subprocess.run([str(binary), operation, str(length), str(seed)],
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr
    return result.stdout.strip()


@pytest.mark.parametrize('operation', ['adler', 'fletcher', 'xor', 'copy-crc',
    'byte-sum', 'raw-crc', 'dispatch-crc', 'word-sum'])
@pytest.mark.parametrize('length', [0, 1, 7, 8, 15, 16, 17, 31, 32, 33,
                                     63, 64, 65, 4095, 4096, 4097, 65537])
@pytest.mark.parametrize('seed', [1, 0x89abcdef])
def test_vectors_tails_and_seeds(checksum_binary, operation, length, seed):
    """Vector and scalar paths agree, retain the seed, and respect guarded tails."""
    data = bytes((index * 37 + 19) & 255 for index in range(length))
    actual = int(invoke(checksum_binary, operation, length, seed))
    assert actual == expected_checksum(operation, data, seed)


def test_feature_detection_is_stable(checksum_binary):
    """Lazy detection and explicit initialization describe the actual CPU."""
    assert invoke(checksum_binary, 'features') == 'features ok'


def test_crc_oracle_matches_castagnoli_check_value():
    """The independent recurrence must match the published standard check word."""
    assert raw_crc(b'123456789', 0xffffffff) ^ 0xffffffff == 0xe3069283
