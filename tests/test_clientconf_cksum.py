"""
Client-conformance: xrdadler32 + xrdcrc32c (differential vs stock).

Both checksum tools share one case shape (``cksum_cases.cases_for``); parity is
on the checksum VALUE plus rc.  Each tool runs through the runner independently.
"""

from pathlib import Path
import os
import subprocess
from types import SimpleNamespace
import zlib

import pytest

from csource_scan import function_body
from clientconf import runner
from clientconf.cases import cksum_cases
from clientconf.diffcore import OURS, STOCK, run_client
from clientconf.fixtures import clientconf_env  # noqa: F401
from settings import DATA_ROOT

pytestmark = pytest.mark.timeout(240)

_ADLER = runner.expand(cksum_cases.cases_for("xrdadler32"))
_CRC = runner.expand(cksum_cases.cases_for("xrdcrc32c"))


@pytest.mark.parametrize("param", _ADLER, ids=runner.ids(_ADLER))
def test_xrdadler32(param, clientconf_env, tmp_path):  # noqa: F811
    runner.run_param("xrdadler32", param, tmp_path, clientconf_env)


@pytest.mark.parametrize("param", _CRC, ids=runner.ids(_CRC))
def test_xrdcrc32c(param, clientconf_env, tmp_path):  # noqa: F811
    runner.run_param("xrdcrc32c", param, tmp_path, clientconf_env)


def test_token_checksum_profile_is_available(clientconf_env):  # noqa: F811
    """A broken managed auth tier must not silently skip 44 checksum cases."""
    endpoint = clientconf_env['endpoints']['token']
    result = run_client(STOCK, 'xrdfs', [endpoint.url(), 'stat', '/clientconf'],
                        endpoint, timeout=20)
    assert result.rc == 0, result.stderr[:4096]
    assert 'token' in clientconf_env['healthy']


@pytest.mark.parametrize("reference", ["01234567 /path", "", "unsupported"])
def test_checksum_reference_limit_cannot_skip_our_assertion(reference):
    """A supported BriX digest stays checked when the reference cannot answer."""
    results = _checksum_results("01234567 /path", reference)
    cksum_cases._post_cksum_value(None, None, results, expected="01234567")


@pytest.mark.parametrize("ours", ["", "unsupported", "deadbeef /path",
                                  "unsupported 01234567 /path"])
def test_checksum_refusal_or_wrong_value_is_a_failure(ours):
    """Neither side's unsupported diagnostic may conceal a BriX regression."""
    results = _checksum_results(ours, "unsupported")
    results["ours"].rc = 1
    with pytest.raises(AssertionError):
        cksum_cases._post_cksum_value(None, None, results, expected="01234567")


def test_checksum_reference_disagreement_is_a_failure():
    """An available independent digest remains a required parity check."""
    results = _checksum_results("01234567 /path", "89abcdef /path")
    with pytest.raises(AssertionError, match="checksum value differs"):
        cksum_cases._post_cksum_value(None, None, results, expected="01234567")


@pytest.mark.parametrize("output", ["unable to open 01234567", "path 01234567",
                                   "adler32 01234567"])
def test_checksum_filename_cannot_supply_the_digest(output):
    """A successful exit cannot bless a hex filename or an error diagnostic."""
    with pytest.raises(AssertionError, match="produced no checksum"):
        cksum_cases._post_cksum_value(None, None, _checksum_results(output, "unsupported"),
                                      expected="01234567")


def _checksum_results(ours, reference):
    """Model completed CLI results without starting a client or server."""
    return {which: SimpleNamespace(stdout=value, stderr="", rc=0)
            for which, value in (("ours", ours), ("stock", reference))}


@pytest.mark.parametrize("algorithm,path,error", [
    ("brix-unsupported", "/clientconf/spaces are ok.bin", "unknown checksum algorithm"),
    ("adler32", "/clientconf/missing name:checksum.bin", "notfound"),
])
def test_checksum_path_errors_remain_errors(clientconf_env, algorithm, path, error):  # noqa: F811
    """Path punctuation must not bypass algorithm or missing-file errors."""
    endpoint = clientconf_env["endpoints"]["anon"]
    result = run_client(OURS, "xrdfs", [endpoint.url(), "cksum", "-a", algorithm, path],
                        endpoint, timeout=20)
    assert result.rc != 0, result.stdout
    assert error in result.stderr.lower(), result.stderr


def test_checksum_path_punctuation_cannot_escape_export(clientconf_env, tmp_path):  # noqa: F811
    """A space/colon path cannot turn a traversal into an outside checksum."""
    outside = tmp_path / "outside secret:checksum.bin"
    payload = b"private bytes outside the endpoint export"
    outside.write_bytes(payload)
    path = "/" + os.path.relpath(outside, DATA_ROOT)
    assert ".." in Path(path).parts, "negative fixture must be outside the export"
    endpoint = clientconf_env["endpoints"]["anon"]
    result = run_client(OURS, "xrdfs", [endpoint.url(), "cksum", "-a", "adler32", path],
                        endpoint, timeout=20)
    assert result.rc != 0, result.stdout
    assert f"{zlib.adler32(payload):08x}" not in result.stdout
    assert outside.read_bytes() == payload


@pytest.fixture(scope="module")
def checksum_prefix_probe(tmp_path_factory):
    """Compile the actual bounded parser, with both memory/error sanitizers."""
    directory = tmp_path_factory.mktemp("checksum-prefix")
    root = Path(__file__).resolve().parents[1]
    source = root / "src/protocols/root/query/checksum_qcksum_path.c"
    signature = "static ngx_flag_t brix_qcksum_find_algo_sep(const u_char *payload, " \
                "size_t payload_len, size_t *sep_off, size_t *alg_len)"
    code = _PREFIX_PREAMBLE + signature + function_body(
        source.read_text(), "brix_qcksum_find_algo_sep") + _PREFIX_MAIN
    program, binary = directory / "probe.c", directory / "probe"
    program.write_text(code)
    result = subprocess.run(["cc", "-std=c11", "-D_POSIX_C_SOURCE=200809L",
                             "-Wall", "-Wextra", "-Werror", "-fsanitize=address,undefined",
                             "-fno-sanitize-recover=all", str(program), "-o", str(binary)],
                            capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stdout + result.stderr
    return binary


@pytest.mark.parametrize("payload,separator", [
    (b"/spaces are ok.bin", None), (b"/adler32:secret", None),
    (b"/a /../secret", None), (b"//a:b c?cks.type=crc32c", None),
    (b"dir/space colon:name", None), (b"file?opaque=has space:colon", None),
    (b"adler32:/spaces are ok.bin", 7), (b"crc32c /a:b c", 6),
    (b"unknown:/file", 7), (b"unknown /file", 7),
    (b"adler32\0:/file", None), (b"/a\0crc32c /file", None),
    (b"", None), (b"x", None), (b"x" * 1024, None),
])
def test_checksum_prefix_respects_path_and_wire_bounds(checksum_prefix_probe,
                                                       payload, separator):
    """Path punctuation cannot select an algorithm or escape the wire bound."""
    expected = -1 if separator is None else separator
    result = subprocess.run([str(checksum_prefix_probe), str(len(payload)), str(expected)],
                            input=payload, capture_output=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr


_PREFIX_PREAMBLE = r'''
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef unsigned char u_char;
typedef int ngx_flag_t;
'''

_PREFIX_MAIN = r'''
int main(int argc, char **argv) {
    assert(argc == 3);
    size_t length = strtoul(argv[1], NULL, 10);
    long expected = strtol(argv[2], NULL, 10);
    u_char *payload = malloc(length ? length : 1);
    assert(payload != NULL && fread(payload, 1, length, stdin) == length);
    size_t separator = 99, algorithm = 99;
    int found = brix_qcksum_find_algo_sep(payload, length, &separator, &algorithm);
    assert(found == (expected >= 0));
    assert(separator == (expected >= 0 ? (size_t) expected : 0));
    assert(algorithm == separator);
    free(payload);
    return 0;
}
'''
