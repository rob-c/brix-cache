"""Exact JWT clock boundaries using the real validator and a controlled clock."""

from pathlib import Path
import re
import subprocess

import pytest


@pytest.fixture(scope="module")
def clock_validator(tmp_path_factory):
    root = Path(__file__).resolve().parents[1]
    source = (root / "src/auth/token/validate.c").read_text()
    body = re.search(r'static int\ntoken_check_time_window\([^{}]+\n\{.*?\n\}', source, re.S)
    assert body
    directory = tmp_path_factory.mktemp("token-clock")
    program = directory / "clock.c"
    program.write_text('''
#include <stdint.h>
#include <time.h>
#include <stdlib.h>
typedef struct { int64_t exp, nbf; } claims_t;
typedef struct { claims_t *claims; int clock_skew; } brix_token_validate_args_t;
#define BRIX_LOG(...) ((void)0)
static time_t fixed_time(time_t *out) { if (out) *out = 1700000000; return 1700000000; }
#define time fixed_time
''' + body[0] + '''
int main(int argc, char **argv) {
    if (argc != 4) return 2;
    claims_t claims = {strtoll(argv[1], NULL, 10), strtoll(argv[2], NULL, 10)};
    brix_token_validate_args_t args = {&claims, atoi(argv[3])};
    return token_check_time_window(&args) == 0 ? 0 : 1;
}
''')
    binary = directory / "clock"
    result = subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                             str(program), "-o", str(binary)],
                            capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stdout + result.stderr
    return binary


@pytest.mark.parametrize("exp,nbf,skew,accepted", [
    (1700003600, 1700000000, 30, True),
    (1700003600, 1700000001, 30, False),
    (1699999970, 0, 30, True),
    (1699999969, 0, 30, False),
    (1699999999, 0, 0, False),
    (1700000000, 0, 0, True),
    (1700000001, 0, 0, True),
    (9223372036854775807, 0, 30, True),
    (9223372036854775807, 9223372036854775807, 30, False),
    (-9223372036854775808, 0, 30, False),
])
def test_exact_production_time_windows(clock_validator, exp, nbf, skew, accepted):
    result = subprocess.run([str(clock_validator), str(exp), str(nbf), str(skew)], timeout=5)
    assert result.returncode == (0 if accepted else 1)
