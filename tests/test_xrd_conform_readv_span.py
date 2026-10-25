"""The conformance readv checker accepts the explicit span, including one item."""

from pathlib import Path
import re
import shutil
import subprocess

import pytest


@pytest.fixture(scope="module")
def span_checker(tmp_path_factory):
    compiler = shutil.which("cc")
    if compiler is None:
        pytest.skip("C compiler required for conformance readv contracts")
    root = Path(__file__).resolve().parents[1]
    source = (root / "client/apps/diag/xrd_conform_root_readv_limits.c").read_text()
    body = re.search(r'static int\nreadv_exact\([^{}]+\n\{.*?\n\}', source, re.S)
    assert body
    directory = tmp_path_factory.mktemp("readv-span")
    program = directory / "span.c"
    program.write_text('''
#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <sys/types.h>
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic error "-Wstringop-overflow"
#endif
typedef struct { int denied; } xrd_conform_execution;
typedef struct { const uint8_t *data; int corrupt; unsigned calls; } brix_conn;
typedef struct { int unused; } brix_file;
typedef struct { int unused; } brix_status;
typedef struct { void *buf; int64_t offset; size_t len, got; } brix_readv_seg;
static int xrd_conform_reserve(xrd_conform_execution *e, size_t n, char *r, size_t c) {
    (void)n; (void)r; (void)c; return !e->denied;
}
static void brix_status_clear(brix_status *s) { (void)s; }
static ssize_t brix_file_readv(brix_conn *c, brix_file *f,
    brix_readv_seg *segments, size_t count, brix_status *s) {
    size_t total = 0;
    (void)f; (void)s; c->calls++;
    for (size_t i = 0; i < count; i++) {
        memcpy(segments[i].buf, c->data + segments[i].offset, segments[i].len);
        segments[i].got = segments[i].len; total += segments[i].len;
    }
    if (c->corrupt) ((uint8_t *)segments[0].buf)[0] ^= 1;
    return (ssize_t)total;
}
''' + body[0] + '''
int main(int argc, char **argv) {
    const uint8_t expected[] = "abcdefgh";
    uint8_t output[8];
    xrd_conform_execution execution = {0};
    brix_conn connection = {expected, 0, 0};
    brix_file file = {0};
    brix_status status = {0};
    brix_readv_seg one = {output, 0, 4, 0};
    brix_readv_seg two[2] = {{output, 0, 4, 0}, {output + 4, 4, 4, 0}};
    int result;
    assert(argc == 2);
    execution.denied = strcmp(argv[1], "denied") == 0;
    connection.corrupt = strcmp(argv[1], "corrupt") == 0;
    if (strcmp(argv[1], "two") == 0)
        result = readv_exact(&execution, &connection, &file, two, 2, expected, &status);
    else
        result = readv_exact(&execution, &connection, &file, &one, 1, expected, &status);
    assert(result == !(execution.denied || connection.corrupt));
    assert(connection.calls == (unsigned)!execution.denied);
    return 0;
}
''')
    binary = directory / "span"
    built = subprocess.run([compiler, "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror",
                            str(program), "-o", str(binary)],
                           capture_output=True, text=True, timeout=30)
    assert built.returncode == 0, built.stdout + built.stderr
    return binary


@pytest.mark.parametrize("case", ["one", "two", "denied", "corrupt"])
def test_explicit_readv_span_and_refusals(span_checker, case):
    """One/two entries work; refused budgets and corrupt bytes never certify."""
    subprocess.run([str(span_checker), case], check=True, timeout=5)
