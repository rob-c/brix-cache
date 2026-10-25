"""Linux openat2 retries transient proof races, finitely and fail-closed."""

from __future__ import annotations

import errno
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

from cmdscripts.compile_run import PLATFORM_HOST_FLAGS


REPO = Path(__file__).resolve().parents[1]
PROGRAM = r'''
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include "platform/platform_api.h"

static unsigned int calls;
static int behavior;

long test_syscall(long number, ...)
{
    (void) number;
    calls++;
    if (behavior == 0 && calls == 4) {
        return 123;
    }
    errno = behavior == 1 ? EACCES : EAGAIN;
    return -1;
}

int main(int argc, char **argv)
{
    int fd;

    if (argc != 2) {
        return 2;
    }
    behavior = atoi(argv[1]);
    fd = brix_plat_openat2(-1, "object", 0, 0, 0);
    printf("fd=%d errno=%d calls=%u\n", fd, fd < 0 ? errno : 0, calls);
    return 0;
}
'''


def _compiler():
    if sys.platform != "linux":
        pytest.skip("Linux openat2 PAL only")
    compiler = shutil.which("cc") or shutil.which("gcc")
    if compiler is None:
        pytest.skip("no C compiler on PATH")
    return compiler


def _compile_probe(work):
    compiler = _compiler()
    source = work / "probe.c"
    source.write_text(PROGRAM, encoding="utf-8")
    binary = work / "probe"
    build = subprocess.run(
        [
            compiler,
            "-std=gnu11",
            "-D_GNU_SOURCE",
            "-Dsyscall=test_syscall",
            *PLATFORM_HOST_FLAGS,
            "-Wall",
            "-Werror",
            "-I",
            str(REPO / "src"),
            str(source),
            str(REPO / "src/platform/linux/path_wrapper.c"),
            "-o",
            str(binary),
        ],
        capture_output=True,
        text=True,
        timeout=180,
    )
    assert build.returncode == 0, build.stderr
    return binary


def _result_fields(result):
    assert result.returncode == 0, result.stdout + result.stderr
    return {
        key: int(value)
        for key, value in (field.split("=") for field in result.stdout.split())
    }


@pytest.fixture(scope="module")
def probe(tmp_path_factory):
    binary = _compile_probe(tmp_path_factory.mktemp("openat2-retry"))

    def run(behavior):
        result = subprocess.run(
            [str(binary), str(behavior)],
            capture_output=True,
            text=True,
            timeout=5,
        )
        return _result_fields(result)

    return run


def test_transient_eagain_is_retried_until_success(probe):
    assert probe(0) == {"fd": 123, "errno": 0, "calls": 4}


def test_nontransient_error_is_not_retried(probe):
    assert probe(1) == {"fd": -1, "errno": errno.EACCES, "calls": 1}


def test_persistent_eagain_exhausts_a_finite_fail_closed_budget(probe):
    assert probe(2) == {"fd": -1, "errno": errno.EAGAIN, "calls": 64}
