"""``brix_plat_self_exe`` / ``brix_plat_boot_id``: process and boot identity
through the PAL on every host.

``xrd`` finds its sibling tools next to its own binary and brixautofs re-execs
itself; both read ``/proc/self/exe`` on Linux, which Darwin lacks
(``_NSGetExecutablePath``).  ``brixcvmfs repo`` records the boot id in its
transaction lock, which is ``/proc/sys/kernel/random/boot_id`` on Linux and
``kern.bootsessionuuid`` on Darwin.  The PAL bodies live in
``src/platform/<host>/process_wrapper.c`` and are linked by the client too.
"""
import os
import shutil
import subprocess
import sys

import pytest

from cmdscripts.compile_run import PLATFORM_HOST_FLAGS

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HOST = {"linux": "linux", "darwin": "darwin"}.get(sys.platform)

PROGRAM = r'''
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "platform/platform_api.h"

/* argv: exe|boot <cap> ; prints rc, errno and the value. */
int main(int argc, char **argv)
{
    char   buf[4096];
    size_t cap;
    int    rc;

    if (argc != 3) { return 2; }
    cap = (size_t) atoi(argv[2]);
    if (cap > sizeof(buf)) { return 2; }
    memset(buf, 'X', sizeof(buf));
    errno = 0;
    rc = strcmp(argv[1], "exe") == 0 ? brix_plat_self_exe(buf, cap)
                                     : brix_plat_boot_id(buf, cap);
    printf("rc=%d errno=%d value=%s\n", rc, rc == 0 ? 0 : errno,
           rc == 0 ? buf : "-");
    return 0;
}
'''


def _toolchain():
    """The C compiler for this POSIX host, or the pytest skip for not having one."""
    if HOST is None:
        pytest.skip("POSIX hosts only")
    cc = shutil.which("cc") or shutil.which("gcc")
    if cc is None:
        pytest.skip("no C compiler on PATH")
    return cc


def _compile_probe(work):
    cc = _toolchain()
    src = work / "probe.c"
    src.write_text(PROGRAM)
    out = str(work / "identity_probe")
    sources = [os.path.join(REPO, "src", "platform", HOST, "process_wrapper.c")]
    build = subprocess.run([cc, "-std=gnu11", "-D_GNU_SOURCE", *PLATFORM_HOST_FLAGS,
                            "-Wall", "-Werror", "-I", os.path.join(REPO, "src"),
                            str(src), *sources, "-o", out],
                           capture_output=True, text=True, timeout=180)
    if build.returncode != 0:
        pytest.fail(f"probe failed to compile:\n{build.stderr}")
    return out


@pytest.fixture(scope="module")
def probe(tmp_path_factory):
    binary = _compile_probe(tmp_path_factory.mktemp("identity"))

    def call(what, cap=4096):
        run = subprocess.run([binary, what, str(cap)], capture_output=True,
                             text=True, timeout=30)
        assert run.returncode == 0, run.stdout + run.stderr
        fields = dict(kv.split("=", 1) for kv in run.stdout.strip().split(" ", 2))
        return int(fields["rc"]), int(fields["errno"]), fields["value"]

    return binary, call


def test_self_exe_is_the_running_binary(probe):
    """success: an absolute, canonical path to the very file that is running."""
    binary, call = probe
    rc, err, value = call("exe")
    assert (rc, err) == (0, 0)
    assert os.path.isabs(value)
    assert os.path.samefile(value, binary)
    assert value == os.path.realpath(value), "not canonical"


def test_boot_id_is_a_stable_non_empty_token(probe):
    """success: a non-empty single-line id, identical across two reads."""
    _binary, call = probe
    rc, err, first = call("boot")
    assert (rc, err) == (0, 0)
    assert first and "\n" not in first and first != "unknown"
    assert call("boot")[2] == first


@pytest.mark.parametrize("what", ["exe", "boot"])
def test_a_short_buffer_is_enametoolong_not_a_truncated_answer(probe, what):
    """error + security-negative: a buffer that cannot hold the answer fails
    ENAMETOOLONG; a truncated path or id must never be returned as valid."""
    import errno as e
    _binary, call = probe
    rc, err, value = call(what, cap=4)
    assert (rc, err, value) == (-1, e.ENAMETOOLONG, "-")
