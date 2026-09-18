"""``brix_plat_fuse_opt_supported`` (client PAL): which libfuse mount-option
spellings the host's library accepts.  The mount apps drop the rest before
``fuse_main()`` so one ``-o`` string — the Linux one the docs and every test
use — mounts on macFUSE too, whose libfuse rejects ``auto_unmount`` outright
("fuse: unknown option(s)") although it unmounts on exit regardless."""
import os
import shutil
import subprocess
import sys

import pytest

from cmdscripts.compile_run import PLATFORM_HOST_FLAGS

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HOST = {"linux": "linux", "darwin": "darwin"}.get(sys.platform)
PROGRAM = r'''
#include <stdio.h>
#include "platform/platform.h"

int main(int argc, char **argv)
{
    for (int i = 1; i < argc; i++) {
        printf("%s=%d\n", argv[i], brix_plat_fuse_opt_supported(argv[i]));
    }
    printf("empty=%d\n", brix_plat_fuse_opt_supported(""));
    printf("null=%d\n", brix_plat_fuse_opt_supported(NULL));
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


@pytest.fixture(scope="module")
def probe(tmp_path_factory):
    cc = _toolchain()
    work = tmp_path_factory.mktemp("fuseopt")
    src = work / "probe.c"
    src.write_text(PROGRAM)
    out = str(work / "probe")
    build = subprocess.run(
        [cc, "-std=gnu11", "-D_GNU_SOURCE", *PLATFORM_HOST_FLAGS,
         f"-DBRIX_PLATFORM_{HOST.upper()}=1", "-Wall", "-Werror",
         "-I", os.path.join(REPO, "client", "lib"), "-I", os.path.join(REPO, "src"), str(src),
         os.path.join(REPO, "client", "lib", "platform", HOST, "posix.c"), "-o", out],
        capture_output=True, text=True, timeout=180)
    if build.returncode != 0:
        pytest.fail(f"probe failed to compile:\n{build.stderr}")

    def run(*opts):
        proc = subprocess.run([out, *opts], capture_output=True, text=True, timeout=30)
        assert proc.returncode == 0, proc.stderr
        return dict(line.rsplit("=", 1) for line in proc.stdout.split())

    return run


def test_portable_options_are_always_supported(probe):
    """success: the spellings every host's libfuse knows pass through."""
    wanted = ("attr_timeout=0", "entry_timeout=0", "ro", "allow_other")
    got = probe(*wanted)
    assert all(got[k] == "1" for k in wanted), got


def test_auto_unmount_follows_the_host_library(probe):
    """error path: the Linux-only element is dropped exactly where the library
    would reject it, and kept where it is meaningful."""
    got = probe("auto_unmount")
    assert got["auto_unmount"] == ("0" if HOST == "darwin" else "1")


def test_lookalikes_and_empties_are_not_silently_accepted(probe):
    """security-negative: filtering is exact-match — a spelling that merely
    starts with the dropped name still reaches libfuse (which will refuse it
    loudly rather than mount with an option silently discarded) — and an
    empty or NULL element is never reported as supported."""
    got = probe("auto_unmount_extra", "xauto_unmount")
    assert got["auto_unmount_extra"] == "1" and got["xauto_unmount"] == "1"
    assert got["empty"] == "0" and got["null"] == "0"
