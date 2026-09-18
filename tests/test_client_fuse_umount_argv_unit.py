"""``brix_plat_fuse_umount_argv`` / ``brix_plat_umount_expire`` /
``brix_plat_fuse_host_opts``: the client PAL's unprivileged FUSE unmount
tiers, idle-expiry answer and host mount options on this host.

``xrd unmount`` and brixautofs used to spell fusermount3 / fusermount / umount
themselves; macFUSE has no fusermount and the owner unmounts with plain
umount.  The tier table lives in ``client/lib/platform/<host>/posix.c`` and
``tests/lib_py/fuse_host.py`` mirrors it for the Python tier, so this test
pins the two against each other.
"""
import os
import shutil
import subprocess
import sys

import pytest

from cmdscripts.compile_run import PLATFORM_HOST_FLAGS
from lib_py import fuse_host

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HOST = {"linux": "linux", "darwin": "darwin"}.get(sys.platform)

PROGRAM = r'''
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "platform/platform.h"

/* argv: tiers <lazy>  -> one line per tier "n: a b c";
 *       expire <path> -> "rc=.. errno=.." */
int main(int argc, char **argv)
{
    if (argc == 3 && strcmp(argv[1], "tiers") == 0) {
        int lazy = atoi(argv[2]), tier, n;
        char *av[BRIX_PLAT_UMOUNT_ARGV_MAX];
        for (tier = 0; (n = brix_plat_fuse_umount_argv("/mnt/x", lazy, tier, av)) > 0; tier++) {
            int i;
            if (av[n] != NULL) { printf("argv not NULL-terminated\n"); return 3; }
            printf("%d:", n);
            for (i = 0; i < n; i++) { printf(" %s", av[i]); }
            printf("\n");
        }
        printf("end:%d\n", brix_plat_fuse_umount_argv("/mnt/x", lazy, -1, av));
        return 0;
    }
    if (argc == 2 && strcmp(argv[1], "hostopts") == 0) {
        const char *o = brix_plat_fuse_host_opts();
        printf("%s\n", o ? o : "(none)");
        return 0;
    }
    if (argc == 3 && strcmp(argv[1], "expire") == 0) {
        int rc = brix_plat_umount_expire(argv[2]);
        printf("rc=%d errno=%d\n", rc, rc == 0 ? 0 : errno);
        return 0;
    }
    return 2;
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
    out = str(work / "umount_probe")
    sources = [os.path.join(REPO, "client", "lib", "platform", HOST, "posix.c")]
    build = subprocess.run([cc, "-std=gnu11", "-D_GNU_SOURCE", *PLATFORM_HOST_FLAGS,
                            "-Wall", "-Werror",
                            "-I", os.path.join(REPO, "client", "lib"),   # client umbrella first
                            "-I", os.path.join(REPO, "src"),
                            str(src), *sources, "-o", out],
                           capture_output=True, text=True, timeout=180)
    if build.returncode != 0:
        pytest.fail(f"probe failed to compile:\n{build.stderr}")
    return out


@pytest.fixture(scope="module")
def probe(tmp_path_factory):
    binary = _compile_probe(tmp_path_factory.mktemp("umount"))

    def call(*args):
        run = subprocess.run([binary, *args], capture_output=True, text=True,
                             timeout=30)
        assert run.returncode == 0, run.stdout + run.stderr
        return run.stdout

    return call


def _tiers(out):
    rows = [line.split(":", 1)[1].split() for line in out.splitlines()
            if not line.startswith("end:")]
    return rows


@pytest.mark.parametrize("lazy", [0, 1])
def test_tiers_match_the_python_mirror(probe, lazy):
    """success: the C tiers, in order, are exactly what lib_py.fuse_host says
    this host runs, each ending in the mount point."""
    got = _tiers(probe("tiers", str(lazy)))
    want = [tier + ["/mnt/x"] for tier in fuse_host.unmount_tiers(bool(lazy))]
    assert got == want


def test_a_tier_past_the_end_or_negative_is_zero(probe):
    """error: no such tier answers 0 (and the loop above stopped on it)."""
    out = probe("tiers", "0")
    assert out.strip().endswith("end:0")


def test_lazy_never_changes_the_tool_only_its_flag(probe):
    """security-negative: lazy detach may add a flag but must never switch
    the tool or drop the mount point, so a lazy request cannot be routed to
    an unexpected program."""
    plain = _tiers(probe("tiers", "0"))
    lazy = _tiers(probe("tiers", "1"))
    assert [t[0] for t in plain] == [t[0] for t in lazy]
    assert all(t[-1] == "/mnt/x" for t in plain + lazy)
    assert all(set(l) >= set(p) for p, l in zip(plain, lazy))


def test_expire_of_an_unmounted_path_is_refused_not_faked(probe, tmp_path):
    """error: unprivileged, or on a host without MNT_EXPIRE, expiry answers
    -1 with a real errno (EPERM / EINVAL), never a fabricated success."""
    import errno as e
    out = probe("expire", str(tmp_path))
    fields = dict(kv.split("=") for kv in out.split())
    assert int(fields["rc"]) == -1
    assert int(fields["errno"]) in (e.EPERM, e.EINVAL, e.ENOENT, e.EACCES)


def test_host_mount_opts_match_the_python_mirror(probe):
    """success + security-negative: the `-o` value every mount gets is the
    one the Python tier expects (Linux: none; macFUSE: noappledouble), and it
    is never an empty string, which libfuse would reject as a bad option."""
    got = probe("hostopts").strip()
    want = fuse_host.host_mount_opts() or "(none)"
    assert got == want
    assert got != ""

