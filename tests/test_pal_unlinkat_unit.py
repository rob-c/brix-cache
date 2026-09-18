"""``brix_plat_unlinkat``: Linux errno semantics for unlink on every host.

The delete fast path (``ns_delete_fast`` in ``src/core/compat/namespace_ops.c``)
and the async queue key their "unlink a file, rmdir a directory" fallback on
``EISDIR``.  Linux's ``unlinkat(2)`` answers exactly that; Darwin's answers
``EPERM``, which the wire layer reports as an authorization failure.  The PAL
primitive normalises the directory case so callers see one contract.
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
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "platform/platform_api.h"

int main(int argc, char **argv)
{
    int dirfd, rc;

    if (argc != 4) { return 2; }
    dirfd = open(argv[1], O_RDONLY | O_DIRECTORY);
    if (dirfd < 0) { perror("open"); return 2; }
    rc = brix_plat_unlinkat(dirfd, argv[2],
                            strcmp(argv[3], "rmdir") == 0 ? AT_REMOVEDIR : 0);
    printf("rc=%d errno=%d\n", rc, rc == 0 ? 0 : errno);
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
    """The probe binary linked against this host's PAL path primitives."""
    cc = _toolchain()
    src = work / "probe.c"
    src.write_text(PROGRAM)
    out = str(work / "probe")
    sources = [os.path.join(REPO, "src", "platform", HOST, "path_wrapper.c")]
    build = subprocess.run([cc, "-std=gnu11", "-D_GNU_SOURCE", *PLATFORM_HOST_FLAGS,
                            "-Wall", "-Werror", "-I", os.path.join(REPO, "src"),
                            str(src), *sources, "-o", out],
                           capture_output=True, text=True, timeout=180)
    if build.returncode != 0:
        pytest.fail(f"probe failed to compile:\n{build.stderr}")
    return out


@pytest.fixture(scope="module")
def probe(tmp_path_factory):
    binary = _compile_probe(tmp_path_factory.mktemp("unlinkat"))

    def call(parent, name, mode="unlink"):
        run = subprocess.run([binary, str(parent), name, mode], capture_output=True,
                             text=True, timeout=30)
        assert run.returncode == 0, run.stdout + run.stderr
        fields = dict(kv.split("=") for kv in run.stdout.split())
        return int(fields["rc"]), int(fields["errno"])

    return call


def test_unlink_removes_a_regular_file(probe, tmp_path):
    """success: a plain file goes away and the call reports 0."""
    (tmp_path / "f").write_text("x")
    assert probe(tmp_path, "f") == (0, 0)
    assert not (tmp_path / "f").exists()


def test_unlink_of_a_directory_is_eisdir_on_every_host(probe, tmp_path):
    """error: the directory contract callers rely on, whatever the kernel says."""
    (tmp_path / "d").mkdir()
    (tmp_path / "d" / "child").write_text("x")
    import errno as e
    assert probe(tmp_path, "d") == (-1, e.EISDIR)
    assert (tmp_path / "d" / "child").exists()
    assert probe(tmp_path, "d", "rmdir") == (-1, e.ENOTEMPTY)


def test_unlink_never_follows_a_symlink_to_a_directory(probe, tmp_path):
    """security-negative: the link itself is removed, the target survives, and
    a genuine permission failure is not rewritten as EISDIR."""
    import errno as e
    target = tmp_path / "target"
    target.mkdir()
    (target / "keep").write_text("x")
    os.symlink(target, tmp_path / "link")
    assert probe(tmp_path, "link") == (0, 0)
    assert (target / "keep").exists()
    assert probe(tmp_path, "missing") == (-1, e.ENOENT)
    if os.geteuid() == 0:
        pytest.skip("root bypasses directory write permission")
    locked = tmp_path / "locked"
    locked.mkdir()
    (locked / "f").write_text("x")
    locked.chmod(0o500)
    try:
        assert probe(locked, "f") == (-1, e.EACCES)
    finally:
        locked.chmod(0o700)
