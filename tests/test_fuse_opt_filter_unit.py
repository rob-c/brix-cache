"""``brix_plat_fuse_opt_supported`` (client PAL): which libfuse mount-option
spellings the host's library accepts.  The mount apps drop the rest before
``fuse_main()`` so one ``-o`` string — the Linux one the docs and every test
use — mounts on macFUSE too, whose libfuse rejects ``auto_unmount`` outright
("fuse: unknown option(s)") although it unmounts on exit regardless."""
import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

from cmdscripts.compile_run import compile_binary, library_compile_args, platform_host_name
from test_platform_linux_native import native_compile

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HOST = platform_host_name()
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
    printf("native_nodev=%d\n", BRIX_HAS_FUSE_NODEV);
    return 0;
}
'''


def _toolchain():
    """The C compiler for this POSIX host, or the pytest skip for not having one."""
    if HOST not in ('linux', 'darwin', 'freebsd'):
        pytest.skip("POSIX hosts only")
    cc = shutil.which("cc") or shutil.which("gcc")
    if cc is None:
        pytest.skip("no C compiler on PATH")
    return cc


@pytest.fixture(scope="module")
def probe(tmp_path_factory):
    _toolchain()
    work = tmp_path_factory.mktemp("fuseopt")
    src = work / "probe.c"
    src.write_text(PROGRAM)
    out = str(work / "probe")
    build = compile_binary(Path(out),
        ["-std=gnu11", "-D_GNU_SOURCE", "-Wall", "-Werror",
         "-I", os.path.join(REPO, "client", "lib"), "-I", os.path.join(REPO, "src"), str(src),
         os.path.join(REPO, "client", "lib", "platform", HOST, "posix.c"),
         *([os.path.join(REPO, "client/lib/platform/fuse_bsd.c")]
           if HOST in ("darwin", "freebsd") else [])], cwd=Path(REPO))
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
    assert got["auto_unmount"] == ("0" if HOST in ("darwin", "freebsd") else "1")


def test_lookalikes_and_empties_are_not_silently_accepted(probe):
    """security-negative: filtering is exact-match — a spelling that merely
    starts with the dropped name still reaches libfuse (which will refuse it
    loudly rather than mount with an option silently discarded) — and an
    empty or NULL element is never reported as supported."""
    got = probe("auto_unmount_extra", "xauto_unmount")
    assert got["auto_unmount_extra"] == "1" and got["xauto_unmount"] == "1"
    assert got["empty"] == "0" and got["null"] == "0"


def test_native_device_mount_option_matches_the_kernel(probe):
    """FreeBSD relies on its non-devfs device policy, not a fabricated flag."""
    assert probe()['native_nodev'] == ('0' if HOST == 'freebsd' else '1')


@pytest.fixture(scope='module')
def readonly_statfs_probe(native_compile):
    """Pin BriX's callback before the kernel applies its preferred I/O size."""
    from cmdscripts.cvmfs_driver_units import _fuse3_flags

    available, flags, _libraries, reason = _fuse3_flags()
    if not available:
        pytest.skip(reason)
    return native_compile('cvmfs-readonly-statfs', r'''
#include <assert.h>
#include <string.h>
#include <sys/statvfs.h>
extern int brixcvmfs_op_statfs(const char *, struct statvfs *);
int main(int argc, char **argv) {
    assert(argc == 2);
    struct statvfs value;
    memset(&value, 0xa5, sizeof(value));
    assert(brixcvmfs_op_statfs(argv[1], &value) == 0);
    assert(value.f_bsize == 4096 && value.f_frsize == 4096);
    assert(value.f_bfree == 0 && value.f_bavail == 0);
    assert(value.f_blocks == 0 && value.f_files == 0 && value.f_ffree == 0);
    assert(value.f_namemax == 255);
    return 0;
}
''', ['client/apps/fs/brixcvmfs_ops.c'],
        [*flags, '-ffunction-sections', '-fdata-sections', '-Wl,--gc-sections'],
        include_dirs=[Path(REPO) / 'client/lib', Path(REPO) / 'shared'])


@pytest.mark.parametrize('path', ['/', '/missing', '../' * 1024])
def test_readonly_statfs_units_and_capacity_never_depend_on_path(readonly_statfs_probe, path):
    result = subprocess.run([str(readonly_statfs_probe), path],
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.fixture(scope='module')
def automount_shutdown_probe(native_compile):
    """Execute the real control thread with an unmount/exit ordering oracle."""
    from cmdscripts.cvmfs_driver_units import _fuse3_flags

    available, flags, _libraries, reason = _fuse3_flags()
    if not available:
        pytest.skip(reason)
    return native_compile('automount-shutdown', r'''
#include <assert.h>
#define FUSE_USE_VERSION 31
#include <fuse3/fuse.h>
#include <pthread.h>
static int probe_create(pthread_t *, const pthread_attr_t *, void *(*)(void *), void *);
static int probe_join(pthread_t, void **);
static int probe_cancel(pthread_t);
static int probe_loop(struct fuse *, int);
static void probe_unmount(struct fuse *);
static void probe_destroy(struct fuse *);
#define pthread_create probe_create
#define pthread_join probe_join
#define pthread_cancel probe_cancel
#undef fuse_loop_mt
#define fuse_loop_mt probe_loop
#define fuse_unmount probe_unmount
#define fuse_destroy probe_destroy
#include "client/apps/fs/brixautofs_ext.c"

autofs_state_t g_af;
static int exited;
static int unmounts;
static int expected_unmounts;
static int refuse_unmount;
static int failed_create;
static int create_calls;
static int joins;
static int cancels;
static int library_unmounts;
static int destroyed;

static int probe_create(pthread_t *thread, const pthread_attr_t *attributes,
                        void *(*entry)(void *), void *argument) {
    (void) attributes; (void) entry; (void) argument;
    memset(thread, 0, sizeof(*thread));
    create_calls++;
    return create_calls == failed_create ? EAGAIN : 0;
}
static int probe_join(pthread_t thread, void **result) {
    (void) thread; (void) result;
    joins++;
    return 0;
}
static int probe_cancel(pthread_t thread) {
    (void) thread;
    cancels++;
    return 0;
}
static int probe_loop(struct fuse *session, int clone_descriptor) {
    (void) session; (void) clone_descriptor;
    assert(failed_create != 1);
    return 0;
}
static void probe_unmount(struct fuse *session) { (void) session; library_unmounts++; }
static void probe_destroy(struct fuse *session) { (void) session; destroyed++; }

void af_log(const char *format, ...) { (void) format; }
int brixautofs_find_pid_locked(brixautofs_table_t *table, pid_t pid) {
    (void) table; (void) pid;
    return -1;
}
void brixautofs_release_locked(brixautofs_table_t *table, int slot) {
    memset(&table->slot[slot], 0, sizeof(table->slot[slot]));
}
void af_child_path(const char *name, char *output, size_t capacity) {
    snprintf(output, capacity, "/owned/farm/%s", name);
}
int af_is_mounted(const char *path) { (void) path; return 0; }
int af_umount_path(const char *path) {
    /* A real FreeBSD unmount needs the event loop to answer FUSE_DESTROY. */
    assert(!exited);
    const char *expected = expected_unmounts == 2 && unmounts == 0
        ? "/owned/farm/repo.test" : "/owned/umbrella";
    assert(strcmp(path, expected) == 0);
    unmounts++;
    return refuse_unmount ? -1 : 0;
}
void fuse_exit(struct fuse *session) {
    assert(session == g_af.fuse);
    assert(unmounts == expected_unmounts);
    exited++;
}
int main(int argc, char **argv) {
    assert(argc == 2);
    memset(&g_af, 0, sizeof(g_af));
    assert(pthread_mutex_init(&g_af.tab.mu, NULL) == 0);
    strcpy(g_af.mnt, "/owned/umbrella");
    assert(pipe(g_af.sigpipe) == 0);
    if (strncmp(argv[1], "start-", 6) == 0) {
        int no_idle = strcmp(argv[1], "start-no-idle") == 0;
        failed_create = strcmp(argv[1], "start-control-error") == 0 ? 1
            : strcmp(argv[1], "start-idle-error") == 0 ? 2 : 0;
        g_af.o.idle_s = no_idle ? 0 : 60;
        assert(af_run() == (failed_create == 1));
        assert(create_calls == (failed_create == 1 || no_idle ? 1 : 2));
        int have_idle = !failed_create && !no_idle;
        assert(joins == (failed_create == 1 ? 0 : 1 + have_idle));
        assert(cancels == have_idle);
        assert(library_unmounts == 1 && destroyed == 1);
        if (failed_create == 1) {
            assert(fcntl(g_af.sigpipe[0], F_GETFD) == -1 && errno == EBADF);
        } else { close(g_af.sigpipe[0]); }
        pthread_mutex_destroy(&g_af.tab.mu);
        return 0;
    }
    int eof = strcmp(argv[1], "eof") == 0;
    int child = strcmp(argv[1], "child") == 0;
    expected_unmounts = eof ? 0 : child ? 2 : 1;
    refuse_unmount = strcmp(argv[1], "refused") == 0;
    if (child) {
        g_af.tab.slot[0].st = BRIXAUTOFS_MOUNTED;
        strcpy(g_af.tab.slot[0].fqrn, "repo.test");
    }
    if (!eof) {
        const char *events = strcmp(argv[1], "reap") == 0 ? "CT" : "T";
        size_t count = strlen(events);
        assert(write(g_af.sigpipe[1], events, count) == (ssize_t) count);
    }
    assert(close(g_af.sigpipe[1]) == 0);
    assert(af_control_thread(NULL) == NULL);
    assert(exited == !eof && unmounts == expected_unmounts);
    assert(g_af.shutting_down == !eof);
    close(g_af.sigpipe[0]);
    pthread_mutex_destroy(&g_af.tab.mu);
    return 0;
}
''', extra=library_compile_args([
            '-I' + str(Path(REPO) / 'client/lib'), *flags, '-UNDEBUG',
            '-ffunction-sections', '-fdata-sections', '-Wl,--gc-sections', '-lpthread']),
        include_dirs=[Path(REPO), Path(REPO) / 'client/lib', Path(REPO) / 'shared'])


@pytest.mark.parametrize('event', ['terminate', 'child', 'refused', 'reap', 'eof',
    'start-control-error', 'start-idle-error', 'start-no-idle', 'start-both'])
def test_automount_serves_destroy_until_owned_unmount_finishes(automount_shutdown_probe, event):
    """Keep callbacks live during teardown; EOF cannot authorize an unmount."""
    result = subprocess.run([str(automount_shutdown_probe), event],
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr
