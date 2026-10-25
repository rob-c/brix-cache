"""Compile and execute Linux PAL regressions with configured nginx headers.

Run with BRIX_NGINX_BUILD_DIR=build/alma9-merged and pytest --noconftest.
The compiler uses the selected nginx Makefile; no fleet or installed service
is involved. Sysinfo and liburing failure injection stays in the test binary.
"""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys

import pytest

from lib_py.nginx_build import (
    configured_compile_layout, configured_compiler_variables,
    native_test_link_flags, native_test_sdk_flags,
)


pytestmark = pytest.mark.skipif(sys.platform != 'linux', reason='Linux PAL')


@pytest.fixture(scope='module')
def native_compile(tmp_path_factory):
    """Compile production C against the current nginx SDK in a private folder."""
    root = Path(__file__).resolve().parents[1]
    layout = configured_compile_layout(root, os.environ)
    if layout is None:
        pytest.skip('Set BRIX_NGINX_BUILD_DIR or TEST_NGINX_SRC to a configured nginx build')
    makefile, working_directory = layout
    flags = configured_compiler_variables(makefile)
    output = tmp_path_factory.mktemp('linux-pal-native')

    def compile_program(name, code, sources=(), extra=(), include_dirs=()):
        """Link the real implementation and return its executable."""
        source = output / f'{name}.c'
        executable = output / name
        source.write_text(code)
        # Clang may predefine _FORTIFY_SOURCE (notably under ASan). Undefine
        # that builtin before replaying the configured value, retaining both
        # the build's hardening level and strict macro-redefinition checks.
        command = flags['CC'] + ['-U_FORTIFY_SOURCE'] + flags['CFLAGS']
        includes, extra = native_test_sdk_flags(extra)
        command += includes
        # Native client headers deliberately shadow the module PAL umbrella.
        # Keep caller-selected include owners ahead of the module SDK paths.
        command += ['-I' + str(path) for path in include_dirs] + flags['ALL_INCS']
        # Nix's compiler wrapper enables fortification. Keep optimization so
        # glibc can honor that contract instead of turning every unit into a
        # -Werror=cpp failure; disabling LTO retains object-level interposition.
        command += ['-O1', '-fno-lto', '-Werror=implicit-function-declaration',
                    '-Werror=int-conversion', str(source)]
        command += [str(root / path) for path in sources]
        # BRIX_LOG is header-only, so extracted production functions inherit
        # nginx's formatter symbols even when their test log is always NULL.
        # The weak inert definitions keep these object-level units standalone;
        # a unit that links nginx's formatter still resolves to the strong one.
        command.append(str(root / 'tests/c/brix_log_link_stubs.c'))
        command += native_test_link_flags(extra, sys.platform) + ['-o', str(executable)]
        result = subprocess.run(command, cwd=working_directory,
                                capture_output=True, text=True, timeout=60)
        assert result.returncode == 0, result.stdout + result.stderr
        return executable

    return compile_program


def _run(executable, case, *arguments):
    """Require native assertions to pass and retain failures verbatim."""
    result = subprocess.run([str(executable), case, *map(str, arguments)],
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.fixture(scope='module')
def memory_binary(native_compile):
    """Inject documented sysinfo counters, including syscall failure."""
    return native_compile('memory', r'''
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sysinfo.h>
#include "platform/platform_api.h"
int __wrap_sysinfo(struct sysinfo *info) {
    const char *mode = getenv("BRIX_MEMORY_TEST");
    memset(info, 0, sizeof(*info));
    if (strcmp(mode, "error") == 0) { errno = EIO; return -1; }
    info->totalram = 1024;
    info->freeram = strcmp(mode, "swap-only") == 0 ? 0 : 2;
    info->freeswap = ULONG_MAX;
    info->bufferram = 100;
    info->mem_unit = 4096;
    return 0;
}
int main(int argc, char **argv) {
    assert(argc == 2);
    assert(setenv("BRIX_MEMORY_TEST", argv[1], 1) == 0);
    uint64_t expected = strcmp(argv[1], "success") == 0 ? 8192 : 0;
    assert(brix_plat_available_memory() == expected);
    if (strcmp(argv[1], "error") == 0) {
        assert(errno == EIO);
        assert(brix_plat_total_memory() == 0);
    } else { assert(brix_plat_total_memory() == 4194304); }
    return 0;
}
''', ['src/platform/platform_runtime.c',
      # brix_plat_total_memory/_available_memory live in the HOST PAL file
      # (INVARIANT 14), not in the portable runtime — without it the probe
      # cannot link.  Sibling fixtures below list their linux/ source the
      # same way; this one was missed, and the whole native family skips
      # unless BRIX_NGINX_BUILD_DIR is configured, so it stayed latent.
      'src/platform/linux/host_info.c'], ['-Wl,--wrap=sysinfo'])


@pytest.mark.parametrize('case', ['success', 'error', 'swap-only'])
def test_memory_contract(memory_binary, case):
    """Scale free RAM correctly, propagate failure, and never count swap."""
    _run(memory_binary, case)


@pytest.fixture(scope='module')
def canonical_pointer_binary(native_compile):
    """Exercise the host-owned user-pointer shape without dereferencing it."""
    return native_compile('canonical-pointer', r'''
#include <assert.h>
#include <stdint.h>
#include <string.h>
#include "platform/platform_api.h"
int main(int argc, char **argv) {
    assert(argc == 2);
    if (strcmp(argv[1], "live") == 0) {
        assert(brix_plat_pointer_is_canonical((const void *) &main));
    } else if (strcmp(argv[1], "arm-high") == 0) {
#if BRIX_ARCH_ARM64
        assert(brix_plat_pointer_is_canonical(
            (const void *) (uintptr_t) 0x0000ffff8e773c80ULL));
#else
        assert(!brix_plat_pointer_is_canonical(
            (const void *) (uintptr_t) 0x000080008e773c80ULL));
#endif
    } else {
        assert(!brix_plat_pointer_is_canonical(
            (const void *) (uintptr_t) 0x123400008e773c80ULL));
    }
    return 0;
}
''', ['src/platform/linux/host_info.c'])


@pytest.mark.parametrize('case', ['live', 'arm-high', 'mangled'])
def test_canonical_pointer_contract(canonical_pointer_binary, case):
    """Accept live/ARM high VAs and reject a mangled non-canonical value."""
    _run(canonical_pointer_binary, case)


@pytest.fixture(scope='module')
def event_binary(native_compile):
    """Link calls through the declared public event API."""
    return native_compile('events', r'''
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/epoll.h>
#include "platform/platform_api.h"
int main(int argc, char **argv) {
    assert(argc == 2);
    int event_fd = brix_platform_event_init();
    assert(event_fd >= 0);
    assert(fcntl(event_fd, F_GETFD) & FD_CLOEXEC);
    int descriptors[2];
    assert(pipe(descriptors) == 0);
    if (strcmp(argv[1], "success") == 0) {
        assert(brix_platform_event_watch(event_fd, descriptors[0], BRIX_EVENT_READ) == 0);
        assert(write(descriptors[1], "x", 1) == 1);
        struct epoll_event event;
        assert(brix_platform_event_wait(event_fd, &event, 1, 1000) == 1);
        assert(event.data.fd == descriptors[0]);
        assert(event.events & EPOLLIN);
    } else if (strcmp(argv[1], "invalid-fd") == 0) {
        assert(brix_platform_event_watch(event_fd, -1, BRIX_EVENT_READ) == -1);
        assert(errno == EBADF);
    } else {
        assert(brix_platform_event_watch(event_fd, descriptors[0], BRIX_EVENT_DELETE) == -1);
        assert(errno == EINVAL);
    }
    close(descriptors[0]); close(descriptors[1]);
    brix_platform_event_close(event_fd);
    assert(fcntl(event_fd, F_GETFD) == -1 && errno == EBADF);
    return 0;
}
''', ['src/platform/linux/event_wrapper.c'])


@pytest.mark.parametrize('case', ['success', 'invalid-fd', 'filesystem-mask'])
def test_event_api(event_binary, case):
    """Exercise readiness, bad descriptors, and rejected event types."""
    _run(event_binary, case)


@pytest.fixture(scope='module')
def spawn_closefrom_binary(native_compile):
    """Force the pre-glibc-2.34 closefrom action fallback."""
    return native_compile('spawn-closefrom', r'''
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>
#include "platform/platform_api.h"
extern char **environ;
int main(int argc, char **argv) {
    if (argc == 3 && strcmp(argv[1], "child-closed") == 0) {
        int fd = atoi(argv[2]);
        assert(fcntl(fd, F_GETFD) == -1 && errno == EBADF);
        return 0;
    }
    if (argc == 3 && strcmp(argv[1], "child-open") == 0) {
        assert(fcntl(atoi(argv[2]), F_GETFD) >= 0);
        return 0;
    }
    assert(argc == 2);
    posix_spawn_file_actions_t actions;
    posix_spawnattr_t attr;
    assert(posix_spawn_file_actions_init(&actions) == 0);
    assert(posix_spawnattr_init(&attr) == 0);
    if (strcmp(argv[1], "invalid") == 0) {
        assert(brix_plat_spawn_closefrom(&actions, &attr, -1) == EBADF);
        return 0;
    }
    int descriptors[2];
    assert(pipe(descriptors) == 0);
    int lowfd = strcmp(argv[1], "preserve-lower") == 0
        ? descriptors[1] : descriptors[0];
    assert(brix_plat_spawn_closefrom(&actions, &attr, lowfd) == 0);
    char fd_text[32];
    int checked_fd = strcmp(argv[1], "preserve-lower") == 0
        ? descriptors[0] : descriptors[1];
    assert(snprintf(fd_text, sizeof(fd_text), "%d", checked_fd) > 0);
    char *child_argv[] = { argv[0],
        strcmp(argv[1], "preserve-lower") == 0 ? "child-open" : "child-closed",
        fd_text, NULL };
    pid_t child;
    assert(posix_spawn(&child, argv[0], &actions, &attr, child_argv, environ) == 0);
    int status;
    assert(waitpid(child, &status, 0) == child);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    return 0;
}
''', ['src/platform/linux/process_wrapper.c'],
       ['-DBRIX_TEST_FORCE_SPAWN_CLOSEFROM_FALLBACK=1'])


@pytest.mark.parametrize('case', ['closes-range', 'preserve-lower', 'invalid'])
def test_spawn_closefrom_fallback(spawn_closefrom_binary, case):
    """Close the selected range, preserve lower fds and reject negatives."""
    _run(spawn_closefrom_binary, case)


@pytest.fixture(scope='module')
def watcher_binary(native_compile):
    """Use real inotify events to test portable deletion and rename masks."""
    return native_compile('watcher', r'''
#include <assert.h>
#include <stdio.h>
#include "platform/linux/fs_watcher.c"
int main(int argc, char **argv) {
    assert(argc == 3);
    brix_plat_fs_watcher_t watcher;
    brix_plat_fs_event_t event;
    assert(brix_plat_fs_watcher_init(&watcher) == 0);
    assert(fcntl(watcher.inotify_fd, F_GETFD) & FD_CLOEXEC);
    if (strcmp(argv[1], "invalid") == 0) {
        assert(brix_plat_fs_watcher_add(&watcher, NULL, 0) == -1);
        assert(errno == EINVAL);
        assert(brix_plat_fs_watcher_next(NULL, &event, 0) == -1);
        assert(errno == EINVAL);
    } else {
        assert(brix_plat_fs_watcher_add(&watcher, argv[2], 0) >= 0);
        if (strcmp(argv[1], "delete-self") == 0) {
            assert(rmdir(argv[2]) == 0);
            assert(brix_plat_fs_watcher_next(&watcher, &event, 0) == 1);
            assert(event.events == BRIX_FS_EVENT_DELETE);
        } else {
            char before[4096], after[4096];
            assert(snprintf(before, sizeof(before), "%s/../from", argv[2]) > 0);
            assert(snprintf(after, sizeof(after), "%s/to", argv[2]) > 0);
            int fd = open(before, O_CREAT | O_EXCL | O_WRONLY, 0600);
            assert(fd >= 0); close(fd);
            assert(rename(before, after) == 0);
            assert(brix_plat_fs_watcher_next(&watcher, &event, 0) == 1);
            assert(event.events == BRIX_FS_EVENT_RENAME);
            assert(strcmp(event.path, "to") == 0);
        }
    }
    brix_plat_fs_watcher_destroy(&watcher);
    return 0;
}
''')


@pytest.mark.parametrize('case', ['delete-self', 'move-to', 'invalid'])
def test_watcher_masks(watcher_binary, case, tmp_path):
    """Translate real events and reject invalid watcher input."""
    watched = tmp_path / 'watched'
    watched.mkdir()
    _run(watcher_binary, case, watched)


@pytest.fixture(scope='module')
def aio_binary(native_compile):
    """Inject liburing results without requiring kernel io_uring permission."""
    return native_compile('aio', r'''
#include <assert.h>
#include "platform/linux/aio_wrapper.c"
int __wrap_io_uring_submit(struct io_uring *ring) {
    (void)ring;
    if (strcmp(getenv("BRIX_AIO_TEST"), "submit-error") == 0) { return -EBADF; }
    assert(setenv("BRIX_AIO_SUBMITTED", "1", 1) == 0);
    return 1;
}
int __wrap_io_uring_wait_cqe_timeout(struct io_uring *ring,
    struct io_uring_cqe **cqe, struct __kernel_timespec *timeout) {
    (void)ring; (void)cqe;
    assert(getenv("BRIX_AIO_SUBMITTED") != NULL);
    assert(timeout != NULL);
    assert(timeout->tv_sec == 1 && timeout->tv_nsec == 250000000);
    return -ETIME;
}
int main(int argc, char **argv) {
    assert(argc == 2);
    assert(setenv("BRIX_AIO_TEST", argv[1], 1) == 0);
    struct brix_aio_ctx context;
    memset(&context, 0, sizeof(context));
    context.pending_ops = 1;
    if (strcmp(argv[1], "null") == 0) {
        assert(brix_aio_wait(NULL, 1250) == -1 && errno == EINVAL);
    } else if (strcmp(argv[1], "submit-error") == 0) {
        assert(brix_aio_wait(&context, 1250) == -1 && errno == EBADF);
    } else {
        assert(brix_aio_wait(&context, 1250) == 0);
        assert(context.pending_ops == 1);
    }
    return 0;
}
''', extra=['-DBRIX_HAVE_LIBURING=1', '-luring', '-Wl,--wrap=io_uring_submit',
            '-Wl,--wrap=io_uring_wait_cqe_timeout'])


@pytest.mark.parametrize('case', ['timeout', 'submit-error', 'null'])
def test_aio_wait(aio_binary, case):
    """Submit before waiting, pass a valid deadline, and preserve failures."""
    _run(aio_binary, case)


@pytest.fixture(scope='module')
def posix_binary(native_compile):
    """Link the shared descriptor owner together with Linux xattr wrappers."""
    return native_compile('posix', r'''
#include <assert.h>
#include <errno.h>
#include <string.h>
#include "platform/platform_api.h"
int main(int argc, char **argv) {
    assert(argc == 2);
    int fd = brix_plat_anon_fd("pal-native-test", NULL);
    assert(fd >= 0);
    assert(fcntl(fd, F_GETFD) & FD_CLOEXEC);
    char value[8] = {0};
    if (strcmp(argv[1], "success") == 0) {
        assert(brix_plat_fsetxattr(fd, "user.brix_pal", "test", 4, 0) == 0);
        assert(brix_plat_fgetxattr(fd, "user.brix_pal", value, sizeof(value)) == 4);
        assert(memcmp(value, "test", 4) == 0);
        assert(brix_plat_fremovexattr(fd, "user.brix_pal") == 0);
        assert(brix_plat_fsync_data(fd) == 0);
        assert(brix_plat_sync_tree(fd) == 0);
    } else if (strcmp(argv[1], "invalid-fd") == 0) {
        assert(brix_plat_fgetxattr(-1, "user.brix_pal", value, sizeof(value)) == -1);
        assert(errno == EBADF);
    } else {
        assert(brix_plat_fsetxattr(fd, "invalid.brix_pal", "test", 4, 0) == -1);
        assert(errno == EOPNOTSUPP);
        assert(brix_plat_fgetxattr(fd, "user.brix_pal", value, sizeof(value)) == -1);
        assert(errno == ENODATA);
    }
    close(fd);
    return 0;
}
''', ['src/platform/linux/posix_wrapper.c', 'shared/cvmfs/platform/platform.c'])


@pytest.mark.parametrize('case', ['success', 'invalid-fd', 'invalid-namespace'])
def test_posix_shared_linkage(posix_binary, case):
    """Preserve shared descriptor helpers and native xattr error contracts."""
    _run(posix_binary, case)


@pytest.fixture(scope='module')
def security_binary(native_compile):
    """Compile the real wrapper and avoid installing process-wide filters."""
    return native_compile('security', r'''
#include <assert.h>
#include <errno.h>
#include <string.h>
#include "platform/linux/security_wrapper.c"
int main(int argc, char **argv) {
    assert(argc == 2);
    if (strcmp(argv[1], "disabled") == 0) {
        assert(brix_security_init(NULL) == 0);
        assert(brix_security_init("off") == 0);
    } else if (strcmp(argv[1], "unsupported") == 0) {
        assert(brix_security_load_profile("missing-profile") == -1);
        assert(errno == ENOSYS);
    } else {
        assert(brix_security_init("unrecognized-policy") == -1);
        assert(errno == ENOSYS);
    }
    return 0;
}
''', extra=['-lseccomp'])


@pytest.mark.parametrize('case', ['disabled', 'unsupported', 'unknown-policy'])
def test_security_wrapper_compiles(security_binary, case):
    """Keep disabled success and unsupported policy failures explicit."""
    _run(security_binary, case)
