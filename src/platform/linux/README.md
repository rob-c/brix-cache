# Linux platform adapters

This directory supplies the Linux implementations selected by the repository
[module configuration](../../../config). Shared declarations and feature gates
live in [platform_api.h](../platform_api.h) and [platform.h](../platform.h).
The nginx build supplies the configured headers and optional library flags.

| File | Responsibility |
| --- | --- |
| [posix_wrapper.c](posix_wrapper.c) | File transfers, descriptor operations, filesystem identity, randomness, xattrs, and process execution. |
| [event_wrapper.c](event_wrapper.c) | The `brix_platform_event_*` epoll interface. |
| [fs_watcher.c](fs_watcher.c) | Inotify watcher registration, removal, and event decoding; unavailable builds return `ENOSYS`. |
| [aio_wrapper.c](aio_wrapper.c) | io_uring submission and completion handling when liburing is enabled; unavailable builds return `ENOSYS`. |
| [security_wrapper.c](security_wrapper.c) | PAL libseccomp entry points; custom profile loading remains unimplemented. |
| [copy_range.c](copy_range.c) | The `brix_platform_copy_range` interface with partial-copy and interruption handling. |
| [crc32c_arm64.c](crc32c_arm64.c) | ARM64 CRC32C implementation and runtime hardware selection. |
| [arm64_crypto.c](arm64_crypto.c) | ARM64 capability detection and checksum dispatch helpers. |
| [checksum_neon.c](checksum_neon.c) | ARM64 NEON checksum routines. |

Anonymous descriptors, data/tree sync, and read-only mappings are owned by
[the shared platform implementation](../../../shared/cvmfs/platform/platform.c).
The Linux module links that source alongside these wrappers. Keep each exported
function with its existing owner when extending the API.

## Build and validation

Follow [BUILD.md](../../../docs/03-configuration/BUILD.md) from a configured nginx source tree. The
repository `config` selects the Linux source list; the local development
Makefile does not supply a configured nginx SDK by itself. Add new module
sources to `config`.

[PAL tests](../../../tests/platform/) include native C bindings and host-level
checks. Supply `TEST_NGINX_SRC` for the configured nginx tree. ARM64 cases run
only on ARM64, so an x86_64 pass does not validate the accelerated routines.

The presence of liburing at build time does not guarantee that the running
kernel permits ring creation. The PAL security audit toggle is currently a
stub, and custom profile loading returns `ENOSYS`. Worker syscall filtering
has its own implementation in [core/seccomp](../../core/seccomp/).
[Native ownership tests](../../../tests/test_linux_security_ownership.py) link
the actual PAL wrapper with libseccomp stubs and sanitizers; they verify builder
cleanup without installing a filter in the test process.
