# Darwin platform adapters

This directory contains the macOS sources selected by the repository
[module configuration](../../../config). They require a Darwin SDK and the
nginx headers generated for that build. Shared declarations and feature gates
live in [platform_api.h](../platform_api.h) and [platform.h](../platform.h).

| File | Responsibility |
| --- | --- |
| [posix_wrapper.c](posix_wrapper.c) | macOS descriptor, sendfile, randomness, xattr, and process adapters, with explicit unsupported-operation returns. |
| [event_wrapper.c](event_wrapper.c) | Kqueue event registration and waiting. |
| [fs_watcher.c](fs_watcher.c) | Per-descriptor `EVFILT_VNODE` watches; this is not a recursive FSEvents implementation. |
| [aio_wrapper.c](aio_wrapper.c) | Unavailable-AIO stubs; submission and wait return `-ENOSYS`. |
| [security_wrapper.c](security_wrapper.c) | Placeholder security hooks; successful returns do not install or enforce a sandbox profile. |
| [copy_range.c](copy_range.c) | The `brix_platform_copy_range` buffered pread/pwrite adapter. |
| [clonefile_optimized.c](clonefile_optimized.c) | Clonefile helpers, copy fallback, and clone capability queries; clone statistics are stubbed. |
| [cpu_topology.c](cpu_topology.c) | Sysctl-based CPU information and worker-placement hints. |
| [cpu_cache.h](cpu_cache.h) | Shared CPU-model cache-size policy used by topology estimates. |
| [sysctl_value.h](sysctl_value.h) | Typed integer sysctl reads shared by runtime and standalone topology code. |
| [cpu_topology_unittest.c](cpu_topology_unittest.c) | Standalone topology probe with its own implementation; excluded from the module source list. |
| [apple_silicon.c](apple_silicon.c) | ARM64 chip detection, memory/copy helpers, and optimization metadata. |
| [checksum_accelerate.c](checksum_accelerate.c) | Scalar and Accelerate-backed checksum routines. |

## Build and validation

Use [BUILD.md](../../../docs/03-configuration/BUILD.md) and nginx's generated build through the
repository `config`. The local development Makefile needs the configured
nginx include paths and appropriate macOS SDK/framework inputs supplied by
the caller; it is not the module's source-list authority.

Run [PAL tests](../../../tests/platform/) on a native macOS host, with
`TEST_NGINX_SRC` pointing at that host's configured nginx tree. Exercise Intel
and ARM64 paths separately. Linux checks do not establish Darwin compilation,
link closure, or runtime behavior; the standalone topology probe also does not
exercise the production topology translation unit.

The AIO and sandbox placeholders above are implementation limits. Account for
their return values and behavior when assessing supported features; full
macOS feature parity has not been established by the AlmaLinux merge checks.
