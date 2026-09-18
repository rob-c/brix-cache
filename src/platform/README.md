# Platform abstraction layer

This directory holds host detection, shared PAL declarations, and operating
system adapters. The module build selects one host implementation through the
repository [config](../../config). Source availability and feature flags must
be checked against native build and runtime results for each supported host.

| Entry | Responsibility |
| --- | --- |
| [platform.h](platform.h) | Host selection: one computed `#include` of `<host>/host.h` from the build's `-DBRIX_PLATFORM_HOST=linux\|darwin\|windows`; no host conditional. |
| [platform_arch.h](platform_arch.h) | `BRIX_ARCH_ARM64` / `BRIX_ARCH_X86_64` from the compiler's target macros (instruction set, not OS). |
| [openat2_abi.h](openat2_abi.h) | The openat2(2) `RESOLVE_*` / `struct open_how` ABI for hosts without `<linux/openat2.h>`. |
| [platform_api.h](platform_api.h) | Public umbrella for the API families below; callers keep this include. |
| [platform_api_info.h](platform_api_info.h), [platform_api_lifecycle.h](platform_api_lifecycle.h) | Runtime host information and PAL lifecycle. |
| [platform_api_file.h](platform_api_file.h), [platform_api_xattr.h](platform_api_xattr.h) | File descriptor, transfer, synchronization, and extended attribute declarations. |
| [platform_api_event.h](platform_api_event.h) | Events, pipes, and filesystem-watch types and declarations. |
| [platform_api_security.h](platform_api_security.h), [platform_api_process.h](platform_api_process.h) | Confinement, identity, entropy, and process execution. |
| [platform_api_endian.h](platform_api_endian.h) | Inline byte-order conversions over the host's `host_endian.h` natives. |
| [platform_api_posix.h](platform_api_posix.h) | The POSIX surface guaranteed on every host: Linux names (byte order, Linux-shaped xattr calls, O_PATH, SOCK_CLOEXEC, RESOLVE_*, PR_*, CAP_*) and the `brix_plat_*` entry points whose Darwin semantics differ (openat2, renameat2, wake descriptors, peer credentials, birth time, block-device size, ...). |
| [platform_runtime.c](platform_runtime.c) | Host-free runtime: kernel release, architecture, root check, init. |
| `<host>/host.h`, `host_endian.h`, `host_posix.h`, `host_api.h`, `host_info.c` | Each host directory's answer to the interface: platform flags and `BRIX_HAS_*` gates, native byte order, its part of the POSIX surface, host-only extensions (Apple Silicon, Win32), name/CPU/memory. Every `#if` on the host lives in these directories. |
| [linux/](linux/README.md) | Linux syscall, epoll, inotify, optional io_uring/libseccomp, and ARM64 adapters. |
| [darwin/](darwin/README.md) | macOS syscall, kqueue, filesystem-watch, copy, and CPU/checksum adapters. |
| [windows/](windows/README.md) | Windows adapters and their platform-specific documentation. |

## Implementation status

The AlmaLinux 9 merge validation exercises the Linux x86_64 build and native
PAL units. Native macOS, Windows, and ARM64 results must be established on
those hosts; tests for a different OS or architecture are skipped.

Implementation limits remain visible in the source. Darwin PAL AIO reports
unavailable operations, and Darwin security hooks do not enforce sandbox
profiles. Linux PAL custom security-profile loading is unimplemented, and
runtime kernel policy can prevent io_uring use even when liburing is installed.
See the directory READMEs for the current owners and limitations. Historical
phase-completion reports in this directory are not a platform certification.

## Build integration

Follow [BUILD.md](../../docs/03-configuration/BUILD.md). nginx's configure step reads the repository
`config`, chooses host sources and compiler definitions, and generates the
Makefile used to build the module. New module translation units belong in
that source list. The platform-local Makefiles are development helpers and
require a configured nginx SDK; they do not replace this build path.

Linux also links [shared/cvmfs/platform/platform.c](../../shared/cvmfs/platform/platform.c)
for anonymous descriptors, sync, and read-only mappings. Keep existing owners
when adding PAL entry points to avoid duplicate or unresolved definitions.

Include `platform/platform_api.h` where its declarations are needed and use
the declared API for platform work. The build passes `-DBRIX_PLATFORM_HOST=<host>`
(`./config`, `client/Makefile`, the host Makefiles); the interface headers select
the host with that name and carry no `#if`. No production file outside
`src/platform/<host>/`, `client/lib/platform/<host>/` and `shared/cvmfs/platform/`
may test an OS macro
(`__APPLE__`, `__linux__`, `_WIN32`, `BRIX_PLATFORM_*`) or include an
OS-private header; `tools/ci/check_platform_leak.py` enforces that with no
backlog and no waiver. Optional features are gated on the `BRIX_HAS_*`
capability macros `platform.h` defines. Storage operations continue through the
[VFS](../fs/vfs/), which owns storage and mutation policy.

## Tests

[tests/platform](../../tests/platform/) contains host-level checks and native
bindings that compile production PAL sources using the selected nginx SDK.
From the repository root, a configured local environment can run:

```sh
BRIX_NGINX_BUILD_DIR=build/alma9-merged \
PYTHONPATH=tests python3 -m pytest tests/platform -q
```

Check both compiled behavior and supported runtime capabilities. A passing
host-level Python check alone does not establish the corresponding C adapter's
behavior; the native fixtures provide that coverage for their selected APIs.
