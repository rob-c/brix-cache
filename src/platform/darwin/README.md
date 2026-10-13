# Darwin platform adapters

This directory contains the macOS sources selected by the repository
[module configuration](../../../config). They require a Darwin SDK and the
nginx headers generated for that build. Shared declarations and feature gates
live in [platform_api.h](../platform_api.h) and [platform.h](../platform.h).

| File | Responsibility |
| --- | --- |
| [host.h](host.h), [host_endian.h](host_endian.h), [host_posix.h](host_posix.h), [host_api.h](host_api.h) | The Darwin answer to the PAL interface: platform flags and `BRIX_HAS_*` gates, OSByteOrder natives plus the `<endian.h>` names, the Linux-shaped xattr calls / missing constants / openat2 ABI, and the Apple Silicon extensions (ARM64). |
| [host_info.c](host_info.c) | Host identity plus CMS sysload: CPU/load (sysctl/getloadavg), memory and paging (Mach host statistics), and 64-bit non-loopback `NET_RT_IFLIST2` network counters. |
| [posix_wrapper.c](posix_wrapper.c) | macOS descriptor, sendfile, randomness, xattr, and process adapters, with explicit unsupported-operation returns. |
| [path_wrapper.c](path_wrapper.c) | The openat2(2) emulation (a component walk on an fd stack giving the RESOLVE_BENEATH / IN_ROOT / NO_SYMLINKS verdicts), the confined stat, renameatx_np and the birth time. |
| [process_wrapper.c](process_wrapper.c) | Wake-descriptor pipes, accept + FD_CLOEXEC, LOCAL_PEERCRED, close-from loops, getgrouplist, `_NSGetExecutablePath` and `kern.bootsessionuuid`; libc-only, also linked by the native client. |
| [storage_wrapper.c](storage_wrapper.c) | DKIOCGETBLOCK* size, bounded positional copy, APFS preallocation, preadv, write(2) for O_APPEND handles, pipe + fcntl; libc-only, also linked by the native client. Descriptor sealing remains unavailable. |
| [priv_wrapper.c](priv_wrapper.c) | Saved-ID calls fail honestly, getenv is gated on `issetugid`, and crypt is native. `PR_SET_NO_NEW_PRIVS` installs a deny-`process-exec` sandbox profile (stronger for exec-chain escalation); other prctl and capability operations fail explicitly. |
| [event_wrapper.c](event_wrapper.c) | Kqueue event registration and waiting, including simultaneous read/write filters and explicit rejection of mixed vnode/socket masks. |
| [fs_watcher.c](fs_watcher.c) | Per-descriptor `EVFILT_VNODE` watches; this is not a recursive FSEvents implementation. |
| [aio_wrapper.c](aio_wrapper.c) | Bounded pthread worker-pool asynchronous positional reads and writes, finite waits, callback dispatch, and drain-on-destroy. |
| [security_wrapper.c](security_wrapper.c) | Honest legacy confinement hooks: explicit `off` succeeds; audit, enforcement, default, and custom profiles fail with `ENOTSUP`. Darwin has no supported implementation behind this ABI. |
| [copy_range.c](copy_range.c) | The `brix_platform_copy_range` buffered pread/pwrite adapter. |
| [clonefile_optimized.c](clonefile_optimized.c) | Clonefile helpers, copy fallback, and clone capability queries; unavailable clone statistics fail with `ENOTSUP` rather than emitting fabricated zeros. |
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

The module and native client are verified by
[`verify_platform_builds.sh`](../../../tools/ci/verify_platform_builds.sh) against
Homebrew's nginx source and configure options. Because BriX requires nginx
thread support, the verifier adds `--with-threads`; the resulting nginx and
modules are a matched Homebrew-derived build, not ABI-compatible drop-ins for a
stock Homebrew nginx bottle built without threads.

Darwin cannot provide Linux `NO_NEW_PRIVS`, capability bounding, seccomp-BPF,
splice, or clone-sharing statistics. Those contracts fail with `ENOTSUP` or
`ENOSYS`; worker startup also fails when its promised no-new-privileges floor
cannot be installed. No unsupported security control is reported as active.

The installed worker sandbox denies every process execution. Configuration
therefore rejects `brix_prepare_command`, `brix_frm_stagecmd`,
`brix_frm_purge_polprog`, `brix_cms_perf_pgm`, and `brix_cms_fsxeq` on Darwin.
An environment-selected FRM exec adapter fails startup with `ENOTSUP`, while
request-selected `oidc-agent` and `token-exchange` delegation fail explicitly.
In-process FRM library adapters and network/storage features remain available.
