# Client platform abstraction layer

The native client's PAL owner: the only client sources that may branch on the
host. Everything else in `client/` includes `platform/platform.h` (this
directory's umbrella, which re-exports the module PAL under `src/platform/`)
and calls `brix_plat_*`. `tools/ci/check_platform_leak.py` enforces that with
no backlog and no waiver.

| Entry | Responsibility |
| --- | --- |
| [platform.h](platform.h) | The client umbrella: the module PAL headers, the client-only entry points, and one computed `#include` of `<host>/host.h`; no host conditional. |
| [linux/host.h](linux/host.h), [darwin/host.h](darwin/host.h) | The epoll(7) calls the client loop uses: `<sys/epoll.h>` on Linux, the kqueue emulation's declarations on Darwin. |
| [linux/posix.c](linux/posix.c), [darwin/posix.c](darwin/posix.c) | `brix_plat_umount`, `brix_plat_umount_expire` the unprivileged FUSE unmount tiers (`brix_plat_fuse_umount_argv`: fusermount3 / fusermount / umount on Linux, umount on Darwin) and the host's FUSE mount options (`brix_plat_fuse_host_opts`: NULL on Linux, `noappledouble` for macFUSE). Every other body the client calls is linked from `src/platform/<host>/{storage,process}_wrapper.c` (libc-only PAL files) via `PLATFORM_SRCS`, so each host has one body. |
| [linux/mounts.c](linux/mounts.c), [darwin/mounts.c](darwin/mounts.c) | `brix_plat_mounts_walk` over `/proc/self/mountinfo` / `getmntinfo(3)` for `xrd mount`. |
| [darwin/epoll.c](darwin/epoll.c) | `epoll_create1` / `epoll_ctl` / `epoll_wait` over kqueue. |
| [linux/preload_stream.c](linux/preload_stream.c), [darwin/preload_stream.c](darwin/preload_stream.c) | The POSIX preload shim's `FILE*` over a shadow descriptor: glibc `fopencookie` / BSD `funopen`. |
| [linux/preload_lfs.c](linux/preload_lfs.c) | The glibc-only entry points the shim interposes on Linux: the LFS `*64` names and `statx`. |
| [darwin/preload_interpose.c](darwin/preload_interpose.c) | The Mach-O `__interpose` table binding libSystem's names to the shim's `brixposix_*` wrappers (DYLD_INSERT_LIBRARIES). |
| [linux/preload.h](linux/preload.h), [darwin/preload.h](darwin/preload.h) | How a wrapper is named and how the real libc symbol behind it is found on each host (`BRIXPOSIX_WRAP`, `BRIXPOSIX_REAL_RESOLVE`). |

`client/Makefile` selects one body set per host (`PLATFORM_SRCS`).
