# FreeBSD client PAL

| File | Responsibility |
|---|---|
| `host.h` | Native epoll-shim dependency headers. |
| `host_net.h` | TCP_INFO units and retransmit-field mapping. |
| `preload.h` | ELF libc interposition and native directory-entry layout. |
| `posix.c` | FUSE mount/unmount option and lifecycle semantics. |
| `mounts.c` | Native mount snapshots, with explicit portable fixture support. |
| `preload_stat.c` | Native libc stat entry-point resolution. |
| `preload_copy.c` | Preserve native kernel copies; remote shadow descriptors refuse offload without mutation, allowing the caller's read/write fallback. |

Server and client descriptor/process primitives share the FreeBSD module PAL
implementations. Native compilation and runtime proofs remain required.
