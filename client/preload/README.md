# `client/preload/` — LD_PRELOAD POSIX → XRootD shim

## Overview

An `LD_PRELOAD` shim that lets **unmodified POSIX tools** (`cat`, `md5sum`, `ls`,
analysis jobs) read data from a remote XRootD `root://` export with no recompile
and **no libXrdCl / XrdPosix** — just `libxrdc`. It interposes the libc read-path
calls and routes any path under a configured prefix to the remote server; every
other path falls straight through to the real libc call.

```
LD_PRELOAD=libxrdposix_preload.so XROOTD_VMP=/xrd=root://host:port/ cat /xrd/file
```

`$XROOTD_VMP = "<localprefix>=root://host[:port][/base]"`. A path starting with
`<localprefix>` is rewritten to the remote logical path and opened through a single
lazily-connected, mutex-guarded `libxrdc` session (one request in flight).

## How it works

- **Interposed calls:** `open`/`read`/`pread`/`lseek`/`close`, the `stat` family
  (incl. `statx` and the LFS `*64` variants), and `access`. Real libc symbols are
  resolved with `dlsym(RTLD_NEXT)` via the `__typeof__`-based `REAL()` helper, so
  each wrapper inherits libc's exact prototype.
- **Shadow fd table:** remote descriptors live at `fd >= XFS_FD_BASE` so
  `read`/`lseek`/`close`/`fstat` can distinguish them from real libc fds.

## Scope

First cut is the **read path**. Documented fall-throughs to libc (passed straight
to the real call): files opened for **write** under the prefix, `fopen`/`mmap`, and
the legacy `__xstat()` routing (modern glibc exports `stat`/`lstat`/`fstat` as real
symbols, which are interposed directly).

## Files

| File | Responsibility |
|---|---|
| `xrdposix_preload.c` | The entire shim: env parsing, the interposed wrappers, the shadow fd table, and the lazy `libxrdc` session. |

## See also

- `../lib/README.md` — the `libxrdc` library the shim opens its sessions through.
- `../README.md` (client tree) and the FUSE driver (`xrootdfs`) for the
  mount-based alternative to this preload approach.
