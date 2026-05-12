# fattr — kXR_fattr extended attribute operations

Implements the XRootD file extended-attribute protocol, which maps directly
onto POSIX `xattr` syscalls.

| File | XRootD sub-code | POSIX syscall |
|------|----------------|---------------|
| `get.c` | `kXR_fattrGet` | `getxattr` |
| `set.c` | `kXR_fattrSet` | `setxattr` |
| `del.c` | `kXR_fattrDel` | `removexattr` |
| `list.c` | `kXR_fattrList` | `listxattr` |
| `dispatch.c` | — | routes by sub-code to the above |
| `helpers.c` | — | shared name parsing, rc encoding, and vector status responses |
| `ngx_xrootd_fattr.h` | — | internal types and prototypes |

Attribute names are prefixed with `user.` (the POSIX user namespace) before
being passed to the kernel.  Both path-based and open-handle-based operations
are supported; `helpers.c` resolves the `/proc/self/fd/N` path for handle
requests so the same syscall can be used in both cases.
