# Filesystem client entry points

The default `xrootdfs` driver uses libfuse's low-level interface on every host.
Kernel node IDs belong to mount-local inode objects, not individual pathnames.
The root and read-only HTTP transports share this adapter. The explicitly
selected legacy driver remains separate.

| File | Responsibility |
| --- | --- |
| `xrootdfs.c` | Async driver options, shared metadata runners and daemon readiness. |
| `_xrootdfs_part2.c` | Endpoint bring-up and connection teardown. |
| `xrootdfs_internal.h` | Caller-aware transport operation contract. |
| `xrootdfs_identity.c` | Bounded per-caller SSS metadata/data connection owners. |
| `xrootdfs_meta.c` | Existing namespace, stat, directory and access operations. |
| `xrootdfs_io.c` | Authorized handles and buffered async reads/writes. |
| `xrootdfs_xattr.c` | Opt-in xattr translation and protected checksum attributes. |
| `xrootdfs_nodes.h` | Mount-local inode/alias registry contract. |
| `xrootdfs_nodes.c` | Bounded hash indexes, lookup/open references and reserved rename keys. |
| `xrootdfs_lowlevel.h` | Low-level session state and request callback contract. |
| `xrootdfs_session.c` | Mount lifecycle, checked child keys, UID propagation and entry replies. |
| `xrootdfs_lookup.c` | Lookup/forget, attributes, readlink, access and capacity replies. |
| `xrootdfs_namespace.c` | Preallocated create/link and coherent rename/unlink transactions. |
| `xrootdfs_lowlevel_io.c` | Handle replies and open-reference ownership. |
| `xrootdfs_lowlevel_dir.c` | Bounded per-open directory snapshots and continuation offsets. |
| `xrootdfs_lowlevel_xattr.c` | Bounded xattr size/value/list replies. |

The registry permits at most 65,536 live nodes, 262,144 aliases and 64 MiB of
alias strings per mount. Reservations count against those limits before a
server mutation. Namespace operations serialize with alias changes; handle
reads/writes use the existing per-handle I/O locks and remain parallel. Lookup
and open owners are independent: forget, unlink and rename cannot free a live
handle's inode. Known server identities remain stable across cache eviction;
new registry owners receive monotonically advancing generations. Unknown web
identities use checked path-derived candidates, never hash-based alias merging.

Directory snapshots have a separate 64 MiB per-open bound. Their advisory
unknown directory inode is nonzero; only a successful lookup/entry reply grants
a kernel inode reference. Directory cursors are encoded by libfuse itself.

The kernel request's UID is passed explicitly to metadata and open operations.
Per-caller SSS mounts disable shared attribute/entry and file-page caching;
failed identity acquisition never uses the mount owner's connections.
