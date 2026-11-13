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

HTTP reads use the requested byte offset even when an origin ignores `Range`
and returns a complete `200` representation. The reader skips the prefix,
returns the requested slice, and drains the remainder before reusing the
connection. Truncated prefixes fail without returning unrelated bytes; partial
requested data remains resumable. A `416` response closes its connection because
an error body may remain unread. Native response contracts live in
`tests/test_webfile_io_native.py`.

After a lost mutation reply, retry handling accepts a matching `EEXIST` or
`ENOENT` as success only on reissue. The configured errno is positive; the
status mapper returns negative errno values. Initial errors, authorization
failures, and mismatched errors remain failures. The same rule applies to
pooled FUSE metadata requests and the client request wrappers; native contracts
are in `tests/test_resilience_policy_native.py`.

Native FUSE create and truncate publish an empty file before replying to the
kernel, then retain an update-in-place remote handle. Resumable origins stage
create/truncate until remote close; FUSE release is asynchronous, so leaving
publication to release can make an immediate reopen see ENOENT. Publishing at
open adds one remote close and one update-open for creates/truncates. Existing
update opens retain their handle, including across unlink. Live regressions are
in `tests/test_xrootdfs_publication.py`.

Writable FUSE FLUSH also sends remote SYNC after draining buffered writes.
This adds one remote durability barrier per writable flush, allowing the origin
to publish integrity tags before a subsequent OPEN snapshots them. The remote
handle remains open for duplicated descriptors and operations after unlink.

The CVMFS automount controller owns a signal self-pipe. Shutdown closes the
writer, joins the control thread, and closes the reader before destroying the
FUSE session. Native lifecycle contracts cover startup failures, child reaping,
idle expiry, and both descriptor ends in `tests/test_autofs_lifecycle_native.py`.

Recursive root copies reject absolute and parent-traversing names from server
directory listings before copying or mirror deletion. Both paths use the shared
`brix_rel_is_unsafe` check; `tests/test_root_recursive_native.py` also checks
that local mirror deletion never follows symlinks outside the destination.
