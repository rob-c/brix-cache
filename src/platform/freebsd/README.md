# FreeBSD platform adapter

Native build and runtime validation is required; source availability alone is
not release certification. Linux capabilities and seccomp are not emulated by
successful no-ops. FreeBSD's native no-new-privileges control is used instead.

| File | Responsibility |
|---|---|
| `host.h` | Explicit FreeBSD feature gates. |
| `host_endian.h` | Native byte-order operations. |
| `host_posix.h` | Native headers, constants and Linux-shaped xattr surface. |
| `host_api.h` | Public host-only extension surface. |
| `host_info.c` | Native CPU, memory and measured sysload fields. |
| `path_wrapper.c` | Confined path walking, exclusive rename, unlink and birth time. |
| `process_wrapper.c` | Native wake descriptors, peer credentials, close/spawn, executable/boot identity and bounded exit wait. |
| `priv_wrapper.c` | Native saved IDs/procctl, owned process descriptors and fixed-helper Capsicum rights; unsupported Linux capabilities remain refused. |
| `storage_wrapper.c` | Native descriptor copying, append IO, pipe/disk operations, checked readable aliases and fd-based sendfile safety policy. |
| `xattr_wrapper.c` | Native user-namespace metadata, bounded list conversion and explicit conditional-update refusal. |
| `posix_wrapper.c` | Native fadvise, sendfile, entropy and socket/runtime operations. |

The bounded descriptor-relative namespace walker is shared with Darwin under
`../posix/`; native namespace operations remain in this directory.

`brix_plat_file_sendfile_safe` refuses ZFS and failed/unknown filesystem
inspection without changing errno. OpenZFS 2.4.2 and 2.4.4 both deadlocked
sendfile against concurrent writes in native testing. A read-only handle does
not prevent other writers. UFS retains its normal path; no kernel-version
guess, pathname-based check, or global sendfile disable is used. HTTP's
request-local bounded copy filter and root's bounded buffered strategy retain
the original VFS, credential, range and framing contracts. This does not fix
the separately reproduced ZFS SA-xattr data loss.

See [the FreeBSD target guide](../../../docs/03-configuration/FREEBSD.md) for
the repeatable build/test command, recorded native proofs and remaining limits.
