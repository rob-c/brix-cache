# query — kXR_query sub-protocol handlers

Implements the XRootD query protocol.  The `infotype` field in the request
header selects which sub-handler runs.

| File | infotype(s) | Description |
|------|-------------|-------------|
| `dispatch.c` | — | `xrootd_handle_query` — routes by infotype |
| `checksum.c` | `kXR_Qcksum`, `kXR_Qckscan` | Compute adler32, md5, sha1, or sha256 of a file by path or open handle; accept checksum-cancel queries as synchronous no-ops |
| `space.c` | `kXR_Qspace`, `kXR_QFSinfo` | Filesystem capacity via `statvfs` |
| `metadata.c` | `kXR_QStats`, `kXR_Qxattr`, `kXR_QFinfo`, `kXR_Qvisa`, `kXR_Qopaque`, `kXR_Qopaquf`, `kXR_Qopaqug` | Server stats, xattr listing, file info, and reference-compatible FSctl/fctl query hooks |
| `config.c` | `kXR_Qconfig` | Server capability string (best-effort; returns known keys) |
| `prepare.c` | `kXR_prepare` | Local-storage staging / cache hint (no-op for direct-attach storage) |
| `util.c` | — | File checksum helpers shared by path and handle queries |
| `query_internal.h` | — | Internal prototypes and shared types |

Checksum algorithms are negotiated via the `xrootd_checksum_alg` directive;
the default is adler32 for compatibility with xrdcp.

The opaque and visa query subtypes are extension hooks in the reference
XRootD server.  nginx-xrootd recognizes and validates the same wire requests,
then returns the reference-compatible unsupported response because it does not
embed the XrdOfs FSctl/fctl plugin layer.
