# query — kXR_query sub-protocol handlers

Implements the XRootD query protocol.  The `infotype` field in the request
header selects which sub-handler runs.

| File | infotype(s) | Description |
|------|-------------|-------------|
| `dispatch.c` | — | `xrootd_handle_query` — routes by infotype |
| `checksum_qcksum.c` | `kXR_Qcksum` | Compute adler32, crc32c, md5, sha1, or sha256 of a file by path or open handle |
| `checksum_ckscan_*.c` | `kXR_Qckscan` | Walk a file or directory tree off the event loop and return one adler32/crc32c line per regular file |
| `space.c` | `kXR_Qspace`, `kXR_QFSinfo` | Filesystem capacity via `statvfs` |
| `metadata.c` | `kXR_QStats`, `kXR_Qxattr`, `kXR_QFinfo`, `kXR_Qvisa`, `kXR_Qopaque`, `kXR_Qopaquf`, `kXR_Qopaqug` | Server stats, xattr listing, file info, and reference-compatible FSctl/fctl query hooks |
| `config.c` | `kXR_Qconfig` | Server capability string (best-effort; returns known keys) |
| `prepare.c` | `kXR_prepare`, `kXR_QPrep` | Local-storage staging hint and per-path availability status |
| `util.c` | — | File checksum helpers shared by path and handle queries |
| `query_internal.h` | — | Internal prototypes and shared types |
| `checksum_qcksum_async.c` | Async adler32/crc32c/md5/sha1/sha256 checksum via nginx thread pool |
| `prepare_cmd.c` | Prepare command handler — staging hint wire format construction |
| `set.c` | kXR_set query: server-side configuration parameter setting |

`kXR_Qconfig chksum` advertises the checksum algorithms supported by Qcksum.
Qckscan defaults to adler32 for xrdadler32 compatibility and also accepts a
`crc32c:<path>` request prefix.

The opaque and visa query subtypes are extension hooks in the reference
XRootD server.  nginx-xrootd recognizes and validates the same wire requests,
then returns the reference-compatible unsupported response because it does not
embed the XrdOfs FSctl/fctl plugin layer.
