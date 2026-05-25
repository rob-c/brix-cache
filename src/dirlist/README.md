# dirlist — kXR_dirlist handler

Implements the XRootD directory listing operation.

| File | Responsibility |
|------|----------------|
| `handler.c` | `xrootd_handle_dirlist` — main handler: opens the directory, iterates entries, dispatches to formatters, sends `kXR_oksofar`/`kXR_ok` chunked responses |
| `dirlist.h` | Directory list types and cross-file prototypes |
| `dcksm.c` | Checksum algorithm negotiation (`cks.type=` CGI param), per-entry checksum computation, and 9-field dcksm stat body formatting |
| `dcksm.h` | DCKSM constants and helper prototypes |

In dStat mode every directory entry is followed by a stat line; in plain
mode only the filename is returned.  `kXR_dcksm` implies dStat mode and adds a
reference-compatible checksum token to each stat line.  All modes use the same
chunked response framing with `kXR_oksofar` continuation frames for directories
with many entries.
