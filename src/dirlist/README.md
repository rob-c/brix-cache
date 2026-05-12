# dirlist — kXR_dirlist handler

Implements the XRootD directory listing operation.

| File | Responsibility |
|------|----------------|
| `handler.c` | `xrootd_handle_dirlist` — main handler: opens the directory, iterates entries, dispatches to formatters, sends `kXR_oksofar`/`kXR_ok` chunked responses |
| `dcksm.c` | Checksum algorithm negotiation (`cks.type=` CGI param), per-entry checksum computation, and 9-field dcksm stat body formatting |
| `stat.c` | Per-entry stat line formatting for dStat mode (the `kXR_dstat` flag requests size/mtime/flags for each entry) |
| `name_sanitize.c` | Detects and skips unsafe filenames (e.g. entries containing NUL bytes or path separators) |
| `util.c` | Directory open/close helpers and error-to-XRootD-status mapping |

In dStat mode every directory entry is followed by a stat line; in plain
mode only the filename is returned.  `kXR_dcksm` implies dStat mode and adds a
reference-compatible checksum token to each stat line.  All modes use the same
chunked response framing with `kXR_oksofar` continuation frames for directories
with many entries.
