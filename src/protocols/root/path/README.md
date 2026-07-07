# path — wire-path extraction, sanitization, and stat formatting

## Overview

Every filesystem path that arrives on the XRootD wire passes through this
directory before anything touches storage. It is the security choke point
between "bytes a client sent" and "a path the VFS may resolve": embedded
NULs are rejected as malicious, oversized payloads are rejected against
`BRIX_MAX_PATH`, CGI query suffixes (`?checksum=md5`, `?xrdcl.unzip=…`)
are stripped so only the POSIX path component reaches resolution, and the
repeated extract → depth-check → resolve sequence used by namespace
operations is centralized in one helper instead of ten.

Confinement itself is NOT enforced here — that is the VFS seam's job
([../../../fs/path/](../../../fs/path/), `openat2` RESOLVE_IN_ROOT). This
directory guarantees the *string* handed to the VFS is well-formed.

## Files

| File | Responsibility |
|---|---|
| `extract.c` | extract + sanitize a path from wire payload: NUL-embedding, length, optional CGI strip; single validation point |
| `strip_cgi.c` | truncate a wire path at `?` — resolver only ever sees the POSIX component |
| `op_path.c` | unified extract → depth-check → resolve pre-gate for namespace ops (was duplicated across 10+ handlers) |
| `op_path.h` | the pre-gate contract |
| `stat_body.c` | format `struct stat` into the kXR_stat/kXR_statx 4-field wire body (VFS and non-VFS modes) |

## Invariants, security & gotchas

1. A payload with an embedded NUL anywhere but the final byte is rejected —
   never "repaired".
2. `extract.c` is a pure function (no shared state); keep it that way — it
   runs on every request.
3. Trailing-slash handling in `op_path.c`'s parent gate is load-bearing for
   nested mkdir on object backends (fixed 2026-06; see the pblock suite).
4. Nothing here calls `realpath(3)` — resolution/confinement belongs to the
   VFS layer, not the extractor.

## See also

- [../../../fs/path/README.md](../../../fs/path/README.md) — confined canonical resolution (the *other* path directory)
- [../read/README.md](../read/README.md), [../write/README.md](../write/README.md) — the consumers
