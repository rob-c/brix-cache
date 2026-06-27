# `client/apps/` — native client CLI tools

The command-line front-ends built on `libxrdc` (`../lib/`). All are pure-C,
libXrdCl-free, and speak `root://`/`roots://` plus (where noted) HTTP/WebDAV/S3.
Binaries are listed in `BINS` in `client/Makefile` and land in `client/bin/`.

Several tools are **split across multiple `.c` files** (a single-responsibility
refactor, behavior-identical) that link into one binary — e.g. `xrdcp` =
`xrdcp.c` + `xrdcp_transfer.c` + `xrdcp_recursive.c`. The `*_SPLIT` Make variables
record the groupings; the table lists each tool by its binary, not its files.

## Data movement

| Tool | Purpose |
|---|---|
| `xrdcp` | Copy files: `root://`, web URLs (`davs://`/`http(s)://`/`dav://`/`s3://`/`s3s://`), local paths, or `-`. Recursive + ZIP-member support. |
| `xrdfs` | Filesystem operations (`ls`/`stat`/`mkdir`/`rm`/`mv`/`cat`/`xattr`/…); with no command, an interactive shell (`root://`). Web backends too. |
| `xrd` | Multi-call swiss-army front-end exposing the full verb set (ls/stat/cat/cp/du/df/tree/find/locate/query/prepare/stage/evict/explain/…) plus the `battery`/`doctor`/`clockskew`/`mount` subcommands. |

## Checksums & verification

| Tool | Purpose |
|---|---|
| `xrdcrc32c` | CRC32c of a local or `root://` file. |
| `xrdcrc64` | CRC-64/XZ of a local or `root://` file. |
| `xrdadler32` | Adler-32 of a local or `root://` file. |
| `xrdckverify` | Verify a file on disk against its recorded checksum (xattr/`.cks`). |

## Diagnostics & monitoring

| Tool | Purpose |
|---|---|
| `xrddiag` | Connection/auth diagnostics + human-readable error explanation; subcommands `check`/`bench`/`watch`/`topology`/`compare`/`doctor`. |
| `xrdqstats` | Query and print a server's monitoring / config / space info. |
| `mpxstats` | Aggregate + pretty-print a server's summary statistics. |
| `xrdmapc` | Query a manager/redirector for the live cluster map of a path. |
| `wait41` | Block until an XRootD server accepts connections (scripting/orchestration). |

## Auth & security

| Tool | Purpose |
|---|---|
| `xrdgsiproxy` | Create / inspect / destroy an X.509 GSI proxy. |
| `xrdgsitest` | GSI handshake self-test against a server. |
| `xrdsssadmin` | Manage an SSS (Simple Shared Secret) keytab. |

## Namespace / staging

| Tool | Purpose |
|---|---|
| `xrdprep` | Issue a `kXR_prepare` (stage/cancel/evict/…) for one or more paths. |

## Optional (built only when `libfuse3` is present — not in `BINS`)

| Binary | Purpose |
|---|---|
| `xrootdfs` | FUSE mount. One binary containing both drivers — the async/resilient default and a simple synchronous `--legacy` fallback (front-end `xrootdfs_main.c`, multi-call like `xrd`). |
| `libxrdposix_preload.so` | LD_PRELOAD POSIX→XRootD read-path shim (see [`../preload/`](../preload/)). |

## See also

- [`../lib/README.md`](../lib/README.md) — the `libxrdc` library these tools link against.
- [`../lib/sec/README.md`](../lib/sec/README.md) — the authentication modules.
