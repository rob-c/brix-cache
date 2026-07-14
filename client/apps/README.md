# `client/apps/` — native client CLI tools

The command-line front-ends built on `libbrix` (`../lib/`). All are pure-C,
libXrdCl-free, and speak `root://`/`roots://` plus (where noted) HTTP/WebDAV/S3.
Binaries are listed in `BINS` in `client/Makefile` and land in `client/bin/`.

Several tools are **split across multiple `.c` files** (a single-responsibility
refactor, behavior-identical) that link into one binary — e.g. `xrdcp` =
`xrdcp.c` + `xrdcp_transfer.c` + `xrdcp_recursive.c`. The `*_SPLIT` Make variables
record the groupings; the table lists each tool by its binary, not its files.

## Data movement

| Tool | Purpose |
|---|---|
| `xrdcp` | Copy files: `root://`, web URLs (`davs://`/`http(s)://`/`dav://`/`s3://`/`s3s://`), local paths, or `-`. Recursive + ZIP-member support. Sync/mirror semantics (`--sync`, `--sync-check size\|mtime\|cksum`, `--delete`), dry-run (`-n`/`--dry-run`), path filters (`--exclude`/`--include`), resumable batches (`--journal`/`--resume`), post-transfer source removal (`--remove-source`). Local-disk overlap ring (`--io-uring on\|off\|auto`). X.509 proxy override (`--proxy`). TPC token-mode pass-through (`--tpc-token-mode`). |
| `xrdfs` | Filesystem operations (`ls [-l -R -j]`/`stat [-j]`/`mkdir`/`rm [-r]`/`mv`/`cat [-z codec]`/`tail [-f]`/`du [-j]`/`xattr`/…); `upload`/`download` both accept `--io-uring on\|off\|auto` for local-disk pipelining; with no command, an interactive shell (`root://`). Web backends support read-only metadata. |
| `xrd` | Multi-call swiss-army front-end exposing the full verb set (ls/stat/cat/cp/du/df/tree/find/locate/query/prepare/stage/evict/explain/…) plus the `battery`/`doctor`/`clockskew`/`mount` subcommands and the backend-storage verbs `inventory`/`verify`/`drift`/`inspect` (→ `xrdstorascan`). |

## Checksums & verification

| Tool | Purpose |
|---|---|
| `xrdcrc32c` | CRC32c of a local or `root://` file. |
| `xrdcrc64` | CRC-64/XZ of a local or `root://` file. |
| `xrdadler32` | Adler-32 of a local or `root://` file. |
| `xrdckverify` | Verify a file on disk against its recorded checksum (xattr/`.cks`). |
| `xrdcksum tree` | Produce a sha256sum-style manifest of a local directory or `root://` tree (`--algo NAME`; default `adler32`; `-o FILE`). |
| `xrdcksum check` | Verify every digest in a manifest against a local directory or `root://` tree (`--algo NAME`). |

## Diagnostics & monitoring

| Tool | Purpose |
|---|---|
| `xrddiag` | Connection/auth diagnostics + human-readable error explanation; subcommands `check`/`bench`/`watch`/`topology`/`compare`/`doctor`. `check <url>` and `topology <url>` both accept `--json` for machine-readable output. `replay <file.xrdcap>` decodes a previously captured session; add `--playback <url>` to re-issue it against a live server. |
| `xrdqstats` | Query and print a server's monitoring / config / space info. |
| `mpxstats-brix` | Aggregate + pretty-print a server's summary statistics. |
| `xrdmapc` | Query a manager/redirector for the live cluster map of a path. |
| `wait41-brix` | Block until an XRootD server accepts connections (scripting/orchestration). |
| `xrdstorascan` | Backend-aware storage admin tool. Phase 1 (client-side, any backend): `verify <url>` — end-to-end single-file integrity (pull the bytes, recompute, compare to the server's `kXR_Qcksum`); `bench <url>` — gateway throughput/IOPS/latency sweep over block size × parallelism. Later phases add server-engine modes (`inspect`/`inventory`/`drift`/`health`). |

## Auth & security

| Tool | Purpose |
|---|---|
| `xrdgsiproxy` | Create / inspect / destroy an X.509 GSI proxy. |
| `xrdgsitest` | GSI handshake self-test against a server. |
| `xrdsssadmin-brix` | Manage an SSS (Simple Shared Secret) keytab. |

## Namespace / staging

| Tool | Purpose |
|---|---|
| `xrdprep` | Issue a `kXR_prepare` (stage/cancel/evict/…) for one or more paths. |

## Optional (built only when `libfuse3` is present — not in `BINS`)

| Binary | Purpose |
|---|---|
| `xrootdfs` | FUSE mount. One binary containing both drivers — the async/resilient default and a simple synchronous `--legacy` fallback (front-end `xrootdfs_main.c`, multi-call like `xrd`). |
| `brixMount` | Umbrella FUSE front-end: `brixMount <type> <endpoint> <mountdir>` — `cvmfs` (CVMFS-brix, read-only), `cvmfs-rw` (CVMFS-brix-rw: same mount plus a local writable overlay in `<mountdir>/.brixwrites` — copy-up, whiteout deletes; manage with `brixMount --overlay-list/--overlay-reset <mountdir>`), `eos`/`root`/`roots` (XRootDFS-brix). |
| `libbrixposix_preload.so` | LD_PRELOAD POSIX→XRootD read-path shim (see [`../preload/`](../preload/)). |

## Ceph operator tools (`apps/ceph/` — built only when the Ceph dev headers are present)

Storage-plane migration and rescue utilities linking librados directly (they
do not speak `root://`). Compile-gated per tool; `make -C client ceph-tools`
builds exactly this group. The migration pair ships BOTH a compiled C++
primary and a pure-Python variant (`.py` suffix, installed under
`libexec/brix/` with `bin/` symlinks) with extra operator plumbing
(`--json`, resumable `--state`, `--prefix`/`--match` filters, `--progress`)
backed by the `pymigrate/` package (ctypes bridge to librados's C++-only
manifest ops, with a compiled shim fallback).

| Binary | Purpose |
|---|---|
| `xrdceph_striper_migrate` (+ `.py`) | libradosstriper (stock XrdCeph) pool → CephFS. Zero-move redirect default, `--mode copy`, `--rollback` (detaches stubs first — source always intact), `--finalize`. |
| `xrdceph_cephfs_to_striper` (+ `.py`) | Quiesced CephFS → libradosstriper pool (namespace walked from pure RADOS). Zero-move redirects, `--rollback`, `--finalize`; requires `--assume-quiesced`. |
| `xrdrados_rescue` | Offline recovery from a flat RADOS pool (`ls`/`stat`/`get`/`cp`). |
| `xrdcephfs_rescue` | Offline CephFS recovery via pure RADOS — no mount, no MDS (drives the read-only `cephfsro` driver core). |
| `xrdceph_migrate` | Flat pool → filesystem tree copy-through-mount (the only sound flat→CephFS upgrade). |

## Configuration — `~/.xrdrc`

The per-user config file supports two kinds of section:

**`[alias NAME]`** — endpoint credential bundles (looked up by URL prefix or explicit
alias argument). Keys: `url`, `token`, `token_file`, `bearer_token_file`, `s3_access`,
`s3_secret`, `s3_region`.

**`[defaults]`** — connection timeout overrides that apply when no CLI flag or
environment variable is set. All values are positive integers in milliseconds.
Precedence: CLI flag > environment variable > `[defaults]` value > compiled default.

| Key | Equivalent env var | Description |
|---|---|---|
| `connect_timeout_ms` | `XRDC_CONNECT_TIMEOUT_MS` | TCP + protocol bring-up timeout |
| `io_timeout_ms` | `XRDC_IO_TIMEOUT_MS` | Per-operation I/O timeout once connected |
| `max_stall_ms` | `XRDC_MAX_STALL_MS` | Reconnect/resume patience window |
| `backoff_base_ms` | — | Base for exponential reconnect back-off (default 25 ms) |

Override the config file path with `$XRDRC`.

## Man pages & bash completion

Man pages land in `client/man/` (section 1). Install them system-wide:

```bash
sudo cp client/man/*.1 /usr/local/share/man/man1/
```

Bash completion is in `client/completions/brix-tools.bash`. Source it in your
shell or drop it in `/etc/bash_completion.d/`:

```bash
# per-user
echo 'source /path/to/client/completions/brix-tools.bash' >> ~/.bashrc

# system-wide
sudo cp client/completions/brix-tools.bash /etc/bash_completion.d/brix-tools
```

zsh: `autoload -U +X bashcompinit && bashcompinit`, then source the same file.

## CLI compatibility contract (binding for all flag/env/output work)

Per [`docs/superpowers/specs/2026-07-06-client-cli-usability-design.md`](../../docs/superpowers/specs/2026-07-06-client-cli-usability-design.md) §2:

- **C1** — existing flags, env vars, subcommands, and exit codes never change
  meaning; new spellings are additive aliases only.
- **C2** — legacy env names (`XrdSec*`) are accepted forever; new lookups go
  through `brix_env_resolve()` chains (see `brix-env(7)`).
- **C3** — interactive hints go through `brix_cli_hint*()` ONLY (TTY-gated,
  `BRIX_NO_HINTS` opt-out); non-TTY output is byte-identical, enforced by
  `tests/test_cli_golden.py`.
- **C4** — diagnostics never print to stdout.
- **C5** — exit-code values are frozen (documented per tool in the man pages).

Usage text, man page, and shell completion must stay in sync for every flag —
`client/man/check_man.sh` and `client/completions/check_completions.sh` run in
`make -C client test` and fail the build on drift.

## See also

- [`../lib/README.md`](../lib/README.md) — the `libbrix` library these tools link against.
- [`../lib/sec/README.md`](../lib/sec/README.md) — the authentication modules.
- [`../README.md`](../README.md) — client/ directory overview and build instructions.
