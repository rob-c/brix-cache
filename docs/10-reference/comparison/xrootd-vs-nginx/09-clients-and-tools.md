# Client Tooling — Official XRootD vs. gnuBall Native Suite

> Part of the [XRootD vs gnuBall comparison set](./README.md).

This document compares the **official XRootD client tooling** (the `XrdCl` C++
library, the `xrdcp` / `xrdfs` apps, the `XrdClHttp` plugin, the `XrdFfs`
`xrootdfs` FUSE driver, and the `pyxrootd` Python bindings) against the
**gnuBall native client suite**: a clean-room, pure-C set of tools built on
`libxrdc` and the project's shared `libxrdproto`, with **no dependency on
`libXrdCl` / `libXrdSec*`**.

Every claim below is grounded in source. The official side cites
`/tmp/xrootd-src/src/XrdCl/` (the C++ library), `XrdApps/` (the `xrdcp` /
`xrdfs` config + driver), `XrdClHttp/` (the HTTP transport plugin), `XrdFfs/`
(the FUSE driver), and `python/` (the bindings). The gnuBall side cites
this repository's `client/` tree (`apps/`, `lib/`) and `shared/xrdproto/`.
Where behaviour was already verified by earlier work, this doc reuses the facts
from the companion documents and the source-verified comparison rather than
re-deriving them:

- [`../../source-verified-xrootd-comparison.md`](../../source-verified-xrootd-comparison.md) — the source-grounded server/protocol comparison.
- [`02-rootd-protocol.md`](./02-rootd-protocol.md) — the `root://` wire-protocol parity this client speaks.
- [`../conformance-findings.md`](../conformance-findings.md) — fixed wire divergences vs. the spec + stock tools.

---

## Scope

This is a comparison of **client-side tooling** — the programs and libraries an
end user or an embedding application runs to move data and manipulate the
namespace. It is *not* a comparison of the servers (that is the rest of this
set). Concretely it covers:

- the copy tool (`xrdcp`),
- the filesystem/namespace tool (`xrdfs`),
- the FUSE driver (`xrootdfs`),
- the embeddable client library (`libXrdCl` vs. `libxrdc`),
- the resilience/UX behaviours the native suite layers on top, and
- interop in both directions (our clients vs. stock/EOS/dCache servers; stock
  clients vs. our server).

The native suite is the phase-37 clean-room rewrite. Its design log is
`docs/refactor/phase-37-clean-room-log.md`; the wire facts it implements come
only from the `src/protocols/root/protocol/` headers (cross-checked against
`XProtocol.hh`), never from `XrdCl` source.

---

## In official XRootD (XrdCl & apps)

The official client stack is a **heavyweight, asynchronous C++ library** with the
apps as thin front-ends on top of it.

- **`XrdCl` core library** (`/tmp/xrootd-src/src/XrdCl/`). The public API is the
  C++ classes `XrdCl::File` (`XrdClFile.hh:51`), `XrdCl::FileSystem`
  (`XrdClFileSystem.hh:208`), and `XrdCl::CopyProcess` /
  `XrdCl::CopyJob` / `XrdCl::CopyProgressHandler` (`XrdClCopyProcess.hh`).
  Underneath sits a full async machine: `XrdClPostMaster.{cc,hh}` (the connection
  multiplexer), `XrdClAsyncSocketHandler.{cc,hh}`, and `XrdClJobManager.{cc,hh}`
  (a thread-pool callback dispatcher). Transports are pluggable through
  `XrdClPlugInManager.{cc,hh}`.
- **`xrdcp`** — driven by `XrdCl/XrdClCopy.cc`, configured by
  `XrdApps/XrdCpConfig.{cc,hh}`. It drives `CopyProcess` jobs and supports TPC,
  parallel streams/sources, ZIP, checksums, and resume.
- **`xrdfs`** — `XrdCl/XrdClFS.cc` plus the command registry
  `XrdClFSExecutor.cc`; each subcommand is a `DoXxx` handler that calls
  `FileSystem`.
- **`XrdClHttp` plugin** (`/tmp/xrootd-src/src/XrdClHttp/`) — a *separate*
  bolt-on transport (factory `XrdClHttpFactory`, with `XrdClHttpFile` /
  `XrdClHttpFilesystem` and per-op files) that teaches `XrdCl` to speak
  `http(s)://` via davix. It is a plugin, not part of the core.
- **`pyxrootd` bindings** (`/tmp/xrootd-src/python/`) — a C extension module
  named `client` (`PyXRootDModule.cc:68`), packaged as `XRootD.client`, exposing
  `FileSystem`, `File`, `URL`, and `CopyProcess` Python types with async response
  handlers.
- **`xrootdfs` FUSE driver** (`/tmp/xrootd-src/src/XrdFfs/`) — notably does
  **not** use `XrdCl`; it rides the synchronous `XrdPosixXrootd` POSIX shim with
  its own `pthread` worker pool (`XrdFfsQueue`) and a write cache
  (`XrdFfsWcache`). `root://` only.

Strengths: mature, feature-complete, the reference for wire behaviour, broad
auth via `XrdSec*` plugins. Cost: a large C++ dependency graph
(`libXrdCl`, `libXrdSec*`, `libXrdUtils`, davix for HTTP), and the FUSE driver is
a separate, synchronous, single-transport codepath.

---

## In gnuBall (native pure-C suite)

The native suite is a **clean-room, pure-C** reimplementation built directly on
the project's own wire vocabulary.

- **`libxrdc`** (`client/lib/`) — the connection/session + metadata/file/transfer
  layer. Header `client/lib/xrdc.h` documents the whole API. It is built on
  `shared/xrdproto/libxrdproto.a` (the ngx-free protocol core shared
  server↔client) and links only OpenSSL, optionally `krb5`
  (`client/lib/sec/sec_krb5.c`, compile-gated `XROOTD_HAVE_KRB5`) and `liburing`
  (`client/lib/uring.c`, compile-gated `XROOTD_HAVE_LIBURING`). **No `libXrdCl`,
  no `libXrdSec*`** (`client/Makefile` header).
- **`xrdcp`** (`client/apps/xrdcp.c`) — a copy tool that handles `root://`,
  `roots://`, and the web schemes `davs:// http(s):// dav:// s3:// s3s://` in one
  binary, with batch/glob/manifest expansion, web→web relay, and parallel jobs.
- **`xrdfs`** (`client/apps/xrdfs.c`) — a filesystem tool whose subcommand set is
  a **superset** of the stock client (it adds `du`, `tree`, `find`, `grep`, `wc`,
  `head`, `hexdump`, `dd`, `cmp`, `touch`, `ln`, `readlink`, `cksum`, `readv`,
  `writev`, `stage`, `evict`, `explain`, plus an interactive REPL).
- **`xrootdfs`** (`client/apps/xrootdfs.c`, with `xrootdfs_legacy.c`) — an
  async, network-resilient FUSE driver on `libfuse3` that also mounts
  `http/https/dav/davs` read-only via `webfile.c`.
- **A family of single-purpose tools** under `client/apps/`, fronted by a
  git-style dispatcher `xrd` (`client/apps/xrd.c`): `xrddiag`, `xrdmapc`,
  `xrdprep`, `xrdqstats`, `xrdgsiproxy`, `xrdsssadmin`, `mpxstats`, `wait41`,
  `xrdadler32`, `xrdcrc32c`, `xrdcrc64`, `xrdgsitest`.

**Why a from-scratch client?** To get a `libXrdCl`-free toolchain that the test
harness can drive (`TEST_XRDCP_BIN` / `TEST_XRDFS_BIN`) for a meaningful
conformance diff against the stock tools, to ship small static binaries with no
C++ runtime dependency, and to grow a "swiss-army-knife" WLCG data mover whose
resilience and UX can be tuned for laptops on bad networks. The native suite
deliberately mirrors the *documented* `xrdcp.1` / `xrdfs.1` option semantics,
not the `XrdCl` internals.

---

## xrdcp parity

Official option letters/long names are from `XrdApps/XrdCpConfig.{cc,hh}` (short
string `":C:d:D:EfFhHI:NpPrRsS:t:T:vVX:y:z:ZA"`, `opVec[]`, and the `Op*` enums).
Native flags are from the parse loop in `client/apps/xrdcp.c` (≈ lines
1173–1229).

| Capability | Official `xrdcp` | Native `xrdcp` | Notes |
|---|---|---|---|
| Force overwrite | `-f` / `--force` | `-f` | parity |
| No progress bar | `-N` / `--nopbar` | `-N` (accepted; native shows no bar unless `--progress`) | parity-ish |
| Silent | `-s` / `--silent` | `-s` | parity |
| Recursive | `-r` / `--recursive` (+ `-R`) | `-r` / `-R` | parity; native adds web↔local + web→web recursion |
| Persist-on-close (POSC) | `-P` / `--posc` | `-P` only | **gap: no `--posc` long flag** |
| Checksum | `--cksum <type>[:source\|:print\|:<hex>]` | `--cksum <t>[:source\|:print\|:<value>]` (+ `--verify`) | parity on syntax; see soft-pass gap below |
| Parallel TCP streams | `-S` / `--streams <n>` | `-S` / `--streams <n>` (`kXR_bind` secondaries) | parity |
| Parallel **sources** | `-y` / `--sources <n>` (default 12) | not implemented | gap (single source per file) |
| Concurrent file copies | `--parallel <n>` (1–128) | `-j` / `--jobs <n>` (batch mode) | equivalent feature, different flag |
| Retry | `-t` / `--retry <n>` (+ `--retry-policy`) | `--retry <n>` (equal-jitter backoff) | flag differs (`-t` vs `--retry`) |
| Third-party copy | `-T` / `--tpc <first\|only [delegate]>` | `--tpc first\|only\|delegate` (+ `--tpc-token-mode`) | parity |
| Rate cap | `-X` / `--xrate` (+ `--xrate-threshold`) | not implemented | gap |
| Remove bad-cksum target | `--rm-bad-cksum` | not implemented | gap |
| SOCKS proxy | `-D` / `--proxy` | not implemented | gap (rarely used) |
| ZIP | `-z` / `--zip` (+ `--zip-append`) | `--zip` / `--zip-append` | parity |
| Resume | `--continue` | not implemented | gap |
| stdin/stdout `-` | via file list (gated by `optNoStdIn`) | `-` as src/dst | parity |
| In-protocol TLS control | `-E`/`--tlsnodata`, `--notlsok` | `--tls`, `--notlsok`, `--noverifyhost` | parity-ish |
| **Inline compression** | — | `--compress <gzip\|deflate\|zstd\|br\|xz\|bzip2>` | **native extension** (server opt-in, transparent) |
| **Paged I/O + per-page CRC** | — (internal) | `--pgrw` (`kXR_pgread`/`kXR_pgwrite`) | native exposes it as a flag |
| **`--sync` (size-skip)** | — | `--sync` | native extension (rsync-like) |
| **`--from <manifest>`** | `-I` / `--infiles` | `--from <file>` (`-`=stdin) | equivalent feature |
| **`--auto-refresh` creds** | — | `--auto-refresh` (+ `--oidc-account`) | native extension (oidc-agent / GSI proxy) |
| **S3 SigV4 keys** | — (S3 not a native scheme) | `--s3-access/-secret/-region` | native extension |
| **Bearer token** | (env / URL) | `-T` / `--token` (or `$BEARER_TOKEN`) | native convenience |
| **`--wire-trace` / `--timing`** | `-d` debug | `--wire-trace[=N]`, `--timing` | native diagnostics |
| Version / help | `-V`, `-H`/`--license`, `-h` | `-V`, `-h` | parity |

Net: the native `xrdcp` covers the common transfer flags (force/recursive/posc/
streams/cksum/tpc/zip/stdio) and *adds* multi-protocol (davs/http/s3) transfers,
inline compression, `--sync`, credential auto-refresh, and richer wire
diagnostics; it lacks `--sources`, `--xrate`, `--rm-bad-cksum`, `--continue`, and
the SOCKS `--proxy`, and the POSC long-flag and `-t` retry letter differ.

---

## xrdfs parity

Official subcommands are registered in `XrdCl/XrdClFS.cc` via
`executor->AddCommand(...)` (the registry is `XrdClFSExecutor.cc`). Native
subcommands are in the dispatch table at the bottom of `client/apps/xrdfs.c`
(≈ lines 2560–2595).

| Subcommand | Official `xrdfs` | Native `xrdfs` | Notes |
|---|---|---|---|
| `cd` / `pwd` | yes (REPL) | yes (REPL) | parity |
| `ls` | yes | yes (`-l -R -h`) | parity + `-h` human sizes; see `ls <file>` gap |
| `stat` | yes | yes (incl. extended ctime/atime/mode/owner/group) | parity+ |
| `statvfs` | yes | yes | parity |
| `locate` | yes | yes | parity |
| `query` | yes (`config\|space\|checksum\|stats`) | yes (same four) | parity |
| `cat` | yes | yes (resilient streaming) | parity |
| `tail` | yes | yes (`-c -n -f --interval`) | parity+ (`-f` follow) |
| `mkdir` | yes (`-p`, mode) | yes (`-p -m`) | parity |
| `rmdir` | yes | yes | parity |
| `rm` | yes | yes | parity |
| `mv` | yes | yes | parity |
| `chmod` | yes — **symbolic `rwxr-xr-x` only** (`ConvertMode`, length must be 9) | yes — **accepts both symbolic `rwxr-xr-x` and octal `755`** (`parse_chmod_mode`) | native superset (gap was fixed; see below) |
| `truncate` | yes | yes | parity |
| `cp` | yes (`DoCp`) | not a subcommand — uses `upload`/`download`/`dd` | feature covered, name differs |
| `prepare` | yes | yes (`-s -w -c -f -e`) | parity |
| `spaceinfo` | yes (`DoSpaceInfo`) | covered by `df` / `query space` / `statvfs` | name differs |
| `xattr` | yes (`ls\|get\|set\|rm`) | yes (`ls\|get\|set\|rm`) | parity; see output gap below |
| `cache` | yes | not implemented | gap (cache-context op) |
| **`du`** | — | yes (`-h`, recursive size) | native extension |
| **`tree`** | — | yes (`-d -L N`) | native extension |
| **`find`** | — | yes (`-name`, `-type`, `-size`) | native extension |
| **`grep`** | — | yes (`-i -n` POSIX regex) | native extension |
| **`wc`** | — | yes (`-c -l -w`) | native extension |
| **`head`** | — | yes (`-c -n`) | native extension |
| **`hexdump`** | — | yes (`-n`) | native extension |
| **`dd`** | — | yes (`bs/skip/count/rate`) | native extension |
| **`upload`/`download`** | — | yes (rate-paced, resumable) | native extension |
| **`cmp`** | — | yes | native extension |
| **`touch`** | — | yes (`-c -a -m -t`) | native extension |
| **`ln` / `readlink`** | — | yes (`-s -f`; wire ext) | native extension |
| **`cksum`** | (via `query checksum`) | yes (`-a algo`, multi-algo) | native convenience |
| **`readv` / `writev`** | — | yes (scatter-gather, `kXR_readv`/`kXR_writev`) | native extension |
| **`stage` / `evict`** | (via `prepare`) | yes (`stage --wait` polls residency) | native convenience |
| **`explain`** | — | yes (connection/auth/TLS facts) | native diagnostics |
| **WebDAV endpoint** | — | `ls`/`stat` over `http(s)/dav(s)` (PROPFIND) | native extension |

Net: the native `xrdfs` is a **strict superset** of the stock subcommand set
plus a large toolbox of POSIX-style convenience commands, with `chmod` accepting
both mode forms. The only true gap is `cache`; `cp`/`spaceinfo` are present under
different names (`upload`/`download`/`dd` and `df`/`statvfs`).

---

## FUSE (xrootdfs)

| Aspect | Official `XrdFfs` xrootdfs | Native `client/apps/xrootdfs.c` |
|---|---|---|
| Library base | `XrdPosixXrootd` POSIX shim (not `XrdCl`) | `libxrdc` async core (`aio.c` / `aio_mgr.c`) + `libfuse3` |
| Concurrency | synchronous + own `pthread` worker pool (`XrdFfsQueue`); may need FUSE `-s` | async, multi-in-flight transport over a connection pool; pipelining hides RTT |
| Transport | `root://` only (rewrites `xroot://`→`root://`) | `root://` **and** read-only `http/https/dav/davs` via `webfile.c` (PROPFIND + ranged GET) |
| Resilience | reconnect on drop (POSIX layer) | transparent reconnect + **handle reopen + offset resume** mid-transfer (never re-truncates); kXR_ping heartbeat; per-request adaptive deadlines |
| Write cache | `XrdFfsWcache` (write cache) | shared read-ahead / write-back engine (`iobuf.c`); random writes via `kXR_open_updt` |
| Symlink/link/readlink | implemented | implemented when the server advertises the vendor POSIX extension; honest fallback (`-ENOTSUP` / no-op utimens/chown so `cp -p` works) otherwise |
| xattr | `setxattr/getxattr/listxattr/removexattr` | same four, via `fattr.c` + shared `posix_map.c` translation |
| Mode | one driver | async is default; `xrootdfs_legacy.c` (`xrd mount --legacy`) is the simple sync driver |

FUSE op coverage on the native side (`fuse_operations` in `xrootdfs.c`):
`init, getattr, readdir, open, create, read, write, flush, release, fsync,
mkdir, unlink, rmdir, rename, chmod, truncate, chown, utimens, symlink,
readlink, link, statfs, access, getxattr, setxattr, listxattr, removexattr` —
matching the official driver's op set (`XrdFfsXrootdfs.cc:1316-1343`), with the
async transport, the alternate HTTP/WebDAV transport, and mid-transfer
resilience as the differentiators. The official driver's edge is maturity and
its `mknod`/full-POSIX history; the native driver's edge is "tolerant to bad
wifi from a laptop abroad" — its stated design goal.

---

## libxrdc vs libXrdCl

What an **embedder** gets:

| Concern | `libXrdCl` (official) | `libxrdc` (native) |
|---|---|---|
| Language / ABI | C++ classes (`XrdCl::File`, `XrdCl::FileSystem`, `XrdCl::CopyProcess`) | C structs + functions (`xrdc_conn`, `xrdc_file`, `xrdc_copy`, `xrdc_pool`) — `client/lib/xrdc.h` |
| Dependencies | `libXrdCl`, `libXrdSec*`, `libXrdUtils`, davix (HTTP) | OpenSSL; optional `krb5`, `liburing`; built on `libxrdproto` |
| Concurrency model | async event loop (`PostMaster` + `JobManager` callbacks) | blocking sockets + `poll(2)`; one in-flight per `xrdc_conn`; an async manager (`xrdc_mgr`/`xrdc_mfile`, `aio.h`) for pipelined file I/O; a thread-safe `xrdc_pool` for concurrent callers |
| File API | `Open/Read/Write/PgRead/PgWrite/VectorRead/Sync/Close`, checkpoints | `xrdc_file_{open_read,open_write,open_update,read,write,readv,writev,pgread,pgwrite,sync,close}`; resilient `xrdc_rfile`/`xrdc_mfile` variants |
| FS API | `Stat/DirList/MkDir/Rm/RmDir/Mv/ChMod/Truncate/Locate/Query/Prepare` | `xrdc_{stat,lstat,dirlist,mkdir,rm,rmdir,mv,chmod,truncate,locate,query,prepare,statvfs,setattr,symlink,link,readlink,fattr_*}` |
| Copy | `CopyProcess` jobs | `xrdc_copy()` (one call drives root/web/s3, TPC, compression, cksum, progress) |
| Transports | root:// core + HTTP via plugin | root:// + web (HTTP/WebDAV/S3) first-class in `http.c`/`s3.c`/`webfile.c` |
| Auth | `XrdSec*` plugins (gsi/krb5/sss/unix/ztn/pwd/…) | `client/lib/sec/`: `sec_gsi.c`, `sec_krb5.c`, `sec_sss.c`, `sec_token.c` (ZTN), `sec_unix.c`, `sec_host.c`, `sec_pwd.c` |
| Status model | `XRootDStatus` objects | `xrdc_status` (kXR code + errno + message) with `xrdc_status_retryable` / `xrdc_kxr_to_errno` |
| Diagnostics | logging env vars | wire-trace, per-opcode timing, `.xrdcap` capture/replay, netdiag, `explain` (`xrdc.h` §15) |

The native library trades the official async-everywhere model and plugin
ecosystem for a small, dependency-light C surface that is easy to static-link and
embed (it is what the FUSE driver and every native app sit on).

---

## Resilience & UX extensions

These are nginx-forward behaviours the native suite layers on top — most have no
direct stock equivalent. All are grounded in `client/lib/`:

- **Auth pre-flight diagnostics** (`credinfo.c`, `xrdc_cred_diagnose` /
  `xrdc_cred_hint_for_status`): before a transfer, locally inspect the bearer
  token / GSI proxy (no network, no signature verify) and print a specific hint
  ("token expired 3m ago", "scope grants read only") instead of a bare
  "permission denied".
- **Atomic / cancellable transfers** (`copy.c`,
  `xrdc_copy_install_signal_handlers`): SIGINT/SIGTERM drops the partial
  destination rather than leaving a corrupt file.
- **`--auto-refresh` credentials** (`credrefresh.c`,
  `xrdc_cred_autorefresh`): proactively reacquire a stale bearer token via
  `oidc-agent` and/or a GSI proxy before transferring.
- **IPv6→IPv4 sticky auto-downgrade** (`netpref.c`): on a dual-stack host, once a
  broken IPv6 path is observed the whole session demotes to IPv4-only (logged
  once), with self-heal and an `XRDC_NO_IPV6_FALLBACK` opt-out.
- **Firewall / connect-timeout handling** (`nettmo.c`): separate connect+
  handshake bring-up cap (`XRDC_CONNECT_TIMEOUT_MS`) vs. steady-state I/O cap
  (`XRDC_IO_TIMEOUT_MS`), with exponential-plus-jitter backoff so a black-holed
  handshake fails fast.
- **Fast-fail on permanent errors** (`status.c`, the `XRDC_E*` sentinels in
  `xrdc.h`): resolve failures (`XRDC_ERESOLVE`), redirect loops
  (`XRDC_EREDIRECT`), integrity failures (`XRDC_EINTEGRITY`), and unsupported
  features (`XRDC_EUNSUPPORTED`) are classified non-retryable, so the resilient
  loop does not burn its stall window retrying something that cannot succeed.
- **Synchronous-tool resilience** (`resilient.c`, `xrdc_with_resilience` /
  `xrdc_rfile`): brings the FUSE driver's reconnect+reopen+offset-resume to the
  one-shot CLI flows (e.g. `xrdfs cat` rides out a mid-stream sever), gated by an
  idempotency class and disabled by `--no-retry`.

---

## Known client gaps (from conformance testing)

These gaps were surfaced by differential conformance testing against the stock
tools during this session. Some are fixed; the rest are documented for parity.

- **`xrdfs chmod` symbolic mode — FIXED.** Stock `xrdfs` takes only the 9-char
  symbolic form (`rwxr-xr-x`); the native tool previously ran it through
  `strtol(...,8)`, turning `rwxr-xr-x` into mode `000`. `parse_chmod_mode`
  (`xrdfs.c`) now accepts **both** the symbolic form and an octal absolute mode
  (`755`).
- **`xrdcp --posc` long flag missing.** Only `-P` is accepted; the documented
  `--posc` long form is not wired in the parse loop. (POSC itself works via
  `-P`.)
- **`xrdcp <remote> <existing-dir>` wrong outcome + `rc=0`.** A single-source
  copy whose destination is an existing directory should land
  `dir/<basename>`; the single-copy path does not derive the basename the way the
  batch path (`batch_copy_one`) does, and can report success incorrectly.
- **`xrdcp -r` flattens the source directory name.** Recursive copy places the
  source's *contents* into the destination rather than preserving the top-level
  source directory name (the web/s3 recursive walkers copy
  `dstdir/<rel-under-source>`, dropping the source dir component).
- **`xrdfs ls <file>` errors.** Listing a path that is a file (not a directory)
  returns an error from `xrdc_dirlist` rather than printing the single entry the
  way stock `ls` does.
- **`xrdcp --cksum` soft-pass when unverifiable.** When the server cannot supply
  the requested checksum, the transfer can pass silently instead of failing — the
  verify step is not strict about an *absent* server checksum.
- **`xrdfs xattr get`/`ls` output incomplete.** `xattr_ls` strips the one-letter
  namespace tag for round-tripping, but the get/list formatting does not fully
  match stock output (value framing / multi-value cases), so a byte-for-byte diff
  against the stock client differs.

---

## Parity summary

| Tool / library | Verdict |
|---|---|
| `xrdcp` | Core transfer flags at parity (force/recursive/posc/streams/cksum/tpc/zip/stdio); native adds multi-protocol (davs/http/s3), inline compression, `--sync`, manifests, cred auto-refresh, wire diagnostics. Gaps: `--sources`, `--xrate`, `--rm-bad-cksum`, `--continue`, SOCKS `--proxy`, `--posc` long flag; plus the conformance bugs above. |
| `xrdfs` | **Superset** of the stock subcommand set, with both chmod mode forms and a large POSIX-style toolbox; only `cache` is genuinely absent; `cp`/`spaceinfo` exist under other names. Output-format edge cases (`ls <file>`, `xattr` framing) remain. |
| `xrootdfs` (FUSE) | Functional parity on the op set, **ahead** on async transport, mid-transfer resume, and an alternate HTTP/WebDAV transport; behind on maturity. |
| `libxrdc` vs `libXrdCl` | Different shape: small dependency-light C library vs. large async C++ stack. Native is easier to static-link/embed; official is more featureful and the wire reference. |
| Interop | Native clients interoperate with **real EOS** (GSI x509 proxy, cap-opaque host split, `Qcksum`), and aim at stock-xrootd / dCache; stock `xrdcp`/`xrdfs`/`pyxrootd` interoperate with the gnuBall server (the conformance suite drives both directions). |

---

## Source references

**Official (`/tmp/xrootd-src/src/`):**
- `XrdCl/XrdClFile.hh`, `XrdClFileSystem.hh`, `XrdClCopyProcess.hh` — public API classes.
- `XrdCl/XrdClPostMaster.{cc,hh}`, `XrdClAsyncSocketHandler.{cc,hh}`, `XrdClJobManager.{cc,hh}`, `XrdClPlugInManager.{cc,hh}` — async core + plugins.
- `XrdApps/XrdCpConfig.{cc,hh}`, `XrdCl/XrdClCopy.cc` — `xrdcp` options + driver.
- `XrdCl/XrdClFS.cc` (incl. `ConvertMode`, `DoChMod`, `DoCp`, `DoSpaceInfo`, `DoXAttr`), `XrdClFSExecutor.cc` — `xrdfs`.
- `XrdClHttp/` (`XrdClHttpFactory`, `XrdClHttpFile`, `XrdClHttpFilesystem`, per-op files) — HTTP transport plugin.
- `XrdFfs/XrdFfsXrootdfs.cc`, `XrdFfsWcache.{cc,hh}`, `XrdFfsQueue.{cc,hh}`, `XrdFfsPosix.{cc,hh}` — FUSE driver (sync, root:// only, write cache).
- `python/PyXRootDModule.cc` + `python/libs/client/` — `pyxrootd` bindings.

**gnuBall (`client/` + `shared/`):**
- `client/lib/xrdc.h` — the `libxrdc` public API (conn/file/fs/copy/pool/auth/diagnostics).
- `client/apps/xrdcp.c` — copy tool (multi-protocol, batch/glob/manifest, web→web relay, parallel jobs).
- `client/apps/xrdfs.c` — filesystem tool + REPL (`parse_chmod_mode`, the subcommand table, the power-tool handlers).
- `client/apps/xrootdfs.c`, `client/apps/xrootdfs_legacy.c` — async/resilient + legacy FUSE drivers; op set in `fuse_operations`.
- `client/lib/`: `conn.c`, `copy.c`, `aio.c`/`aio.h`/`aio_mgr.c`, `uring.c`, `resilient.c`, `netpref.c`, `nettmo.c`, `credinfo.c`, `credrefresh.c`, `status.c`, `http.c`, `s3.c`, `webfile.c`, `weblist.c`, `fattr.c`, `streams.c`, `pool.c`, `sec/`.
- `client/apps/`: `xrd.c` (dispatcher), `xrddiag.c`, `xrdmapc.c`, `xrdprep.c`, `xrdqstats.c`, `xrdgsiproxy.c`, `xrdsssadmin.c`, `mpxstats.c`, `wait41.c`, `xrdadler32.c`, `xrdcrc32c.c`, `xrdcrc64.c`, `xrdgsitest.c`.
- `shared/xrdproto/` — the ngx-free protocol core shared by server and client.
- `client/Makefile` — the libXrdCl-free build (krb5/liburing/codec compile gates).
