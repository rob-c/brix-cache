# Native Client Tools

This project now ships a clean-room client stack in `client/` alongside the
nginx module. These tools are built on the project's own protocol vocabulary and
client library, not on upstream `libXrdCl`, `libXrdSec*`, `XrdFfs`, or
`XrdPosix`.

```text
   CLI tools            FUSE / POSIX            ← user-facing
   xrdcp xrdfs xrddiag  xrootdfs (async+legacy)
   xrdgsiproxy …        libxrdposix_preload.so
        └─────────┬───────────┘
                  ▼
        ┌───────────────────────┐   clean-room C API (client/lib/xrdc.h)
        │      libxrdc           │   connect · auth · I/O · TPC · checksums
        │  auth: unix·ztn·sss·   │   resilience · IPv6→v4 downgrade · pools
        │        gsi·(krb5)      │
        └──────────┬────────────┘
                   ▼
        ┌───────────────────────┐   shared protocol vocabulary
        │  libxrdproto           │   wire structs · framing · helpers
        │  (shared with the      │   (compiled -DXRDPROTO_NO_NGX for client)
        │   nginx module)        │
        └──────────┬────────────┘
                   ▼
            system OpenSSL · zlib · optional krb5 / libfuse3
                   ✗ NOT linked: libXrdCl / libXrdSec* / XrdFfs / XrdPosix
                     (asserted by ldd — one auditable stack, no upstream runtime)
```

This page is source-verified against:

- `client/Makefile`
- `client/lib/xrdc.h`
- `client/apps/*.c`
- `client/preload/xrdposix_preload.c`
- `client/man/xrootdfs.1`
- `docs/09-developer-guide/fuse-async-resilient-driver.md`

Older Phase 37 planning docs are useful history, but this page is the
operator-facing summary of the current client surface.

## Build And Install

Build the client suite from the repository root:

```bash
make -C client
```

The Makefile builds:

- `libxrdc.a` and `libxrdc.so.0.1.0`, plus `libxrdc.pc`
- protocol/client command-line tools in `client/`
- `libxrdposix_preload.so`
- optional FUSE binary `xrootdfs` (with a `--legacy` synchronous mode) when `fuse3` is available

Install the library, headers, pkg-config file, binaries, and man pages with:

```bash
make -C client install
make -C client install-bin
```

The client build is intentionally independent of the nginx module build. It links
the in-tree protocol/client code plus system OpenSSL/zlib, optional Kerberos, and
optional libfuse3.

## What Is Different From Upstream XRootD Clients

| Topic | In-tree native clients | Upstream XRootD clients |
|---|---|---|
| Core library | `libxrdc`, clean-room C API | `libXrdCl` C++ API |
| Security plugins | In-tree auth code for unix, token/ztn, SSS, GSI, optional Kerberos | `libXrdSec*` plugin stack |
| Protocol vocabulary | Shared project headers and helpers | Upstream XRootD implementation |
| Diagnostics | Wire trace, timing, capture/replay, remote-doctor | Upstream tooling varies by install |
| POSIX surfaces | Clean-room FUSE drivers and preload shim | `XrdFfs`, `XrdPosix`, `XrdPosixPreload` |

The goal is not byte-for-byte CLI parity with every upstream option. The goal is
a small, auditable client stack that exercises the same protocol features this
module implements and that can be shipped without pulling the official XRootD
client runtime into a deployment.

## Tool Matrix

| Tool | Purpose | Source-verified behavior |
|---|---|---|
| `xrdcp` | Copy local, `root://`, `roots://`, WebDAV/HTTP, and S3 paths | Supports `-f`, `-r`, `-P`, `--from`, `--retry`, `-j/--jobs`, `--sync`, `--tls`, `--notlsok`, `--noverifyhost`, `--auth`, `--pgrw`, `--cksum`, `-S/--streams`, `--tpc`, `--token`, S3 SigV4 flags, `--wire-trace`, and `--timing`. |
| `xrdfs` | Metadata, namespace, query, and simple file operations | One-shot command mode or interactive shell. Commands include `stat`, `ls`, `du`, `tree`, `find`, `mkdir`, `rm`, `rmdir`, `mv`, `chmod`, `truncate`, `cat`, `tail`, `readv`, `writev`, `locate`, `query`, `statvfs`, `prepare`, and `explain`. |
| `xrddiag` | Diagnostics and comparison harness | Subcommands include `check`, `bench`, `topology`, `status`, `compare`, `probe-robustness`, `replay`, `srr`, `tape`, and `remote-doctor`. |
| `xrdadler32` | Adler32 checksums | Local files are streamed through zlib; `root://` paths use server `kXR_Qcksum`. |
| `xrdcrc32c` | CRC32c checksums | Uses the same CRC32c primitive as pgread/pgwrite and server checksum code. |
| `xrdcrc64` | CRC-64/XZ checksums | Local or `root://`; the server-side name is `crc64`. |
| `xrdckverify` | Verify a file **on disk** against its recorded checksum | Recomputes a local file and compares it to the value already stored for it — in a storage endpoint's `user.XrdCks.<alg>` xattr (text or stock binary `XrdCksData`) / `<file>.cks` sidecar (`--storage`), or a proxy cache's `<file>.cinfo` / `<file>.meta` digest (`--cache`); `--auto` (default) tries both. `--algo <name>` narrows the algorithm. Exit 0 = match, 1 = mismatch (corruption), 2 = no recorded checksum, 3 = error. |
| `xrdqstats` | Query server config, space, or stats | Uses `kXR_query` with default `QStats`, `-c` for `Qconfig`, or `-s` for `Qspace`. |
| `xrdprep` | Submit prepare/stage/evict/cancel/fresh requests | Thin CLI over `kXR_prepare`. |
| `wait41-brix` | Wait for a server readiness condition | Older utility-style tool; treats its positional argument as `host[:port]` and waits up to its timeout. |
| `mpxstats-brix` | Summarize Prometheus `/metrics` output | Reads from a host metrics endpoint or from stdin. |
| `xrdmapc` | Map/verify path holders in a cluster | Uses locate/map style queries and can probe advertised holders with `--verify`. |
| `xrdgsitest` | GSI handshake smoke test | Forces GSI auth and reports whether the handshake authenticated. |
| `xrdgsiproxy` | Create, inspect, destroy RFC 3820 X.509 proxies | Local OpenSSL implementation: `init`, `info`, and `destroy`. |
| `xrdsssadmin-brix` | Manage SSS keytabs | Creates/lists/deletes shared-secret entries with mode-0600 keytab writes. |
| `xrootdfs` | Network-resilient FUSE filesystem | Async/pipelined mount over `root://` or http(s)/WebDAV with reconnect, retry, heartbeat, and open-file resumption. A `--legacy` flag selects a simple synchronous fallback mode (root:// only). |
| `libxrdposix_preload.so` | LD_PRELOAD read path for legacy POSIX tools | Maps paths under `$BRIX_VMP` to a `root://` export through `libxrdc`; first cut is read-oriented. |

Test and development binaries also exist under `client/tests` or the build
output: `aio_smoke`, `aio_resil`, `aio_mfile`, and `fault_proxy`.

## `xrdcp`

The native `xrdcp` accepts:

```bash
xrdcp [opts] <src>... <dst>
```

Each source or destination may be:

- a local path
- `-` for stdin/stdout
- `root://host[:port]//path`
- `roots://host[:port]//path`
- a WebDAV/HTTP URL: `davs://`, `dav://`, `https://`, `http://`
- an S3 URL: `s3://` or `s3s://`

Common examples:

```bash
xrdcp file.root root://store.example:1094//data/file.root
xrdcp root://store.example:1094//data/file.root ./file.root
xrdcp --tls --auth gsi root://store.example:1094//data/file.root .
xrdcp --pgrw --cksum adler32:source file.root root://store.example//data/file.root
xrdcp -r --from manifest.txt root://store.example//dataset/ ./dataset/
xrdcp --tpc first root://src.example//data/a.root root://dst.example//data/a.root
xrdcp -T "$BEARER_TOKEN" davs://dav.example:8443//data/a.root .
xrdcp --s3-access "$AWS_ACCESS_KEY_ID" --s3-secret "$AWS_SECRET_ACCESS_KEY" \
  s3s://s3.example/bucket/object ./object
```

Important implemented features:

- `--pgrw` uses `kXR_pgread` / `kXR_pgwrite` with per-page CRC32c.
- `--cksum <algo>[:source|:print|:<value>]` supports at least `adler32`,
  `crc32c`, and `md5` in the copy path.
- `-S/--streams N` opens secondary `kXR_bind` data streams.
- `--tpc first|only|delegate` attempts native server-side third-party copy for
  remote-to-remote XRootD transfers.
- WebDAV/HTTP transfers use bearer tokens from `--token` or `$BEARER_TOKEN`.
- S3 transfers use SigV4 credentials from flags or standard AWS environment
  variables.
- `--wire-trace[=N]`, `--timing`, `--capture`, and `--redirect-trace` expose
  client-side protocol diagnostics.
- `--retry`, `--jobs`, and `--sync` support batch workflows.
- Endpoint aliases can be resolved from `$XRDRC` **(EXPANDED)** or `~/.xrdrc`;
  aliases may also carry per-endpoint credentials.

Reviewer attention: older Phase 37 text says `http(s)://`, `dav(s)://`, and
`s3://` copy were declined for the initial native client. That is now stale; the
current `xrdcp` usage text and `client/lib/xrdc.h` expose those web/S3 paths.

## `xrdfs`

The native `xrdfs` accepts a host or a URL endpoint:

```bash
xrdfs [opts] host[:port]|root[s]://host[:port]|http[s]|dav[s]://host/path [command [args]]
```

Without a command it opens an interactive shell with `cd`, `pwd`, `help`, and
`exit` (root:// only).

An **http(s)/WebDAV URL** endpoint (matching the official client, which also
accepts an `https://` WebDAV URL) is served over WebDAV `PROPFIND` for the
read-only metadata commands `ls` and `stat`; the URL path is the export base, so
`xrdfs https://host/base ls sub` lists `base/sub`. Authenticate with `--token TOK`
(or `-T`, or `$BEARER_TOKEN`); `--noverifyhost` skips the TLS chain check for a
self-signed endpoint. Mutating/file commands over a WebDAV endpoint report that a
`root://` endpoint is required rather than failing cryptically.

Implemented commands from the source dispatch table:

| Command | Use |
|---|---|
| `stat <path>` | Stat a path. |
| `ls [-l] [-R] [path]` | List a directory. |
| `du [-h] <path>...` | Recursive size summary. |
| `tree [-d] [-L N] [path]` | Tree view. |
| `find <path> [-name GLOB] [-type f|d] [-size +N|-N]` | Server-side walk plus client filtering. |
| `mkdir [-p] [-m mode] <path>` | Create directories. |
| `rm <path>` / `rmdir <path>` | Remove files/directories. |
| `mv <src> <dst>` | Rename. |
| `chmod <path> <octal-mode>` | Change mode bits. |
| `truncate <path> <size>` | Resize a file. |
| `cat <path>` / `tail [-c bytes] <path>` | Read data to stdout. |
| `readv <path> <off len>...` | Scatter-gather read. |
| `writev <path> <off hexdata>...` | Scatter-gather write. |
| `locate <path>` | Ask where a path is served. |
| `query <config|space|checksum|stats> [args]` | Query server metadata. |
| `statvfs [path]` | Filesystem stats. |
| `prepare [-s|-w|-c|-f|-e] <path>...` | Prepare/stage/cancel/fresh/evict operations. |
| `explain` | Print connection, auth, TLS, signing, and capability facts. |

Examples:

```bash
xrdfs root://store.example:1094 stat /data/file.root
xrdfs --tls --auth ztn root://store.example ls -l /data
xrdfs root://store.example query checksum "adler32 /data/file.root"
xrdfs root://store.example
```

## Diagnostics

`xrddiag` is the "tell me what is actually happening" tool. The source usage
lists these subcommands:

| Subcommand | Purpose |
|---|---|
| `check <url>` | Protocol-correctness probes. |
| `bench <url> [-S N] [--sweep]` | Timed download and stream-count knee finding. |
| `topology <url> [--cluster-url URL]` | Locate and redirect convergence checks. |
| `status <url> [--metrics-port N]` | Pull `/metrics` and summarize. |
| `compare <urlA> --vs-reference <urlB>` | Root-vs-root size/list/md5 comparison. |
| `compare <root-url//path> --davs <host[:port]>` | Cross-protocol oracle. |
| `probe-robustness <url> --i-am-authorized` | Adversarial reject auditor. |
| `replay <file.xrdcap> [--playback <url>]` | Decode or re-issue a captured session. |
| `srr <http[s]-url>` | Fetch WLCG Storage Resource Reporting. |
| `tape <http[s]-url//path>` | Drive WLCG/FRM Tape REST stage and poll. |
| `remote-doctor <url>...` | Multi-protocol active diagnosis for root, HTTP, DAV, S3, and CMS endpoints. |

`xrdcp` and `xrdfs` can write capture files:

```bash
xrdcp --capture session.xrdcap root://store.example//data/file.root .
xrddiag replay session.xrdcap
xrddiag replay session.xrdcap --playback root://test.example:1094/
```

Useful low-level flags shared by the client stack include:

- `--wire-trace[=N]` for decoded request/response frames.
- `--timing` for per-opcode RTT summaries.
- `--tls`, `--notlsok`, and `--noverifyhost` for native TLS control.
- `--auth <gsi|ztn|krb5|sss|unix>` where the specific tool exposes all auth
  choices.

## Security And Credentials

The native client library supports these auth paths in source:

| Auth | How it is supplied |
|---|---|
| Anonymous | No credential required when the server allows it. |
| Token / `ztn` | Discovered from `BEARER_TOKEN`, `BEARER_TOKEN_FILE`, `$XDG_RUNTIME_DIR`, or `/tmp/bt_u<uid>`; `xrdcp` also accepts `--token` for WebDAV/HTTP. |
| GSI | Uses X.509 proxy/cert material and `$X509_USER_PROXY` / `$X509_CERT_DIR`; `xrdgsiproxy` can create and inspect proxies. |
| SSS | Uses SSS keytabs managed by `xrdsssadmin-brix`. |
| Kerberos | Optional compile-time support when Kerberos development libraries are present. |

The client library also includes credential diagnostics. It can explain JWT
payload fields, proxy validity, VOMS FQANs, and can print early warnings for
expired or read-only credentials before a transfer fails with a generic access
error.

## IPv6 To IPv4 Auto-Downgrade

Every native tool that connects through `libxrdc` (`xrdcp`, `xrdfs`, `xrddiag`,
`wait41-brix`, the `xrootdfs` mount, the preload shim — all of them)
automatically downgrades to IPv4 on a dual-stack host whose IPv6 path is broken
but whose IPv4 backend works. This keeps a FUSE mount serving silently through a
busted IPv6 network instead of stalling on dead v6 addresses.

The downgrade is triggered on positive evidence, two ways:

- **At connect time** — an IPv6 connect attempt fails and the following IPv4
  attempt succeeds (a v6 path that was broken from the start).
- **Over the wire** — a connection that came up over IPv6 then fails mid-session
  (reset, timeout, or truncated transfer); the next reconnect comes back over
  IPv4 and the application never sees the error.

On either trigger the whole process (the mount session) is pinned to IPv4-only
for the rest of its life — the resolver stops returning v6 records, so no later
connection pays a v6 connect timeout — and the downgrade is logged once to
standard error:

```
xrootd: an IPv6 connection to the server failed over the wire; downgrading this
        session to IPv4-only for all further connections
```

The downgrade is **self-healing**: if IPv4 then turns out not to work after all
(for example a transient wire error tripped it on a host that is really
IPv6-only), the next connect reverts to dual-stack so the connection still comes
up. An IPv6-only host therefore never stays downgraded, and a healthy IPv6 host
never trips it. Set `XRDC_NO_IPV6_FALLBACK=1` to disable the behavior entirely.

## Network Resilience

The native client is built to keep working on a flaky or hostile network — the
case of a misbehaving inline firewall that silently drops packets, injects
resets, or hangs connections half-open. Several layers cooperate:

- **Bounded bring-up.** Connecting, the protocol handshake, TLS, and login are
  capped by a short connect timeout (`XRDC_CONNECT_TIMEOUT_MS`, default 15s,
  `--connect-timeout` on `xrootdfs`), separate from the longer steady-state
  I/O timeout (`XRDC_IO_TIMEOUT_MS`, default 30s). A firewall that completes the
  TCP handshake then black-holes the protocol bytes fails promptly instead of
  hanging for the full data timeout.
- **Fire-and-forget teardown.** Closing a connection no longer waits for an
  `kXR_endsess` reply, so a black-holing peer cannot stall teardown for a second
  timeout; an already-failed (no-session) connection skips it entirely.
- **Reconnect with backoff + jitter.** The async core (`xrootdfs`)
  transparently reconnects a dropped link. Open files reopen non-destructively and
  resume at the same offset; in-flight metadata retries.
- **Fast transport retry, deadline-bounded.** A read/write/reopen severed by the
  wire is retried *promptly* (short jittered backoff — a reset is instant, not
  server overload) and kept up for the whole `--max-stall` patience window rather
  than a small fixed count. This is what rides out sustained packet loss, where a
  large transfer is frequently severed mid-flight and must simply be re-attempted
  many times. Server-throttle (`kXR_wait`/overload) still uses the slower
  exponential backoff. Verified against an **official `xrootd` server** through an
  in-repo fault proxy (`tests/test_official_brix_resilience.py`): byte-exact
  through latency, tiny segmentation, single + repeated mid-transfer drops, a
  multi-second outage, and sustained packet loss up to ~12% (beyond which a
  multi-round-trip link is effectively dead; raise `--max-stall` to extend
  patience).
- **Liveness probes.** TCP keepalive plus an application-level `kXR_ping`
  heartbeat (`--keepalive`, default 15s) detect a silently-dead peer; the
  reconnect window is bounded by `--max-stall` (default 60s).

Tighten `--connect-timeout` / `XRDC_CONNECT_TIMEOUT_MS` when a known-bad firewall
makes the handshake hang, so failures are detected and retried in seconds.

## Environment Variables

Variables marked **(EXPANDED)** are extensions specific to this project's native
clients (`libxrdc`). They do **not** exist in — and have no effect on — a vanilla
upstream XRootD client; do not rely on them outside this project. Every other
variable below follows the standard XRootD / Grid / cloud-ecosystem convention
and behaves the same as upstream.

| Variable | Status | Used for |
|---|---|---|
| `XRDC_NO_IPV6_FALLBACK` | **(EXPANDED)** | Set to `1` to disable the automatic [IPv6→IPv4 downgrade](#ipv6-to-ipv4-auto-downgrade) on a dual-stack host. |
| `XRDC_CONNECT_TIMEOUT_MS` | **(EXPANDED)** | Cap (ms) on the connect + handshake + login phase (default 15000). Lower it to fail faster against a firewall that hangs the handshake. |
| `XRDC_IO_TIMEOUT_MS` | **(EXPANDED)** | Steady-state per-operation read/write cap in ms (default 30000). |
| `XRDRC` | **(EXPANDED)** | Path to the endpoint-alias rc file (else `~/.xrdrc`). |
| `XRD_MOUNTINFO_PATH` | **(EXPANDED)** | Test-only override of the mountinfo file parsed by `xrd mount` listing. |
| `X509_USER_PROXY`, `X509_USER_CERT`, `X509_CERT_DIR` | standard | GSI / X.509 proxy, certificate, and CA-hash-dir material. |
| `BEARER_TOKEN`, `BEARER_TOKEN_FILE` | standard | WLCG bearer-token discovery. |
| `OIDC_ACCOUNT` | standard | `oidc-agent` account used by the token-refresh helpers. |
| `XDG_RUNTIME_DIR` | standard | A bearer-token discovery location. |
| `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_DEFAULT_REGION` | standard | S3 SigV4 credentials and region. |
| `XrdSecSSSKT`, `XrdSecsssKT` | standard | SSS keytab path (upstream-compatible names). |
| `BRIX_VMP` | standard | POSIX preload virtual-mount prefix (upstream-compatible). |

## FUSE Mounts

Two FUSE drivers are built when libfuse3 is available.

### `xrootdfs --legacy` (synchronous fallback mode)

The same `xrootdfs` binary also carries a simple synchronous driver, selected
with `--legacy` (or `xrd mount --legacy`). It mounts with filesystem type
`fuse.xrootdfs_legacy` so listings still distinguish it:

```bash
xrootdfs --legacy [conn-opts] root[s]://host[:port][/] <mountpoint> [fuse-opts]
```

It provides metadata operations, readdir-plus, read/write, random update,
create/truncate, mkdir/unlink/rmdir/rename/chmod, statfs, access, optional
kernel caching, per-handle read-ahead/write-back buffering, and optional
extended attributes via `--xattr`.

Known wire-level limitations of the synchronous mode:

- XRootD has no base wire op for mtime or ownership updates, so `utimens` and
  `chown` are accepted as no-ops.
- Symlinks and hardlinks are unsupported.
- root:// only (no http(s)/WebDAV transport), and no reconnect/resumption.

Use the default `xrootdfs` (no `--legacy`) when you need resilience, the
http(s)/WebDAV transport, or the vendor setattr/symlink/readlink/hardlink path.

### `xrootdfs`

`xrootdfs` is the default driver — it uses the async client core for poor
networks (and can also mount http/https/dav/davs read-only):

```bash
xrootdfs [opts] root[s]|http|https|dav|davs://host[:port][/base] <mountpoint> [fuse-opts]
```

Additional resilience options include:

- `--streams N`
- `--max-stall MS`
- `--keepalive MS`
- `--max-retries N`

The async driver can reopen and resume an open file after a connection drop or
server restart, re-issuing the read/write at the same offset. It also probes
project vendor extensions (`kXR_setattr`, `kXR_symlink`, `kXR_readlink`,
`kXR_link`, plus `kXR_statNoFollow`) through `kXR_Qconfig "xrdfs.ext"` and only
uses them when the server advertises support.

For implementation detail and tests, see
[Async, network-resilient FUSE driver](../09-developer-guide/fuse-async-resilient-driver.md).

## POSIX Preload Shim

`libxrdposix_preload.so` lets legacy POSIX-read tools access a remote export
without linking a client library:

```bash
LD_PRELOAD=/path/to/libxrdposix_preload.so \
BRIX_VMP=/xrd=root://store.example:1094/ \
cat /xrd/data/file.root
```

The shim interposes open/read/pread/lseek/close, stat-family calls, and access.
Paths under the local prefix from `$BRIX_VMP` are rewritten to the remote
logical path and served through a lazily connected `libxrdc` session. Other paths
fall through to libc.

Reviewer attention: the source comments call this a first-cut read path. Writes
under the prefix fall through to libc, and `fopen`, `mmap`, and legacy `__xstat`
routing are not part of the current preload surface.

## Public C Library

External C consumers can use `libxrdc` through `client/lib/xrdc.h`.

A minimal stat example exists at `client/examples/xrdc_stat_demo.c`:

```bash
cc client/examples/xrdc_stat_demo.c $(pkg-config --cflags --libs libxrdc) -o demo
./demo root://store.example:1094 /data/file.root
```

The public header exposes:

- URL and endpoint parsing.
- Connect/reconnect/close.
- Handshake, login, auth, TLS, redirect, and wait handling.
- Metadata ops: stat, lstat, dirlist, locate, query, statvfs.
- Namespace ops: mkdir, rm, rmdir, mv, chmod, truncate.
- File ops: open/read/write/close/sync, readv/writev, pgread/pgwrite.
- Checksums: local streaming and remote `kXR_Qcksum`.
- TPC-aware copy orchestration.
- HTTP/WebDAV streaming helpers and S3 SigV4 signing.
- FUSE/preload helpers such as errno mapping and connection pools.
- Diagnostics: wire trace, timing, session capture/replay, connection explain,
  network facts, token/proxy introspection.

The synchronous connection object allows one in-flight request per connection and
is not thread-safe. Multi-threaded users should use the connection pool or the
async manager abstractions used by the FUSE drivers.

## Current Limitations To Keep Visible

These are not bugs in the documentation; they are boundaries visible in source
that reviewers should keep in mind:

| Area | Current boundary |
|---|---|
| Upstream CLI parity | The tools implement a practical XRootD/WebDAV/S3 surface, not every upstream XrdCl flag or plugin behavior. |
| UDP monitoring | Intentionally absent. Diagnostics use client traces/captures and server `/metrics`, not the upstream binary UDP monitoring stream. |
| FUSE sync driver resilience | `xrootdfs --legacy` is synchronous and does not resume an in-flight transfer after a connection drop; the default `xrootdfs` (no `--legacy`) does. |
| POSIX preload | Read-oriented first cut; writes/fopen/mmap are not implemented as remote operations. |
| Native root TPC | ztn/GSI outbound auth exists, but TLS-upgraded source origins and multihop delegation remain caveats requiring site validation. |
| Vendor POSIX extensions | `setattr`, symlink/readlink, and hardlink operations are emitted only when a server advertises `xrdfs.ext`; stock servers will not see those opcodes. |
