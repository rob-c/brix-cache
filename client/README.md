# `client/` — native BriX client tools

Pure-C, libXrdCl-free client suite built on `libbrix` and the in-tree
`libxrdproto` wire layer. No libXrdSec*, no Xrootd headers beyond the wire
structs in `src/protocols/root/protocol/`.

## Directory layout

| Directory | Contents |
|---|---|
| `lib/` | `libbrix` — connection/session/ops library; see [`lib/README.md`](lib/README.md). |
| `apps/` | CLI front-ends (`xrdcp`, `xrdfs`, `xrddiag`, `xrdcksum`, …); see [`apps/README.md`](apps/README.md). |
| `man/` | Man pages (section 1) for every CLI tool. |
| `completions/` | Bash/zsh completion script (`brix-tools.bash`). |
| `preload/` | `libbrixposix_preload.so` — LD_PRELOAD POSIX→XRootD read shim. |
| `examples/` | Short usage examples. |
| `tests/` | Unit and integration tests driven by `make test`. |
| `bin/` | Built binaries and test executables (generated; not committed). |

## Build

```bash
# From the repo root — builds libbrix.a + all CLI binaries
make -C client

# Incremental (after changing a source file)
make -C client

# Run unit tests
make -C client test
```

The build requires only a C99 compiler and OpenSSL (`libssl-dev`). FUSE
binaries (`xrootdfs`, `brixMount`) are built automatically when `libfuse3-dev`
is present but are not in the default `BINS` list.

## Feature summary (2026-07-05)

### xrdcp

| Feature | Flags |
|---|---|
| Sync/mirror semantics | `--sync`, `--sync-check size\|mtime\|cksum[:algo]`, `--delete` |
| Dry-run | `-n` / `--dry-run` |
| Path filters | `--exclude <pat>` (repeatable), `--include <pat>` (repeatable) |
| Resumable batch | `--journal <path>`, `--resume` (derives path from `--from`) |
| Post-transfer source removal | `--remove-source` (local and `root://` sources) |
| X.509 proxy override | `--proxy <path>` (overrides `$X509_USER_PROXY`) |
| Local-disk overlap ring | `--io-uring on\|off\|auto` (also `$XRDC_IO_URING`) |
| TPC token forwarding | `--tpc-token-mode <m>` (nginx-xrootd `tpc.token_mode` extension) |

### xrdfs

| Feature | Details |
|---|---|
| Recursive remove | `rm -r <path>` — removes a tree; `-v` logs each deletion |
| JSON output | `stat -j`, `ls -j`, `du -j` — machine-readable output |
| Compressed cat | `cat -z <codec> <path>` — decompress on the fly (gzip/zstd/…) |
| Live tail | `tail -f <path>` — follow a growing remote file |
| io_uring for bulk I/O | `upload --io-uring on\|off\|auto`, `download --io-uring on\|off\|auto` |

### xrdcksum

| Feature | Details |
|---|---|
| `xrdcksum tree <root>` | Produce a sha256sum-style manifest (`--algo NAME`, `-o FILE`) |
| `xrdcksum check <manifest> <root>` | Verify every digest in a manifest (`--algo NAME`) |

### xrddiag

| Feature | Details |
|---|---|
| `check <url> [--json]` | Protocol-correctness probes; `--json` for machine-readable output |
| `topology <url> [--json]` | Locate + redirect convergence; `--json` for machine-readable output |
| `replay <file.xrdcap>` | Decode a captured session; `--playback <url>` re-issues it live |

## Configuration — `~/.xrdrc`

See [`apps/README.md`](apps/README.md#configuration----xrdrc) for the full
reference, including the `[alias NAME]` credential bundles and the `[defaults]`
timeout section.

**`[defaults]` keys and precedence** (CLI flag > env var > `~/.xrdrc` > compiled default):

| Key | Env var | Description |
|---|---|---|
| `connect_timeout_ms` | `XRDC_CONNECT_TIMEOUT_MS` | TCP + protocol bring-up timeout |
| `io_timeout_ms` | `XRDC_IO_TIMEOUT_MS` | Per-operation I/O timeout |
| `max_stall_ms` | `XRDC_MAX_STALL_MS` | Reconnect/resume patience window |
| `backoff_base_ms` | — | Exponential reconnect back-off base (default 25 ms) |

## Man pages & bash completion

```bash
# Install man pages
sudo cp client/man/*.1 /usr/local/share/man/man1/

# Per-user bash completion
echo 'source /path/to/client/completions/brix-tools.bash' >> ~/.bashrc

# System-wide bash completion
sudo cp client/completions/brix-tools.bash /etc/bash_completion.d/brix-tools
```

zsh: `autoload -U +X bashcompinit && bashcompinit`, then source the same file.

## See also

- [`apps/README.md`](apps/README.md) — per-tool reference
- [`lib/README.md`](lib/README.md) — `libbrix` internals
- [`lib/auth/sec/README.md`](lib/auth/sec/README.md) — authentication modules
- [`preload/README.md`](preload/README.md) — LD_PRELOAD shim
