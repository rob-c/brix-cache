# Phase 100 — Metalink virtual redirector + Extreme copy (multi-source XCp)

**Date:** 2026-08-09
**Source:** `docs/refactor/xrootd-feature-parity-audit-2026-08-04.md` §7.1 (Metalink,
master-list #2) and §7.2 (Extreme copy, master-list #4) — the two largest client
feature bodies still open after the phase-94 substream landing.

**Status:** ✅ IMPLEMENTED & TESTED (2026-08-09). Client-side only (the audit marks
the server half of metalink N/A). Landed as three new `client/lib/xfer/` TUs + one
copy.c seam, `--sources N` / `--no-metalink` on brix-xrdcp, a parser C-unit
(`client/tests/c/metalink_unit.c`) and two dedicated pytest suites
(`tests/test_metalink.py`, `tests/test_extreme_copy.py`).

---

## 1. What upstream has (and what we match)

**Metalink (XrdCl VirtualRedirector):** a `.meta4` (RFC 5854 metalink v4) or
`.metalink` (v3) XML document lists mirror URLs for one logical file, ranked by
`priority` (v4, 1 = best) / `preference` (v3, 100 = best), plus optional `<size>`
and `<hash>` digests. XrdCl treats such a file — local or remote — as a *virtual
redirector*: the copy opens the ranked mirrors in order, failing over on error,
and can feed the full replica list into the extreme copy. BriX previously had
zero metalink support repo-wide.

**Extreme copy (XrdCl XCpCtx, `xrdcp --sources N`):** N connections to distinct
replicas of the same file download disjoint blocks concurrently; when the shared
block queue drains, idle sources *steal* blocks still in flight on slower
sources (duplicate fetch, first-writer-wins) so the transfer finishes at the
speed of the fastest replicas. Replica lists come from a metalink mirror set or
from a locate on the source.

## 2. What landed where

### 2.1 `client/lib/xfer/metalink.c` + `metalink.h` — parser (pure, no I/O)

- `brix_metalink_is_name(s)` — case-insensitive `.meta4` / `.metalink` suffix
  on the URL path (query stripped).
- `brix_metalink_parse(xml, len, out, st)` — self-contained tag scanner (no
  libxml dependency), handling both dialects:
  - v4: `<metalink xmlns="urn:ietf:params:xml:ns:metalink"><file><url priority="p">`
  - v3: `<metalink version="3.0"><files><file><resources><url preference="p">`
  - First `<file>` element only (a copy resolves ONE logical file, matching
    XrdCl's redirector semantics).
  - XML entity decoding (`&amp; &lt; &gt; &quot; &apos; &#NN; &#xNN;`) in URL
    text and attributes.
  - Ranking: v4 ascending priority and v3 descending preference are both mapped
    onto one internal ascending `rank`; ties keep document order (stable
    insertion sort).
  - `<size>` (optional, -1 when absent) and the strongest *client-supported*
    digest — `md5` preferred, then `crc32c`, then `adler32` — captured as
    `hash_algo`/`hash_hex` (hex-validated; sha-* are noted but unusable since
    `--cksum` speaks adler32/crc32c/md5).
- **Bounds (hostile-input hard caps):** document ≤ 4 MiB
  (`XRDC_METALINK_MAX_BYTES`), ≤ 16 mirrors kept (`XRDC_METALINK_MAX_URLS`,
  overflow noted in a counter, not an error), URL ≤ 2303 bytes
  (`XRDC_METALINK_URL_MAX`-1), attribute scan windows bounded, parser is
  single-pass with no recursion.
- **Mirror scheme policy (security):** only remote pull schemes are accepted —
  root/roots/xroot/xroots/http/https/dav/davs. `file://`, bare paths, s3
  (mirrors carry no credentials) and unknown schemes are *skipped with a note*:
  a hostile remote metalink must not be able to make xrdcp read an arbitrary
  local file (exfiltration via mirror → remote-destination upload) or invoke
  credentialed transports the user never selected.

### 2.2 `client/lib/xfer/copy_metalink.c` — virtual-redirector orchestration

`brix_copy` detects a metalink source (suffix check, unless `--no-metalink` /
`o->metalink_off`) *before* the web/block/ftp scheme routing, so metalinks work
from every source transport the client speaks:

1. **Fetch** — a local metalink is read directly (bounded); a remote one
   (root://, http(s)://, davs://) is pulled through the normal copy engine into
   a private `mkstemp` temp under `$TMPDIR` with `metalink_off` forced on (no
   recursion), then read + unlinked.
2. **Parse** → ranked mirror list; zero usable mirrors is a hard
   `XRDC_EUSAGE`-class failure naming the reason.
3. **Digest inheritance** — when the metalink carries a supported digest and
   the user gave no `--cksum`, the transfer runs with
   `--cksum <algo>:<hex>` (the existing literal-compare mode), so a corrupt
   mirror is dropped exactly like a failed `--cksum` download today
   (committed-but-bad file unlinked).
4. **Failover loop** — mirrors are attempted in rank order through the normal
   single-source dispatch (`copy_dispatch_one`). Transport/server/auth/
   redirect/integrity failures advance to the next mirror (with a stderr note
   unless `-s`); *local* verdicts stop immediately: usage errors, local-IO
   failures, destination-exists (`-f` needed — identical for every mirror), and
   operator cancel.
5. **XCp hand-off** — with `--sources N` (N ≥ 2), the ranked root-family mirror
   list rides `o->xcp_mirrors` into the download path below; web-only mirror
   sets fall back to the serial failover loop.

### 2.3 `client/lib/xfer/copy_xcp.c` — block-stealing multi-source download

`copy_download_xcp(job, &rc, st)` slots into `copy_download` *ahead of* the
phase-94 `copy_download_parallel` check, same 1/0 "handled?" contract:

- **Eligibility:** `o->sources >= 2`, local-file destination, known size ≥ 2
  blocks, no `--pgrw`, no `--compress`.
- **Replica list**, in order of preference:
  1. metalink mirrors (`o->xcp_mirrors`, root-family only);
  2. `kXR_locate` on the already-open control connection — `S`/`s` server
     tokens (`S[rw]<host>:<port>`, bracketed IPv6 ok) become
     `root://host:port//<path>` replicas (manager `M/m` entries skipped);
  3. fewer than 2 replicas → the single source URL is *duplicated* up to N
     (documented divergence: parallel TCP streams to one host still help on
     high-latency links, and it keeps `--sources` honest against a single
     data server).
- **Engine:** the file is cut into blocks (`BRIX_XCP_BLOCK` bytes, default the
  8 MiB `XRDC_COPY_CHUNK`, clamped to [64 KiB, 64 MiB]). Per-block atomic state
  bytes (`TODO/BUSY/DONE`) + a per-block one-extra-stealer latch. Each worker
  owns one connection to its replica (connect + open-read on its own thread),
  claims TODO blocks (CAS TODO→BUSY, rotating scan start so workers spread
  out), reads the block (short-read loop), `pwrite`s it into the shared VFS
  temp at its absolute offset (io_uring OFF ⇒ plain thread-safe `pwrite(2)`,
  the phase-94 pattern), and marks DONE.
- **Stealing:** a worker finding no TODO block picks the first BUSY block whose
  stealer latch is free, re-downloads it on its own (faster) connection and
  races the original — both write identical bytes at identical offsets, so
  first-writer-wins needs no coordination beyond the DONE mark. At most one
  stealer per block bounds duplicate work.
- **Failure model — fail-closed:** a worker error returns its BUSY block to
  TODO and kills only that worker; the transfer survives while ≥ 1 worker
  lives. All workers dead with blocks remaining → the copy fails with the
  first worker's status and the temp is aborted (never a partial destination —
  the shared `download_commit_or_abort` helper, factored out of the phase-94
  TU, owns commit/abort/cksum-drop).
- **Coordinator:** the main thread never touches data; it polls atomic
  progress (single-threaded `o->progress` callback, matching the serial pump's
  threading contract) and joins the workers.
- `BRIX_XCP_DEBUG=1` prints `xcp sources=<n> blocks=<n> per-source=[…]
  steals=<k>` on stderr — the observability hook the dedicated tests assert on.

### 2.4 Surface + plumbing

- `brix_copy_opts` gains `sources`, `metalink_off`, and the internal
  `xcp_mirrors`/`xcp_n_mirrors` pair (documented as resolver-owned).
- brix-xrdcp: `--sources N` (clamped 2..16 with a clean usage error outside
  1..16; `--sources 1` is a no-op), `--no-metalink`, usage text for both.
- `copy.c`: the post-scheme-routing body of `brix_copy` is now
  `copy_dispatch_one` (shared with the mirror loop); `brix_copy` itself gained
  only the metalink branch.
- `client/Makefile`: three new TUs in `LIB_SRCS`; `metalink_unit` added to
  `CLIENT_UNIT_TESTS`.

## 3. Deliberate scope cuts (documented, not bugs)

- `--dynamic-src` (upstream's growing-source mode) — not taken; BriX xcp
  requires a known size (the block table is sized up front).
- `--tls-metalink` / `--zip-mtln-cksum` — not taken this phase; the TLS
  requirement can ride `--tls` per-mirror already, and the zip flag pairs with
  a zip surface BriX spells differently (`--zip` = store-into-archive).
- Multi-`<file>` metalink documents resolve the FIRST file entry only.
- Web (http/davs) mirrors participate in serial failover but not in the
  block-stealing engine (root-family only there); s3 mirrors are skipped.
- The metalink `<size>` is advisory; the mirror's `kXR_stat` size remains
  authoritative (a mismatch surfaces via the digest check when one is present).

## 4. Tests

- **C unit** `client/tests/c/metalink_unit.c` (runs in `make -C client test`):
  v4 + v3 parse success (rank order, hash, size), entity decoding, error cases
  (empty/truncated/not-XML/no-urls), security-negative (file:// and oversized
  URL mirrors skipped, >4 MiB doc refused, >16 mirrors capped, non-hex digest
  ignored).
- **`tests/test_metalink.py`** — against the shared fleet (anon + readonly
  dedicated servers): local .meta4 download; dead-mirror→live-mirror failover;
  remote (root://-served) metalink; metalink digest auto-verify dropping a
  corrupt-replica download (security-neg); all-mirrors-dead clean failure
  (error); file:// mirror refused (security-neg); `--no-metalink` copies the
  XML bytes verbatim.
- **`tests/test_extreme_copy.py`** — same-bytes file staged into both the anon
  and readonly export roots: `--sources 2` via metalink mirrors reassembles
  byte-exact and BOTH sources carry blocks (debug line); dead-mirror
  robustness (blocks stolen/rescued, transfer completes); locate-fallback
  single-server duplication path; corrupt-replica + digest → fail-closed, no
  destination file (security-neg); `--sources 17` usage error.

Run: `PYTHONPATH=tests pytest tests/test_metalink.py tests/test_extreme_copy.py -v`
and `make -C client test` for the parser unit.
