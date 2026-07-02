# Phase 42 — Comprehensive compression across all components (gzip/deflate, xz/lzma, zstd, brotli, bzip2, lz4)

**Status:** ✅ IMPLEMENTED + TESTED (2026-06-21), **including the formerly-deferred
W5 (write-side)**.  Authored 2026-06-16; scope expanded 2026-06-21 from "DEFLATE/ZIP
parity" to the full modern codec set across every server surface and the native
client, in all four directions.

**W5 — root:// inline WRITE decompression (DONE 2026-06-21).** The symmetric inverse
of W4: a WRITE handle opened with `?xrootd.compress=<codec>` (gated by the new
`xrootd_write_compress`, off by default; advertised via `kXR_Qconfig cmpwrite`) makes
the client compress each `kXR_write` payload as a self-contained frame; the server
decompresses it on ingest and stores the file **plaintext** (saving upload-wire
bytes).  Isolated handler `src/write/write_compress.c` (`xrootd_write_compressed`)
branched at the top of `xrootd_handle_write` on `write_codec != 0` → the default
write path (AIO + write-recovery journal) is byte-identical; `pgwrite`/`writev` never
reach it (per-page CRC32c invariant preserved).  Decode is on UNTRUSTED input, so it
streams the plaintext to `pwrite` in a bounded 1 MiB window under an absolute 256 MiB
per-frame output cap (NOT a ratio guard — legitimate writes are often >1000:1
compressible, which a ratio guard would false-reject; memory is bounded by the window
and the bytes land in the client's own quota).  Client: `xrdc_file.write_codec` +
`xrdc_file_write`/`xrdc_mfile_pwrite` compress via `xrdc_deflate_frame`; `xrdcp
--compress` and `xrootdfs_aio --compress` now apply on upload too.  Verified: 1.9 MB →
~tiny wire, all 6 codecs byte-exact, multi-frame (21 MB) offset-addressable, plaintext
upload byte-identical + invisible, bogus codec degrades, `cmpwrite` advertised
(`tests/test_compression_write.py` 11/11). All
workstreams done and green: **W0** codec kernel + 5 backends (`tests/c/codec_test`),
**W1** inbound PUT decode (`test_compression_inbound` 9/9), **W2** outbound GET
encode (`test_compression_outbound` 9/9), **W3** ZIP member reads
(`tests/c/zip_test` + `test_compression_zip` 4/4), **W4** root:// inline read
compression (`test_compression_root` 9/9 — 1.65 MB → 109 B, all 6 codecs
byte-exact, plaintext/bogus degrade cleanly). Read-path regression verified
(readv/pgread 26/26, integrity 35/35, native-client 7/7, conformance 30/30, path
confinement 15/15). Every feature OFF BY DEFAULT; the uncompressed paths are
byte-identical and stock peers never see the extensions.

**Extension — lz4 (6th codec) + build matrix (2026-06-21).** Beyond the plan's five
codecs, **lz4 (LZ4 Frame)** was added end-to-end as a 6th backend to prove the codec
vtable is genuinely pluggable: `XROOTD_CODEC_LZ4 = 7`, new `src/core/compat/codec_lz4.c`
(`#if XROOTD_HAVE_LZ4`, else `available=0` stub), `http_token "lz4"`, compiled into
BOTH the module and `libxrdproto.a`.  Detection is via an env-hint
(`XROOTD_LZ4_CFLAGS`/`XROOTD_LZ4_LIBS`) → pkg-config → header-probe ladder, and links
the system soname `-l:liblz4.so.1` (deliberately NOT a global `PKG_CONFIG_PATH`, which
would poison the OTHER codec links with conda sonames not on the runtime path).  lz4 is
wired through every surface: inbound PUT (WebDAV+S3), outbound GET (WebDAV+S3; appended
last in the `xrootd_compress_pref[]` preference — fastest but weakest ratio), root://
inline read AND write, and the native client (`xrdcp --compress lz4`).  Note the LZ4
Frame `step()` consumes its input in internal 64 KB chunks and returns `OK` (not `END`)
with output room remaining, so both the server (`xrootd_compress_frame`) and client
(`xrdc_deflate_frame`) compress loops were corrected to keep calling `step()` until
`END` rather than treating "output not full" as "grow the buffer" (which lost data on a
scratch realloc).  Tested: C-unit (`codec_test`/`codec_edge_test`) + all phase-42
pytest surfaces parametrised over lz4 — full suite **131/131 green** (104 core + 27
clean-room/FUSE); client `ldd` still shows zero `libXrd*`.

**Build matrix (graceful degradation + dynamic-module load).** Two build-time
tests guard the compile-gating contract:

* **Graceful degradation when a codec lib is absent** (`tests/c/codec_nolib_test.c`,
  run by default).  Compiles the kernel with the mandatory zlib backend but every
  optional backend (zstd/xz/brotli/bzip2/lz4) built WITHOUT its `-DXROOTD_HAVE_*`
  macro — i.e. as its `available=0` stub, linking none of those libs.  Asserts the
  descriptor table has no holes, the absent codecs report unavailable, and
  `xrootd_codec_open()` returns `NULL` for them (so the server degrades to plaintext
  / rejects rather than crashing or failing to link).

* **Per-codec drop matrix** (`tests/c/codec_avail_probe.c` +
  `test_compression_build_matrix.py`, default).  For each optional codec, a probe is
  built with that ONE codec's `-DXROOTD_HAVE_*` and lib omitted while the others are
  kept; it asserts the dropped codec reports `available=0`, every kept codec stays
  `available=1`, and gzip stays available — proving codecs are independent (dropping
  one never disables another nor leaves a table hole).

* **Real `--with-compat` dynamic build** (`tests/build_dynamic_modules.sh`, opt-in via
  `XRD_RUN_BUILD_MATRIX=1`; ~90 s).  A full isolated `--add-dynamic-module` build in
  its own tree (never touches the harness binary) that asserts all codec libs
  **including lz4** are linked into the combined dynamic `.so` as `DT_NEEDED` records
  and resolve at load — the reason `XROOTD_CODEC_LIBS` is in the stream module's
  `ngx_module_libs` (a `.so` carries its own NEEDED records; `CORE_LIBS` would only
  link the binary) — AND that `nginx -t` dlopens the full module set cleanly.  Since
  **phase-47 W1** bundles every non-filter module into ONE combined `.so` (the HTTP
  AUX filter stays separate), the former cross-`.so` symbol cycle (stream ↔ dashboard
  ↔ webdav ↔ metrics) resolves at link time, so the dlopen succeeds; an earlier
  per-module split could not dlopen under nginx's `RTLD_NOW`.  The script fails on any
  dlopen error or unresolved codec symbol.

See `tests/c/codec_nolib_test.c` + `tests/c/codec_avail_probe.c` +
`tests/build_dynamic_modules.sh` + `tests/test_compression_build_matrix.py`.

**Adversarial audit + hardening (2026-06-21).** A 10-surface adversarial audit
(each finding independently verified by a refuting skeptic) over the whole
compression feature produced 46 confirmed findings; the real bugs were fixed and
the genuine coverage gaps closed with ~70 new tests. Code fixes:
 - **Inbound decode absolute cap** — both PUT callers now pass a finite
   `XROOTD_DECODE_MAX_OUTPUT` (16 GiB) instead of 0/unbounded, so a sub-1000:1 but
   enormous decode can't fill the disk (the ratio guard already caught classic
   tiny→huge bombs; this bounds the absolute case). `webdav/put.c`, `s3/put.c`.
 - **S3 aws-chunked + inner codec** — `Content-Encoding: aws-chunked,gzip` previously
   stored the still-gzip bytes (the de-chunker strips only the chunk envelope). Now
   `s3_aws_chunked_has_inner_coding()` rejects it 400 + discards the staged object,
   matching the non-chunked "never store undecoded bytes" invariant. `s3/aws_chunked.c`.
 - **Outbound MIME deny list was dead code** — content-type was empty at negotiate
   time, so `image/*`,`video/*`,`.gz`,… were re-compressed. `file_serve.c` now calls
   `ngx_http_set_content_type()` before negotiating so the deny list fires.
 - **Accept-Encoding q-values** — `q=0.0`/`q=0.00`/`q=0.000` are exactly zero
   (refuse) but were accepted; the fractional digits are now scanned. HTAB (not just
   SP) is accepted as OWS around list members (RFC 7230). `http_compress.c`.
 - **Client codec asymmetry** — a client built without a codec the server confirmed
   would silently copy the still-compressed bytes as "plaintext" and corrupt the
   transfer. The client open-reply parse now (a) requires the `cpsize` big-endian
   magic before trusting `cptype[0]` (the documented dual-check) and (b) FAILS the
   open if the server confirmed a codec this build cannot decode. `ops_file.c`,
   `aio_mgr.c`.
 - **Qconfig chksum** advertised `zcrc32` but omitted the working `crc32` alias —
   added (interop: stock XRootD advertises `crc32`). `query/config.c`.
 - **Memory budget** — the compressed-read `cmp_scratch` was invisible to the
   phase-31 heap gauge; added to `xrootd_budget_ctx_footprint`. `connection/budget.h`.
 - **Diagnostics** — the compressed-write io-error path now snapshots `errno` before
   `xrootd_codec_close()` can clobber it. `write/write_compress.c`.
New tests (≈70): codec-kernel post-frame-trailing-bytes + level-clamp + lz4 in the
edge matrix; ZIP corrupt-DEFLATE / declared-bomb / STORE-size-mismatch / empty-archive
fuzz; per-codec build-drop matrix; and pytest files for outbound q-value/MIME/HEAD
negotiation, S3 aws-chunked+inner-codec rejection, all-codec inbound bombs + trailing
bytes + double-CE, root:// incompressible/EOF/offset/stock-invisibility, zcrc32+crc32
advertise/reachable/value/empty, and raw-wire write corrupt/invariant. Two findings
are documented `xfail`s (honest limitations, not regressions): LZ4's frame format caps
at ~254:1 expansion so the 1000:1 ratio guard never fires for lz4 (the 16 GiB absolute
cap is its bound); nothing else.

W4 wire mechanism (as built): per-request whole-range codec frames (simpler and
more robust than the originally-sketched block descriptors — each kXR_read is an
independent, offset-addressable, resumable frame). Server gate
`xrootd_read_compress on`; advertised via `kXR_Qconfig cmpread`; negotiated with
the open opaque `?xrootd.compress=<codec>`; confirmed in the open reply
cpsize(=big-endian marker `0x5A`)/cptype[0](=codec ordinal). pgread/readv stay plaintext.

**Hardening + exhaustive-test pass (2026-06-21).** A 6-agent audit vs §6/§7 closed
the remaining plan items and a few real gaps the first cut had missed; then an
11-file test blitz (4 C-unit + 7 pytest) drove it all green and found two real
bugs, now fixed:
- **zcrc32 checksum (W0)** — `XROOTD_CHECKSUM_ZCRC32` (zlib CRC-32; folds onto the
  existing CRC32 kernel) across module + client + `kXR_Qconfig chksum`.
- **S3 inbound error mapping** — `s3/put.c` now maps a decode failure to a clean
  S3 XML 400/413 instead of a blanket 500 (`s3_put_finalize_codec_error`).
- **S3 outbound** — added the missing `xrootd_s3_compress` directive (+create/merge);
  GetObject compression was dead config before.
- **W4 async client** — `aio_mgr.c` `xrdc_mfile` now carries `read_codec`, decodes
  frames in `xrdc_mfile_pread`, and re-learns the codec on reopen (FUSE/resilient
  reads were returning compressed bytes undecoded before); FUSE `--compress` opt.
- **W3 ZIP write** — `client/lib/zip.c` STORE-only writer (`xrdc_zip_writer_*`,
  ZIP64-capable) + `xrdcp --zip`/`--zip-append` (local + remote), stock-`unzip`
  interoperable.
- **Bug 1 (fuzz test)** — 10-byte leak in `xrdc_zip_open` on the `lfh_off`-reject
  path (entry name freed only after `out->n` bump); fixed + ASAN-clean.
- **Bug 2 (invariant test)** — `cpsize` was written host-order; now big-endian
  (`htonl`) per the kXR wire convention (functionally harmless — the client keys
  off `cptype[0]` — but now conformant).
- **C1** (ZIP LFH bounds) was already correct (`member_data_offset` + `read_exact`
  bound every offset/size) — proven by the new fuzz suite, no code change.

Test inventory: C-unit `tests/c/{codec_test,codec_edge_test,zcrc32_test,zip_test,
zip_fuzz_test,zip_write_test}.c` (run via `tests/c/run_compression_tests.sh`);
pytest `tests/test_compression_{inbound,outbound,zip,root,s3_inbound,s3_outbound,
inbound_adversarial,root_adversarial,root_invariant,fuse_resilience,cleanroom_lint}.py`
+ `test_zip_write.py` + `test_zcrc32_checksum.py`. All green (**110 pytest + 6
C-unit**); regression unaffected (readv/pgread, integrity, s3, conformance — 194).

Final §7-coverage pass added the items the first test blitz had left:
- **`test_compression_fuse_resilience.py`** — mounts `xrootdfs_aio --compress zstd`
  through `tests/c/fault_proxy.c` and proves compressed reads are byte-exact on a
  clean link AND across a mid-read RESET / outage window.  This is the only test
  that exercises the async `xrdc_mfile_pread` decode + the reopen-re-learns-codec
  path (the riskiest new code) — a lost-codec-on-reopen or undecoded-frame bug
  would corrupt the file exactly here.
- **`test_compression_s3_outbound.py`** — standalone S3 nginx with
  `xrootd_s3_compress on`, all 6 codecs GetObject byte-exact + Range/HEAD/tiny
  identity guards (exercises the A3 directive).
- **Dynamic-module dlopen (§7)** verified by symbol graph: the WebDAV/S3 objects
  leave `xrootd_codec_by_http_token` undefined; `codec_core.o` (stream module,
  loaded first) defines+exports it → RTLD_GLOBAL resolution holds.  The full `.so`
  dlopen is exercised by the RPM dynamic build.  Graceful-degrade-with-lib-absent
  is covered structurally (each `codec_*.c` `#else` stub → `available=0`) and by
  `codec_edge_test` (`available()`/`open()` behaviour for absent codecs).
**Scope:** support gzip/deflate + xz/lzma + zstd + brotli + bzip2 on the root://
stream, WebDAV, and S3 surfaces **and** the native client (xrdcp/xrdfs/xrootdfs/
libxrdc), for inbound decompress, outbound compress, ZIP archive reads, and
root:// inline transfer compression. **Everything new is OFF BY DEFAULT and
invisible to stock XRootD peers.**

---

## 0. The fact that scopes this phase

An exhaustive sweep of `/tmp/xrootd-src` (all `src/` + every `CMakeLists.txt` /
`*.cmake`) shows **official XRootD's own code ships exactly one compression
algorithm: DEFLATE via zlib.** There is **no** lzma/xz, zstd, brotli, bzip2,
snappy, or lz4 anywhere upstream. Where XRootD uses DEFLATE:

| Context | Where | Model |
|---|---|---|
| **ZIP archive member read** (STORE+DEFLATE read; STORE-only write) | `XrdCl/XrdClZipArchive.cc`, `XrdClZipCache.hh` | **Client-side**: server serves raw `.zip` bytes; client inflates DEFLATE members (`inflateInit2(-MAX_WBITS)`) locally. `?xrdcl.unzip=` / `xrdcp --zip` |
| `kXR_compress` / `cpsize` / `cptype` | `XProtocol.hh:482,1091`, `XrdXrootdXeq.cc:1530`, `XrdOss/XrdOssApi.cc` | **Vestigial** — real (de)compress is `#ifdef XRDOSSCX` (an external plugin **not shipped**); default builds do raw `pread`. `cpsize`/`cptype` are populated only by that plugin |
| `zcrc32` checksum | `XrdCks/XrdCksCalczcrc32.cc` | zlib `crc32()` — a checksum, not compression |
| HTTP (XrdHttp) | `XrdHttp/XrdHttpReq.cc` | **No** `Accept-Encoding`/`Content-Encoding`; chunked = framing only |

**Therefore:** gzip/deflate + ZIP-member reads = true upstream parity; **lzma,
zstd, brotli, bzip2, outbound HTTP compression, and root:// inline compression are
deliberate extensions *beyond* upstream** — which is exactly this project's
swiss-army-toolkit goal. (This also answers the recurring "does it support lzma?"
question: upstream does not — we are adding it on purpose.) nginx-xrootd already
*exceeds* XRootD on one axis: it decompresses `Content-Encoding: gzip|deflate` PUT
bodies (`src/core/compat/http_body.c`), which XrdHttp does not do at all.

---

## 1. Locked scope (from clarifying questions, 2026-06-21)
- **Codecs:** gzip/deflate (zlib, always available) + zstd (libzstd) + xz/lzma
  (liblzma) + brotli (libbrotlienc/dec) + bzip2 (libbz2). The four non-zlib codecs
  are **compile-time-gated** (pkg-config → `-DXROOTD_HAVE_*`), exactly like
  krb5/fuse3, and degrade gracefully when their lib is absent at build time.
- **Directions:** all four — inbound decompress (PUT), outbound compress (GET),
  ZIP archive reads, root:// inline + native client.

---

## 2. Keystone — ONE unified codec abstraction, shared by module AND client

The single most important decision. A build-in-place, **ngx-free** codec kernel so
the nginx module and `libxrdc` use one implementation — the `checksum_core.c`
precedent (ngx-free kernel under `src/core/compat/`, listed in
`shared/xrdproto/Makefile` `NAMES`, compiled into `libxrdproto.a`, linked by both
the module via `config` and the client via `client/Makefile`).

- New `src/core/compat/codec_core.{c,h}` (ngx-free) + per-codec backends
  `codec_zlib.c` / `codec_zstd.c` / `codec_lzma.c` / `codec_brotli.c` /
  `codec_bzip2.c`. Each backend is `#if XROOTD_HAVE_*`-gated and registers a
  descriptor; an absent lib compiles to `available=0` (init returns an error),
  so the dispatch table is always full and branch-free (table-driven, no `goto` —
  the coding standard now covers `src/` **and** `client/`).
- Descriptor vtable:
  `{ id, name, http_token, available, level{min,max,default}, init/step/end }`
  with lookups `by_id` / `by_name` / `by_http_token` / `available`. One streaming
  pump (`xrootd_codec_open/step/close`) drives **both** compress and decompress for
  **all** surfaces — callers never see `z_stream` / `ZSTD_CCtx` / `lzma_stream` /
  brotli / bz2 state. Backend `step` return codes are normalized
  (`OK/END/AGAIN/ERR_DATA/ERR_MEM/ERR_BOMB/ERR_PARAM`).
- **Decompression-bomb guard** in the codec layer (`xrootd_codec_guard_t`:
  absolute `out_cap` + `max_ratio`), enforced centrally in `xrootd_codec_step`, so
  **every** untrusted inbound decode (PUT body, ZIP member, client-side) is covered
  uniformly. Conservative defaults; configurable.
- Add the codec names to `shared/xrdproto/Makefile` `NAMES`; the archive stays
  ngx-free (`make check` / `check-ngx-free.sh` passes).

### Header sketch (`src/core/compat/codec_core.h`, ngx-free)
```c
typedef enum { XROOTD_CODEC_IDENTITY=0, XROOTD_CODEC_GZIP, XROOTD_CODEC_DEFLATE,
               XROOTD_CODEC_ZSTD, XROOTD_CODEC_BROTLI, XROOTD_CODEC_XZ,
               XROOTD_CODEC_BZIP2, XROOTD_CODEC_MAX } xrootd_codec_id_t;       /* append-only ordinals */
typedef enum { XROOTD_CODEC_DIR_COMPRESS, XROOTD_CODEC_DIR_DECOMPRESS } xrootd_codec_dir_t;
typedef struct { uint64_t out_cap; uint32_t max_ratio; uint64_t total_in, total_out; } xrootd_codec_guard_t;
typedef struct xrootd_codec_stream_s xrootd_codec_stream_t;
const xrootd_codec_desc_t *xrootd_codec_by_http_token(const char *tok, size_t len);
int  xrootd_codec_available(xrootd_codec_id_t id);
xrootd_codec_stream_t *xrootd_codec_open(xrootd_codec_id_t, xrootd_codec_dir_t, int level,
                                         const xrootd_codec_guard_t *);
xrootd_codec_rc_t xrootd_codec_step(xrootd_codec_stream_t*, const uint8_t *in, size_t in_len,
                                    size_t *in_pos, uint8_t *out, size_t out_cap, size_t *out_pos, int flush);
void xrootd_codec_close(xrootd_codec_stream_t*);
```
The same `open → step-loop → close` pattern is the only thing inbound, outbound,
ZIP, and root:// code call.

---

## 3. Build / dependency wiring
- `config` (repo root): after the krb5 block, a pkg-config probe per codec
  (`libzstd`, `liblzma`, `libbrotlienc`+`libbrotlidec`, `bzip2`) →
  `-DXROOTD_HAVE_<C>=1` + `XROOTD_<C>_LIBS`. Make zlib explicit too
  (`-DXROOTD_HAVE_ZLIB`, `XROOTD_ZLIB_LIBS="-lz"`). bzip2 often lacks a `.pc` →
  header/`-lbz2` fallback probe (the krb5-config precedent); brotli requires both
  enc + dec modules.
- **Dynamic-module rule (the load-bearing lesson from phase RPM work):** add the
  codec libs to the **stream module's** `ngx_module_libs` (it owns `codec_*`,
  `http_body.c`, `file_serve.c`, the new `http_compress.c`); WebDAV/S3/dashboard
  resolve those symbols at load via RTLD_GLOBAL (stream loads first per
  `mod-xrootd.conf`), so they need no extra `ngx_module_libs` — the same pattern
  the `config` comments already document for `xrootd_*`/`checksum_*`. Codec `.c`
  files go ONLY in the stream module's `ngx_module_srcs`; `codec_core.h` into
  `ngx_xrootd_stream_deps`.
- `shared/xrdproto/Makefile` + `client/Makefile`: clone the `HAVE_KRB5` gate for
  each codec; append cflags + libs (next to `-lz`); add the enabled codec
  pkg-config names to `libxrdc.pc` `Requires.private`. **libxrdc stays clean-room**
  — zlib/zstd/lzma/brotli/bz2 are not `libXrd*`, so the `ldd | grep libXrd == 0`
  assertion holds.
- `packaging/rpm/nginx-mod-xrootd.spec`: optional `BuildRequires` (libzstd-devel,
  xz-devel, libbrotli-devel, bzip2-devel) behind `%bcond_with` toggles so the SRPM
  builds on minimal hosts; runtime `Requires` auto-detected from ELF link records.
- **Graceful degradation:** absent lib → `available=0`; inbound unsupported codec →
  415; outbound negotiation filters by `xrootd_codec_available()` so only
  compiled-in codecs are ever advertised/used.

---

## 4. Workstreams — all off by default, independently shippable

### W0 — Foundation (behaviour-preserving)
`codec_core` + the zlib backend + the bomb guard + the `zcrc32` checksum
(XRootD's zlib-CRC, distinct name from `crc32c`): add `XROOTD_CHECKSUM_ZCRC32`
(append-only) to `src/core/compat/checksum_core.{c,h}` + register `"zcrc32"` in
`src/core/compat/checksum.c` name/parse/is_u32; mirror in `client/lib/checksum.c`. No
behaviour change — pure scaffolding + checksum parity.

### W1 — Inbound decompress (PUT), all codecs
Refactor `src/core/compat/http_body.c` (`xrootd_http_body_inflate_to_fd`,
`inflate_feed`, `xrootd_http_body_inflate_bufs`) from zlib-only to codec-dispatch
via `codec_core` (gzip/deflate stay byte-identical: `codec_zlib` uses
`inflateInit2(15+16)` / `(15)`). Sniff `Content-Encoding` at `src/protocols/webdav/put.c`
(~:247-261) and `src/protocols/s3/put.c` (~:527-543) → `xrootd_codec_by_http_token`; the
thread-pool fast-path gate becomes `codec == IDENTITY`; reply **415** for an
unsupported/disabled codec (instead of storing garbage); map a tripped bomb guard
to **413** (flows through the existing "failed inflate leaves no partial object"
cleanup). Add the four optional backends in this workstream.

### W2 — Outbound compress (GET), all codecs — *separate review (perturbs sendfile)*
New module-only `src/core/compat/http_compress.{c,h}` + a negotiation seam in
`src/protocols/shared/file_serve.c` (`xrootd_http_serve_file_ranged`), after range parse and
before headers: parse `Accept-Encoding` q-values ∩ the location's configured +
`available` codec list; require `size >= min_size`, a compressible MIME (deny
`image/*`, `video/*`, `application/gzip|zstd|x-xz|x-bzip2`, …), **Range → identity**,
HEAD → no body. If a codec is chosen, drop the sendfile path and stream
`read → codec compress → ngx_buf → ngx_http_output_filter`, emit `Content-Encoding`
+ `Vary: Accept-Encoding`, and set `content_length_n = -1` (chunked, since the
compressed size is unknown until done). `IDENTITY` path is byte-identical to today
(zero regression for the common case). Extend `xrootd_http_set_file_headers`
(`src/core/compat/http_file_response.c`) for the encoding header + the chunked case; add
a policy field to `xrootd_http_serve_opts_t` so GET callers (`src/protocols/webdav/get.c`,
`src/protocols/s3/object.c`) pass per-location config. New config directives: enable
per-location + codec list + min-size + MIME set. Keep `Vary`/ETag conservative to
avoid shared-cache poisoning.

### W3 — ZIP archive member reads (real XRootD parity; server unchanged)
New `client/lib/zip.{c,h}` (zlib-only → clean-room preserved). Locate the
End-of-Central-Directory (ZIP64-aware: EOCD locator `0x07064b50` → ZIP64 EOCD
`0x06064b50`), parse the central directory into a member table (name, method,
comp/uncomp size, CRC-32, local-header offset), read a member's extent through a
`pread` adapter (works over the remote `xrdc_mfile_pread` or a local fd, so xrdcp /
FUSE reuse it), STORE-copy or raw-inflate (`inflateInit2(-MAX_WBITS)`), verify
CRC-32. Drive via `?xrdcl.unzip=<member>` (read) and `xrdcp --zip` / `--zip-append`
(STORE-only write, matching XRootD). Server is untouched (highest value-to-risk).
**Untrusted-parser security is mandatory** (see §6).

### W4 — root:// inline read compression + transparent client — *off by default*
The wire extension. **Option B: block-framed compression on `kXR_read` ONLY.**
Compress fixed-size, *plaintext-offset-aligned* blocks independently
(`[u32 plain_off_delta][u32 plain_len][u32 comp_len][comp_bytes]`), so every read
stays offset-addressable and resumable. **`pgread` and `readv` stay plaintext** —
this preserves the mandatory pgread `kXR_status`(4007) + per-page-CRC32c INVARIANT
byte-for-byte (compression is a `kXR_read`-only handle property). Three-signal
negotiation, all backward-compatible:
1. Server advertises `cmpread=zstd,gzip,xz,…` via `kXR_Qconfig`
   (`src/query/config.c`, modeled on `xrdfs.ext`).
2. Willing client opens with opaque `?xrootd.compress=zstd[:bs=N]` (rides the
   existing `path?opaque` channel; stock servers strip/ignore the unknown key).
3. Server confirms by setting the *vestigial* `cpsize` (= block size) / `cptype`
   (= codec tag) in the open reply (`src/read/open_resolved_file.c:412`, currently
   hardcoded 0; stock clients ignore them).

Compatibility matrix: stock↔ours and ours↔stock both stay plaintext/byte-identical;
compression happens only when both ends agree. Disable the sendfile branch for
compressed handles; store `codec_id`+`bs` on `xrootd_file_t` (`src/core/types/context.h`).
Client (`client/lib/ops_file.c::xrdc_file_read`, `client/lib/aio_mgr.c::
xrdc_mfile_pread`) captures `cpsize`/`cptype` from the open reply and transparently
decompresses block-framed reads; **reopen-at-offset still works** because blocks are
standalone + offset-keyed (re-learn the codec on `mfile_reopen`; fall back to
plaintext if a reopened server declines). FUSE (`xrootdfs`/`xrootdfs_aio`) gets it
for free via `xrdc_mfile` + a `-o compress=zstd` mount option; `xrdcp --compress=
<codec>`.

### W5 — Optional, deferred
Server-side **write** decompression (large surface: `src/write/*`, POSC, wrts
journal, checkpoint — separate, off by default, only if justified). xrdcp whole-file
single-stream mode (`--compress=zstd:stream`, download-only, max ratio) as an
explicit opt-in on top of W4.

---

## 5. Critical files (pattern over enumeration)
- **New:** `src/core/compat/codec_core.{c,h}`, `src/core/compat/codec_{zlib,zstd,lzma,brotli,
  bzip2}.c`, `src/core/compat/http_compress.{c,h}` (module-only), `client/lib/zip.{c,h}`,
  `src/read/compress_negotiate.c`.
- **Build:** `config` (probes + stream-module `ngx_module_libs` + srcs),
  `shared/xrdproto/Makefile`, `client/Makefile`, `packaging/rpm/nginx-mod-xrootd.spec`.
- **Inbound:** `src/core/compat/http_body.c`, `src/protocols/webdav/put.c`, `src/protocols/s3/put.c`.
- **Outbound:** `src/protocols/shared/file_serve.c`, `src/core/compat/http_file_response.c`,
  `src/protocols/shared/file_serve.h`, `src/protocols/webdav/get.c`, `src/protocols/s3/object.c`.
- **root:// (W4):** `src/query/config.c`, `src/read/open_request.c`,
  `src/read/open_resolved_file.c`, `src/read/slice_read.c`, `src/read/read.c`,
  `src/core/types/context.h`; `src/read/pgread.c` + `src/read/readv.c` + `src/core/aio/readv.c`
  get only an invariant comment (stay plaintext).
- **Client:** `client/lib/ops_file.c`, `client/lib/aio_mgr.c`, `client/lib/copy.c`,
  `client/apps/xrdcp.c`.
- **Checksum:** `src/core/compat/checksum_core.{c,h}`, `src/core/compat/checksum.c`,
  `client/lib/checksum.c`.

## 6. Security (must-haves)
- Codec-layer bomb guard (ratio + absolute cap), conservative defaults, ON for all
  untrusted inbound decode (PUT, ZIP). Trip → 413.
- The ZIP central-directory parser is fully attacker-controlled: bounds-check every
  offset/size against the archive size, cap entry count + CD size, enforce a
  zip-bomb ratio/absolute cap (never trust the header `uncompressedSize` for
  allocation), CRC-verify each member, reject non-STORE/DEFLATE methods, and reject
  path traversal on extract. Fuzz it (treat like `tests/test_attack_vectors.py`).
- Outbound compress is our own data (not bomb-guarded) but must skip
  already-compressed MIME and never compress byte ranges.
- New `zip.c` / `codec_*.c` must be early-return + helper-decomposed from the start
  (no `goto`; the standard now covers `src/` and `client/`).

## 7. Verification
- Per-codec round-trip oracles vs system tools (`gzip`/`xz`/`zstd`/`brotli`/`bzip2`
  + Python `zlib`/`lzma`/`zstandard`/`brotli`/`bz2`): success + corrupt-stream (4xx)
  + bomb (413) for each codec on each surface (3-tests-per-change rule).
- Inbound: PUT each codec to WebDAV + S3, read back byte-exact; unsupported → 415.
- Outbound: GET with `Accept-Encoding: <codec>` → correct `Content-Encoding`,
  decompresses byte-exact; `Range` + `Accept-Encoding` → 206 identity; confirm
  nginx doesn't re-add `Content-Length` on the chunked path.
- ZIP: fixture archives (STORE, DEFLATE, ZIP64, mixed) — `xrdcp ?xrdcl.unzip=` and
  `--zip` byte-exact vs `unzip -p`; a `--zip-append` member readable by stock
  `unzip` + XrdCl; fuzz the CDFH parser (OOB offset → reject, not read).
- root:// W4: stock↔ours and ours↔stock stay byte-identical (opt-in invisibility);
  ours↔ours compressed read byte-exact incl. random-access; compressed/member read
  survives a mid-stream bounce via `tests/c/fault_proxy.c` (resilient `xrdc_mfile`);
  `ldd` clean-room on the client.
- Clean build under `-Werror` + hardening; `nginx -t`; **dynamic-module dlopen
  test** (build `--with-stream=dynamic`, confirm WebDAV/S3 `.so` load on stock
  nginx — the RTLD_GLOBAL assumption that makes §3 work).

## 8. Risks
- W2 is the only change touching the proven sendfile hot path → default-off,
  independently revertable.
- W4 is a wire-protocol extension → strict opt-in invisibility is the acceptance
  bar; pgread/readv MUST stay plaintext (CRC invariant).
- Stream codecs aren't seekable → block-framing (W4) and inflate-from-start (ZIP
  random access) are the chosen mitigations; document the per-handle cost.
- 5 codecs × build matrix → graceful-degrade must be tested with libs absent.
- bzip2 is the weakest value (slow/legacy) — lowest priority; brotli = two libs.

## 9. Sequencing
W0 → W1 (+ optional backends) → W3 (ZIP — highest value/risk ratio, server
untouched) → W2 (outbound — separate review) → W4 (negotiation first, then the
block data path) → W5 (optional).

## 10. References (official XRootD, `/tmp/xrootd-src`)
- Codec inventory: `cmake/XRootDFindLibs.cmake:4` (ZLIB REQUIRED), `:50-61` (isa-l,
  EC-only — not compression), `:78-89` (libzip, XrdOssArc-only). No lzma/zstd/bzip2/
  brotli/snappy/lz4 anywhere.
- ZIP read: `src/XrdCl/XrdClZipArchive.cc:65,94` (only `0`/`Z_DEFLATED`), `:94-162`
  (client-side inflate), `:174` (STORE); `src/XrdCl/XrdClZipCache.hh:77-96,143-177`.
  Write = STORE only (`XrdZipLFH` `compressionMethod=0`). xrdcp: `xrdcp.1:148-150`.
- `kXR_compress`/cpsize/cptype: `src/XProtocol/XProtocol.hh:482,1091-1093`;
  `src/XrdXrootd/XrdXrootdXeq.cc:1530-1531,1718-1720`; `src/XrdOfs/XrdOfs.cc:1826-1842`
  (`getCXinfo`); `src/XrdOss/XrdOssApi.cc:1287-1293,1374-1379` (XRDOSSCX conditional).
  Vestigial without the unshipped `XRDOSSCX` plugin.
- zcrc32: `src/XrdCks/XrdCksCalczcrc32.cc:36,73,89`.
- HTTP (no content compression): `src/XrdHttp/XrdHttpReq.cc:118-241`,
  `src/XrdHttp/XrdHttpProtocol.cc:1505-1527`; `src/XrdOssArc/XrdOssArcZipFile.cc:170-173`
  (compressed archives unsupported server-side).
