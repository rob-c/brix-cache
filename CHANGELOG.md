# Changelog

Notable changes per release. The version in `src/core/ident.h`
(`BRIX_SERVER_VERSION_BARE`) is the single source of truth; the RPM version,
the spec's literal fallback, this file's top entry and the git tag all derive
from it, and `tools/ci/check_version_sync.py` fails CI if they drift apart.
Cutting a release is documented in
[docs/09-developer-guide/release-process.md](docs/09-developer-guide/release-process.md).

Versions that were never cut: **1.0.6**, **1.1.0**, **1.2.x**. The version line
skipped them; they are not missing entries. Releases before 1.3.0 were shipped
as RPM revisions (`1.1.1-3` … `1.1.1-25`) whose per-revision packaging detail
lives in the `%changelog` of
[`packaging/rpm/nginx-mod-brix-cache.spec`](packaging/rpm/nginx-mod-brix-cache.spec)
— that file remains authoritative for packaging changes; this one summarises
what changed for a user of the server.

---

## Unreleased

### Security

- **Two S3 endpoints in one server no longer share a signing key.** The
  worker-local SigV4 signing-key cache was keyed on date + region only, not on
  the secret it came from. One worker verifies for every `brix_s3` block in the
  configuration, so whichever block signed first captured the single cache slot,
  and for the rest of the calendar day another block would **accept a request
  forged with the first block's secret** (an access key id is an identifier, not
  a secret) and **reject its own legitimate credential**, because the cache-hit
  path never re-derives. The cache is now keyed on date + region + a SHA-256 of
  the secret (a digest, so no key material sits in the static). Deployments with
  a single `brix_s3` block were never affected; anything re-exporting a bucket
  through a co-hosted gateway was. Pinned by `tests/test_s3_nested_gateway.py`,
  which fails in both directions against the old code.

- **HTTP-TPC pulls can now be verified before they are committed**: a WebDAV
  `COPY` pull committed whatever curl produced, because its only in-band
  "the whole file arrived" signal is "curl stopped without an error" — which a
  chunked source that dies mid-body, a truncating middlebox and a corrupting one
  all produce. The native `root://` plane has refused those since Phase 58; the
  HTTP plane had no completion gate at all. Two new directives close it, named and
  behaving like the native pair so there is one contract to reason about:
  `brix_webdav_tpc_require_source_size on|off` and
  `brix_webdav_tpc_verify_checksum <alg>`. When either is on, one HEAD re-probes
  the source before the staged temp is published — carrying `Want-Digest: <alg>`
  when a checksum algorithm is configured — and the declared `Content-Length` is
  compared against the bytes on disk, then the returned RFC-3230 `Digest` is
  recomputed over the temp. A declared length that disagrees always refuses; a
  source that declares *no* length refuses only under `require_source_size`; the
  checksum half is fail-closed (absent, unparseable, uncomputable or mismatching
  all refuse). Refusals are `502` and the staged temp is aborted, so nothing is
  published. Both halves default off, so an existing deployment sees no new
  refusal, and the algorithm name is validated at config parse time — a typo is
  `[emerg]`, never a silently disabled gate. All three pull tiers (202-marker,
  thread-pool, synchronous) pass through it exactly once; push is unaffected.
  See [docs/04-protocols/http-tpc-reference.md](docs/04-protocols/http-tpc-reference.md) §8.

- **WebDAV TPC push now faces the source-host egress allowlist**: a COPY *pull*
  had its `Source` authority vetted against `brix_webdav_tpc_source_allow`, but a
  COPY *push* returned into the push handler before that guard, so the
  `Destination` authority it dialled was subject only to the Layer-1
  address-range/DNS preflight. Push and pull now share the same naming verdict,
  the same 403, and the same `signal=tpc_egress` audit line.

- **A hostile manager could forge lines into `error.log` through a CMS existence
  probe.** The `kYR_state` payload is a raw namespace path, and its validator
  bounds the length, requires a leading `/` and rejects `..` — but accepts every
  other byte, CR and LF included. That path then reached five log sites as a bare
  `%s`, so a manager (or anything that had taken one over) could embed a newline
  and write whole synthetic records — including fake `cmsd-action` audit lines,
  which is exactly the record an operator would trust when reconstructing who
  asked for what. The probe path is now rendered through
  `brix_sanitize_log_string()` at every log site on both the sub-manager and the
  data-node arm; the wire reply and the `openat2`-confined stat keep the real
  bytes, so nothing about resolution changes. Pinned by
  `test_state_probe_path_is_escaped_in_the_error_log`, which pushes a probe
  carrying `\n cmsd-action …` and asserts the escaped `\x0A` appears while no
  `error.log` line *begins* with `cmsd-action`.

### Fixed

- **A WebDAV auth test asserted a status the RFC forbids.** The GSI fixture
  endpoint carries a JWKS as well as a CA dir, so it is bearer-protected and
  owes an uncredentialled request `401` + `WWW-Authenticate: Bearer` (RFC 6750
  §3) — `403` is reserved for `insufficient_scope` on a *valid* token, and is
  what a cert-only export still returns. The server had it right; the test
  still expected the pre-bearer `403`. It now asserts the 401 **and** the
  challenge header, so the RFC obligation is covered rather than just the code.

- **A clustered rename left the manager's namespace permanently wrong.** Data
  servers report namespace mutations up the CMS link so the manager can answer
  `kXR_stat` from its Composite Cluster Name Space inventory instead of
  redirecting — but `kXR_mv` emitted no event at all, on either the inline or
  the `brix_backend_async` durable-queue path. The manager therefore kept
  serving the pre-rename path (with the pre-rename size) and never learned the
  new one, for the life of the entry. A rename now emits one **two-path**
  `MV` event which the manager applies **subtree-aware**: every recorded child
  of a renamed directory moves with it. That is why it is a single event rather
  than a `DEL` + `ADD` pair — a pair strands the children at a path that no
  longer exists, and is not safe against out-of-order arrival. Interop is
  preserved in both directions: the CNS frame code is private to BriX peers, so
  a manager built before this change ignores the added payload and then treats
  the unknown op as a no-op. Covered end-to-end (file, directory subtree, and
  the async waker) in `tests/test_cns.py`, plus the inventory contract in the
  standalone `cns_inventory` unit test.
- **A path-based `kXR_truncate` left a stale size in the manager inventory.**
  It is the only size change in the protocol with no `kXR_close` behind it — the
  handle form is followed by a close, which already emits the authoritative
  record — so it was the one mutation whose new size never reached the manager.
  It now re-emits with the size observed on the object itself (through the VFS
  seam, so it is also correct over a non-POSIX backend), rather than trusting the
  length in the request.

- **Every `stub-upstream-*` test ran against a dead upstream.** None of the
  seven fronts declared `requires=("upstream-stubs",)`, and under the zero-boot
  gate a `registry_server` marker starts only the dependency closure — so the
  stub process never came up, and nginx answered each locate with `kXR_error`
  because it could not reach its backend. That failure is indistinguishable
  from "the proxy correctly forwarded an upstream error", which is how it went
  unnoticed; `test_locate_wait_then_redirect` was failing outright (`4003 !=
  4004`). All seven specs now name the stub process.
- **`brix_io_ops_total{op="tpc"}` had no booking owner and exported a permanent
  zero.** The label value was declared in the unified op enum and scraped
  cleanly, so it read as a working metric that measured nothing — third-party
  copies were invisible in the unified ledger even though the protocol-specific
  `brix_tpc_transfers_total` counted them. `brix_tpc_metric_book()` now also
  calls the new `brix_metric_op_count(proto, op, err)` — the count-only sibling
  of `brix_metric_op_done()`, for operations that have no single meaningful
  latency (a TPC transfer's duration is the remote leg's, not this server's).
  Recorded as Pattern 13 in `docs/08-metrics-monitoring/metrics-bug-patterns.md`,
  the inverse of the single-owner rule: a row with *no* owner rather than two.

- **Server-side COPY could not succeed on any export with an explicit
  `brix_storage_backend`.** `sd_posix_server_copy()` passed the vtable's
  root-relative keys to `brix_ns_local_copy()`, which strips `root_canon` off
  *absolute* paths and treats a non-match as a cross-root copy — so every copy
  failed `EXDEV`, surfacing as WebDAV `COPY` → 403 and S3 `CopyObject` → 500.
  A plain export was unaffected: its driver is NULL, so the copy took the VFS
  namespace branch instead. This is the same calling-convention bug fixed in
  `sd_posix_rename` one day earlier, in the sibling slot that fix did not check;
  `brix_io_ops_total{op="copy"}` had a structurally impossible 100% error rate on
  driver-backed exports for as long as the row existed.

- **A WebDAV GET that triggered a cache fill was missing from the response
  ledger.** Such a request parks with `NGX_DONE` and is re-entered by the fill
  worker, which called the raw GET handler rather than the metrics-wrapped
  dispatch tail — so the one request that actually paid for an origin fetch never
  booked `brix_webdav_responses_total` or `brix_io_ops_total{op="read"}`, while
  its bytes still landed via the scrape-time ledger fold (ops and bytes disagreed
  by exactly one per cold object). A fill that ended 404/403/502 never re-entered
  at all and booked nothing; that tail now has an `on_fail` hook. Only exports
  that offload fills (remote-backed) were affected — a local posix export serves
  inline and was always counted correctly.

- **`rmdir` of a regular FILE on an HTTP origin deleted the file** and reported
  success. WebDAV has one DELETE method for both kinds of resource, so the
  `sd_http` unlink slot discarded the `is_dir` the VFS passes it. A type probe
  (PROPFIND `Depth: 0`) now runs before anything is issued: an `rmdir` of a
  non-collection is refused `ENOTDIR`, exactly as the POSIX backend refuses it,
  and nothing reaches the origin.

- **A populated collection could be removed by a non-recursive delete.** The VFS
  calls the driver's unlink slot non-recursively (recursive deletes are walked by
  `brix_vfs_driver_rmtree`), but a WebDAV DELETE of a collection is recursive per
  RFC 4918 §9.6 — so against a spec-conforming origin an `xrdfs rmdir` of a
  non-empty collection would have erased the whole subtree, where POSIX refuses
  `ENOTEMPTY`. Against an origin that refuses it (409) the client was told the
  removal **succeeded** while the data survived, because the shared status map
  read that 409 as `ENOENT` and the root layer treats a missing rmdir target as
  idempotent success. The delete slot now gates on an emptiness probe and maps a
  DELETE 409 to `ENOTEMPTY`; an empty collection is still removable by both `rm`
  and `rmdir`, matching `brix_ns_delete`.

- **Deleting a path that does not exist on an HTTP origin looked like a real
  deletion**: the unlink slot counted 404 as success ("idempotent"), so `rm` of a
  missing object returned OK where every other backend returns `kXR_NotFound`.
  404 is now `ENOENT` — and reachable only as a lost race, since the gate has
  already established the entry existed.

- **`stat` of an HTTP origin reported EVERY path as a regular file**: a HEAD of a
  collection and a HEAD of an empty object are the same `200` with
  `Content-Length: 0`, so a directory stat'd as a zero-byte file — `xrdfs stat`
  showed no `isDir`, and any caller branching on the type took the file branch.
  A zero-sized stat now resolves the ambiguity with one PROPFIND `Depth: 0`
  (the same probe the delete gate uses) and stamps `S_IFDIR` for a collection.
  A non-zero size is unambiguous and costs no extra round trip, so plain HTTP and
  CVMFS origins keep their flat-object view unchanged.

- **`mkdir -p` over an existing regular FILE reported success** — on the POSIX
  path and through every driver mkpath walk. The walks tolerate `EEXIST` so an
  already-present prefix is benign, but at the FINAL component that tolerance
  decided the whole operation: a client was told a directory existed where its
  own data was, and the next write into that "directory" failed `ENOTDIR` with no
  explanation. An `EEXIST` at the leaf is now benign only over a directory
  (`brix_mkdir_existed` on the POSIX side, `brix_vfs_backend_leaf_isdir` on the
  driver side, both failing closed when the type cannot be established) —
  the same conflict coreutils `mkdir -p` reports.

- **A write-stage tier made every write to a subdirectory impossible**: with
  `brix_stage` configured, a create-open of any nested key failed
  `kXR_NotFound` (3011). The stage store is a private spool, so the chain the
  client built with `mkdir`/`kXR_mkpath` exists in the export and (at flush) on
  the origin, but never in the spool the write-back leg opens — flat keys worked,
  everything else did not. The tier now builds the key's parent chain in the
  store before opening it; the staged whole-object leg was unaffected because the
  POSIX store's `staged_open` already mkpaths its own parents.

- **`kXR_fattr` list answered `kXR_FSError` for a backend that simply has no
  extended attributes**: `fattr_list()` degrades to an empty list only when the
  underlying call reports `ENOTSUP`/`EOPNOTSUPP`, but the storage seam reports a
  leaf driver with no `listxattr` slot as `ENOSYS`
  (`brix_sd_listxattr_maybe_cred`). An export whose http origin sits under the
  default write-stage tier therefore failed a plain attribute listing, while the
  same origin used directly returned the documented empty list. `ENOSYS` is now
  accepted alongside the other two.
- **`brix_upload_resume` (and with it `brix_stage_dir`) was disabled for every
  plain `brix_export` on the root:// plane**: the P80.2 resume divert had been
  widened to fire whenever `brix_vfs_backend_resolve()` returned an instance, but
  since phase-68 every plain export registers a **default-POSIX** backend row, so
  the resolve is never NULL and the divert cleared `use_resume` unconditionally.
  Uploads still landed byte-exact, but unstaged — writes touched the final path
  mid-transfer and an interrupted upload could not be resumed. The divert now
  keys on the driver being something other than `brix_sd_default_driver()`, the
  same discriminator `brix_commit_staged()` uses, so driver-backed exports keep
  taking the whole-object staged seam while local POSIX storage — the case the
  resume skeleton exists for — keeps its staging.
- **A failed staged commit on the `stage` and `frm` backends freed the handle
  the caller was then required to abort**: the storage-driver contract is that
  `staged_commit` consumes (frees) the heap handle **only on success** — every
  caller (`stage_engine`, `cstb_pump_and_commit`, the cache fetch path) calls
  `staged_abort` after a commit that failed. `sd_stage`'s synchronous write-back
  freed both allocations even when the inline flush failed, and it left
  `ss->inner` dangling after the inner store commit had already consumed it;
  `sd_frm` freed both when `mss->migrate()` failed. In each case the mandatory
  abort re-entered released memory — a use-after-free plus a double free, and in
  the frm case a second purge of the online buffer. Only successful commits free
  now, and `sd_stage`'s abort skips an inner handle that was already consumed.
  This is the same family as the earlier posix double-free; the remaining
  drivers were surveyed and are conformant (`ceph` is pool-allocated and frees
  nothing by design).

- **`brix_cache_meta sidecar` never produced a sidecar on an xattr-capable
  store**: `brix_xmeta_save()` prefers the `user.xrd.cinfo` xattr whenever the
  store driver has `setxattr`, and the cache called it unconditionally — so an
  explicitly configured sidecar mode silently degraded to the xattr carrier, and
  a store that could hold only sidecars kept none of the metadata it was told to
  write. The mode is a request, not a hint: `brix_cstore_cinfo_store()` now
  routes `BRIX_CMETA_SIDECAR` through a new `brix_xmeta_save_sidecar()`.

- **A `root://` store could not hold a cache sidecar at all**: with the above
  fixed, the `<key>.cinfo` open came back `kXR_NotFound` (3011). Every reserved
  name is answered as absent on the root plane so a client can neither read nor
  create one — but unlike the HTTP planes, the root plane had no trusted-store
  exception, so `brix_cache_store root://…` with sidecar metadata failed every
  cinfo store and refilled on every read. See `brix_cache_store_endpoint` under
  *Added*.

- **`root://` token auth was unusable from a stock XRootD client**: the
  `kXR_login` security block advertised `&P=ztn,v:10000`, a parameter form
  borrowed from the GSI dialect. `XrdSecProtocolztn` parses its parameters as
  `<expiry>:<maxtsz>:` — minimum acceptable token lifetime, then maximum
  accepted token size, each closed by a colon and the size required positive —
  so every stock `XrdCl` aborted the login with *"Secztn: Malformed client
  parameters"* and fell through to "No protocols left to try". The server now
  advertises `&P=ztn,0:4096:` (the reference server's own default `-maxsz`), in
  the token-only block and in the `brix_auth both` block alike. The bug survived
  because every pre-existing `ztn` test drove the credential exchange by hand
  rather than through a real client; `test_token_auth.py` now pins the grammar,
  and `test_tpc_token_auth.py` exercises it end-to-end with `xrdcp`.

- **S3: a key ending in `/` is a folder marker**: the server had no folder-marker
  path on either side, so BriX talking to its own S3 origin could neither create
  nor see a directory. `PUT "dir/"` fell into the object-write path and its
  atomic publish tried to rename the staged temp *onto* the directory its own
  parent-prefix mkdir had just created (`EINVAL` → 500, directory left behind);
  over `root://` that surfaced as `xrdfs mkdir` → EIO. `HEAD "dir/"` answered 404
  `NoSuchKey` like every other directory path, so a folder that existed stat'd as
  absent and a rename into it was refused with "invalid destination path". A
  marker `PUT` now creates the directory and is idempotent (a marker carrying a
  body is refused 400 `InvalidRequest` rather than silently dropped), and `HEAD`
  of the marker form reports it with zero length. Keys *without* the trailing
  slash that merely resolve to a directory remain 404 `NoSuchKey`.
- **Metrics accuracy — HTTP upload double-count**: WebDAV/S3 PUT booked the
  unified WRITE row twice (once at the VFS staged commit, once at the protocol
  response), doubling `brix_io_ops_total{op="write"}`, `brix_io_bytes_written`
  and the write-latency histogram for every HTTP upload. The staged commit now
  books only the per-backend `brix_storage_io_bytes_*` totals and the access-log
  line; the unified WRITE row is owned solely by the protocol response path.
- **Metrics accuracy — PROPFIND responses uncounted**: PROPFIND-with-body
  finalized through a bare `ngx_http_finalize_request`, so
  `brix_webdav_responses_total{method="PROPFIND"}` never moved. The async body
  handler now finalizes via the metrics-aware wrapper, matching
  PUT/PROPPATCH/SEARCH.
- **WebDAV MOVE always failed with 500 (EXDEV)**: `sd_posix_rename` forwarded the
  vtable's export-relative keys straight to `brix_ns_rename()`, whose contract
  demands absolute paths under `root_canon` — every rename, even within one
  directory, was refused as a cross-root move. The driver now builds the
  absolute paths exactly as `sd_posix_mkdir`/`unlink` already did.
- **MOVE metrics folded into `method="OTHER"`**: the WebDAV metric enum had no
  MOVE slot, so `brix_webdav_requests_total`/`_responses_total` booked every
  MOVE as OTHER. MOVE is now a first-class method label (new enum slot, string
  table, and operation-table row; OTHER shifted to the last slot).
- **Metrics exposition — unquoted `hash` label**: `brix_user_sessions_total`
  emitted its label value unquoted (`{hash=a1b2c3d4}`), which strict Prometheus
  text-format parsers reject. The value is now quoted; a board-wide
  label-residue test keeps every hand-formatted row honest.
- **WebDAV malformed `Range`: wire status and accounting disagreed**: the GET
  path left the core nginx range filter enabled (`allow_ranges = 1`) on top of
  the module's own range handling. A malformed/backwards `Range` was correctly
  ignored by the module (RFC 9110 §14.2 — full 200 served and ledgered), then
  the core filter re-parsed the same header and rewrote the response to a 416
  error page — booking a full-object read for a response the client never got.
  The serve path now owns range semantics end-to-end (`allow_ranges = 0`,
  explicit `Accept-Ranges: bytes`).
- **A GridFTP `MLST` fact line could carry uninitialised stack bytes.** The
  event-engine formatter checked `gmtime_r()` but used `strftime()`'s result
  unconditionally, and `strftime()` leaves its buffer *indeterminate* when it
  returns 0 — so a timestamp `gmtime_r` accepts but the format cannot render
  (a year beyond four digits) put whatever was on the stack into `modify=`.
  The buffer is re-cleared on that arm, so the fact degrades to a valueless
  `modify=` rather than leaking. `tests/test_gridftp_engine_event.py` pins the
  fact's shape at the filesystem's own mtime ceiling (ext4 clamps to 2446, which
  is the closest a real on-disk mtime gets to the arm), asserts `MLST` and
  `MDTM` agree, and adds a security-negative test that every byte of a fact line
  is printable ASCII.

### Changed

- **Agent-memory knowledge folded into the repo docs.** Everything durable that
  had accumulated only in the agent memory store was relocated into the docs it
  belongs to, and the memories themselves reduced to pointers. New or extended
  material: harness/fleet gotchas and wire-stub traps
  (`history-testing-and-incidents.md` §1.3); hermetic C-unit link rules, the
  `-DBRIX_HAVE_*` harness-ABI trap, the unbalanced-quote-in-`config` silent
  source drop, nginx's wiped worker environment, and the private-build-tree
  recipe for a box shared by concurrent sessions
  (`history-build-infra-and-decisions.md` §1/§5); fault-injection rate regimes
  and the sticky-lever trap (`hostile-network-lessons.md`); the pblock
  versioning reachability rule (`phase-83-pblock-lab-features.md`); the Ceph
  live-lab runbook (`phase-60-ceph-rados-backend.md`); the `-brix` tool
  naming policy with `xrdsssadmin-brix`'s non-stock CLI
  (`native-client-tools.md`); the fleet signing-key-desync signature — every
  token accept-case red while every reject-case passes — added to the
  testing field-guide table; and the standing Python-replaces-bash tooling
  policy written down as `history-build-infra-and-decisions.md` Part 2 §7. A
  second pass emptied the index file itself: `logged_in` is set when the CMS
  login is *sent*, not acknowledged, so nothing may assert cluster membership on
  it (`cms-protocol.md` §8 item 11); `brix_sanitize_log_string` emits **uppercase**
  hex, which is a test-assertion trap (`comparison-nginx-xrootd-vs-canonical.md`
  §4.10); and through the phase-97 CMS/CNS work every red was a concurrent
  session's `TEST_ROOT` wipe or fixed-port contention and none was a code defect,
  so on a shared box a red is re-run solo before the diff is read
  (`history-testing-and-incidents.md` §1.3). The memory store went from 672 KB to
  140 KB (21%): each entry is now frontmatter plus one line — the doc pointer, the
  commit/date/file archaeology, and its cross-links — and only the operating rules
  keep imperative text, each carrying a doc reference for the why.
- **Two red CI guards re-greened, neither of which was reporting real debt.**
  `check_doc_links` failed on a single untracked link *target*
  (`docs/05-operations/cvmfs-stratum0.md`, written during the Stratum-0 work and
  never added) — the guard treats an untracked target as dead because it
  resolves locally and 404s in every fresh clone. `check_duplication` reported 10
  new duplicated blocks in `src/` files that had not been edited; the ratchet
  keys a grandfathered block on its exact line spans, so an edit *above* a
  duplicated block, or lizard regrouping which spans it clusters, resurfaces that
  block as "new". All 10 were classified as churn before regenerating, and the
  regenerated backlog confirms it: 10 entries added (exactly the 10 failures) and
  7 dropped for duplication that has since been factored out. See
  [docs/09-developer-guide/ci-guards-burndown-2026-07-21.md](docs/09-developer-guide/ci-guards-burndown-2026-07-21.md)
  §"Follow-on: 2026-08-05".

- **`brix_authdb` (native format) now works behind every authenticating scheme**:
  the config-time gate whitelisted `gsi`, `token` and both, so a server using
  `sss`, `krb5`, `pwd`, `host` or `unix` was refused at startup — those five
  mechanisms could authenticate a user but could not authorize one, on any path.
  They all stamp `ctx->login.dn` exactly as gsi/token do (`pwd`/`sss` fill the VO
  list too), so `u`/`g`/`p` rules bind behind them unchanged. The gate now
  refuses exactly one configuration, an anonymous server (`brix_auth none`), and
  `brix_authdb_format xrdacc` stays exempt even there because it authorizes
  anonymous `u *` rules. See
  [docs/06-authentication/identity-mapping.md](docs/06-authentication/identity-mapping.md)
  §4.2 for which scheme feeds which rule type.

### Added

- **Background block prefetch for the slice cache** (`brix_cache_prefetch`,
  `brix_cache_prefetch_window`), closing the highest-value cache gap in the
  2026-08-04 XRootD parity audit (XrdPfc `pfc.prefetch`). A sequential read of
  a slice-cached object now WILLNEED-hints the storage driver, and the cache
  decorator fills the absent successor blocks on a worker thread — a rolling
  runway that stays up to `prefetch_window` ahead of the reader (default 8 MiB)
  with at most `prefetch` jobs in flight (default 0 = off). Implemented as a
  **generic VFS feature** on the driver `read_advise` slot: both the `root://`
  sequential-read engine (with XrdPfc disable-on-random parity) and the HTTP
  memory-backed serve loop (WebDAV/S3 range GETs ≥ 1 MiB) issue the hints, so
  any protocol plane over `brix_cache_store` + `brix_cache_slice_size` gets
  speculative fills. Jobs reuse the credential captured at open, skip
  foreground-filled blocks, and report as `brix_cache_prefetch_jobs_total` /
  `_blocks_total` / `_failures_total` on `/metrics`. Covered by
  `tests/test_vfs_prefetch.py` (parse/validate, window cap, disable-on-random,
  default-off security negative, background-failure resilience, offline
  serving of a prefetch-completed object, HTTP successor-block warming).

- **Multi-manager redundancy: `brix_cms_manager` now takes up to 15 endpoints**
  (multiple arguments and/or repeated directives; the stock `all.manager`
  `MaxMan` cap), closing the highest-impact operational gap in the 2026-08-04
  XRootD parity audit. The node opens one heartbeat link **per manager** and
  logs into **all of them concurrently** — stock cmsd semantics, where a
  redundant manager set is only redundant if every manager knows the node.
  Registry-miss lookups (`kXR_locate`, manager-mode open/stat/query) rotate
  round-robin over the logged-in links (stock `ClientMan` rotation) and fail
  over to the survivors when a manager drops, falling back to the legacy
  single-manager error path only when every link is down. CNS namespace events
  fan out to **every** live link, so each redundant manager keeps a complete
  inventory. Each link gets a disjoint streamid lane (seed = manager index,
  stride = manager count), so concurrent replies can never collide in the
  worker-keyed pending table. A duplicate endpoint (same resolved address) is
  rejected at parse time — stock managers 30 s-blacklist a second login from
  the same node identity, so a duplicate would break membership, not add
  redundancy. Single-manager configurations are unchanged. Covered end-to-end
  (concurrent login, rotation, failover, CNS fan-out, rogue unsolicited
  `kYR_select`, parse negatives) in `tests/test_cms_multi_manager.py`.

- **Fault injection now reaches the two legs that have no client on them, and
  the sss login.** `tests/resilience/` could only ever damage one connection —
  the one between the client and the server. Two legs that carry real grid
  traffic had never had a single fault injected: a `root://` front fetching from
  a remote `http://` origin, and the native third-party-copy pull, where the
  *destination* dials the source. Those are the legs where a short read is most
  likely to be committed as a complete file, because the client sees a clean 0
  either way. `test_server_leg_faults.py` (12 tests) covers both;
  `test_sss_leg_sweep.py` (7) adds the last login mechanism with no fault
  coverage. The origin leg is then driven a second time through `s3://` rather
  than `http://` — sd_s3 and sd_http share no fetch code, and they do not behave
  the same. `test_server_leg_faults.py` is 18 tests; directory total: 90 passed,
  3 skipped.

  The measurements are worth stating, because two of them contradict what the
  tests were first written to assert:

  - **A severed upstream fetch is refused; a corrupted one is not.** Truncation
    is visible to the front, which fails the read (rc 54, nothing delivered). A
    length-preserving bit flip is visible to nothing, so it is relayed to the
    client as a full-length file under rc 0. The same holds for the TPC pull leg
    with `brix_tpc_verify_checksum` off — the documented stock-parity default,
    now also pinned on the raw-transport path.
  - **`--pgrw` cannot protect the origin leg**, by construction: the per-page
    CRC32c is computed by the *front*, over bytes it has already read from the
    origin. An upstream flip is faithfully CRC'd and delivered. `--verify`, an
    end-to-end checksum, does catch it — and is the only client option that
    does. `--cksum <alg>` with no `:source` suffix merely prints a digest
    (`copy_cksum_verify.c`), which is documented but reads like a check, so it
    is now pinned as a security-negative test.
  - **`--verify` is fail-open when the checksum *query* fails — and the query
    crosses the same damaged leg.** Over 20 corrupted fetches from an `s3://`
    origin, 19 were refused on a checksum mismatch; on the twentieth the
    server's re-read died, and the client printed `checksum computation failed`
    and **exited 0, keeping the corrupted file**. That is deliberate policy
    (`download_reconcile_cksum`: an unverifiable query is a hiccup, not a
    transfer failure) and defensible in isolation, but the two events are
    correlated rather than independent — the damage `--verify` exists to catch
    is the damage that disables it. The `http://` leg refused 20/20 only because
    sd_http fetches in one GET where sd_s3 issues many ranged ones, giving far
    more response headers for a flip to land in; the policy is the same on both.
    A strict mode for `--verify` is the obvious follow-up and is not implemented.
  - On the client leg the contrast is sharper still: over cleartext `root://` a
    plain read delivers corruption silently, while `--pgrw` and `--verify` each
    refuse it. Three tests in `test_tls_token_leg_sweep.py` pin that trio.

  **Known issue, deliberately not asserted:** `xrdcp --pgrw` against a
  *corrupted* `http://` origin leg stalls for ~180 s (3x the 60 s per-request
  timeout) before failing with a misleading `FileNotOpen`, after which the same
  object returns `NotFound` instantly even though the origin is unreachable
  rather than empty. Both want a fix in the `sd_http` retry/health path; a test
  that waits out a 180 s stall would hang CI, and pinning the second would pin a
  bug as a contract. Reproducer in the module docstring. The `s3://` leg narrows
  the diagnosis: the identical fault through sd_s3 returns in 0.1 s, so the
  stall is not a property of pgread, of remote backends, or of corruption in
  general — and that 0.1 s path is what finally makes "`--pgrw` cannot protect
  the origin leg" an assertion rather than a claim in a comment.

- **The manager's namespace inventory now covers WebDAV, S3 and gridftp writes,
  not just `root://`.** A data server reports its namespace mutations up the CMS
  link so the manager can answer `kXR_stat` from its Composite Cluster Name Space
  inventory instead of redirecting — but only the `root://` plane ever reported.
  A site that also accepted writes over WebDAV, S3 or gridftp — which is most of
  them — therefore built a manager inventory that silently tracked a fraction of
  its own namespace. Every plane now reports: WebDAV PUT/DELETE/MKCOL/MOVE/COPY,
  S3 PutObject/POST-upload/CompleteMultipartUpload/CopyObject/DeleteObject(s),
  and gridftp STOR/DELE/MKD/RMD/RNFR+RNTO, all against the same logical paths the
  `root://` plane uses, so one object has one entry however it was written.

  There is **nothing new to configure**: a node that already declares
  `brix_cns emit` on its `stream{}` server picks this up. The emitting server
  block is resolved from the cycle at emit time rather than cached, so no new
  directive and no new global were needed. Where several managers are configured,
  a mutation goes to **all** of them rather than being round-robined like a
  locate — each manager keeps its own inventory, so rotating mutations would have
  left every manager but one permanently missing the object.

  Every report is made on the success path (a refused mutation can neither seed a
  phantom entry nor evict a live one) and on the event loop; the offloaded paths
  — threaded PUT, collection MOVE, collection COPY, the durable-queue DELETE
  waker, multipart assembly — report from their event-loop completions, never
  from the pool thread that did the work. Covered per plane, success + error +
  traversal-negative, in `tests/test_cns_http.py`, which publishes one export
  over all four planes at once and asserts they converge on one inventory.

  Known limit, unchanged from before: the CMS link is worker-0 only, so a
  mutation handled by another worker still reports nothing. The manager falls
  through to locate for anything it does not hold, so this bounds inventory
  coverage rather than correctness.

- **A node now reports whether it is still in the federation.**
  `brix_cms_registered_links` is a gauge of upward CMS links currently logged in
  — `0` means this site has fallen out of the cluster and its redirector has
  stopped sending it clients, which previously could only be established from
  the manager. Alongside it, `brix_cms_logins_total` counts joins (rising while
  the gauge stays at zero means the link is flapping, not down) and
  `brix_cms_connect_failures_total` counts dials torn down before LOGIN ever
  went out. The counters are decremented and incremented from the single link
  teardown path, because a refused dial does not necessarily surface at
  `connect()`: on loopback, and wherever the peer resets rather than drops, it
  arrives on the read side as `recv()` returning `ECONNREFUSED`.

- **The federation join is now tested across a link that is being abused.**
  Every existing CMS test spoke to its peer over a clean loopback socket, but a
  real AAA site reaches its redirector over a WAN. `tests/test_cms_aaa_join_noise.py`
  puts a `brix-fault-proxy` in between and drives 13 cases — joining through
  latency and jitter, reassembling a LOGIN that was segmented and reordered,
  losing the redirector to silence, refusal, accept-then-close and a mid-stream
  sever, rejoining when the link heals, and surviving a corrupting, oversized-
  framing, storming redirector — while a 200-connection storm and 150 abort
  cycles run against the data plane. Every case asserts the node keeps serving
  data and no worker dies: a broken federation leg must never take a site's
  storage offline. The suite needs no privileges, no `netem` and no network.

- **A BriX cluster manager is now tested against a stock one, side by side.**
  The suite already proved a BriX data node registers with a real `cmsd` manager
  and vice versa, but nothing asked whether the two *managers* give a client the
  same answers for the same namespace — the last open cross-implementation item
  in the coverage audit. `tests/test_cms_cross_impl_parity.py` seeds identical
  content into two meshes that differ in exactly one variable, who runs the
  manager, and asserts locate, `stat` size, byte-exact read, directory listing,
  an absent path and a traversal attempt all agree. A divergence is a failure,
  not a skip.

- **`xrdcp` speaks GridFTP: `gsiftp://` and `ftp://` sources and destinations.**
  The native client could reach `root://`, WebDAV/HTTP and S3 endpoints but not
  the GridFTP servers that still front a large share of WLCG storage, so any
  transfer against one needed the Globus toolkit alongside it. The new
  clean-room engine under `client/lib/protocols/ftp/` runs the RFC 959 control
  dialogue, RFC 2228 `AUTH GSSAPI`/`ADAT` security (TLS-in-base64 tokens with an
  RFC 3820 proxy and the mandatory delegation round), transparent protected
  command wrapping, and an `EPSV`-then-`PASV` passive data channel; the copy
  driver (`client/lib/xfer/copy_gsiftp.c`) moves bytes through the same VFS
  staged-commit path as every other scheme, so a failed transfer never leaves a
  partial destination. Two rules are enforced client-side rather than trusted to
  the server: a `gsiftp://` endpoint is **never** downgraded to an anonymous
  login when the proxy is missing or unusable (the copy fails instead), and the
  passive reply is screened before the client dials it — a privileged data port
  is always refused, and an address that is not the control peer is refused
  unless `BRIX_GSIFTP_ALLOW_OFFPEER=1`, which keeps a hostile server from using
  the client as an FTP-bounce relay. Third-party (`gsiftp://`→`gsiftp://`) and
  recursive GridFTP copies are refused up front as usage errors; the server's
  TPC surface owns those. This also puts the Phase-91 reply/MLSx parser kernels
  (`src/fs/backend/gsiftp/gftp_reply.c`, `gftp_mlsx.c`) into a real consumer for
  the first time — they were built and unit-tested but unwired.
- **An ordinary test run now compares against stock XRootD.** Cross-implementation
  parity was reachable but never reached: `TEST_CROSS_BACKEND` is a process-wide
  switch that six modules bind at import time, so covering both sides needed two
  `pytest` invocations, and nothing in `tests/`, `Makefile` or `.github/` ever
  set it — a default run only ever drove the nginx side. Both servers were up the
  whole time (`main` and `ref-anon` are always-on fleet members exporting the
  same data root), so `tests/test_cross_backend_parity.py` resolves the backend
  per *test* instead and compares them in one process: same seeded file, both
  servers, byte-exact read plus identical `stat` size, an absent path erroring
  rather than answering an empty body, and a traversal escaping neither export.
  An implementation difference is now a failure, not an absence.
- **Dead test config templates can no longer accumulate.** 49 files under
  `tests/configs/` are named by nothing in the repo — several of them
  pre-lifecycle duplicates whose live `nginx_lc_*` twin sits beside them
  (`nginx_native_sss.conf` and `nginx_pwd_auth.conf` are dead; their `_lc_`
  twins are used). A dead template is worse than a missing one: it reads as
  coverage that exists, so the next author copies it. `tools/ci/check_template_refs.py`
  freezes that set and fails on any new one, and equally on a frozen entry that
  has since been wired up or deleted, so the count can only fall. `--regen` is
  shrink-only — it refuses and exits 1 rather than blessing a new entry. The
  existing 49 are ratcheted, not deleted: a template can be named at runtime by
  an f-string, which no static scan sees, so the backlog is an allowlist rather
  than a delete-list.
- **The upstream proxy's redirect and error forwarding is now checked byte for
  byte.** `tests/upstream_protocol_stubs.py` gained the two handlers it never
  had — a plain `kXR_redirect` on 13120 and a fixed `kXR_error` on 13123 — so
  the `stub-upstream-redirect` and `stub-upstream-error` fleet fronts, declared
  since the migration, finally have a backend. The real-backend tests beside
  them can only assert the response *kind*, because a live xrootd picks its own
  redirect target and its own error code; the stub emits bytes this repo chose,
  so the new tests assert the redirect host and port and the error code and
  message all survive the proxy unaltered. Two security negatives come with
  them: a forwarded redirect must never point at the front or at the private
  backend (redirect loop, topology disclosure), and forwarded error text must
  never have the upstream endpoint appended to it.
- **The test suite has a combinatorial parametrization layer.** Coverage used to
  grow linearly with author effort: 299 hand-written `NginxInstanceSpec(...)`
  literals across 212 modules, one module and one config template per
  (protocol × auth × tls × backend) cell, and zero `pytest_generate_tests` /
  `indirect=True` anywhere — so a new backend or auth mechanism was tested
  against whatever someone remembered to write, and the matrix re-sparsified with
  every addition. A test now carries `@pytest.mark.matrix(protocols=[...],
  auths=[...], tls=[...], backends=[...])` and takes the `matrix_node` fixture;
  `tests/matrix_layer.py` renders the cell into one of two generic templates,
  stands it up through the registry lifecycle harness, and hides the
  per-protocol client behind `seed()` / `read()`, so one test body runs against
  every cell. `tests/test_matrix_layer.py` is the demonstrator and the
  regression test: four bodies, 28 reachable cells, 63 passing cases in 15 s.
  Unreachable combinations are parametrized too and skip with the product reason
  that makes them impossible (S3 authenticates with SigV4, never a bearer; XrdCl
  refuses to put a token on a cleartext wire; WebDAV GSI means a client
  certificate, which means TLS), because "this cell is empty" and "this cell
  cannot exist" had been indistinguishable from outside.

- **The fault sweeps now cover TLS, tokens and the download direction.**
  `tests/resilience/` was root:// + GSI + cleartext only, so two claims the
  server makes had never been tested: that TLS turns an in-flight bit flip into
  a hard failure, and that a login damaged mid-handshake fails closed instead of
  leaving a session that reads data. `test_tls_token_leg_sweep.py` (10 tests, new
  `NginxTlsAnon` / `NginxTokenRoot` harness classes and their configs) measures
  both legs under truncation and corruption, and pins that a sever **mid
  transfer** is transparently recovered byte-exact — on the token leg that means
  the ztn login is re-run on the reconnect. `test_download_loss_sweep.py` (14
  tests) adds the missing download direction on the WebDAV and S3 planes, where
  HTTP fault coverage had been upload-corruption only: loss and truncation are
  always surfaced as a client-side failure, never a silent short 200, and a
  truncation point armed past a Range request leaves that request alone. The two
  modules together document the contrast — the same length-preserving flip that
  TLS refuses outright is delivered with a clean 200 in cleartext, and on the S3
  plane nothing downstream can detect it, because the ETag is nginx's weak
  mtime+size tag rather than the object MD5 an AWS client would verify against
  (recorded as a known exposure and pinned by test, not changed here: making the
  ETag a digest alters an externally-visible identifier).
  `test_sweep_runners.py` (16 tests) finally collects the four standalone
  `run_*.py` sweeps, which nothing had imported since they were written — one of
  them, `run_http_reorder.py`, had been dead for as long as the registry has
  enforced fixed ports, aborting at startup because its lifecycle spec was never
  added to `fleet_lifecycle_ports.py`. `run_mount_sweep.py` is import- and
  argument-checked but deliberately not executed; a wedged FUSE mount takes the
  fleet with it.

- **The two write cells that were configured for writing and only ever read are
  now driven.** An S3 REST front over a native `root://` origin had its bucket
  addressed with `requests.get` alone, despite its token carrying
  `storage.modify:/`, so the `sd_xroot` create-open / write / close / unlink
  slots reached from the S3 handler had never run; the gsiftp gateway over the
  same origin set `brix_gridftp_allow_write on` and only ever issued RETR. New
  `tests/test_s3_xroot_mutations.py` (15 tests, `configs/nginx_lc_s3_xroot.conf`)
  drives PUT / HEAD / ListObjects / DELETE — including a 3 MiB multi-chunk body,
  a truncating overwrite, and a listing that follows both the write and the
  delete — while `tests/test_gridftp_delegate_xrootd.py` grows from 3 to 8 with a
  300 KiB delegated STOR. Both suites read their verdict off the **upstream**
  export rather than reading back through the front, and both give the front its
  own empty export so that "the bytes left the front" is a filesystem fact; the
  gridftp case additionally asserts a fresh upstream login, proving the write leg
  re-delegates. Four traversal spellings (`../`, `a/../../`, `%2e%2e%2f`,
  `..%2F`) are refused with nothing written above or inside either export, sent
  raw over `http.client` because `requests` collapses `..` client-side. Both
  cells behaved correctly once driven — what was missing was the driving.

- **Cache passthrough is now tested on every plane that has it, and pinned off
  on the one that does not.** `brix_cache_passthrough` (store-then-evict: serve
  an object the admission policy declined, under a separate spool cap, then drop
  the key) was covered on WebDAV GET only. The `allow_pt = 1` opt-in is set in
  exactly one place — the shared HTTP cache-fill worker — which WebDAV, S3 *and*
  cvmfs all route through, so all three inherit it; the comment in
  `sd_cache_fill.c` claimed cvmfs never opts in, which had been untrue since the
  cvmfs handler moved onto the shared worker. `tests/test_cache_passthrough_planes.py`
  (21 cases, new `lc-cache-passthrough` instance) runs an S3 and a cvmfs plane
  with passthrough on, a byte-identical control with it off, and the `root://`
  stream plane with the directive configured but `allow_pt = 0`. Three objects
  sized against the two caps give the whole contract: under the caching cap →
  cached; between the caps → served but *not* retained on the ON planes and 502
  on the OFF controls; over the spool cap → 502 even with passthrough on. The
  stream plane's row is the negative — it serves the over-the-spool-cap object
  that every gated plane refuses, which is what proves it never entered the
  gate, and its store still holds only what admission accepted.

- **INVARIANT 2 is now a behavioural test, not a source grep.** The rule that
  the cleartext file-backed/sendfile response and the memory-backed one must
  never be mixed was asserted only by grepping the sources for `b->in_file = 1`
  and `send_fd = dup(fd)` — which pins the shape of the code, not the bytes on
  the wire. `tests/test_tls_sendfile_matrix.py` (66 cases, new `lc-tls-sendfile`
  instance) drives both branches over both transports: pblock is the vehicle
  because one backend takes both, lending its block-0 fd only for a range that
  starts at offset 0 and fits in one block and declining anything that spans
  blocks, with a posix export of identical bytes as the always-sendfile control.
  Covers whole-object GET, HEAD, six range windows chosen to land on named
  branches, suffix and open-ended ranges, 416, EOF clamping (which sendfile gets
  for free and the memory-backed path must do deliberately), and traversal.

- **CVMFS Stratum-0 publishing (phase-96)**: BriX can now *author* CVMFS
  repositories, not just cache them — a deliberate, documented reversal of the
  phase-85/87 "the proxy stays a cache" non-goal
  ([docs/refactor/phase-96-cvmfs-stratum0-publishing.md](docs/refactor/phase-96-cvmfs-stratum0-publishing.md)).
  Publishing lives entirely on the **tool surface** (`brixcvmfs repo
  mkfs|info|resign|transaction|abort|publish|fsck|gc|tag`): shared writers for
  signed manifests/whitelists (the official client's two distinct RSA
  conventions), SQLite catalogs (including the undocumented official-client
  conventions an oracle lane pins), CAS objects with chunking and
  `.cvmfsdirtab` nested-catalog splits, plus `.cvmfsreflog`, ref-driven GC and
  a tag/history database with rollback. Published repos mount in the
  **official cvmfs client** (oracle-verified) and in brixMount.
  On the serve side, `brix_cvmfs_stratum0_root <dir>` turns a location into
  the master copy: a strict `brix_export` alias that EMERGs at `nginx -t` when
  combined with any cache-fill grammar, answers the `.cvmfs_master_replica`
  probe (synthesized, directive-gated — a cache node cannot advertise itself
  as a replication source), and feeds stock Stratum-1 `add-replica` over plain
  HTTP GET. Gating the repo behind scvmfs (bearer/x509/VOMS) is proven pure
  configuration — the credential wall covers manifest, CAS, GeoAPI and the
  marker, with no anonymous manifest leak
  (`tests/test_cvmfs_stratum0_serve.py`,
  `tests/test_cvmfs_stratum0_scvmfs.py`; cookbook in
  [docs/05-operations/cvmfs-stratum0.md](docs/05-operations/cvmfs-stratum0.md),
  serve contract in
  [docs/04-protocols/cvmfs.md](docs/04-protocols/cvmfs.md) §3.6). The
  remote-ingest gateway (S15) stays deferred.

- **The Stratum-0 release-manager surface is now something you can install and
  read about.** `brixcvmfs` ships as an `argv[0]` personality of `brixMount`
  (a symlink, not a second binary): it self-IDs, prints its own usage, and
  dispatches `repo …` without a type keyword, while no other program name gains
  that surface. It has a man page (`client/man/brixcvmfs.1`), and
  [docs/05-operations/cvmfs-stratum0.md](docs/05-operations/cvmfs-stratum0.md)
  is the unprivileged end-to-end cookbook — keys and where to keep them,
  publishing custom files (modes, symlinks, whiteout deletes, chunking with CAS
  dedup, `.cvmfsdirtab` nesting), the serve block with its four `nginx -t`
  refusals, both client mount paths, private repos, the maintenance cron, the
  three-party integrity model and a troubleshooting table.
  `tests/test_cvmfs_stratum0_quickstart.py` (14 tests) drives the *shipped*
  binary through that exact sequence, so a drift between what is documented and
  what is installed fails a lane rather than a deployment.

- **`brixcvmfs repo fsck --data`**: the payload rot sweep. `fsck` verified
  catalogs and counters but never the bytes they point at, so a flipped or
  deleted CAS object stayed invisible to the publisher until a client hit it
  (and got `EIO`). `--data` additionally checks the certificate and every
  referenced whole-file object and file chunk for presence and CAS identity,
  reporting `object <hash> of <path> fails CAS verification` / `… missing`. It
  verifies the stored form without inflating, and stays opt-in because it is
  linear in repository size: plain `fsck` after every publish, `--data` from
  cron.

- **Documentation for `brix_webdav_upload_resume` and `brix_webdav_stage_dir`**
  in [docs/04-protocols/webdav-directives.md](docs/04-protocols/webdav-directives.md):
  the resumable `Content-Range` PUT contract (200 + `X-Upload-Offset` per chunk,
  201 on the last, append-only 409 with the honest offset) and what happens when
  the stage dir lands on a different filesystem than the export — the commit
  copies to a temp beside the destination and renames that into place, with a
  durable pending-commit marker so an interrupted move is finished by the reaper.
  Both directives shipped without an entry. Behaviour is now covered by
  `tests/test_stage_cross_device_commit.py`, which stages on tmpfs so the
  cross-device path is genuinely taken.

- **Per-driver staged-commit contract units**: `tests/c/test_staged_contract_tiers.c`
  drives `sd_stage` and `sd_frm` under ASan (commit success, commit failure
  followed by the mandatory abort, a security-negative proving a failed inner
  commit never publishes, and the async submit path), and
  `tests/c/test_staged_contract_origin.c` pins the already-conformant
  `sd_http`, `sd_xroot` and `sd_cache` forwarders — including a 403 mapping to
  `EACCES` and an abort that does not re-PUT. Both link the real driver objects,
  so the pre-fix sources fail them.
  The C-unit harness also learned to link against the coverage-instrumented
  build tree and to keep its own `.gcda` out of that tree; with a handful of
  stale object lists repaired, `test_c_regression_units.py` is green end to end.

- **`brix_cache_store_endpoint` on the `root://` plane** (default `off`): marks a
  stream server as the trusted remote cache-STORE surface, where the internal
  sidecar names a cache node writes beside its objects (`<key>.cinfo`,
  `<key>.meta`) are legitimate `kXR_open`/`kXR_stat`/`kXR_statx` targets. The
  WebDAV and S3 planes have carried the directive since the cache-store work;
  the root plane is now symmetric, which is what makes `brix_cache_store
  root://…` usable with `brix_cache_meta sidecar`. Directory listings still skip
  internal names and every client-facing export keeps answering `kXR_NotFound`,
  so the default remains deny. This also un-wedged the live
  `xroot-cachestore-serve` scenario, whose warm hit had been answering 404: its
  `root://` store was an ordinary export, so the node's cinfo store failed and
  every read refilled from a source the scenario had just hidden.

- **Namespace mutations are now compared across backends, not just exercised**
  (`tests/test_ns_mutation_gateways.py`, 37 tests,
  `tests/configs/nginx_lc_ns_gateways.conf`): mkdir, rmdir, rm, mv, `mkdir -p`,
  dirlist and xattr run three ways inside ONE nginx — a POSIX **control** plane
  and the `http://` and `root://` origin-gateway planes — and every case asserts
  the three answers agree. A driver that answers a mutation wrongly still answers
  it consistently, so no single-plane test could see the six defects this found
  (listed under Fixed above); the control plane is what makes "wrong" definable.
  Alongside the agreement cases it pins the stock semantics the control encodes:
  `rm` removes an EMPTY directory, a POPULATED one is never removed
  non-recursively by either spelling, `mkdir -p` over a regular file is
  `kXR_ItExists` with the bytes intact, and a traversal key mutates nothing on
  either gateway.

- **Paged I/O and vector reads are now tested off posix**
  (`tests/test_pgio_nonposix.py`, 20 tests, `tests/configs/nginx_block_dev.conf`):
  every pgread/pgwrite/readv suite bound to a `posix:` export, so the two other
  drivers carrying their own `.preadv`/`.preadv2` slots had never seen a paged
  or vectored request even though both server engines route through the driver
  seam. A `pblock://` export now proves the page split, bytes and per-page
  CRC32c across a 1 MiB block boundary (where the driver stitches two stored
  blocks into one logical page), the pgwrite round-trip at an unaligned
  boundary-crossing offset, corrupt-page detection, and that a read-only handle
  cannot become a write channel; a `block:<device>` export proves the
  fixed-extent window reports *extent-relative* page offsets, refuses a readv or
  pgwrite that runs past the extent end (a fixed extent cannot grow), never
  scribbles outside the written range, and exposes only the extent indices — an
  out-of-range index, a non-numeric name and a path escape all fail to open. The
  device is a regular file, so the plane needs no loop device and no privilege.

- **The five orphaned live scenarios now run in CI**
  (`tests/test_cmd_{http_store_writable,tier_matrix_drivers,cvmfs_verify,remote_backend,tier_remote}.py`,
  19 tests): the sd_http write path, the stage-store driver matrix
  (posix/pblock/xroot/rados), the CVMFS fill-verification plane including the
  documented `verify off` gap, the remote pass-through backend (serve offload,
  metadata forwarding, stream + staged writes, stage-journal reconcile) and the
  remote cache tier (stage, evict/refill, xattr + sidecar metadata, sparse slice
  fills). The scripts existed but nothing collected them.

- **Native `root://` TPC × WLCG token auth** (`tests/test_tpc_token_auth.py`, 9
  tests, `tests/configs/nginx_tpc_token.conf`): the token column of the TPC
  matrix was empty — no config anywhere used `brix_auth token` with a
  third-party copy, so the destination's outbound `ztn` credential paths had
  never run. One nginx now serves a read-only token-authenticated source plus
  three destinations differing only in how the pull leg is credentialed
  (inbound-token passthrough, static `brix_tpc_outbound_bearer_file`, and no
  credential at all), and the source's access log is asserted to name the
  *client's* subject for a passthrough pull and the *gateway's* for a
  bearer-file pull — proving which credential crossed the leg, not merely that
  bytes arrived.

- **Prometheus conformance suite** (`tests/test_cachemx_*.py`, 2070 tests in
  24 files): exposition-format conformance plus exact per-request query-count
  and byte accounting for every protocol/auth plane — root:// (anon/GSI/token/
  SSS), WebDAV (plain, TLS+token, TLS+cert), S3 (anonymous, SigV4 incl. all
  failure modes), cache trim/eviction, and cmsd redirection — plus a full
  196-family catalogue type pin with per-family HELP-text and label-key schema
  snapshots (incl. a strict label-residue format check), the MOVE/rename error
  ladder, namespace-method and Range edges (re-proven per authenticated
  plane), per-flow byte-accuracy ladders from 1 B to the 1 MiB chunked regime,
  repetition linearity, multi-op lifecycle/cross-dialect sequences,
  auth-result edge rows, hashed user-session identity pins, and cross-plane
  ledger-isolation/conservation pins. A per-family grid layer parametrizes
  structural conformance across the full catalogue against live two-scrape
  windows (exposition ordering, duplicate-series rejection, finite sample
  values, counter monotonicity, per-key label-value grammars, histogram
  bucket/`+Inf`/`_sum` invariants), and three credential-route grids add
  byte-exact GET/PUT accounting per auth route and size, per-plane wire
  ok/error splits (incl. pins for the stock-parity idempotent
  mkdir-over-existing and rmdir-of-absent arms), and N-op linearity per
  credential route. Documented accounting
  ownership invariants in
  [docs/08-metrics-monitoring/metrics-overview.md](docs/08-metrics-monitoring/metrics-overview.md)
  and new bug patterns (6–12) in
  [docs/08-metrics-monitoring/metrics-bug-patterns.md](docs/08-metrics-monitoring/metrics-bug-patterns.md).

- **The CMS 4-tier topology suite runs through the server registry**
  (`tests/test_cms_tier_topology.py`): it was the last pytest module embedding a
  runnable nginx config heredoc and launching the binary itself — with its own
  feature-probe launch, its own ephemeral-port grabber and its own teardown. The
  six-node tree is now a committed template (`tests/configs/nginx_cms_tier.conf`)
  driven by `LifecycleHarness` on the fixed `lc-cms-tier` port block, which
  empties the registry lint's inline-config backlog and removes the last
  migratable direct launcher. The two remaining direct launchers are
  standalone labs the registry cannot own (an in-namespace-root privilege
  battery, an operator-invoked perf harness); `_perf_netem_helpers.py` — whose
  nginx lives inside an `unshare -n` network namespace, unreachable from the
  host the registry probes — joins them as a documented entry rather than a
  silent guard failure.

---

## v1.4.0 — 2026-08-03

Storage, auth and cache feature wave, a diagnostic advisor, and a repository
hygiene pass that closed several guards which had stopped enforcing anything.

### Added

- **Client io_uring `O_DIRECT` tier** (`--io-uring-direct`): aligned slab
  allocation with a buffered short-tail fallback for the unaligned remainder.
- **HTTP cache-fill remote passthrough** (`brix_cache_passthrough`,
  `brix_cache_passthrough_max`): store-then-evict for objects that should not
  occupy the cache permanently. HTTP plane only — the `root://` stream plane
  does not passthrough.
- **CVMFS proxy authorization** (`brix_scvmfs_authz x509|voms`): end-entity DN
  authorization with an allow-glob (`brix_scvmfs_x509_dn`), plus a VOMS mode
  (`brix_scvmfs_voms`, `brix_scvmfs_vomsdir`, `brix_scvmfs_voms_cert_dir`).
- **`block:<device>` server plane**: exports a block device as a fixed-extent
  namespace `/0`…`/N-1`.
- **Full S3 namespace mutation** for the remote storage driver, via `path/`
  marker objects, with capability parity for directory writes.
- **WebDAV origin mutation** for the HTTP storage driver: `MKCOL` (`.mkdir`)
  and `MOVE` (`.rename`), advertising `CAP_DIRS_WRITE | CAP_HARD_RENAME`.
- **GridFTP VO ACL gate** (`brix_gridftp_require_vo`): fail-closed VO check on
  every verb at path resolution.
- **Bandwidth reservation** wired into `root://` read-open
  (`brix_throttle_bandwidth_zone`, `brix_throttle_bandwidth_budget`).
- **`xrddiag` remote advisor**: `--config-audit` scrapes `Qconfig`/`Qspace` and
  applies value rules; `--all-servers` fans out across the fleet and diffs;
  `--cap-threshold` tunes the capacity findings.
- **`xrddiag` mesh map**: `--map` with `--map-format ascii|dot|mermaid`,
  classifying nodes from the CMS plane (`kXR_locate`) so redirectors, data
  servers and read-only holders are distinguished — including endpoints that
  cannot be connected to directly.
- **`xrddiag` latency**: `--latency` / `--latency-count` measure bi-directional
  RTT over both the xrootd (`kXR_stat`) and CMS (`kXR_locate`) planes.

### Changed

- **brix-fault-proxy** unified onto the upstream v1.3.0 core and decomposed
  from a 2814-line monolith into seven translation units behind a shared state
  header; below-TCP and MITM fault levers retained.
- **Python dependencies** split into required / optional / dev / cluster-lab
  files, each entry bounded on both sides. `requirements.txt` previously named
  three packages against a suite that imports fifteen.
- **Repository governance**: added `SECURITY.md`, `CODEOWNERS`, Dependabot
  configuration, and issue/PR templates.

### Fixed

- **`urlencode` NUL passthrough** in the percent-codec (a `strchr(set, 0)`
  footgun) — found by a 2946-case non-UTF-8 byte-input suite over the real
  codec, opaque-validation and reserved-name kernels.
- **41 orphaned client sources** were never built: `make -C client` was red on
  `main`. Now wired into `client/Makefile` and enforced by a new guard.
- **The pre-push hook enforced no guards at all** — it globbed for shell
  guards long after the fleet became Python, so it both skipped every check and
  blocked every push on the unmatched pattern.
- **`check_gridftp_interop_image.py`** was committed without its executable
  bit, so CI could not run it.
- **A VFS seam bypass** in the io_uring `O_DIRECT` unaligned tail, and 13 files
  over the 600-line cap, both of which had reddened the tree's own guards.
- An optional test dependency (`zstandard`) was imported at module scope,
  making it mandatory for anyone collecting the test suite.

### Security

- New coordinated disclosure policy in
  [`SECURITY.md`](SECURITY.md): private reporting routes, response targets, and
  an explicit scope.
- Dependency bounds are now two-sided, so a new major of a crypto or HTTP
  dependency cannot enter CI unreviewed.

---

## v1.3.0 — 2026-07-24

### Added

- **CMS auto-role clustering**: a node derives its cluster role (manager /
  sub-manager / leaf) from its configuration and can act as a sub-manager of a
  stock upstream `cmsd` rather than only ever being a leaf. Includes
  control-plane action logging and a four-tier topology test.
- **brix-fault-proxy below-TCP and MITM fault levers.**

### Fixed

- **Per-worker SID collision** that made a stock `cmsd` reject workers 2..N as
  "already logged in" (with a 30s blacklist), so only `worker_processes 1`
  registered cleanly.

---

## v1.1.1 — 2026-07-07

Packaging-focused release; shipped as RPM revisions `-1` through `-25`.

### Added

- **Source-derived versioning**: the RPM version is `sed`ed out of
  `src/core/ident.h` by the build scripts, making the header the single source
  of truth.
- **SELinux support** for enforcing hosts: a targeted-policy subpackage
  (`brix_port_t` on 1094/1095/9001/9100, data-plane labels, impersonation-broker
  rules), plus a verification suite (`tests/test_selinux_rpm.py`).
- **CVMFS packaging**: `brix-cvmfs-automount` (native `brixMount autofs`
  umbrella, `/sbin/mount.cvmfs`, autofs program map) and `brix-cvmfs-config`
  (vendored upstream domain configs and master keys).
- **Co-installable compat subpackages** (`brix-cache-client-compat`,
  `brix-tools-compat`): the same binaries under a `brix-` prefix so a host can
  carry both stock `xrootd-client` and the BriX tools. One name-agnostic
  compile serves both — every tool derives its identity from `argv[0]`.
- **Standalone FUSE subpackages** (`brix-xrootdfs-fuse`, `brix-cvmfs-fuse`) so
  a mount tier can deploy without the full CLI suite.

### Changed

- `io_uring`, `zstd` and `lz4` default ON; Ceph became a stated contract.
- `packaging/` rebranded `nginx-xrootd` → `brix-cache` for everything that is
  not an upgrade-path compatibility name.
- Client binaries colliding with stock XRootD packages renamed
  (`mpxstats` → `mpxstats-brix`, `wait41` → `wait41-brix`, …).

### Fixed

- **CVMFS whitelist/manifest body-binding**: the signed hash line covers the
  body up to but *excluding* the `--\n` separator (verified against live
  stratum-1 artifacts). The verifier previously included it and rejected every
  genuine repository with trust/catalog error -5.
- Container builds.

---

## v1.0.8 — 2026-07-03 — BriX namespace rebrand

Renamed the project's own code namespace to BriX; upstream XRootD / `root://`
protocol references are preserved throughout.

- **Code:** server `xrootd_`→`brix_`, `XROOTD_`→`BRIX_`, `ngx_xrootd*`→`ngx_brix*`
  (incl. `ngx_xrootd_{module,fattr}.h`→`ngx_brix_*`); client `xrdc_`→`brix_`.
- **Breaking:** nginx config directives (`xrootd_*`→`brix_*`), Prometheus metric
  names (`xrootd_*`→`brix_*`), dashboard routes (`/xrootd`→`/brix`), env vars
  (`XROOTD_*`→`BRIX_*`), access-log filenames (`xrootd_access*.log`→
  `brix_access*.log`), and operator log-line prefixes (`xrootd:`→`brix:`).
- **Client:** `libxrdc.{a,so,pc}`→`libbrix.*` (SONAME `libbrix.so.0`),
  `libxrdposix_preload.so`→`libbrixposix_preload.so`, pkg-config `-lbrix`.
- **Preserved:** upstream XRootD/`root://` protocol refs (`kXR_*`, `XrdCl`,
  `XrdHttp`), tool binaries (`xrdcp`/`xrdfs`/`xrdcinfo`/`xrdckverify`/`xrdcrc32c`/
  `xrdcrc64`/`xrootdfs`), the nginx module identity `nginx-xrootd`, and the
  on-disk cache sentinels (`.ngx-xrootd-*`).
- Operator migration map: [docs/refactor/brix-rename-migration.md](docs/refactor/brix-rename-migration.md).

See the plan and rationale in
[docs/refactor/2026-07-03-brix-symbol-rebrand.md](docs/refactor/2026-07-03-brix-symbol-rebrand.md).

---

## v1.0.7 — 2026-07-03

Rebrand to BriX-Cache; CVMFS proxy resilience to upstream flakiness, plus
traffic visibility for it.

## v1.0.5 — 2026-07-02

Phase-67 source layout, gnuBall identity, `writev`/`ckpXeq` stock framing, and
an audit-hardening sweep.

> The 1.0.x line existed in the source only. Packaging went straight from
> `0.1.0-9` to `1.1.1-1`, so no RPM was ever labelled 1.0.x.

---

## v0.1.0 — 2026-04-21 → 2026-06-15

The pre-1.0 line, shipped as nine RPM revisions (`0.1.0-1` … `0.1.0-9`) under
the original `nginx-xrootd` package name. Per-revision detail is in the spec's
`%changelog`; the arc was:

- `-1` initial nginx dynamic module package;
- `-2` SRR, XrdHttp filter and dashboard modules;
- `-3` the native client tools (`xrdcp`/`xrdfs`/… plus the `xrootdfs` FUSE
  driver and the `LD_PRELOAD` shim) and the pytest suite, both as subpackages;
  RPM optflags threaded through the client build (PIE/RELRO/BIND_NOW);
- `-4` … `-9` module load ordering, external library linkage, and packaging
  fixes.
