# s3 — S3-compatible REST endpoint over the local export root

## Overview

This subsystem implements the subset of the AWS S3 REST API that `XrdClS3` (the
XRootD S3 client plugin), the `aws s3` CLI, and browser POST forms actually use,
projecting the **same on-disk export root** that `root://` and `davs://` already
serve. It is a self-contained nginx HTTP module (`ngx_http_brix_s3_module`,
`module.c`): a location with `brix_s3 on;` installs `ngx_http_s3_handler`
(`handler.c`) as its content handler, and every S3 request — GetObject,
HeadObject, PutObject, DeleteObject, ListObjectsV2, the full multipart-upload
lifecycle, CopyObject, UploadPartCopy, DeleteObjects, browser POST Object, and
CORS preflight — flows through that one entry point. Objects carry **user
metadata** (`x-amz-meta-*`, `usermeta.c`) and **tags** (`tagging.c`) round-tripped
through xattrs beside the data.

S3 is a **distinct auth domain** from the rest of the gateway: it authenticates
with AWS Signature Version 4 (HMAC-SHA256), in both header and presigned-URL
form, and never with WLCG tokens or GSI — the SigV4 code shares no logic with
`../token/` or `../gsi/`. When no access key is configured the endpoint is
anonymous (read-only public buckets). The handler is fail-closed on writes:
`cf->common.allow_write` is checked *before* any request body is read, so a write
to a read-only endpoint is rejected without consuming client bandwidth.

In the request lifecycle this subsystem sits entirely inside nginx's HTTP
content phase, parallel to `../webdav/`. It owns URI parsing, SigV4 verification,
and method dispatch, then delegates the heavy lifting downward: path confinement
to `../path/` (via `../compat/`), object reads to the cache-aware VFS in `../fs/`
and the shared range-serving pipeline in `../shared/`, atomic writes to the
staged-file helper in `../compat/`, and namespace mutations (delete, copy) to the
Layer-3 `brix_ns_*` API. It records its own low-cardinality Prometheus counters
through `../metrics/` and reports live transfers to `../dashboard/`.

Path-style addressing only (`/<bucket>/<key>`). Directories are represented the
way `XrdClS3` expects: a zero-byte sentinel object `.xrdcls3.dirsentinel` whose
PUT creates the real parent directory on disk; sentinels are then hidden from all
listings. Object ETags are **synthetic** (`"mtime-size"`), not content MD5 —
stable and cheap, matching `XrdClS3` expectations.

## Files

> Build note: the source list is governed by the top-level `config`
> (`ngx_module_srcs`), not by any in-tree aggregator. The four
> `multipart_complete_*.c` fragments are each compiled standalone.

| File | Responsibility |
|---|---|
| `s3.h` | Public header: `ngx_http_s3_loc_conf_t` config, `ngx_http_s3_req_ctx_t` per-request ctx, `s3_entry_t`, the `XML_APPEND`/`XML_APPEND_ELEM` flat-buffer macros, and every cross-file prototype. |
| `module.c` | nginx module descriptor: directive table (`brix_s3*`), create/merge loc-conf, root + optional cache-root canonicalization, persistent confinement rootfd (`brix_http_open_rootfd`), thread-pool binding (postconfiguration), and `clcf->handler = ngx_http_s3_handler` install. |
| `handler.c` | The content handler `ngx_http_s3_handler`: URI parse (`s3_parse_uri`), SigV4 gate, OPTIONS/CORS preflight, list/`?uploads`/`?delete`/POST-form flag detection, key→fs_path resolution, and method dispatch to every sub-handler. The single chokepoint all S3 traffic passes through. |
| `operation_table.c` | `brix_s3_operations[]` descriptor table (method → metric slot + capability flags) consumed by `../compat/protocol_caps.c` for metric-slot lookup and the OPTIONS `Allow` header. |
| `util.c` | Shared helpers: `s3_resolve_key` (confined key→path via `brix_http_resolve_path`), `s3_etag` (synthetic `"mtime-size"`), `s3_send_xml_error`, `s3_set_header`, `s3_object_crc64nvme_b64` (compute/cache CRC-64/NVME → base64-of-8-big-endian-bytes for `x-amz-checksum-crc64nvme`). |
| `metrics.c` | Per-method request/response accounting: `s3_metrics_method_slot`, `s3_metrics_request_method`, `s3_metrics_return_method`, `s3_metrics_finalize_request_method`, plus the unified-metric op mapping (`s3_unified_op`). NGX_DONE (async body) defers final accounting to the callback. |
| `object.c` | GetObject / HeadObject / DeleteObject. GET opens via the cache-aware VFS and hands the whole range/header/send pipeline to `brix_http_serve_file_ranged`; HEAD stats and sends headers only; DELETE uses idempotent `brix_ns_delete`. GET/HEAD echo `x-amz-checksum-crc64nvme` + `x-amz-checksum-type: FULL_OBJECT` **from the xattr cache only** (no read-path recompute), and the stored `x-amz-meta-*` user metadata (`s3_echo_user_metadata`). |
| `put.c` | PutObject / UploadPart body handler `s3_put_body_handler` + streaming dispatch + dashboard glue. *(Phase 38: split.)* |
| `put_finalize.c` | The `s3_put_finalize_*` result family, `s3_commit_put`, and the CRC64-NVME checksum verify (mismatch → 400 `BadDigest`). *(Phase 38 split of `put.c`.)* |
| `put_chunk.c` | `aws-chunked` decode path (`s3_chunk_*` finalize/aio + chunk-verify build). *(Phase 38 split of `put.c`.)* |
| `put_aio.c` | Thread-pool offload (`s3_put_aio_*`, VFS ctx, lazy thread-pool) for in-memory bodies. *(Phase 38 split of `put.c`.)* |
| `s3_put_internal.h` | Private split contract shared by `put*.c` (the `s3_put_aio_t` ctx + prototypes). |
| `post_object.c` | Browser POST Object body handler + small helpers; auth lives in the form policy/signature. Commits through the staged-file path. *(Phase 38: split.)* |
| `post_form.c` | `multipart/form-data` decode: boundary scan, field/file extraction, filename expansion, form parse. *(Phase 38 split of `post_object.c`.)* |
| `post_policy.c` | POST-policy parse + verify (ISO8601/credential parse, condition + JSON validation). *(Phase 38 split of `post_object.c`.)* |
| `post_response.c` | The empty/created/success POST responses. *(Phase 38 split of `post_object.c`.)* |
| `s3_post_internal.h` | Private split contract shared by `post_*.c`. |
| `copy.c` | CopyObject (`PUT` + `x-amz-copy-source`, no `uploadId`): server-side `brix_ns_local_copy` (copy_file_range with read/write fallback), staged commit, `CopyObjectResult` XML. Source and dest both confined to root. Honours `x-amz-metadata-directive`: REPLACE stores the request's `x-amz-meta-*` on the dest, COPY (default) carries the source's metadata across; a **copy-onto-self with REPLACE skips the byte copy** (metadata-only update — the path `sd_s3_set_meta` drives). |
| `delete_objects.c` | Batch DeleteObjects (`POST /<bucket>/?delete`): libxml2-parsed `<Delete>` body (network + XXE disabled), per-key `brix_ns_delete`, `<DeleteResult>` XML with per-key `<Deleted>`/`<Error>`. |
| `list_objects_v2.c` | ListObjectsV2 (`GET /<bucket>/?list-type=2`): query parsing, b64url continuation-token pagination, delimiter common-prefix grouping, and `ListBucketResult` XML emission. |
| `list_objects_v1.c` | ListObjects **V1** (`GET /<bucket>` with no `list-type=2`, phase-43 W2): shares the `s3_walk`/`entry_cmp` walker with V2; differs only in `marker`/`NextMarker` pagination and the V1 XML dialect (no `KeyCount`/continuation token). |
| `conditional.c` | Conditional requests + response overrides (phase-43 W3/W4): `s3_handle_conditional` (If-Match/If-None-Match/If-(Un)Modified-Since → 304/412 on GET/HEAD, S3 `before` semantics), `s3_put_precondition` (create-if-absent / overwrite-if-match PUT), and `s3_apply_response_overrides` (response-content-type/-disposition/… query overrides, CRLF-rejected). |
| `checksum.c` | Multi-algorithm full-object checksums (phase-43 W1): `s3_checksum_b64` (crc32/crc32c/sha1/sha256/crc64nvme → base64 wire form via the shared integrity engine), `s3_put_checksum_apply` (select/verify/echo on PUT, conflict → 400), `s3_put_trailer_checksum_apply` (aws-chunked trailer), `s3_echo_object_checksums` (GET/HEAD echo gated on `x-amz-checksum-mode`). |
| `aws_chunked.{c,h}` | AWS streaming (`aws-chunked`) request-body decoder (phase-43 W0): `s3_body_is_aws_chunked` detection + `s3_aws_chunked_decode_to_fd` streaming state machine that strips chunk framing, enforces `x-amz-decoded-content-length`, and captures a trailer checksum. The fix that stops default SDK clients corrupting every uploaded object. |
| `tagging.{c,h}` | Object tagging + canned subresources (phase-43 W5): `x-amz-tagging` header + `GET`/`PUT`/`DELETE ?tagging` stored in the `user.s3.tagging` xattr; canned `GetBucketVersioning`/`GetBucketAcl`/`GetObjectAcl`/`?cors` probe-satisfiers; `PUT ?acl` → 501. |
| `usermeta.{c,h}` | User-defined object metadata (`x-amz-meta-*`): the whole set stored as one URL-encoded `k=v&k=v` blob in the `user.s3.usermeta` xattr beside the object (VFS xattr surface, impersonation-correct, keys lowercased). `s3_apply_put_user_metadata` persists it on PutObject (all 3 finalize paths); `s3_echo_user_metadata` emits `x-amz-meta-<k>` on GET/HEAD; `s3_user_meta_copy` carries it on CopyObject COPY (REPLACE stores the request's set). Validated end-to-end against the shared `sd_s3` driver's `get_meta`/`set_meta` (`tests/run_s3_usermeta.sh`, `tests/run_sd_s3_meta.sh`). |
| `list_walk.c` | `s3_walk` recursive directory walker + `entry_cmp` comparator + `s3_entry_fill_stat` (used by both V1 and V2). phase-45 W1: classifies dir/file/symlink from readdir `d_type` (an `lstat` fallback only on `DT_UNKNOWN`) and collects only a pooled, right-sized key into the caller's growable `ngx_array_t` — NO per-entry size/mtime/ETag stat. `s3_entry_fill_stat()` then `lstat`s **only the emitted page slice**, so list stats scale with the page, not the bucket; symlinks are still never listed or traversed. |
| `auth_sigv4_parse.c` | SigV4 component parsing: `parse_authorization` (header form) and `parse_presigned_authorization` (`X-Amz-*` query form) → `sigv4_components_t`; `get_header`; 3-slash credential-scope split (AKID/DATE/REGION). |
| `auth_sigv4_canonical.c` | `build_canonical_qs`: SigV4 canonical query string — decode, sort by name then value, percent-encode, and (for the signed-header form) exclude `X-Amz-Signature` (self-reference). |
| `auth_sigv4_verify.c` | The verifier `s3_verify_sigv4`: canonical request → string-to-sign → 4-round signing-key derive (worker-cached per day/region) → constant-time HMAC compare; clock-skew/expiry checks; STS session-token gating; anonymous-mode short-circuit. |
| `s3_auth_internal.h` | `sigv4_components_t` and the parser/key-derive prototypes shared across the three `auth_sigv4_*.c` fragments. |
| `multipart_helpers.c` | Multipart shared helpers: `s3_has_query_flag`, `s3_get_query_param`, `s3_get_mpu_dir` (hidden `.<key>.mpu-<id>` staging path), `mpu_validate_upload_id` (hex-only), `mpu_rmdir_recursive` (confined `brix_fs_remove_tree_confined`). |
| `multipart_initiate.c` | InitiateMultipartUpload (`POST ?uploads`): generates an opaque hex upload ID (sec+usec+pid), mkdir 0700 staging dir, `InitiateMultipartUploadResult` XML. |
| `multipart_abort.c` | AbortMultipartUpload (`DELETE ?uploadId=<id>`): validate id, `lstat` staging dir → `NoSuchUpload` 404 if absent, recursive remove, 204. |
| `multipart_complete_body.c` | CompleteMultipartUpload async body callback `s3_multipart_complete_body_handler`: concatenates `part.1`…`part.10000` in ascending order into a confined temp file, atomic rename to final, best-effort staging cleanup, `CompleteMultipartUploadResult` XML. The FULL_OBJECT `<ChecksumCRC64NVME>` is computed **directly on the reassembled object** (exact full-object value, so no per-part CRC-combine is needed) and returned in the XML + header. |
| `multipart_complete_list_parts.c` | ListParts (`GET <key>?uploadId=<id>`): enumerate `part.<N>` staging files, sort by part number, paginate (`part-number-marker`/`max-parts`), `ListPartsResult` XML. |
| `multipart_complete_list_uploads.c` | ListMultipartUploads (`GET /<bucket>/?uploads`): scan bucket root for `.<key>.mpu-<id>` staging dirs, sort by key, paginate (`key-marker`/`max-uploads`, cap 1000), `ListMultipartUploadsResult` XML. |
| `multipart_complete_upload_part_copy.c` | UploadPartCopy (`PUT ?partNumber=N&uploadId=<id>` + `x-amz-copy-source`): confined source→part-file copy loop, `CopyPartResult` XML. |
| `multipart_internal.h` | `MPU_MAX_PART_NUMBER` (10000) and the `mpu_validate_upload_id` / `mpu_rmdir_recursive` prototypes shared across the multipart files. |

## Key types & data structures

- **`ngx_http_s3_loc_conf_t`** (`s3.h`) — per-location config. Embeds the shared
  `ngx_http_brix_shared_conf_t common` (enable, `root`, `root_canon`,
  `allow_write`, thread-pool) and adds S3-specifics: `bucket` (prefix to strip),
  `access_key`/`secret_key`/`region` (SigV4 credentials; empty key ⇒ anonymous),
  `allow_unsigned_session_token`, `max_keys`, and an optional read-through
  `cache_root`/`cache_root_canon`.
- **`ngx_http_s3_req_ctx_t`** (`s3.h`) — per-request module context: the resolved
  `fs_path[PATH_MAX]` (set by `handler.c`, read by the async PUT/complete
  callbacks because the handler's stack is gone by then) and the
  `brix_identity_t *identity` populated by SigV4 (access key subject) or left as
  `BRIX_AUTHN_NONE` in anonymous mode.
- **`sigv4_components_t`** (`s3_auth_internal.h`) — parsed Authorization material:
  `akid`, `date`, `region`, `amz_date`, `signed_hdrs`, `signature`, plus
  `presigned`/`amz_expires` for presigned-URL form. The canonical builder and the
  verifier operate on this identical parsed view.
- **`s3_entry_t`** (`s3.h`) — one ListObjectsV2 row: `key`, `is_prefix` (1 ⇒ a
  `<CommonPrefixes>` delimiter entry, not a real file), `size`, `mtime`, `etag`.
- **`s3_put_aio_t`** (`put.c`) — thread-task context carrying the staged file,
  byte counts, body mode, and copied `final_path`/`root_canon` for the off-loop
  PUT write.
- **`s3_post_form_t`** / **`s3_post_field_t`** (`post_object.c`) — accumulated
  browser-form fields, policy, signature, and the file part for POST Object.
- **Metric slot enums** (`../metrics/metrics.h`) — `BRIX_S3_METHOD_*`,
  `BRIX_S3_AUTH_*`, `BRIX_S3_RANGE_*`, `BRIX_S3_PUT_*`,
  `BRIX_S3_EVENT_*`: all low-cardinality (no bucket names, keys, or DNs).

## Control & data flow

**Entry.** A location with `brix_s3 on;` routes its requests to
`ngx_http_s3_handler` (`handler.c`), installed by `ngx_http_s3_set` in `module.c`.
The handler allocates `ngx_http_s3_req_ctx_t` (with an `brix_identity_t`),
classifies the method into a metric slot, and runs (in order): OPTIONS/CORS
preflight → `s3_verify_sigv4` (skipped for POST-Object forms, which carry policy
auth) → `s3_parse_uri` → list / `?uploads` / `?delete` / POST-form flag checks →
empty-key rejection → `s3_resolve_key` → per-method dispatch. Async write paths
(`PUT`, `POST` body, `DeleteObjects`) call `brix_http_read_body` and return
`NGX_DONE`; the body callback finalizes the response and metrics later via
`s3_metrics_finalize_request_method`.

**Calls out to:**

- `../path/README.md` — kernel `RESOLVE_BENEATH` confinement and canonicalization,
  reached through `s3_resolve_key` → `brix_http_resolve_path` and the
  `brix_*_confined_canon` family (open/mkdir/unlink/rename); the persistent
  confinement rootfd is opened in `module.c`.
- `../fs/README.md` — `brix_vfs_open`/`_stat`/`_close` for cache-aware GET/HEAD
  (`object.c`); the VFS also fronts the optional `cache_root` read-through.
- `../shared/file_serve.h` — `brix_http_serve_file_ranged`, the range-parse →
  header → body-send pipeline shared with WebDAV GET (`object.c`).
- `../cache/README.md` — read-through fill when `brix_s3_cache_root` is set.
- `../aio/README.md` — the thread pool that the PUT fast path posts to so large
  in-memory writes never block the event loop.
- `../compat/` — staged-file atomic write (`staged_file.h`), HTTP body/header/query
  helpers, XML emit/escape, URL en/decode, `copy_range.h`, `etag.h`, the
  `brix_ns_*` namespace API (`namespace_ops.h`) for delete/copy, and SigV4
  crypto (`crypto.h`, `hex.h`).
- `../metrics/README.md` — S3 Prometheus counters and the unified auth/op metrics
  (`unified.h`, `http_common.h`).
- `../dashboard/` — live transfer tracking on writes (`brix_dashboard_http_*`).
- `../token/b64url.h` — base64url codec for ListObjectsV2 continuation tokens.

## Invariants, security & gotchas

- **Confinement is non-negotiable.** Every client key reaches the filesystem only
  through `s3_resolve_key` (returns 0 on escape → `AccessDenied` 403) or a
  `brix_*_confined_canon` wrapper anchored at the per-worker `RESOLVE_BENEATH`
  rootfd. Bare `lstat`/`stat` appear only on paths *derived from* an
  already-confined `fs_path` plus a hex-validated `upload_id`
  (`multipart_abort.c:40`, `multipart_complete_body.c`) — the comments at those
  sites spell out why they are safe; do not add raw syscalls on raw client input.
- **Fail-closed writes.** `cf->common.allow_write` is checked before the body is
  read on PUT, POST, DELETE, DeleteObjects, and POST-Object (`handler.c`), each
  emitting `BRIX_S3_EVENT_WRITE_DISABLED` + `AccessDenied`. Never move a write
  gate after `brix_http_read_body`.
- **SigV4 is its own auth domain.** No shared logic with `../token/` or `../gsi/`.
  Anonymous mode (`access_key.len == 0`) short-circuits to `NGX_OK`
  (`auth_sigv4_verify.c:401`). Both header and presigned-URL forms are supported;
  presigned `X-Amz-Expires` is bounded to ≤ 604800 s. STS session tokens
  (`x-amz-security-token`) are rejected unless
  `brix_s3_allow_unsigned_session_token` is on, and for the header form the
  token must itself be in `SignedHeaders`.
- **No SigV4 timing/message oracle (W5).** `auth_sigv4_verify.c` deliberately does
  *not* early-return on an unknown access key. The key-match result (`CRYPTO_memcmp`)
  is folded into a single final decision at line 613 — an unknown key (`!key_ok`)
  and a bad signature traverse identical HMAC work and return the identical
  `SignatureDoesNotMatch` 403. Signatures are length-checked to exactly 64 hex
  chars before compare (line 600). Preserve this property in any refactor.
- **Signing-key cache is worker-local and date/region keyed**
  (`s_signing_key_cache`, `auth_sigv4_verify.c:258`): the 4-round HMAC chain is
  stable for one calendar day per region, cached in one slot to avoid recomputing
  per request. Clock skew is bounded to ±900 s (header form) / future-only
  ±900 s (presigned), plus `X-Amz-Expires` enforcement.
- **Atomic writes only.** PutObject, CopyObject, and CompleteMultipartUpload all
  write to a temp file then `rename` (`brix_staged_*` / `brix_ns_local_copy`
  with `staged_commit=1`); clients never observe a partial object, and a crash
  orphans only the temp. The PUT thread-pool fast path is gated to in-memory,
  non-encoded bodies (`!has_spooled && bytes>0 && window_bits==0 && thread_pool`,
  `put.c:441`); spooled bodies and gzip/deflate take the synchronous path.
- **Directory model.** `.xrdcls3.dirsentinel` PUT ⇒ create the real parent dir +
  zero-byte sentinel; `s3_walk` hides sentinels from listings. GET/HEAD on a
  directory returns `NoSuchKey` 404 (S3 keys are objects, not dirs).
- **Synthetic ETags.** `s3_etag` emits `"mtime-size"`, never content MD5. Listings,
  PUT, CopyObject, UploadPartCopy, and multipart results all use this convention
  consistently.
- **DELETE is idempotent.** Deleting a missing key returns 204 (not 404), matching
  AWS, via `brix_ns_delete` with `idempotent_missing=1`. Non-empty directories
  return 409 `BucketNotEmpty`.
- **DeleteObjects XML parsing is hardened.** `delete_objects.c` uses libxml2 with
  `XML_PARSE_NONET` (+ `XML_PARSE_NO_XXE` when available); `NOENT`/`DTDLOAD`/`HUGE`
  are deliberately *not* set, so no file:// XXE and the billion-laughs cap stays
  on. Body capped at 1 MiB, ≤ 1000 keys.
- **List bounds.** `s3_walk` is capped at `S3_LIST_MAX_ENTRIES` (65536); the XML
  buffer sizing in `list_objects_v2.c` assumes a 6× worst-case entity expansion —
  keep that multiplier if you add escaped fields. Pagination is a b64url
  continuation token encoding the last key; a malformed token degrades gracefully
  to "from the beginning". A client `max-keys` only narrows below `cf->max_keys`.
- **`ngx_snprintf` quirk.** It does not support the `l` length modifier; the upload
  ID and part paths use `%z`/plain `snprintf` instead (see `handler.c:516-521` and the
  `multipart_initiate.c` comment). Honor this when formatting widths.

## Entry points / extending

- **Add an S3 operation / sub-handler:** declare it in `s3.h`, implement the
  handler, and wire a dispatch arm in `ngx_http_s3_handler` (`handler.c`) at the
  correct point in the method/flag order (flag checks like `?uploads`/`?delete`
  must precede the empty-key rejection). Write operations must check
  `cf->common.allow_write` before reading any body. New `.c` files must be added to
  `ngx_module_srcs` in the top-level `config`.
- **Add a directive:** add the field to `ngx_http_s3_loc_conf_t` (`s3.h`), a row to
  `ngx_http_s3_commands[]` (`module.c`), and a `ngx_conf_merge_*` line in
  `ngx_http_s3_merge_loc_conf`. Pure directive additions do not require a
  `./configure` re-run; new source files do.
- **Add a metric:** define the slot in `../metrics/metrics.h`, then increment with
  `BRIX_S3_METRIC_INC`/`_ADD` at the callsite. Keep labels low-cardinality (no
  paths, bucket names, or keys).
- **Touch SigV4:** changes go in the `auth_sigv4_*.c` trio behind
  `s3_auth_internal.h`; never break the constant-time single-decision compare in
  `auth_sigv4_verify.c`.

## See also

- [`../README.md`](../README.md) — master subsystem index
- [`../webdav/README.md`](../webdav/README.md) — sibling HTTP protocol (WebDAV/HTTPS)
- [`../path/README.md`](../path/README.md) — confinement & canonical path resolution
- [`../fs/README.md`](../fs/README.md) — cache-aware VFS (open/read/stat)
- [`../cache/README.md`](../cache/README.md) — read-through / write-through cache
- [`../aio/README.md`](../aio/README.md) — thread-pool I/O offload
- [`../metrics/README.md`](../metrics/README.md) — Prometheus counters & unified metrics
- [`../compat/README.md`](../compat/README.md) — staged-file, HTTP, XML, crypto, namespace helpers
