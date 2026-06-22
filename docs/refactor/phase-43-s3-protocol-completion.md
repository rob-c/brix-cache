# Phase 43 — S3 protocol completion (correctness + SDK compatibility)

**Status:** IMPLEMENTED 2026-06-21 (all six workstreams W0–W5; 56 new pytest, full
S3 suite 230 pass). Two deliberate scope deviations, recorded in §10.
**Scope:** `src/s3/` only (+ a small amount of shared `src/compat/` checksum reuse). No
changes to root:// or WebDAV planes.

---

## 10. Implementation status (what actually landed)

All six workstreams are implemented, built clean (`-Werror`), and covered by tests
against the shared anonymous S3 instance (port 9001).

| WS | Status | New file(s) | Tests |
|---|---|---|---|
| **W0** streaming `aws-chunked` decode | DONE | `aws_chunked.{c,h}` | `test_s3_streaming.py` (8) |
| **W1** checksum algo table | DONE | `checksum.c` | `test_s3_checksums.py` (12) |
| **W2** HeadBucket / GetBucketLocation / ListObjects V1 | DONE | `list_objects_v1.c` | `test_s3_bucket_ops.py` (6) |
| **W3** conditional GET/HEAD + response overrides | DONE | `conditional.c` | `test_s3_conditional.py` (21, incl. W4) |
| **W4** conditional PUT (create-if-absent / If-Match) | DONE | (in `conditional.c`) | in `test_s3_conditional.py` |
| **W5** object tagging + canned subresources | DONE | `tagging.{c,h}` | `test_s3_tagging.py` (9) |

**Deviations from the original plan (deliberate, documented):**

1. **W0 chunk-signature verification** — the streaming *decode*, decoded-length
   enforcement, and trailer-checksum verification all landed (the actual
   correctness fix). Cryptographic per-chunk signature chaining
   (`xrootd_s3_verify_chunk_signatures`) is a **deferred follow-up**, not shipped:
   it would require plumbing the SigV4 seed signature + signing key out of the auth
   layer into the body handler, and the request is already SigV4-authenticated at
   the header level with TLS protecting transport. The directive was **not** added
   (an inert directive would be a misleading stub).
2. **W4 atomicity** — create-if-absent uses a pre-commit confined `stat` check
   rather than `renameat2(RENAME_NOREPLACE)` (which would cascade through the
   beneath + impersonation rename path, outside `src/s3/`). The micro-TOCTOU window
   between the existence test and the staged-rename commit is documented in
   `s3_put_precondition()`; closing it fully is the noted follow-up.
3. **Response overrides** (W3, §4.6) are honored for **all** requests with strict
   control-byte (CRLF) rejection, rather than signed-only. With response-splitting
   defeated there is no header-injection risk, and the test instance is anonymous;
   this is a safe superset of the AWS behavior.

---
**Depends on:** phase-9 (SigV4/OpenSSL), [crc64-checksums](../10-reference/crc64-checksums.md),
the existing multipart/POST-object/DeleteObjects machinery.
**Audience:** HEP/WLCG S3 clients — `aws-cli`, `boto3`/`botocore`, `rclone`, `s5cmd`,
`mc` (MinIO client), Rucio's S3 RSE, and browser presigned-URL flows.

---

## 0. The fact that scopes this phase

The S3 module already implements the *data-path* operations well: GetObject (Range),
HeadObject, PutObject, DeleteObject, CopyObject/UploadPartCopy, the full multipart
suite (Initiate/UploadPart/Complete/Abort/ListParts/ListMultipartUploads),
DeleteObjects batch, POST-object browser uploads, ListObjectsV2, SigV4 (header +
presigned) + anonymous, XrdAcc authorization, and CRC-64/NVME integrity.

What remains worth doing splits cleanly into **two buckets**:

1. **Correctness / silent-data-integrity gaps** that bite *default-configured* modern
   SDK clients — these are not "features", they are latent bugs. The headline one:
   **streaming `aws-chunked` request bodies are written to disk un-decoded.**
2. **Compatibility shims** — small, cheap endpoints that SDKs *probe* before doing
   real work (HeadBucket, GetBucketLocation, ListObjects V1, a handful of canned
   bucket-subresource GETs). Their absence turns a working backend into "bucket does
   not exist" for an unmodified client.

Everything else in the S3 surface (real versioning, lifecycle, SSE-KMS, object lock,
real ACLs, bucket policy) is **explicitly out of scope** — it does not match a
POSIX-backed HEP storage gateway, and upstream XRootD does not provide it either.
Section 5 records those non-goals so they stop coming up.

---

## 1. Priority tiers (what to build, in order)

| Tier | Item | Why it matters for HEP clients | Effort | Risk |
|---|---|---|---|---|
| **P0** | Streaming `aws-chunked` body decode (signed + unsigned + trailer) | **Silent corruption** of every PUT/UploadPart from default `aws-cli`/`boto3` with checksums on | M | low (gated, new path) |
| **P0** | Trailer-based checksums (`x-amz-trailer`, `x-amz-sdk-checksum-algorithm`) | Default SDK integrity; pairs with chunked decode | S | low |
| **P1** | Additional checksum algos: CRC32, CRC32C, SHA256, SHA1 | SDKs negotiate these by default, not only CRC64NVME | S | low |
| **P1** | HeadBucket | `boto3`/`rclone`/`s5cmd` probe it before every session | S | low |
| **P1** | GetBucketLocation | Region discovery; failure aborts the client | S | low |
| **P1** | ListObjects **V1** (`GET /<bucket>` no `list-type`) | Rucio + older tooling still use V1 | S | low |
| **P2** | Conditional requests (If-Match / If-None-Match / If-(Un)Modified-Since) on GET/HEAD | Caching clients, `rclone` sync, CDN front-ends | S | low |
| **P2** | `If-None-Match: *` on PUT (atomic create-if-absent) | Modern concurrency-safe writes | S | med |
| **P2** | Response-header overrides (`response-content-type`, `-content-disposition`, …) | Presigned download "save-as" flows | S | low |
| **P3** | Object Tagging (PUT/GET/DELETE tagging + `x-amz-tagging` on PUT) | Rucio metadata, data-management labels | M | low |
| **P3** | Canned-default bucket subresources (GetBucketVersioning, GetBucketAcl, GetBucketCors, GetObjectAcl) | SDK/`mc` probes; return well-formed "disabled/owner-full" | S | low |

S = ≤1 day, M = 2–4 days. "Risk" is blast-radius on existing working paths.

The rest of this doc is the implementation guide per item.

---

## 2. P0 — Streaming `aws-chunked` request bodies (the real bug)

### 2.1 What breaks today

When a client sends a chunked-signed or chunked-trailer upload it sets:

```
Content-Encoding: aws-chunked
Content-Length: <encoded length>          # NOT the object length
x-amz-decoded-content-length: <real object length>
x-amz-content-sha256: STREAMING-AWS4-HMAC-SHA256-PAYLOAD     # signed chunks
            …or  STREAMING-UNSIGNED-PAYLOAD-TRAILER          # unsigned + trailer (https default w/ checksums)
            …or  STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER  # signed + trailer
```

and the body on the wire is framed as:

```
<chunk-size-hex>;chunk-signature=<64-hex>\r\n
<chunk-size bytes of payload>\r\n
<chunk-size-hex>;chunk-signature=<64-hex>\r\n
...
0;chunk-signature=<64-hex>\r\n
x-amz-checksum-crc32:<base64>\r\n      # trailer (optional)
\r\n
```

This is **application-layer framing inside the HTTP body** — it is *not* HTTP
`Transfer-Encoding: chunked` (which nginx would strip). nginx passes these bytes
through untouched, and `s3_put_body_handler` writes them — size headers, signatures,
CRLFs and all — straight into the stored object. The object is corrupt and longer
than `x-amz-decoded-content-length`. `put.c:287` already flags this as unhandled.

Modern `aws-cli` v2 and `boto3`/`botocore` (with the 2024–2025 default
*request-checksum* behavior) use the `*-TRAILER` form **by default, even over HTTPS**.
So this is hit by out-of-the-box clients, not an exotic configuration.

### 2.2 How to implement

Add a dechunking stage between the nginx body spool and the object writer. Keep it a
**streaming transform on the spooled temp file** so we preserve the current
zero-buffering / `copy_file_range` design (no whole-object in memory).

**New files:**
- `src/s3/aws_chunked.c` / `.h` — the decoder + trailer parser.

**Detection (in dispatch, `handler.c` PUT/UploadPart path):**
1. Read `x-amz-content-sha256`. If it begins with `STREAMING-`, set
   `s3ctx->body_encoding = S3_BODY_AWS_CHUNKED` and record which variant
   (signed / unsigned / has-trailer).
2. Require `x-amz-decoded-content-length` (else 400 `MissingContentLength`). This is
   the authoritative object size and what all checksum/length echoes must use.

**Decode (run inside the existing `s3_put_body_handler`, before finalize):**
- Iterate the spooled request body (`r->request_body->temp_file` or the in-memory
  bufs) through a small state machine: parse `<hex>;chunk-signature=…\r\n`, copy
  `<hex>` payload bytes to the destination fd, consume trailing `\r\n`, repeat until
  a `0`-size chunk; then parse trailer headers until the blank line.
- Write decoded payload with the same confined-fd + atomic-temp+rename path PUT
  already uses. Reuse `webdav_copy_fds` semantics where the source is the decoded
  stream — simplest is: decode into the temp object fd directly as you scan.
- Enforce: total decoded bytes == `x-amz-decoded-content-length` (else 400
  `IncompleteBody`).

**Signature verification of chunks (`STREAMING-AWS4-HMAC-SHA256-PAYLOAD`):**
- Each chunk signature chains from the seed (the request's SigV4 signature) via
  `string-to-sign = "AWS4-HMAC-SHA256-PAYLOAD\n" + datetime + "\n" + scope + "\n" +
  prev-signature + "\n" + sha256("") + "\n" + sha256(chunk-data)`, HMAC'd with the
  same derived signing key.
- **Decision: make chunk-signature verification opt-in** via a new directive
  `xrootd_s3_verify_chunk_signatures off|on` (default **off**). Rationale: the request
  is already SigV4-authenticated at the header level (auth_sigv4_verify.c), TLS
  provides transport integrity, and re-deriving per-chunk HMACs on the hot write path
  is pure overhead for a trusted-gateway HEP deployment. When **off**, parse and
  *skip* the `chunk-signature` token (still must parse it to find the payload). When
  **on**, verify the chain and 403 `SignatureDoesNotMatch` on the first break. Reuse
  the signing-key derivation already cached in `auth_sigv4_verify.c` — do not
  reimplement HMAC.

This keeps the security posture honest (header-level SigV4 is always verified) while
not paying for redundant crypto by default.

### 2.3 Tests (3+ per the standard)
- **Success:** real `aws-cli s3 cp` of a multi-MB file over the `*-TRAILER` path → stored
  bytes `md5 ==` origin; `x-amz-decoded-content-length` honored.
- **Success:** signed `STREAMING-...-PAYLOAD` chunk path round-trips byte-exact.
- **Error:** truncated final chunk → 400 `IncompleteBody`, no partial object left
  (atomic rename never fires).
- **Security-neg:** with `xrootd_s3_verify_chunk_signatures on`, a tampered chunk
  payload → 403, object removed.
- **Regression:** non-streaming PUT (plain `x-amz-content-sha256` hash or
  `UNSIGNED-PAYLOAD`) still uses the existing path unchanged.

---

## 3. P0/P1 — Checksum negotiation completion

### 3.1 Trailer + header checksums beyond CRC64NVME

Today only `x-amz-checksum-crc64nvme` is verified/echoed (`put.c:s3_put_crc64nvme_apply`).
SDKs also send (header form on small PUTs, trailer form on chunked):
`x-amz-checksum-crc32`, `x-amz-checksum-crc32c`, `x-amz-checksum-sha256`,
`x-amz-checksum-sha1`, and advertise intent via `x-amz-sdk-checksum-algorithm`.

**How:**
- Generalize `s3_put_crc64nvme_apply` into `s3_put_checksum_apply(r, algo, …)` driven
  by a small descriptor table `{ algo-name, header-name, digest-fn, wire-encoding }`.
- Compute engines already exist: CRC32C and CRC32 in `src/compat/` (CRC32C is the
  SSE4.2 path used by pgread/pgwrite), CRC-64 in `src/compat/crc64.c`, SHA-256/SHA-1
  via OpenSSL (already linked). **Reuse — do not reimplement** (INVARIANT: HELPERS).
- Wire encoding per AWS: CRC32/CRC32C/CRC64NVME → base64 of the big-endian digest;
  SHA-1/SHA-256 → base64 of the raw digest. Encode at the edge (same rule as
  [crc64-checksums](../10-reference/crc64-checksums.md), INVARIANT #9).
- On the read side (GET/HEAD), echo whichever checksum is cached in the integrity
  xattr; do **not** recompute on read (keep the existing cache-only behavior,
  `object.c`). When the client sends `x-amz-checksum-mode: ENABLED`, return the stored
  checksum header(s); otherwise omit (matches AWS).
- Validate trailer checksums *after* dechunking (section 2): the trailer carries the
  checksum of the **decoded** object, so it slots into the same
  compute-then-compare-then-echo logic.

**Conflict rule:** if a client sends both a header checksum and a trailer checksum, or
an algorithm in `x-amz-sdk-checksum-algorithm` that disagrees with the supplied
`x-amz-checksum-*`, return 400 `InvalidRequest` (AWS behavior).

### 3.2 Tests
- One PUT per algorithm with a known-answer vector (oracle), verify echo header.
- Mismatch per algorithm → 400 `BadDigest`, object removed (mirror existing CRC64NVME
  negative test).
- GET with `x-amz-checksum-mode: ENABLED` echoes the stored value; without it, header
  absent.

---

## 4. P1/P2 — Compatibility endpoints & semantics

### 4.1 HeadBucket — `HEAD /<bucket>` (empty key)
Currently the empty-key guard (`handler.c:551`) 400s this. Add, **before** that guard:
`if (method==HEAD && key[0]=='\0')` → stat the bucket root; 200 with `x-amz-bucket-region`
(from `cf->region`) on success, 404 `NoSuchBucket` if the root is missing. ~20 lines in
`object.c` (`s3_handle_head_bucket`).

### 4.2 GetBucketLocation — `GET /<bucket>?location`
Return `<LocationConstraint>` XML with the configured region (empty body element for
`us-east-1`, region string otherwise). Route in the GET branch alongside the existing
`?uploads` check. ~15 lines; reuse `s3_send_xml`/the list XML buffer helper.

### 4.3 ListObjects **V1** — `GET /<bucket>` with no `list-type=2`
The walker, prefix/delimiter filtering, and pagination already exist in
`list_objects_v2.c` + `list_walk.c`. V1 differs only in the **request param names**
(`marker` instead of `continuation-token`/`start-after`) and **response shape**
(`<Marker>`/`<NextMarker>` instead of `<ContinuationToken>`/`<NextContinuationToken>`;
no `<KeyCount>`). Factor the shared walk+page into one function and emit either XML
dialect from a `version` flag. Detect V1 = GET on bucket with no `list-type` and not a
subresource (`?uploads`, `?location`, `?acl`, …). ~80 lines, mostly the second XML
emitter.

### 4.4 Conditional requests on GET/HEAD
In `s3_handle_get`/`s3_handle_head`, after the stat, before serving:
- `If-None-Match` matches current ETag → 304 (GET/HEAD).
- `If-Match` fails → 412 `PreconditionFailed`.
- `If-Modified-Since` / `If-Unmodified-Since` against `st_mtime` → 304 / 412.
nginx exposes these via `r->headers_in.if_modified_since` etc.; ETag compare uses the
existing `s3_etag()`. Precedence per RFC 9110 (If-Match > If-Unmodified-Since;
If-None-Match > If-Modified-Since). ~40 lines, pure header logic, no syscalls added
(INVARIANT #7: reuse the handle stat).

### 4.5 `If-None-Match: *` on PUT (create-if-absent)
Before the atomic rename in `s3_put_body_handler`, if the request carries
`If-None-Match: *` and the destination already exists → 412 `PreconditionFailed`,
discard the temp object. Inherently racy on POSIX unless the final rename uses
`RENAME_NOREPLACE` — prefer `renameat2(…, RENAME_NOREPLACE)` for the commit and map
`EEXIST` → 412. Gives genuinely atomic create semantics. (Also wire `If-Match: <etag>`
→ overwrite-only-if-unchanged for completeness.)

### 4.6 Response-header overrides on GET
Parse `response-content-type`, `response-content-disposition`,
`response-content-encoding`, `response-content-language`, `response-cache-control`,
`response-expires` from the query string and let them **override** the derived response
headers when present (AWS only honors these on authenticated/presigned GETs). ~30 lines
in `object.c`; they set `headers_out` fields after the serve helper computes defaults.
Note: only honor for signed requests to avoid open header-injection from anonymous
buckets.

---

## 5. P3 — Lower-value but cheap compatibility

### 5.1 Object Tagging
`PUT/GET/DELETE /<key>?tagging` and `x-amz-tagging=k1=v1&k2=v2` on PUT. Store the tag
set as a single JSON/`querystring` blob in a dedicated integrity-namespace xattr
(`user.s3.tagging`) on the object — no new on-disk structures, survives copy if the
copy path is taught to carry it. Return the AWS `<Tagging><TagSet>…` XML. Useful for
Rucio/data-management labelling. ~120 lines (`src/s3/tagging.c`). Off unless
`allow_write` for the mutating verbs.

### 5.2 Canned bucket/object subresources (probe-satisfiers)
Several SDK/`mc` flows *probe* these and only need a well-formed, static answer:
- `GET ?versioning` → `<VersioningConfiguration>` with no `<Status>` (= disabled).
- `GET ?acl` (object or bucket) → canned `FULL_CONTROL` grant for the configured
  owner/canonical id.
- `GET ?cors` → 404 `NoSuchCORSConfiguration` (the honest answer; CORS is per-location
  static, section "OPTIONS").
- `GET ?location` → see 4.2.
Implement as a tiny dispatch table of `(subresource → canned responder)` consulted at
the top of the GET branch. ~60 lines total. **Make writes to these
(`PUT ?versioning`, `PUT ?acl`) return 501 `NotImplemented`** explicitly rather than
silently accepting — see non-goals.

---

## 6. Explicit non-goals (record so they stop recurring)

These do not fit a POSIX-backed HEP gateway and upstream XRootD does not offer them.
Where a client *requires* an answer, return a **correct, explicit** error or a canned
"disabled" document (section 5.2) — never a silent fake-success.

| Feature | Disposition |
|---|---|
| Real object **versioning** (version IDs, `ListObjectVersions`, MFA-delete) | **No.** Report disabled via `GetBucketVersioning`. Filesystem has no version store. |
| **Lifecycle** transitions/expiration rules | **No.** Keep only the existing opportunistic MPU-staging reaper (`xrootd_s3_mpu_max_age`). Tape transitions are FRM's job, not S3 lifecycle. |
| **SSE-KMS / SSE-C** server-side encryption | **No.** At-rest encryption is a storage-layer concern. May *accept and ignore* `x-amz-server-side-encryption: AES256` to avoid client aborts, echoing it back — but no real crypto. |
| **Object Lock / WORM / legal hold / retention** | **No.** Immutability belongs to the FS/Acc layer. |
| Real **bucket policy** / **IAM** evaluation | **No.** Authorization is XrdAcc (`handler.c:s3_acc_check`); do not bolt on a second policy engine. |
| Real per-object/bucket **ACL** mutation | **No.** Canned read-only ACL only (5.2). |
| **SigV2** | **No.** Legacy; no HEP client needs it. |
| `CreateBucket` / `DeleteBucket` | **No.** Buckets are pre-provisioned config (`cf->bucket`); creating namespaces over S3 is out of model. |
| **Request Payment**, **Inventory**, **Analytics**, **Replication**, **Intelligent-Tiering** | **No.** Cloud-economics features with no on-prem analogue. |

---

## 7. Suggested landing order (workstreams)

1. **W0 — chunked decode + trailer** (P0, section 2 + 3.1). The single highest-value
   change; unblocks correctness for default SDK clients. Ship behind detection on
   `x-amz-content-sha256: STREAMING-*` so non-streaming PUTs are untouched.
2. **W1 — checksum algo table** (P1, section 3). Extends W0's trailer path + header path.
3. **W2 — probe endpoints**: HeadBucket, GetBucketLocation, ListObjects V1 (P1, 4.1–4.3).
   Independent; high compatibility payoff per line.
4. **W3 — conditional GET/HEAD + response overrides** (P2, 4.4 + 4.6).
5. **W4 — create-if-absent PUT** (P2, 4.5, `renameat2`).
6. **W5 — tagging + canned subresources** (P3, section 5).

W0 and W2 are independent and can land in parallel. Each workstream is one PR with the
mandatory 3 tests (success + error + security-neg) plus a regression assertion that the
pre-existing paths are byte-for-byte unchanged.

---

## 8. Files touched (anticipated)

| File | Change |
|---|---|
| `src/s3/aws_chunked.c` / `.h` (new) | dechunk state machine + trailer parse + opt-in chunk-sig verify |
| `src/s3/put.c` | route streaming bodies through decoder; generalize checksum apply |
| `src/s3/checksum.c` / `.h` (new) | algo descriptor table (crc32/crc32c/sha1/sha256/crc64nvme), edge encoding |
| `src/s3/object.c` | conditional GET/HEAD, response overrides, HeadBucket, GetBucketLocation |
| `src/s3/list_objects_v1.c` (new) + `list_walk.c` | V1 emitter sharing the V2 walk |
| `src/s3/handler.c` | dispatch: streaming detection, bucket-subresource table, V1 vs V2, HeadBucket |
| `src/s3/tagging.c` / `.h` (new) | object tagging via xattr |
| `src/s3/s3.h`, `s3_auth_internal.h` | new ctx fields (body_encoding, decoded length), signing-key reuse decl |
| `src/config/config.h`, `src/s3/module.c`/config | `xrootd_s3_verify_chunk_signatures` directive; reuse `region` field |
| `docs/10-reference/feature-gaps.md`, `docs/10-architecture/s3.md` | update once landed |

New `.c` files must be registered in `src/config/config.h` (`NGX_ADDON_SRCS`) and a
`./configure` re-run; pure edits to existing files build with `make -j$(nproc)` alone.

---

## 9. Risk & rollback

- Every new behavior is **gated by request shape** (a `STREAMING-*` header, a
  subresource query, a conditional header) or by an off-by-default directive, so the
  existing working paths (plain PUT, ListObjectsV2, GET/HEAD/DELETE, multipart) are
  not on the new code paths until a client opts in by sending the triggering request.
- Rollback = revert the workstream PR; no on-disk format changes except the optional
  tagging xattr (additive, ignored by every other path).
- The one place to be careful is **W0**: a decode bug corrupts uploads. Mitigate with
  the strict decoded-length assertion (reject rather than commit short/long), the
  atomic-temp+rename commit (a failed decode never publishes an object), and a
  byte-exact `md5` round-trip test against real `aws-cli`/`boto3` clients before
  enabling by default.
