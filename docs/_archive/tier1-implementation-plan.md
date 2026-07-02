# Tier 1 Implementation Plan

Status as of 2026-05-19: all Tier 1 query, staging, checksum, and security
level enforcement gaps are implemented.

Source of truth for status: `docs/10-reference/xrootd-feature-matrix.md §13`.

---

## 1. crc32c file checksum (kXR_Qcksum)

**Status:** Complete | **Effort:** Low | **Impact:** High

Implemented in `src/query/checksum_qcksum.c` and
`src/response/crc32c.c`. Raw protocol coverage lives in
`tests/test_query_extended.py::TestChecksumQueries`.

### Problem

`xrdcp --cksum crc32c` and post-transfer validation pipelines request
`crc32c` via `kXR_Qcksum`. nginx-xrootd now returns
`"crc32c <8-hex-chars>\0"` and still returns `kXR_ArgInvalid` for unknown
algorithm names.

The wire computation already exists in `src/response/crc32c.c` (`xrootd_crc32c()`
and a file-streaming variant). It is used only for pgread/pgwrite page frames
today.

### Wire format

`kXR_Qcksum` response: `"crc32c <8-hex-chars>\0"` — same pattern as adler32.

### Implemented Changes

**`src/query/checksum_qcksum.c` — `xrootd_query_build_checksum()`**

Includes a crc32c branch before the EVP block:

```c
} else if (strcmp(algo, "crc32c") == 0) {
    uint32_t cksum = xrootd_crc32c_file(fd, resolved, c->log);
    if (cksum == (uint32_t)-1) {
        XROOTD_OP_ERR(ctx, XROOTD_OP_QUERY_CKSUM);
        return xrootd_query_cksum_send_error(ctx, c, kXR_IOError,
                                             "checksum computation failed");
    }
    snprintf(resp, resp_sz, "crc32c %08x", (unsigned int) cksum);
    return NGX_OK;
}
```

**`src/response/crc32c.c` / `src/response/response.h`**

Provides `xrootd_crc32c_file(int fd, const char *path, ngx_log_t *log)`. It reads
the file in 64 KiB chunks and accumulates the running CRC, same loop shape
as `xrootd_query_adler32_fd`. Returns `(uint32_t)-1` on read error.

**`src/query/config.c`**

`kXR_Qconfig chksum` advertises the supported list:
`adler32,crc32c,md5,sha1,sha256`.

**`src/response/response.h`**

Expose the declaration for `xrootd_crc32c_file`.

### Tests

Three new cases in `tests/test_query_extended.py` plus an xrdcp client-option
round trip:

1. `kXR_Qcksum crc32c` raw protocol request — known `"123456789"` checksum
2. `kXR_Qcksum crc32c` response format matches `"crc32c [0-9a-f]{8}"`
3. Unknown algorithm still returns `kXR_ArgInvalid`
4. `xrdcp --cksum crc32c:source` upload verifies against server Qcksum

---

## 2. kXR_Qckscan — directory checksum scan

**Status:** Complete | **Effort:** Medium | **Impact:** High

Implemented across `src/query/checksum_ckscan_common.c`,
`src/query/checksum_ckscan_dispatch.c`, and
`src/query/checksum_ckscan_async.c`. Coverage lives in
`tests/test_query_extended.py::TestQckscan`.

### Problem

`xrootd_query_ckscan` now resolves and authorizes the requested path, computes
checksums for a regular file or every regular file under a directory, and skips
symlinked entries during recursive scans.

`xrdadler32` (used by FTS and data-quality jobs) sends `kXR_Qckscan <dir>` and
expects one line per file in the response:

```
adler32 <8-hex-digits>  <logical-path>\n
```

(double space between checksum and path — this is the wire format xrdadler32 parses).

For a deep directory tree this is a blocking, CPU-bound operation that must not
run on the nginx event loop.

### Wire protocol

Payload: NUL-terminated logical path (file or directory).

Response body: for each regular file reachable under the path, one line:
```
<algo> <hex-checksum>  <logical-path>\n
```
Followed by a NUL terminator. Total length in `kXR_ok` dlen.

If the path is a regular file, return exactly one line.

### Implemented Changes

**`src/query/checksum_ckscan_*.c`**

`xrootd_query_ckscan` parses the requested logical path, accepts optional
`crc32c:` or `crc32c <path>` prefixes, resolves and authorizes the path, and
then emits one checksum line for either the single regular file or every regular
file under a directory. Directory traversal uses `xrootd_open_confined_canon`,
skips symlinks with `AT_SYMLINK_NOFOLLOW`, and preserves logical paths in the
wire response.

The directory walk is bounded by `xrootd_ckscan_depth` (default 32) and
`xrootd_ckscan_max_files` (default 100000). The response buffer starts at
256 KiB and grows with `ngx_alloc` as needed.

**Thread pool dispatch** (`src/core/aio/` pattern)

Ckscan can take seconds on a large directory. It uses `ngx_thread_task_alloc`
and `xrootd_aio_post_task` to move the file-walking loop off the event loop
when a stream thread pool is configured. The completion callback queues the
pre-built response back on the worker.

**`src/core/types/config.h` / `src/stream/module.c`**

Added `xrootd_ckscan_depth` (default 32) and `xrootd_ckscan_max_files`
(default 100000) to bound runaway scans.

### Tests

Coverage in `tests/test_query_extended.py::TestQckscan`:

1. Single-file Qckscan — response is exactly one line, format correct
2. Directory Qckscan — response contains one line per file, all checksums verify
3. Qckscan on non-existent path — `kXR_NotFound`
4. Symlink escape negative — symlinked external directories are not followed

---

## 3. kXR_QPrep — query staging status

**Status:** Complete | **Effort:** Low | **Impact:** Medium

Implemented in `src/query/prepare.c`. Coverage lives in
`tests/test_prepare_staging.py::TestQPrepStatus`.

### Problem

`xrootd_query_prep_status` stores paths on `kXR_stage`, honors inline paths in
the QPrep payload, and returns `"A <path>\n"` (available) or `"M <path>\n"`
(missing or unauthorized). The implemented fixes covered three gaps:

1. **Empty-path edge case**: when `kXR_prepare` was sent without `kXR_stage`, or
   no paths were stored, `xrootd_query_prep_status` returns the literal string
   `"No information found."` — valid but not the per-path format clients expect.
2. **`has_inline_paths` unused**: declared but never read after assignment, which
   means inline paths in the QPrep payload (paths sent alongside the reqid) are
   effectively ignored.
3. **No auth check on QPrep paths**: the function now checks authdb, VO ACL,
   and token scope before reporting a path as available.

### Implemented Changes

**`src/query/prepare.c` — `xrootd_query_prep_status()`**

When no paths are available, return an empty ok body (zero bytes), not
the literal string. Clients that don't recognise the string may misparse it.

```c
if (rp == resp) {
    return xrootd_send_ok(ctx, c, NULL, 0);  /* was: "No information found." */
}
```

Inline paths after the request ID are honored before falling back to the stored
path list from the previous `kXR_prepare kXR_stage` request.

Per-path authdb, VO ACL, and token-scope checks run before the stat call, same
as in `xrootd_prepare_check_path`. Unauthorized paths are reported as missing.

### Tests

Coverage in `tests/test_prepare_staging.py::TestQPrepStatus`:

1. `kXR_prepare kXR_stage`, then `kXR_QPrep` — all staged paths appear as `"A"`
2. `kXR_prepare kXR_stage` for non-existent file, then QPrep — appears as `"M"`
3. QPrep with no prior prepare — empty ok body (not error)
4. QPrep with inline paths in payload — same result as stored paths
5. QPrep on path outside auth scope — silently treated as missing

---

## 4. Security level enforcement

**Status:** Complete | **Effort:** Medium | **Impact:** Medium

### Completed behavior

nginx-xrootd now advertises and enforces configurable XRootD request-signing
levels for GSI sessions:

- `xrootd_security_level none|compatible|standard|intense|pedantic` stores the
  configured level in `ngx_stream_xrootd_srv_conf_t`.
- `kXR_protocol` replies with a `ServerResponseReqs_Protocol` trailer whenever
  the client sets `kXR_secreqs`.
- `pedantic` advertises `kXR_secOData`, requiring payload bytes to be included
  in signed write envelopes.
- `handshake/dispatch.c` verifies any pending `kXR_sigver` envelope before
  routing, then rejects unsigned requests when the configured level requires a
  signature.

Non-GSI sessions still accept `kXR_sigver` as a no-op and do not enforce signing,
because they do not derive a request-signing key.

### Wire protocol

When a client sends `kXR_protocol` with `kXR_secreqs` set in the flags,
the server's response should include a `ServerResponseReqs_Protocol` appended
after the standard body:

```c
struct ServerResponseReqs_Protocol {
    kXR_char  theTag;   /* always 'S' */
    kXR_char  rsvd;     /* 0 */
    kXR_char  secver;   /* 0 */
    kXR_char  secopt;   /* kXR_secOData (0x01), kXR_secOFrce (0x02) */
    kXR_char  seclvl;   /* kXR_secNone=0 .. kXR_secPedantic=4 */
    kXR_char  secvsz;   /* 0 — no per-opcode override table */
    /* secvec[] absent when secvsz==0 */
};
```

The global level is advertised with `secvsz=0` (no per-opcode override vector).
The opcode policy is mirrored from XRootD's `XrdSecProtect.cc` table.

### Opcode enforcement table

The implementation uses XRootD's three-state policy values:

- `ignore`: no signature required at this level
- `likely`: conditional signature requirement, currently resolved for
  `kXR_open`, `kXR_query`, and `kXR_set`
- `needed`: a valid preceding `kXR_sigver` envelope is required

Important level behavior:

- `none`: no signing enforcement.
- `compatible`: write-mode `kXR_open` is conditional; destructive namespace and
  metadata mutation opcodes are signed.
- `standard`: `kXR_open` is always signed; destructive namespace and metadata
  mutation opcodes are signed.
- `intense`: expands signing to additional stateful and data-write operations.
- `pedantic`: signs the broadest opcode set and rejects signed requests with
  payloads when `kXR_nodata` is set.

### Changed files

- `src/core/types/config.h`, `src/core/config/server_conf.c`, `src/stream/module.c`
  carry and parse `security_level`.
- `src/protocol/flags.h` defines `kXR_secOData` / `kXR_secOFrce`.
- `src/session/protocol.c` appends the `ServerResponseReqs_Protocol` trailer.
- `src/handshake/sigver.c` mirrors the XRootD request-protection table,
  handles conditional opcodes, enforces missing signatures, and rejects pedantic
  `kXR_nodata` payload signatures.
- `src/handshake/dispatch.c` calls the enforcement gate before opcode routing.

### Tests

`tests/test_security_level.py` covers:

1. Default `none` keeps unsigned reads working.
2. `standard` is advertised as `seclvl=2`.
3. `pedantic` is advertised as `seclvl=4` with `kXR_secOData`.

---

## Dependency and ordering

```
1. crc32c Qcksum   — complete
2. QPrep fixes     — complete
3. Qckscan         — complete
4. Security level  — complete
```

The completed query/staging changes are backward-compatible. Default checksum
behavior remains adler32, Qckscan bounds have conservative defaults, and QPrep
still reports disk-local availability without attempting tape recall.

---

## Cross-cutting checklist (all four items)

- [ ] Wire values cross-checked against `XProtocol/XProtocol.hh`
- [ ] Three tests per change: success path, error path, security/auth path
- [ ] Metric increment at each callsite (`XROOTD_OP_OK` / `XROOTD_OP_ERR`)
- [ ] Access log entry for each new operation via `xrootd_log_access`
- [ ] `docs/10-reference/xrootd-feature-matrix.md` status updated from ❌/⚠️ to ✅ on merge
