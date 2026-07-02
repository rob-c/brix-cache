[← WebDAV overview](webdav-intro.md)

## WebDAV methods

Every HTTP method the WebDAV module handles, what RFC it follows, and any nginx-xrootd-specific behavior to be aware of.

| Method | Notes |
|---|---|
| `OPTIONS` | Returns `Allow` header with all supported methods; `DAV: 1` |
| `GET` | Full file and RFC 7233 `Range` requests (including suffix ranges `bytes=-N`) |
| `HEAD` | Returns headers without body |
| `PUT` | Upload; body is written to a staging temp file and **atomically renamed onto the target** on completion (an interrupted PUT never leaves a half-written object). Returns 201 on create, 204 on overwrite |
| `DELETE` | Removes files and empty directories |
| `MKCOL` | Creates a directory; trailing slash in URL is accepted |
| `COPY` | Server-side local copy (RFC 4918 §9.8) when `xrootd_webdav_allow_write on`; HTTP-TPC pull (`Source:` header) or push (`Destination: https://…` header) when `xrootd_webdav_tpc on` |
| `PROPFIND` | `Depth: 0` for stat, `Depth: 1` for directory listing; returns `207 Multi-Status` XML |
| `LOCK` | Acquire or refresh an exclusive write lock for a resource |
| `UNLOCK` | Release a previously held exclusive write lock |

---

## Conditional requests at a glance

The many RFC 7232 rows below collapse into one precedence ladder. The weak ETag
`W/"mtime-size"` and the file mtime are evaluated *before* the body or the write:

```text
  GET / HEAD                              PUT (write)
  ──────────                              ───────────
  If-Match: <etag>                        If-Match: <etag>
     mismatch ──▶ 412                         mismatch ──▶ 412
     match    ──▶ continue                    match    ──▶ continue
  If-None-Match: <etag> | *               If-None-Match: *
     match ──▶ 304 (cached)                   target exists ──▶ 412
     none  ──▶ continue                       target absent ──▶ continue
  If-Modified-Since: <date>                          │
     not newer ──▶ 304                               ▼
     newer     ──▶ continue              parent missing ──▶ 409 Conflict
        │                                          │
        ▼                                          ▼
  Range: bytes=…                          target existed?
     satisfiable   ──▶ 206 + Content-Range   yes ──▶ 204 No Content
     beyond EOF    ──▶ 416                    no  ──▶ 201 Created
     none          ──▶ 200 full body
```

## RFC compliance

The automated test suite (`tests/test_http_webdav_status_codes.py` and
`tests/test_https_webdav_status_codes.py`) checks both correct behaviour and RFC
compliance.  Compliance gaps are marked `@pytest.mark.xfail` with the RFC
citation; they appear as `x` in test output and flip to `X` once resolved.

### Compliant behaviour

| Feature | RFC | Status |
|---|---|---|
| GET with `Range` / 206 Partial Content | RFC 7233 | ✅ |
| GET with `Range` beyond EOF / 416 | RFC 7233 §4.4 | ✅ |
| `Content-Range` header on 206 | RFC 7233 §4.2 | ✅ |
| ETag in GET/HEAD responses | RFC 7232 §2.3 | ✅ |
| `If-Modified-Since` on GET — future date → 304 | RFC 7232 §3.3 | ✅ |
| `If-Modified-Since` on GET — past date → 200 | RFC 7232 §3.3 | ✅ |
| `If-Match` on GET — correct ETag → 200 | RFC 7232 §3.1 | ✅ |
| `If-Match` on GET — wrong ETag → 412 | RFC 7232 §3.1 | ✅ |
| `If-None-Match` on GET — matching ETag → 304 | RFC 7232 §3.2 | ✅ |
| `If-None-Match` on GET — wrong ETag → 200 | RFC 7232 §3.2 | ✅ |
| `If-Unmodified-Since` — past date → 412 | RFC 7232 §3.4 | ✅ |
| `If-Unmodified-Since` — future date → 200 | RFC 7232 §3.4 | ✅ |
| `If-None-Match: *` on PUT to existing → 412 | RFC 7232 §3.2 | ✅ |
| `If-None-Match: *` on PUT to new → 201 | RFC 7232 §3.2 | ✅ |
| `If-Match: <wrong>` on PUT → 412 | RFC 7232 §3.1 | ✅ |
| `If-Match: *` on PUT to existing → 204 | RFC 7232 §3.1 | ✅ |
| PUT new file → 201 Created | RFC 4918 §9.7 | ✅ |
| PUT overwrite → 204 No Content | RFC 4918 §9.7 | ✅ |
| PUT to missing parent → 409 Conflict | RFC 4918 §9.7.1 | ✅ |
| DELETE file → 204 | RFC 4918 §9.6 | ✅ |
| DELETE missing file → 404 | RFC 4918 §9.6 | ✅ |
| MKCOL new → 201 | RFC 4918 §9.3 | ✅ |
| MKCOL existing → 405 | RFC 4918 §9.3.1 | ✅ |
| MKCOL missing parent → 409 | RFC 4918 §9.3.1 | ✅ |
| MOVE to new destination → 201 | RFC 4918 §9.9 | ✅ |
| MOVE with overwrite → 204 | RFC 4918 §9.9 | ✅ |
| MOVE with `Overwrite: F`, dest exists → 412 | RFC 4918 §9.9 | ✅ |
| MOVE missing source → 404 | RFC 4918 §9.9 | ✅ |
| COPY to new destination → 201 | RFC 4918 §9.8 | ✅ |
| COPY with overwrite → 204 | RFC 4918 §9.8 | ✅ |
| COPY with `Overwrite: F`, dest exists → 412 | RFC 4918 §9.8 | ✅ |
| COPY missing source → 404 | RFC 4918 §9.8 | ✅ |
| COPY preserves source | RFC 4918 §9.8 | ✅ |
| PROPFIND `Depth: 0` → 207 with self only | RFC 4918 §9.1 | ✅ |
| PROPFIND `Depth: 1` → 207 with children | RFC 4918 §9.1 | ✅ |
| PROPFIND body is valid XML | RFC 4918 §9.2.2 | ✅ |
| LOCK / UNLOCK | RFC 4918 §9.10, §9.11 | ✅ |
| Exclusive write locks | RFC 4918 §7 | ✅ |

### Previously known gaps — now resolved

All previously identified RFC compliance gaps have been fixed:

| Feature | RFC | Fix |
|---|---|---|
| ETag in GET/HEAD responses | RFC 7232 §2.3 | `W/"mtime-size"` weak ETag added by `xrootd_http_add_etag_header()` in `src/core/compat/http_file_response.c` |
| `If-Modified-Since` on GET → 304 | RFC 7232 §3.3 | Direct check in `src/protocols/webdav/get.c` before range processing |
| `If-None-Match: *` on PUT to existing → 412 | RFC 7232 §3.2 | Pre-open check in `src/protocols/webdav/put.c` |
| `If-Match: <wrong>` on PUT → 412 | RFC 7232 §3.1 | Pre-open ETag comparison in `src/protocols/webdav/put.c` |
| PUT with missing parent collection → 409 | RFC 4918 §9.7 | Map `NGX_HTTP_NOT_FOUND` from `resolve_path` to 409 in `put.c` |
| MOVE method | RFC 4918 §9.9 | New `src/protocols/webdav/move.c` with `rename(2)`, `Overwrite:T/F`, 201/204 |
| COPY method (server-side) | RFC 4918 §9.8 | New `src/protocols/webdav/copy.c` with `copy_file_range(2)` + read/write fallback, `Overwrite:T/F`, 201/204 |
| LOCK / UNLOCK | RFC 4918 | `src/protocols/webdav/lock.c` with xattr-based lock state (`user.nginx_xrootd.lock`) and enforcement in write methods |

---

## Testing with curl

```bash
PROXY=/path/to/proxy_cert.pem
CA=/etc/grid-security/certificates/ca.pem

# OPTIONS
curl -sk --cert $PROXY --key $PROXY --cacert $CA \
  -X OPTIONS https://host:8443/ -I

# Upload
curl -sk --cert $PROXY --key $PROXY --cacert $CA \
  -X PUT https://host:8443/file.txt --data-binary @localfile.txt

# Download
curl -sk --cert $PROXY --key $PROXY --cacert $CA \
  https://host:8443/file.txt -o downloaded.txt

# Stat (PROPFIND Depth:0)
curl -sk --cert $PROXY --key $PROXY --cacert $CA \
  -X PROPFIND -H "Depth: 0" https://host:8443/file.txt

# Create directory
curl -sk --cert $PROXY --key $PROXY --cacert $CA \
  -X MKCOL https://host:8443/newdir/
```

Bearer-token requests use a normal HTTP `Authorization` header:

```bash
TOKEN=$(python3 utils/make_token.py gen \
  --scope "storage.read:/ storage.write:/" /tmp/xrd-test/tokens)

curl -sk -H "Authorization: Bearer $TOKEN" \
  https://host:8443/file.txt -o downloaded.txt

curl -sk -X PUT -H "Authorization: Bearer $TOKEN" \
  --data-binary @localfile.txt https://host:8443/file.txt
```

---
