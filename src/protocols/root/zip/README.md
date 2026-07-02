# src/protocols/root/zip — ZIP member access (phase-57 W2)

Serve one file inside a ZIP archive as a standalone object across root://,
WebDAV, and S3 GET (opaque `xrdcl.unzip=<member>`). Read-only; matches XrdZip
semantics (stored + deflate members).

## Status

| Piece | File | Status |
|---|---|---|
| Shared parsing kernel | `zip_kernel.{c,h}` | **Done** (callback-driven EOCD/ZIP64 locator + LFH resolver; shared with the native client via libxrdproto) |
| Central-directory reader | `zip_dir.{c,h}` | **Done + unit-tested** (15 checks) — fd adapter over the kernel |
| Standalone parser unit test | `zip_dir_unittest.c` | **Done** (not in nginx build) |
| Virtual member handle I/O | `zip_member.{c,h}` | **Done** (stored + deflate streaming) |
| Full-extract helper (HTTP/S3) | `zip_dir.c` (`xrootd_zip_extract_full`) | **Done** |
| Shared HTTP serving | `zip_http.{c,h}` (`xrootd_zip_http_serve`) | **Done** (stored sendfile / deflate memory / Range) |
| WebDAV GET member path | `../webdav/get.c` | **Done** (uses zip_http) |
| S3 GetObject member path | `../s3/object.c` | **Done** (uses zip_http) |
| `xrootd_{webdav,s3}_zip_access` directives | webdav + s3 modules | **Done** (default off) |
| `xrootd_file_t` zip fields | `../types/file.h` | **Done** |
| Open-path opaque trigger | `../read/open_request.c` | **Done** (`open_extract_zip_member`) |
| read / stat routing | `../read/read.c`, `stat.c` | **Done** (zip_mode branch) |
| handle cleanup | `../connection/fd_table.c` | **Done** (frees inflate, clears zip_*) |
| directive `xrootd_zip_access` + `_cd_max_bytes` | `../stream/module.c`, `../types/config.h`, `../config/server_conf.c` | **Done** (default off) |
| Build registration | `../../config` | **Done** (zip_dir.c + zip_member.c) |
| root:// integration test | `../../tests/test_zip_member.py` | **Done** (8 pass, raw-wire) |

**W2 status: COMPLETE.** root:// (stored+deflate, raw-wire verified), WebDAV GET
and S3 GetObject (stored sendfile / deflate memory / single Range), all opt-in
and verified by `tests/test_zip_member.py` (20 tests).

**Note on `root://` vs HTTP.** The native/stock XrdCl client handles
`?xrdcl.unzip=` **client-side** (reads the archive's central directory + member
bytes and inflates locally), so a native `xrdcp` never hits the server member
path — verified via the access log (it opens the archive and does partial reads).
The server-side `root://` path therefore serves raw/non-plugin clients and is the
shared foundation for the **HTTP/WebDAV/S3 GET** surface, where clients cannot
self-inflate — that is the higher-value remaining work.

Status (stored): a `kXR_open` carrying `?xrdcl.unzip=<member>` opens the archive,
resolves the member, and serves its bytes by offset translation; a bad member
name → kXR_ArgInvalid; a missing member → kXR_NotFound; a deflate member opens
but reads return kXR_Unsupported pending streaming inflate. Gated by
`xrootd_zip_access` (default off).

## zip_dir.c — the parser

Pure C (no nginx / OpenSSL), `pread`-only, fully bounds-checked. Entry point:

```c
int xrootd_zip_find_member(int fd, off_t archive_size, const char *member,
                           size_t cd_max, xrootd_zip_member_t *out);
```

Resolves a member name → `{method, comp_size, uncomp_size, data_off, crc32}` by
reading EOCD → (ZIP64 locator/EOCD when 32-bit fields saturate) → central
directory → the member's local file header (for the true data offset). Rejects
encrypted entries, data-descriptor entries (size unknown at open), methods other
than store(0)/deflate(8), and any out-of-bounds field. `cd_max` caps the
central-directory read (bomb guard). On duplicate names the last entry wins.

## Running the unit test (standalone, no nginx build)

```sh
cd src/protocols/root/zip
python3 - <<'PY'
import zipfile
data = bytes((i*31+7) & 0xff for i in range(100000))
with zipfile.ZipFile("/tmp/ziptest.zip","w") as z:
    z.writestr("stored.txt", b"hello stored member\n", compress_type=zipfile.ZIP_STORED)
    zi = zipfile.ZipInfo("sub/defl.bin"); zi.compress_type = zipfile.ZIP_DEFLATED
    z.writestr(zi, data)
    z64 = zipfile.ZipInfo("big64.txt"); z64.compress_type = zipfile.ZIP_STORED
    with z.open(z64, "w", force_zip64=True) as f: f.write(b"zip64 forced member\n")
PY
gcc -O2 -Wall -Wextra -Werror -D_GNU_SOURCE -DXRDPROTO_NO_NGX -I../compat -I../protocol \
    -o /tmp/zip_dir_unittest \
    zip_kernel.c zip_dir.c ../fs/backend/sd_posix.c zip_dir_unittest.c -lz
/tmp/zip_dir_unittest /tmp/ziptest.zip
```

Verifies resolution + that the bytes at `data_off` decompress to the expected
content (stored copy, deflate inflate, ZIP64-extra member), plus missing-member,
bad-name, and bomb-guard rejection.
