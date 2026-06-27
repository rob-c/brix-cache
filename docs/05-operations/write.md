[← Operations overview](operations-guide.md)

## Writing files

Write, truncate, sync, mkdir, rm, mv, chmod — every write-side operation with behavior notes and permission requirements.

Write operations require `xrootd_allow_write on` in the server block. A server without this setting returns `kXR_fsReadOnly` for any write request.

The write family mirrors the read family, but current clients usually prefer
the paged-write path because it carries CRC32c integrity fields. A fresh upload
is staged to a temporary/partial file and **atomically moved into place on a
successful `kXR_close`** (see [Atomic uploads](#atomic-uploads-stage-then-move)
below):

```text
kXR_open(path, create/overwrite flags) -> handle on a STAGING file
        |                                  (.part / temp, NOT the final path)
        +-- kXR_pgwrite
        |      [page data + CRC32c]...
        |      verify CRCs -> strip CRC fields -> write raw bytes to STAGING
        |
        +-- kXR_write
        |      raw byte payload from older clients -> STAGING
        |
        +-- kXR_writev
        |      multiple offset/length/data segments in one request -> STAGING
        |
        +-- kXR_sync
        |      fsync the staging file
        |
        v
   kXR_close(handle)
        |
        +-- clean close  -> COMMIT: rename(staging -> final)   (atomic move)
        +-- aborted/drop -> staging partial preserved for resume, final unchanged
        |
        v
   access log includes close-time transfer summary
```

For a write to succeed, three layers must agree: the server-wide write gate,
the auth/path policy, and the filesystem syscall.

```text
write request
    |
    +-- xrootd_allow_write off? -> kXR_fsReadOnly
    |
    +-- token/VO/path policy denies? -> kXR_NotAuthorized
    |
    +-- filesystem rejects? -> mapped filesystem error
    |
    v
write accepted
```

### Atomic uploads: stage then move

Fresh uploads are **never written directly to the destination path.** The server
opens a **staging file** — a temporary/partial file alongside the destination (or
under `xrootd_stage_dir` when configured) — writes every `kXR_write` /
`kXR_pgwrite` / `kXR_writev` payload there, and only **renames it onto the final
path on a clean `kXR_close`**. `rename(2)` on the same filesystem is atomic, so:

```text
   during upload                            on clean close
   ─────────────                            ──────────────
   /data/file.root.part   ◀── writes        rename(.part → file.root)  atomic
   /data/file.root        (absent or old)   /data/file.root  ← new bytes appear
                                            all-at-once; never torn

   client disconnects mid-upload?
   ──────────────────────────────
   /data/file.root.part   ← partial kept (resume), final path untouched
```

- **Applies to:** `root://` create/overwrite opens (`OpenFlags.NEW`/`DELETE`)
  while `xrootd_upload_resume` is on (the default) or POSC (`kXR_posc`) is set;
  **every** WebDAV `PUT` and S3 `PUT`, via the shared
  `xrootd_staged_open()` → `xrootd_staged_commit()` lifecycle
  ([`src/compat/staged_file.c`](../../src/compat/staged_file.c)).
- **Does not apply to in-place updates:** an `OpenFlags.UPDATE` open that modifies
  an existing file at an offset writes **directly** to the file — staging it
  through an empty temp would lose the bytes it does not rewrite.
- **Resume:** with `xrootd_upload_resume` on, the staging partial is
  deterministic and identity-keyed, so a reconnecting client resumes in place
  rather than restarting; the partial is preserved (not unlinked) on a non-clean
  close. See [reload/resume semantics](../09-developer-guide/reload-semantics.md).
- **Cross-device stage dir:** when `xrootd_stage_dir` is on a different filesystem
  than the storage, the commit falls back to copy-then-rename (still atomic at the
  destination).

---

### Opening a file for writing

```python
from XRootD.client.flags import OpenFlags

f = client.File()
# Create or truncate (overwrite if exists)
status, _ = f.open("root://localhost:1094//upload.root",
                   OpenFlags.NEW | OpenFlags.DELETE)
```

Open flags for writing:

| Flag | Meaning |
|---|---|
| `OpenFlags.NEW` | Create the file; fail if it already exists |
| `OpenFlags.DELETE` | Create or overwrite (truncate if exists) |
| `OpenFlags.NEW \| OpenFlags.DELETE` | Same as `DELETE` — create or overwrite |
| `OpenFlags.UPDATE` | Open an existing file for in-place writes |
| `OpenFlags.APPEND` | Open for writes at the end |

---

### `kXR_pgwrite` — paged write with CRC32c (used by xrdcp v5)

The primary write method used by `xrdcp` in XRootD v5. Data is sent in page fragments with CRC32c fields. The module verifies each CRC32c value, strips the CRC fields, and writes the raw data to disk.

```bash
xrdcp /tmp/local_file.root root://localhost:1094//remote_file.root
# xrdcp uses kXR_pgwrite automatically — no user configuration needed
```

```python
# Python client also uses pgwrite automatically when writing
status, _ = f.write(data, offset=0)
```

---

### `kXR_writev` — scatter-gather vector write

Writes multiple non-contiguous byte ranges in a single round-trip. Each segment in the request specifies a file handle, offset, and length, followed by the data. The module applies each segment sequentially and returns a single `kXR_ok` after all writes complete.

```python
# The Python client uses writev when writing multiple disjoint chunks
status, _ = f.write(data, offset=0)   # client decides whether to use writev
```

---

### `kXR_write` — raw write (v3/v4 clients)

Older XRootD clients (v3, v4) use `kXR_write` instead of `kXR_pgwrite`. The module supports both. If you are using a current client, it will use `kXR_pgwrite`.

---

### `kXR_sync` — flush to disk

Ensures all data written to an open handle is flushed to the filesystem (calls `fsync(2)`).

```python
status, _ = f.sync()
```

---

### `kXR_truncate` — resize a file

Truncates a file to a specific size, either by path or by open file handle.

```python
status, _ = fs.truncate("/data/file.root", 1048576)  # truncate to 1 MB
```

---
