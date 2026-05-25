[← Operations overview](operations-guide.md)

## Writing files

Write, truncate, sync, mkdir, rm, mv, chmod — every write-side operation with behavior notes and permission requirements.

Write operations require `xrootd_allow_write on` in the server block. A server without this setting returns `kXR_fsReadOnly` for any write request.

The write family mirrors the read family, but current clients usually prefer
the paged-write path because it carries CRC32c integrity fields:

```text
kXR_open(path, create/update flags) -> handle
        |
        +-- kXR_pgwrite
        |      [page data + CRC32c]...
        |      verify CRCs -> strip CRC fields -> write raw bytes
        |
        +-- kXR_write
        |      raw byte payload from older clients
        |
        +-- kXR_writev
        |      multiple offset/length/data segments in one request
        |
        +-- kXR_sync
        |      fsync open handle
        |
        v
   kXR_close(handle)
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
