[← Operations overview](operations-guide.md)

## Reading files

Open, read, stat, dirlist — every read-side operation with examples and edge-case notes.

The read family all starts with an open handle, but the response shape differs:

```text
kXR_open(path, READ) -> handle
        |
        +-- kXR_read
        |      contiguous bytes
        |      cleartext regular files can use file-backed nginx buffers
        |
        +-- kXR_pgread
        |      4 KiB pages + CRC32c per page
        |      response terminates with kXR_status
        |
        +-- kXR_readv
               many non-contiguous ranges
               packed into one vector response
```

Use `kXR_read` mentally for "copy this file sequentially", `kXR_readv` for
"read scattered byte ranges efficiently", and `kXR_pgread` for modern clients
that want page-level integrity checks during large transfers.

### `kXR_stat` — file and directory information

Returns the inode number, size (bytes), flags (readable/writable/directory), and modification time for a path.

```bash
xrdfs localhost:1094 stat /store/mc/sample.root
# Path:   /store/mc/sample.root
# Id:     12345
# Flags:  16 (IsReadable)
# Size:   2147483648
# MTime:  2026-04-14 10:00:00
```

```python
from XRootD import client
fs = client.FileSystem("root://localhost:1094")
status, stat_info = fs.stat("/store/mc/sample.root")
print(stat_info.size)       # file size in bytes
print(stat_info.modtime)    # last modification time
```

You can also stat by open file handle (after `kXR_open`).

---

### `kXR_open` — open a file for reading

Opens a file and returns a file handle (a 4-byte opaque token used in subsequent read requests).

Up to 16 files can be open simultaneously per connection.

```python
from XRootD import client
from XRootD.client.flags import OpenFlags

f = client.File()
status, _ = f.open("root://localhost:1094//store/mc/sample.root", OpenFlags.READ)
# f is now open and ready for kXR_read
```

**Opening directories**: returns `kXR_isDirectory` — you cannot read a directory as a file.

---

### `kXR_read` — read data from an open file

Reads up to 4 MB in a single request. For larger reads, the client automatically retries at the new offset.

```python
status, data = f.read(offset=0, size=1048576)   # read 1 MB from offset 0
```

```bash
xrdcp root://localhost:1094//store/mc/sample.root /tmp/local.root
# xrdcp handles the chunking automatically
```

---

### `kXR_pgread` — paged read with CRC32c integrity

The v5 paged-read protocol. The server splits the requested range into 4 KiB pages, appends a CRC32c checksum to each, and streams them in `kXR_oksofar` chunks terminated by a `kXR_status` frame. Clients use the checksums to detect silent data corruption in transit.

```python
# The Python client automatically uses pgread when available
status, data = f.read(offset=0, size=1048576)
```

When nginx is built with `--with-threads`, the `pread(2)` and CRC computation run on a thread-pool worker so disk latency does not block the event loop.

---

### `kXR_readv` — scatter-gather vector read

Reads multiple non-contiguous byte ranges in a single round-trip. This is significantly more efficient than issuing multiple individual `kXR_read` requests when you know which parts of a file you need — common in ROOT file access where the file index is read first to find the data.

Up to 1024 segments per request. Segments can span multiple open files.

```python
# Read three non-contiguous ranges from an open file
chunks = [(0, 100), (4096, 512), (1_048_576, 8192)]
status, result = f.vector_read(chunks)

for chunk in result:
    print(f"offset={chunk.offset} size={len(chunk.buffer)}")
```

---

### `kXR_dirlist` — list a directory

Lists all entries in a directory. Optionally returns stat information for each
entry alongside its name (enabled with the `STAT` flag). The checksum flag
(`DirListFlags.Cksm` in XRootD clients that expose it) implies stat mode and
adds a per-entry checksum token such as `adler32:1a2b3c4d`.

```bash
xrdfs localhost:1094 ls /store/mc
xrdfs localhost:1094 ls -l /store/mc   # with stat info
```

```python
from XRootD.client.flags import DirListFlags

status, listing = fs.dirlist("/store/mc", DirListFlags.STAT)
for entry in listing:
    print(entry.name, entry.statinfo.size)
```

---

### `kXR_locate` — file replica location query

`kXR_locate` asks the server for one or more replica locations for a given path. For a simple data server the module returns a single-entry location string in the format `"S<access><host:port>"` where `S` indicates the endpoint is a server and `<access>` is `r` (read-only) or `w` (read-write).

Manager-mode mapping: when `xrootd_manager_map` contains a matching prefix the server returns an XRootD `kXR_redirect` response (status `4004`) instead of a normal location list. The redirect body is encoded as a 4-byte big-endian port followed by the host name bytes (ASCII). Clients should parse the first four bytes as the port and the remaining bytes as the host string.

Both `locate` and `open` consult the configured manager map and will return a redirect when a mapping matches; mappings use longest-prefix matching so more-specific prefixes take precedence.

Configure static mappings using the `xrootd_manager_map /prefix host:port;` directive in the server block. See [Manager Mode](manager-mode.md) for details and examples.

### `kXR_statx` — bulk multi-path stat

Returns stat information for multiple paths in a single round-trip. Each result contains the same flags as a regular `kXR_stat` (readable, writable, directory, etc.). Paths that do not exist return a sentinel flags value of `0xFF`.

```python
# No direct Python client API — used internally by xrdfs and some frameworks
# The underlying wire request can be sent via raw socket for batch operations
```

```bash
xrdfs localhost:1094 stat /store/mc/file1.root   # single-path fallback
```

---

### `kXR_close` — close a file handle

Releases an open file handle and logs throughput. All handles are automatically closed when the connection drops.

```python
f.close()
```

---
