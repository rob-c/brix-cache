[← Operations overview](operations-guide.md)

## Filesystem management

Namespace operations: mkdir, rm, rmdir, mv, chmod, stat — what gnuBall supports, what it rejects, and what the error codes mean.

These operations require `xrootd_allow_write on`.

### `kXR_mkdir` — create a directory

Creates a directory. With the recursive flag (`kXR_mkdirpath`), creates all intermediate directories as needed (like `mkdir -p`).

```bash
xrdfs localhost:1094 mkdir /store/mc/new_dataset
xrdfs localhost:1094 mkdir -p /store/mc/new_dataset/sub/dir
```

```python
from XRootD.client.flags import MkDirFlags
status, _ = fs.mkdir("/store/mc/new_dataset", MkDirFlags.MAKEPATH)
```

---

### `kXR_rmdir` — remove an empty directory

```bash
xrdfs localhost:1094 rmdir /store/mc/empty_dir
```

```python
status, _ = fs.rmdir("/store/mc/empty_dir")
```

---

### `kXR_rm` — delete a file

```bash
xrdfs localhost:1094 rm /store/mc/unwanted_file.root
```

```python
status, _ = fs.rm("/store/mc/unwanted_file.root")
```

---

### `kXR_mv` — rename or move

Renames a file or directory. Both source and destination must be on the same filesystem (this calls `rename(2)` internally, which is a single atomic syscall and does not copy data).

```bash
xrdfs localhost:1094 mv /store/mc/old_name.root /store/mc/new_name.root
```

```python
status, _ = fs.mv("/store/mc/old.root", "/store/mc/new.root")
```

---

### `kXR_chmod` — change permissions

Changes file or directory permission bits (Unix 9-bit mode: owner/group/other × read/write/execute).

```bash
xrdfs localhost:1094 chmod 0644 /store/mc/file.root
```

```python
from XRootD.client.flags import AccessMode
status, _ = fs.chmod("/store/mc/file.root", AccessMode.UR | AccessMode.UW | AccessMode.GR | AccessMode.OR)
```

---

## Queries

### `kXR_query` — server queries

#### Checksum (`QueryCode.CHECKSUM`)

Returns a checksum for a file. The server supports multiple algorithms; the
default is `adler32` (8 hex digits). You can explicitly request `crc32c`,
`md5`, `sha1` or `sha256` by prefixing the path with the algorithm token using
either `"<alg>:<path>"` or `"<alg> <path>"` (for example
`sha256:/store/mc/sample.root`).

```bash
xrdfs localhost:1094 query checksum /store/mc/sample.root
# adler32 1a2b3c4d

xrdfs localhost:1094 query checksum md5:/store/mc/sample.root
# md5 0123456789abcdef0123456789abcdef

xrdfs localhost:1094 query checksum crc32c:/store/mc/sample.root
# crc32c 89abcdef

xrdfs localhost:1094 query checksum sha256:/store/mc/sample.root
# sha256 0123456789abcdef... (64 hex digits)
```

```python
from XRootD.client.flags import QueryCode
status, resp = fs.query(QueryCode.CHECKSUM, "/store/mc/sample.root")
# resp → b"adler32 1a2b3c4d\x00"
```

`xrdcp` can validate transfers against either adler32 or crc32c when invoked
with `--cksum`.

#### Directory checksum scan (`kXR_Qckscan`)

`kXR_Qckscan` walks a file or directory tree and returns one line per regular
file:

```text
adler32 1a2b3c4d  /store/mc/sample.root
```

The scan runs on the configured stream thread pool when available. Recursive
walks are bounded by `xrootd_ckscan_depth` (default 32) and
`xrootd_ckscan_max_files` (default 100000). The default algorithm is adler32;
`crc32c:<path>` requests return crc32c lines.

#### Space (`QueryCode.SPACE`)

Returns disk space statistics for the `xrootd_root` filesystem in `oss.*` format.

```bash
xrdfs localhost:1094 spaceinfo /
```

```python
status, resp = fs.query(QueryCode.SPACE, "/")
# resp → b"oss.cgroup=default&oss.space=...\x00"
```

#### Stats (`QueryCode.STATS`)

Returns an XML statistics blob summarising open connections, operations, and
server identity. Useful for health checks and monitoring.

```python
status, resp = fs.query(QueryCode.STATS, "")
# resp → b"<statistics>...</statistics>\x00"
```

#### Extended attributes (`QueryCode.XATTR`)

Returns extended attribute key-value pairs for a path (same underlying data as
`kXR_fattr` get/list).

```python
status, resp = fs.query(QueryCode.XATTR, "/store/mc/sample.root")
```

#### File info (`QueryCode.FINFO`)

Returns a hint line describing any compression or checksum annotations stored
on the file. The response is empty when no metadata is present.

```python
status, resp = fs.query(QueryCode.FINFO, "/store/mc/sample.root")
```

#### Filesystem info (`QueryCode.FSINFO`)

Returns filesystem-level metrics for the path's mountpoint in `oss.*` format:
total/free/used bytes, quota, and mount flags.

```python
status, resp = fs.query(QueryCode.FSINFO, "/")
```

#### Configuration (`QueryCode.CONFIG`)

Returns the current value of one or more server configuration keys. Recognised
keys include `bind_max`, `chksum`, `stype`, `version`, `sitename`, and `pio_max`.

```bash
xrdfs localhost:1094 query config version
```

```python
status, resp = fs.query(QueryCode.CONFIG, "version")
```

---

### `kXR_fattr` — file extended attributes

Reads, writes, deletes, and lists Linux `user.*` xattrs on files and directories.
All four subcodes are supported:

| Subcode | Operation |
|---|---|
| `kXR_fattrGet` | Read the value of one or more named attributes |
| `kXR_fattrSet` | Write a named attribute (creates or overwrites) |
| `kXR_fattrDel` | Delete a named attribute |
| `kXR_fattrList` | List all attribute names on the path |

Attribute names are stored under the `user.U.` prefix in the filesystem (e.g. `user.U.checksum`). Requests can be path-based or handle-based (after `kXR_open`).

```bash
xrdfs localhost:1094 xattr /store/mc/sample.root set checksum abc123
xrdfs localhost:1094 xattr /store/mc/sample.root get checksum
xrdfs localhost:1094 xattr /store/mc/sample.root list
xrdfs localhost:1094 xattr /store/mc/sample.root del checksum
```

```python
from XRootD.client.flags import XAttrCode
status, result = fs.set_xattr("/store/mc/sample.root",
                               [client.XAttr("checksum", "abc123")])
status, result = fs.get_xattr("/store/mc/sample.root", ["checksum"])
```

---

## Prepare

`kXR_prepare` is accepted as a local-storage staging hint. The module parses
the official newline-separated path payload, validates each path under
`xrootd_root`, applies authdb, VO ACL, and token-scope checks, and returns
success when all requested files are already online.

With `xrootd_frm on`, `kXR_prepare` creates a durable FRM stage request and
returns a real host-qualified request id instead of the legacy `"0"` id. The
queue survives client disconnects and worker restarts, `kXR_QPrep` reports
queued/staging/failed/available states for known requests, and `kXR_cancel`
removes matching queued work. `kXR_evict` is accepted as a backend-delegated
operation; deployments that require exact tape purge or MSS behavior must test
against their storage manager.

With FRM disabled, the legacy local-storage behavior remains: `kXR_prepare`
performs path validation/existence checks, may invoke `prepare_command` as a
fire-and-forget hook, returns request id `"0"` for stage requests, and
`kXR_QPrep` reports only `A <path>` for present regular files or `M <path>` for
missing/unauthorized paths. In this mode `kXR_cancel` and `kXR_evict` are
acknowledged no-ops.

---

## Unsupported opcodes

The following opcodes return `kXR_Unsupported` and are not implemented:

| Opcode | Reason not implemented |
|---|---|
| `kXR_gpfile` (3005) | Legacy get-from-proxy — obsolete |

---

## Limits

| Limit | Value |
|---|---|
| Simultaneous open files per connection | 16 |
| Maximum contiguous `kXR_read` size per request | 64 MB |
| Maximum `kXR_readv` segment size | 4 MB |
| Maximum write chunk size | 16 MB |
| Maximum path length | 4 KB |
| Maximum `kXR_readv` segments per request | 1024 |
| Maximum total `kXR_readv` response | 256 MB |
| Maximum `kXR_writev` segments per request | 1024 |

---

## Authentication and authorisation notes

All data and namespace operations require a completed session login. When `xrootd_auth` is `gsi`, `token`, or `both`, the client must also complete the advertised security exchange before file operations are accepted.

Native stream write access is controlled by both token/VO authorization and the
server-wide `xrootd_allow_write` gate. JWT/WLCG scopes are enforced on
path-resolving native operations: read scopes for read opens and metadata, and
write/create scopes for write opens and namespace mutations. Handle-based I/O
inherits the authorization decision made at open time. Path-level restrictions
use `xrootd_require_vo`; token `wlcg.groups` claims are mapped into the same VO
list used by VOMS proxies.
