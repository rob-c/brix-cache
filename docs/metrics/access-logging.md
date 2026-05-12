# Access Logging

This document covers access log configuration, format, rotation, and interpretation patterns for diagnosing client sessions.

---

## Enable

```nginx
xrootd_access_log /var/log/nginx/xrootd_access.log;
```

One line is written per XRootD operation. The file is opened `O_APPEND` and is safe for multiple nginx worker processes to write concurrently.

---

## Log Format

```
<ip> <auth> "<identity>" [<timestamp>] "<verb> <path> <detail>" <status> <bytes> <ms>ms ["<errmsg>"]
```

Before any client-controlled text is written, the logger escapes whitespace, control bytes, quotes, backslashes, and non-ASCII bytes as `\xNN`. This keeps every record single-line and prevents log injection.

| Field | Meaning |
|---|---|
| `ip` | Client IP address |
| `auth` | `gsi` for GSI-only listeners; `anon` for anonymous, token, and mixed listeners in the current implementation |
| `identity` | X.509 subject DN for GSI-only connections; `-` for anonymous, token, mixed, or before authentication completes. Unsafe bytes are escaped as `\xNN`. |
| `timestamp` | `DD/Mon/YYYY:HH:MM:SS +ZZZZ` |
| `verb` | Operation name — see table below |
| `path` | Resolved filesystem path, or `-` for session-level operations. Unsafe bytes are escaped as `\xNN`. |
| `detail` | Extra context — depends on the verb. Unsafe bytes are escaped as `\xNN`. |
| `status` | `OK` or `ERR` |
| `bytes` | File data bytes transferred; `0` for non-data operations |
| `ms` | Server-side processing time in milliseconds |
| `errmsg` | Error description — only appears on `ERR` lines |

### Verbs and their detail fields:

| Verb | What happened | Detail field |
|---|---|---|
| `LOGIN` | Client logged in | Username |
| `AUTH` | GSI certificate verified | `gsi` |
| `STAT` | `kXR_stat` request | `vfs` for filesystem-level stat, `-` otherwise |
| `OPEN` | File opened | `rd` for read-only, `wr` for write |
| `READ` | Data read from file | `offset+length` e.g. `0+4194304` |
| `WRITE` | Data written to file | `offset+length` e.g. `8388608+8388608` |
| `SYNC` | `fsync` called | `-` |
| `CLOSE` | File handle closed | Throughput e.g. `582.54MB/s`, or `interrupted` if connection dropped |
| `DIRLIST` | Directory listed | `stat` if per-entry stat requested, else `-` |
| `MKDIR` | Directory created | `-` |
| `RMDIR` | Directory removed | `-` |
| `RM` | File deleted | `-` |
| `MV` | File renamed | `-` |
| `CHMOD` | Permissions changed | `-` |
| `PING` | Liveness check | `-` |
| `QUERY` | Checksum, space, stats, xattr, finfo, fsinfo, or config query | `cksum`, `space`, `stats`, `xattr`, `finfo`, `fsinfo`, `config` |
| `READV` | Vector read | Segment count, e.g. `3_segs` |
| `PGREAD` | Paged read (`kXR_pgread`) | `offset+length` |
| `WRITEV` | Vector write (`kXR_writev`) | Segment count, e.g. `3_segs` |
| `LOCATE` | File replica location query | `-` |
| `STATX` | Bulk multi-path stat | Path count, e.g. `2_paths` |
| `FATTR` | File extended attribute operation | `get`, `set`, `del`, or `list` |
| `SIGVER` | Request signature verification | `-` |
| `DISCONNECT` | Connection closed | Session summary: `rx=N.NNMiB/s tx=N.NNMiB/s` |

---

## Example Log Lines

### Anonymous upload:
```
127.0.0.1 anon "-" [14/Apr/2026:10:23:45 +0000] "LOGIN - alice" OK 0 0ms
127.0.0.1 anon "-" [14/Apr/2026:10:23:45 +0000] "OPEN /data/upload/file.root wr" OK 0 1ms
127.0.0.1 anon "-" [14/Apr/2026:10:23:45 +0000] "WRITE /data/upload/file.root 0+8388608" OK 8388608 0ms
127.0.0.1 anon "-" [14/Apr/2026:10:23:45 +0000] "WRITE /data/upload/file.root 8388608+8388608" OK 8388608 0ms
127.0.0.1 anon "-" [14/Apr/2026:10:23:46 +0000] "CLOSE /data/upload/file.root 718.20MB/s" OK 52428800 0ms
127.0.0.1 anon "-" [14/Apr/2026:10:23:46 +0000] "DISCONNECT - rx=689.85MB/s tx=0.00MB/s" OK 52428800 76ms
```

### GSI read with failed stat:
```
192.168.1.1 gsi "-" [14/Apr/2026:10:23:44 +0000] "LOGIN - rcurrie" OK 0 0ms
192.168.1.1 gsi "/DC=test/CN=Test\x20User" [14/Apr/2026:10:23:44 +0000] "AUTH - gsi" OK 0 48ms
192.168.1.1 gsi "/DC=test/CN=Test\x20User" [14/Apr/2026:10:23:45 +0000] "STAT /missing.root -" ERR 0 0ms "No\x20such\x20file\x20or\x20directory"
192.168.1.1 gsi "/DC=test/CN=Test\x20User" [14/Apr/2026:10:23:45 +0000] "OPEN /store/mc/data.root rd" OK 0 2ms
192.168.1.1 gsi "/DC=test/CN=Test\x20User" [14/Apr/2026:10:23:45 +0000] "READ /store/mc/data.root 0+4194304" OK 4194304 18ms
192.168.1.1 gsi "/DC=test/CN=Test\x20User" [14/Apr/2026:10:23:46 +0000] "CLOSE /store/mc/data.root 234.56MB/s" OK 4194304 0ms
192.168.1.1 gsi "/DC=test/CN=Test\x20User" [14/Apr/2026:10:23:46 +0000] "DISCONNECT - rx=0.00MB/s\x20tx=234.56MB/s" OK 4194304 1ms
```

---

## Log Rotation

```bash
# Rename the old log, then signal nginx to reopen
mv /var/log/nginx/xrootd_access.log /var/log/nginx/xrootd_access.log.1
kill -USR1 $(cat /run/nginx.pid)
```

nginx reopens all log files without dropping connections.

---

## Interpreting Access Log Patterns

The access log provides per-operation timing and byte counts that Prometheus counters cannot. Use it for diagnosing individual client sessions, tracing slow reads, or auditing which identities accessed which paths.

### Identifying slow reads:

```bash
# Find operations taking more than 500ms
awk '$NF ~ /[0-9]+ms$/ { gsub("ms","",$NF); if ($NF+0 > 500) print }' \
    /var/log/nginx/xrootd_access.log
```

The `ms` field for `READ` and `READV` includes disk latency and any send blocking. A value significantly above what the disk hardware can sustain (e.g. >100ms for a local NVMe for a small read) points to disk contention, cache thrashing, or AIO thread-pool saturation.

### Identifying low-throughput transfers:

```bash
# Print all CLOSE lines with their throughput
grep '"CLOSE' /var/log/nginx/xrootd_access.log
```

The `CLOSE` line reports the throughput achieved for the file handle's lifetime. Compare it to the `DISCONNECT` line on the same IP for session-level throughput. A large gap between the two on a session with multiple files means some files transferred fast and some slow, which can indicate cache cold-start effects or network bursts.

### Identifying connection churn:

A high rate of `LOGIN` lines without subsequent `OPEN` lines on the same IP means clients are completing the session setup but not opening any files. Check for access-denied errors (`ERR` on `STAT` or `OPEN`) immediately following the login, or for clients that probe for file existence and exit on miss.

### Correlating errors with identity:

```bash
# Show all ERR lines grouped by identity
awk '/ERR/ { print $3 }' /var/log/nginx/xrootd_access.log | sort | uniq -c | sort -rn
```

If one DN accounts for the majority of errors, the problem is credential- or path-specific. If errors are spread uniformly across identities, it is more likely a server-side condition (full disk, I/O error, config change).

---

## Next Steps

- See [metrics-overview.md](./metrics-overview.md) for Prometheus metric definitions
- See [metrics-analysis.md](./metrics-analysis.md) for health check interpretation and alerting rules
