# Python API Deep-Surface Cross-Backend Test Plan

This document defines a strategy for **maximum exploration** of the `pyxrootd` (XRootD Python API) surface area. It ensures that every implemented feature in the client library is validated against both the **gnuBall** plugin and the **official XRootD** reference server.

---

## 1. Objective: Total Surface Validation
The primary goal is to verify that for every possible `XRootD.client` call, the behavior of `nginx-xrootd` is semantically and technically indistinguishable from an official XRootD daemon.

---

## 2. The Dual-Backend Validation Loop
Every test in this plan must be executed twice, targeting different backends but using identical test logic.

### Environment Variable Control
Backends are toggled using the `TEST_CROSS_BACKEND` environment variable:

| Backend | Command | Purpose |
|---|---|---|
| **Nginx-XRootD** | `TEST_CROSS_BACKEND=nginx pytest ...` | Validate the plugin implementation. |
| **Official XRootD** | `TEST_CROSS_BACKEND=xrootd pytest ...` | Establish the "Ground Truth" (Oracle). |

### The "Oracle" Comparison
A test failure is only considered a bug in `nginx-xrootd` if the same test **passes** against the `xrootd` backend. If it fails on both, it indicates a client-side issue, environmental problem, or an unsupported protocol version.

---

## 3. Deep-Surface API Exploration Matrix

### 3.1 `XRootD.client.File` (Stateful Handles)
Explore all handle-based operations and internal state management.

| Method | Exploration Goal | Validation Metric |
|---|---|---|
| `open()` | Test all combinations of `OpenFlags` (NEW, DELETE, UPDATE, READ, FORCED, MAKEPATH, POSC). | File presence, size, and status code. |
| `read()` | Test small, large, unaligned offsets, and reading past EOF. | MD5 integrity and short-read status. |
| `write()` | Test sequential, random-access, and overlapping writes. | Final file content parity. |
| `sync()` | Verify that data is flushed and visible to other handles. | Sequential consistency. |
| `truncate()` | Shrink/extend files via handle. | `os.path.getsize` matches. |
| `stat()` | Fetch metadata via open handle (handle-stat). | Parity with path-based stat. |
| `readv()` | Vector read from multiple non-contiguous offsets. | Correct data reassembly. |
| `is_open()` | Verify state tracking in the client. | Boolean consistency. |

### 3.2 `XRootD.client.FileSystem` (Stateless Namespace)
Explore global filesystem management and administrative operations.

| Method | Exploration Goal | Validation Metric |
|---|---|---|
| `stat()` | Fetch standard metadata (size, flags, mtime). | Binary parity of `StatInfo`. |
| `statx()` | Bulk stat multiple paths in one round-trip. | Individual result correctness. |
| `dirlist()` | Recursive and non-recursive listings with `DirListFlags`. | Filename set intersection == 100%. |
| `mkdir()` | Create nested directories with `MAKEPATH`. | Directory hierarchy on disk. |
| `rmdir()` | Remove empty and non-empty directories. | `kXR_ArgInvalid` vs `kXR_ok`. |
| `rm()` | Remove files. | `os.path.exists` == False. |
| `mv()` | Atomic rename across directories. | Atomic swap verification. |
| `chmod()` | Update POSIX permissions. | `stat()` flags updated. |
| `truncate()` | Path-based truncation. | Size verification. |
| `query()` | Execute `kXR_query` for checksums, config, and stats. | Response string/buffer parity. |
| `locate()` | Query file locations and instance roles. | `kXR_locate` response format. |
| `prepare()` | Issue staging requests. | Status code progression. |
| `copy()` | Initiate Server-Side Copy (TPC). | File duplication without client proxying. |

### 3.3 Advanced Protocol Features (New Opcodes)
Verify support for modern protocol extensions (v5.2+).

| Feature | Description | Implementation Check |
|---|---|---|
| **kXR_pgread** | Paged read with CRC32c verification. | Automatic checksum validation in client. |
| **kXR_writev** | Scatter-gather writes. | Data integrity of non-contiguous writes. |
| **kXR_sigver** | Request signing. | Success with `kXR_ok` (accepted). |

---

## 4. Semantic Verification Suite

For every API call, we must verify the "Four Pillars of Parity":

1. **Status Code**: `status.code` must match exactly (e.g., `3001` for `kXR_NotFound`).
2. **OS Error Mapping**: `status.errNo` must match (e.g., `2` for `ENOENT`).
3. **Metadata Purity**: Every bit in the `StatInfo.flags` bitmask must be identical.
4. **Data Bit-Identity**: Buffers returned from `read()` or `pgread()` must have identical MD5/Adler32 hashes.

---

## 5. Execution Strategy

### Step 1: Baseline (Official XRootD)
Run the full suite against the official server to ensure the tests are valid and the client library is behaving as expected.
```bash
export TEST_CROSS_BACKEND=xrootd
pytest tests/test_file_api.py -v
pytest tests/test_fs_ops.py -v
pytest tests/test_new_opcodes.py -v
```

### Step 2: Implementation Validation (Nginx-XRootD)
Run the same tests against the plugin.
```bash
export TEST_CROSS_BACKEND=nginx
pytest tests/test_file_api.py -v
pytest tests/test_fs_ops.py -v
pytest tests/test_new_opcodes.py -v
```

### Step 3: Comparative Analysis
Any divergence in output between Step 1 and Step 2 is flagged as a **conformance regression**.
