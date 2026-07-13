# Wave 0 File #1: xrdcp.c Refactor Plan

**File**: `client/apps/copy/xrdcp.c`  
**Function**: `main` — CCN 187, 527 lines (lines 349-875)  
**Estimated effort**: 2.5–3 days  
**Status**: Ready to begin

## Completed Wave 0 Files

✅ **File #11** (`src/net/proxy/forward_request.c`): CCN 93 → 69 (26-point reduction)
✅ **File #17** (`src/protocols/webdav/propfind_props.c`): CCN 68 → 14 (all functions ≤ 15)

## Current State

The `main()` function is a 527-line monolith that:
- Parses 40+ CLI flags with complex interactions
- Validates flag combinations (--delete + --remove-source conflict, --sync implies --force, etc.)
- Builds credential stores (GSI proxy, bearer tokens, S3 keys, OIDC)
- Expands globs and reads manifests
- Dispatches to 4 different transfer modes (web recursive, single, batch sequential, batch parallel)
- Manages journal lifecycle for resumable transfers

## Extraction Strategy (per plan)

### 1. parse_and_validate_args() — Lines ~349-589
**Extract**: Argument parsing loop + flag validation  
**Signature**:
```c
static int
parse_and_validate_args(int argc, char **argv, brix_copy_opts *opts,
                         brix_opts *conn, char ***pos, size_t *npos,
                         char ***excl, size_t *nexcl, char ***incl, size_t *nincl,
                         const char **from, const char **journal_path,
                         int *resume, int *retries, int *jobs,
                         int *force_progress, int *no_progress, int *verify,
                         int *auto_refresh, const char **oidc_account,
                         const char **proxy, int *sync_mode);
```
**Returns**: 0 = success, 50 = usage error, 51 = OOM  
**Invariants**:
- `--sync` → `opts->force = 1`
- `--delete` requires `-r` and `--sync`
- `--delete` + `--remove-source` → reject (contradictory)
- `--verify` without `--cksum` → `opts->cksum = "adler32:source"`
- `--resume` without `--from <file>` → reject

### 2. build_credential_store() — Lines ~600-670
**Extract**: Alias resolution, glob expansion, credential pre-flight, store build  
**Signature**:
```c
static struct brix_cred_store *
build_credential_store(char **pos, size_t npos, char **exp, size_t nexp,
                        const char *dst, const char *proxy,
                        const char *bearer, const char *s3_access,
                        const char *s3_secret, const char *oidc_account,
                        int auto_refresh, int silent, int dst_is_cred);
```
**New file**: `xrdcp_cred.c` (move `merge_alias_auth` + cred logic)  
**Invariants**:
- Alias resolution happens AFTER argument parsing, BEFORE glob expansion
- Credential diagnosis runs AFTER auto-refresh attempt
- Cred store built BEFORE any transfer

### 3. dispatch_transfer() — Lines ~673-865
**Extract**: Mode routing (web-recursive vs single vs batch) + journal lifecycle  
**Signature**:
```c
static int
dispatch_transfer(char **exp, size_t nexp, const char *dst,
                   brix_copy_opts *opts, brix_opts *conn,
                   const char *journal_path, int retries,
                   int jobs, int sync_mode, int force_progress,
                   int no_progress, struct brix_cred_store *cred_store);
```
**New file**: `xrdcp_mode.c` (dispatch logic)  
**Invariants**:
- Web recursive handled first (exits early)
- Journal opened batch-only (never single, never dry-run)
- Single-file progress bar gated on TTY + not `-` + not silent

### 4. do_single_transfer_with_progress() — Lines ~745-779
**Extract**: Single-file transfer with progress bar setup  
**Signature**:
```c
static int
do_single_transfer_with_progress(const char *src, const char *dst,
                                   brix_copy_opts *opts, brix_opts *conn,
                                   int retries, int sync_mode,
                                   int force_progress, int no_progress,
                                   brix_status *st);
```

### 5. do_batch_transfer() — Lines ~813-858
**Extract**: Batch sequential/parallel dispatcher  
**Signature**:
```c
static int
do_batch_transfer(char **exp, size_t nexp, const char *dst,
                   brix_copy_opts *opts, brix_opts *conn,
                   int retries, int sync_mode, int jobs,
                   brix_journal *jrn);
```

## Execution Order

1. **parse_and_validate_args** (largest, self-contained)
2. **build_credential_store** → move to `xrdcp_cred.c`
3. **do_single_transfer_with_progress** + **do_batch_transfer** (small helpers)
4. **dispatch_transfer** → move to `xrdcp_mode.c`
5. Verify `main()` is now ≤ CCN 15
6. Run tests: `cd client && make test`
7. Regenerate backlog

## Expected Outcome

- `main()`: CCN 187 → ~10 (orchestration only)
- 5 new static helpers in `xrdcp.c`
- 2 new files: `xrdcp_cred.c`, `xrdcp_mode.c`
- `./config` updated with new source files
- All client tests passing
- Backlog entry reduced from CCN 187 to ~10

## Risk Assessment

**Low risk**:
- Client-side tool (no wire protocol changes)
- Extensive test suite (`client/tests/`)
- Flag validation matrix already well-tested
- No shared state with server

**Medium effort**:
- 527-line function is the largest in the codebase
- Flag interaction logic is intricate (40+ flags, 10+ validation rules)
- 5 extractions + 2 file splits

## Ready to Proceed

All prerequisites met:
- ✅ Tests exist (`client/tests/test_copy.py`)
- ✅ Plan documented with seams and invariants
- ✅ No blocking dependencies
- ✅ Build system ready (`./config` can accept new files)

**Next action**: Begin extraction #1 (parse_and_validate_args)
