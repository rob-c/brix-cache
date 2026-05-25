#include "open.h"
#include <string.h>
#include <unistd.h>
#include "../manager/registry.h"
#include "../manager/pending.h"
#include "../cms/cms_internal.h"
#include "../session/registry.h"
#include "../cache/writethrough_decision.h"

/* ---- File Open Lifecycle — kXR_open opcode handler and resolved-file opener ----
 *
 * WHAT: This file implements the two functions that handle XRootD's kXR_open request:
 *       xrootd_handle_open() — the protocol-level entry point that parses the open request,
 *                               validates permissions, resolves paths, detects TPC transfers,
 *                               and dispatches to the appropriate handler.
 *       xrootd_open_resolved_file() — the POSIX-level function that opens the actual file on disk,
 *                                     allocates a file handle (fhandle), sets up bookkeeping state,
 *                                     evaluates write-through policy, and assembles the response body.
 *
 * WHY: kXR_open is the densest request in the protocol because it bridges multiple layers:
 *      1. Protocol semantics — flags like kXR_new (create), kXR_mkpath (make parent dirs),
 *         kXR_retstat (return file stats) determine how the open behaves.
 *      2. POSIX operations — actual open(2) call with proper flags, confined path validation,
 *         fd allocation in the global handle table.
 *      3. Bookkeeping — per-handle tracking of readable/writable status, cache origin,
 *         bytes read/written counters, timestamps. All reused by subsequent read/close opcodes.
 *      4. Security gates — authdb checks, VO ACL evaluation, token scope enforcement.
 *      5. TPC detection — third-party copy transfer context embedded in the open path as opaque params. */

/* ---- Section: Path Resolution and Permission Gates (xrootd_handle_open) ----
 *
 * WHAT: The first phase of xrootd_handle_open() determines file access permissions by checking:
 *       1. Manager mode — redirect to data server or CMS upstream locate
 *       2. Static manager map — prefix-based redirection
 *       3. Path resolution — realpath for reads, write resolver for writes
 *       4. Auth layers — authdb (authorization database), VO ACL (virtual organization access control),
 *          token scope (JWT bearer permission)
 *       Each gate returns early on denial with kXR_NotAuthorized error code. */

/* ---- Section: TPC (Third-Party Copy) Detection and Handling ----
 *
 * WHAT: XRootD TPC allows direct server-to-server file transfers without routing through the client.
 *       The transfer context is embedded as CGI-style opaque parameters in the open path payload.
 *       Two roles exist:
 *       - TPC destination (pull): write-open + tpc.src=root://source-host//path + tpc.key=<token>
 *         We fetch the file from source, stream it locally, then return fhandle after pull completes.
 *       - TPC source (serve): read-open with tpc.key=<token> (+ optional tpc.dst=)
 *         We serve normally; the caller is a TPC destination server waiting for bytes.
 *
 * WHY: Native TPC avoids client-side bandwidth bottleneck and reduces latency by streaming
 *      directly between storage servers using shared-shm key registry (src/tpc/key_registry.c). */

/* ---- Section: Cache-Aware Read-Open (xrootd_open_cached_read) ----
 *
 * WHAT: When the cache module is enabled AND the path starts with conf->cache_root,
 *       this function delegates to xrootd_open_cached_read() which handles:
 *       1. ACL check against auth root for cached content access
 *       2. Cache-hit open — serve directly from cached copy on local disk
 *       3. Cache-miss fill trigger — initiate background fetch from origin server
 *
 * WHY: XCache-style caching allows anonymous read opens to populate the cache while serving
 *      concurrent requests, reducing latency for repeated access patterns across sessions. */

/* ---- Section: Write-Through Policy Decision (wt_policy evaluation) ----
 *
 * WHAT: At open time we evaluate write-through policy and cache the decision on the handle.
 *       The cached wt_policy determines close-time flush behavior — whether dirty writes are
 *       flushed to origin before closing, synchronously or asynchronously. */

/* ---- Section: File Open and Handle Allocation (xrootd_open_resolved_file) ----
 *
 * WHAT: This function performs the actual POSIX open(2) call with proper security guarantees:
 *       1. POSC mode — staging temp file for persist-on-successful-close writes
 *       2. Confined open — xrootd_open_confined() prevents post-open path escape attacks
 *       3. Handle allocation — xrootd_alloc_fhandle() assigns a slot (0–255) in fd_table.c
 *       4. Bookkeeping initialization — readable/writable flags, cache origin, inode/device tracking,
 *          byte counters, timestamps, read-ahead state. */

/* ---- Section: Response Assembly and Logging ----
 *
 * WHAT: After successful open we assemble the kXR_ok response body containing:
 *       1. ServerOpenBody with fhandle (single-byte handle ID) and cpsize=0
 *       2. Optional retstat string if client requested file statistics: inode, size, flags, mtime
 *       3. Publish to session registry if not yet bound (manager/cluster mode) */

/*
 * ---- Function: xrootd_handle_open() ----
 *
 * WHAT: Protocol-level entry point for kXR_open. Parses the open request,
 * validates permissions via authdb/VO ACL/token scope checks, resolves paths
 * based on read/write mode, detects TPC transfers from opaque parameters, and
 * dispatches to either cached-read or resolved-file opener.
 *
 * WHY: kXR_open bridges protocol semantics, POSIX operations, security gates,
 * bookkeeping initialization for subsequent read/close opcodes, and TPC context
 * detection. The dispatch decision determines whether we serve cached content
 * or open a fresh file on disk.
 */

/*
 * ---- Function: xrootd_open_resolved_file() ----
 *
 * WHAT: POSIX-level function that performs the actual open(2) call with proper
 * security guarantees. Handles confined open, handle allocation (fhandle 0-255),
 * bookkeeping initialization, and write-through policy evaluation.
 *
 * WHY: The confined open prevents post-open path escape attacks (critical
 * security invariant). Handle allocation is reused by read/pgread/readv/write
 * opcodes. Write-through policy determines whether dirty writes flush to origin
 * synchronously or asynchronously before close.
 */

/*
 * Extract the opaque query string (everything after '?') from the raw open
 * payload into out[].  Returns 1 if a '?' was found, 0 otherwise.
 */
int
open_extract_opaque(const u_char *payload, size_t payload_len, char *out,
    size_t out_size)
{
    const u_char *question_mark;
    const u_char *opaque_start;
    size_t        opaque_len;

    out[0] = '\0';
    question_mark = memchr(payload, '?', payload_len);
    if (question_mark == NULL) {
        return 0;
    }

    opaque_start = question_mark + 1;
    opaque_len = payload_len - (size_t) (opaque_start - payload);

    /* Trim trailing NUL byte that kXR_open payloads may carry. */
    if (opaque_len > 0 && opaque_start[opaque_len - 1] == '\0') {
        opaque_len--;
    }
    if (opaque_len == 0 || opaque_len >= out_size) {
        return 0;
    }

    memcpy(out, opaque_start, opaque_len);
    out[opaque_len] = '\0';
    return 1;
}

