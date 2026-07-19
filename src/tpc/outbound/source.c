#include "tpc/engine/tpc_internal.h"
#include "source_internal.h"

/* File: source.c — TPC remote source pull (open → read loop → close)
 * WHAT: Single public function `tpc_pull_from_source()` executes the complete native XRootD third-party-copy fetch from a remote origin into dst_fd. Phase 1 → builds ClientOpenRequest with src_path + opaque key/org params, sends kXR_open to remote, receives ServerOpenBody fhandle (handles both minimal 4-byte and full 12+ byte responses), extracts fhandle; Phase 2 → streaming read loop via repeated kXR_read requests at TPC_CHUNK_SIZE offsets, accumulates kXR_oksofar + kXR_ok frames per request, writes each frame's body bytes to dst_fd through the VFS core, tracks offset advancement and total bytes_written; Phase 3 → syncs dst_fd through the VFS core for durability, sets result=NGX_OK/xrd_error=0, best-effort remote close via kXR_close. Returns -1 on failure with error message + xrd_error code, 0 on success.
 *
 * WHY: TPC (Third-Party Copy) transfers require the destination server to connect to a remote root:// origin, open the source file, stream all bytes into dst_fd, and close the remote handle. This function encapsulates the entire pull lifecycle — open → read loop → fsync → close — so launch.c/thread.c can delegate it to a thread-pool worker without managing the protocol sequence themselves. Handles peer diversity (minimal vs full ServerOpenBody), oksofar accumulation for large reads, EINTR-safe writes, and best-effort remote cleanup on failure paths.
 *
 * HOW: Build open_buf with ClientOpenRequest header + src_path + opaque "?tpc.key=...&tpc.org=..." → send_all(fd) kXR_open → recv_response fd status/body → check kXR_ok + dlen>=XRD_FHANDLE_LEN → memcpy fhandle → free(body) → offset=0 loop: build ClientReadRequest with streamid[1]=3, kXR_read, fhandle, htobe64(offset), htonl(TPC_CHUNK_SIZE) → send_all → inner for-loop: recv_response accumulating kXR_oksofar/kXR_ok frames → write body bytes to dst_fd using a positional VFS WRITE job at offset+got_this_req → got_this_req+=dlen → offset+=got_this_req → outer loop exits when done=1(got_this_req==0/EOF) or failed=1 → VFS SYNC dst_fd → shared remote-close ladder: build ClientCloseRequest with kXR_close + fhandle → send_all + recv_response (best-effort, discard result). */


/*
 * tpc_pull_from_source — execute the complete native XRootD third-party-copy
 * fetch from a remote origin into t->dst_fd: open the source (Phase 1), stream
 * every byte and fsync (Phase 2/3), then best-effort close the origin handle on
 * either outcome so it is never leaked. Returns 0 on success (t->result=NGX_OK),
 * -1 on failure (t->err_msg / t->xrd_error set). See the per-phase helpers above.
 */
int
tpc_pull_from_source(brix_tpc_pull_t *t, int fd)
{
    u_char fhandle[XRD_FHANDLE_LEN];
    int    rc;

    if (tpc_open_source(t, fd, fhandle) != 0) {
        return -1;
    }

    /*
     * Capture the source's authoritative size BEFORE streaming so the stream
     * loop can distinguish a complete pull from a stopped/truncated one (its only
     * in-band EOF signal — a zero-byte read — is forgeable). A stat socket/framing
     * failure aborts (handle already open, so close it); an errored/size-less stat
     * is not fatal here (policy is weighed in tpc_stream_to_dst).
     */
    if (tpc_stat_source(t, fd) != 0) {
        tpc_close_source(t, fd, fhandle);
        return -1;
    }

    rc = tpc_stream_to_dst(t, fd, fhandle);

    /*
     * Opt-in post-copy integrity: only on a fully-streamed, size-verified file do
     * we query and compare the source checksum. A mismatch turns success into a
     * fail-closed error so the caller unlinks the poisoned destination.
     */
    if (rc == 0 && t->conf != NULL && t->conf->tpc_verify_checksum) {
        rc = tpc_verify_source_checksum(t, fd);
        if (rc != 0) {
            t->result = NGX_ERROR;
        }
    }

    tpc_close_source(t, fd, fhandle);
    return rc;
}
