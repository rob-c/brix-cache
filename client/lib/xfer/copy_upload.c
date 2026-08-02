/*
 * copy_upload.c - PUT upload path (root:// + web/S3) + copy_web dispatcher.
 * Phase-38 split of copy_local.c; behavior-identical.
 */
#include "copy_internal.h"


/*
 * WHAT: Open the upload destination write handle, retrying reconnect+reopen
 *       within the stall deadline on a transport fault.
 * WHY:  A restart can hit during connect/open, before the write loop's resilient
 *       sink is reached; retrying the INITIAL open is safe because nothing is
 *       written yet, so a fresh create/truncate retry is idempotent (matches
 *       download_open_resilient and brix_rfile_open_write).  Split out so
 *       upload_stream_body stays a flat sequence.
 * HOW:  Issues brix_file_open_opaque (write=1, force, posc) when a compress
 *       opaque is set (ctx->opaque), else brix_file_open_write; on failure applies
 *       csctx_retry_gate and, if it permits, reconnects to home and retries.
 *       Returns 0 with *f open, or -1 (st set) once the retry gate gives up.
 *       `force`/`posc` are the destination open flags.
 */
static int
upload_open_resilient(const copy_stream_ctx_t *ctx, int force, int posc,
                      brix_file *f, brix_status *st)
{
    unsigned attempt = 0;
    for (;;) {
        int orc = (ctx->opaque != NULL)
                  ? brix_file_open_opaque(ctx->c, ctx->path,
                                          ctx->opaque, 1, force, posc,
                                          f, st)
                  : brix_file_open_write(ctx->c, ctx->path, force, posc, f, st);
        if (orc == 0) {
            return 0;
        }
        if (!csctx_retry_gate(st, ctx->deadline_ns, &attempt)) {
            return -1;
        }
        csctx_reopen_home(ctx->c, st);
    }
}


/*
 * WHAT: Resiliently perform the upload's final close, which is the COMMIT
 *       (renames the staged partial onto the destination).
 * WHY:  A restart landing on the final close would otherwise leave a
 *       fully-written-but-uncommitted partial.  Retrying the close within the
 *       stall window — reconnecting + reopening IN PLACE (no truncate) between
 *       attempts — commits it, since the bytes are all present on the server.
 *       Split out so upload_stream_body stays flat.
 * HOW:  Loops brix_file_close (sink->c / sink->f are the connection + handle);
 *       on failure, gives up on cancel/deadline, else backs off and reopens the
 *       partial in place (pump_sink_reopen) to re-commit.  If reopen-in-place
 *       fails a PRIOR close may already have committed with its ack lost to the
 *       sever — for a known size (total >= 0) confirm the commit by the
 *       destination's (sink->path) size and treat as success; otherwise fall back
 *       to retryability.  Returns 0 (committed) or -1 (st set).
 */
static int
upload_close_commit_resilient(pump_remote_t *sink, int64_t total,
                              brix_status *st)
{
    uint64_t deadline = brix_mono_ns()
                      + (uint64_t) sink->max_stall_ms * 1000000ULL;
    unsigned attempt = 0;
    for (;;) {
        if (brix_file_close(sink->c, sink->f, st) == 0) {
            return 0;
        }
        if (brix_copy_quit_requested() || brix_mono_ns() >= deadline) {
            return -1;
        }
        brix_backoff_sleep_fast(attempt++);
        if (pump_sink_reopen(sink, st) == 0) {
            continue;   /* reopened the partial in place — loop re-commits */
        }
        /*
         * Reopen-in-place failed.  A PRIOR close may have already committed
         * (renamed the staged partial onto the destination) with its ack lost
         * to the sever — so the partial is gone and reopen-update NotFounds.
         * Confirm the commit by the destination's size and treat as success.
         * (total < 0 = stdin: no known size, so fall back to retryability.)
         */
        if (total >= 0) {
            brix_statinfo si;
            if (brix_stat(sink->c, sink->path, &si, st) == 0
                && si.size == total) {
                brix_status_clear(st);
                return 0;
            }
        }
        if (!brix_status_retryable(st) || brix_mono_ns() >= deadline) {
            return -1;
        }
    }
}


/*
 * WHAT: Verify a persisted upload's checksum, reconciling the verdict into rc.
 * WHY:  After the commit the file is on the server, so its checksum can be
 *       compared against the local source digest; confining that policy here
 *       keeps upload_stream_body's tail a single call.
 * HOW:  For stdin (XRDC_SCHEME_STDIO) there is no on-disk file, so passes NULL
 *       as the local path (cksum_verify skips gracefully).  MISMATCH returns -1;
 *       UNVERIFIED prints the note (unless silent) and clears st (a could-not-
 *       verify is not a transfer failure); OK returns 0.
 */
static int
upload_reconcile_cksum(brix_conn *c, const brix_url *su, const brix_url *du,
                       const brix_copy_opts *o, brix_status *st)
{
    const char *ck_local = (su->scheme == XRDC_SCHEME_STDIO) ? NULL : su->path;
    int ck = cksum_verify(c, du->path, ck_local, o->cksum, o->silent, st);
    if (ck == XRDC_CK_MISMATCH) {
        return -1;
    }
    if (ck == XRDC_CK_UNVERIFIED) {
        if (!o->silent) {
            fprintf(stderr, "xrdcp: uploaded but checksum NOT verified: %s\n",
                    st->msg);
        }
        brix_status_clear(st);   /* could-not-verify is not a transfer failure */
    }
    return 0;
}


/*
 * WHAT: Connect the destination, open it for write, stream bytes from the
 *       caller-supplied (src, srcctx) into it, then tear the whole remote side
 *       down (file close on success, checksum, bound streams, connection) — the
 *       entire "destination session is up" lifetime.
 * WHY:  Confining the connection / write handle / secondary streams to one helper
 *       keeps copy_upload() a flat early-return sequence whose only lingering
 *       resource is the caller-owned VFS handle.  Both pre-open failure paths
 *       (connect, open_write) return early without entering the finish teardown.
 * HOW:  connect → open_write → streams_open → transfer_pump(src→remote) → finish.
 *       `total` is the known source size for progress and resilient-close checks
 *       (-1 for stdin / unknown).  src is either pump_src_local (stdin) or
 *       pump_src_local_vfs (local file via brix_vfs).  su->path is used as the
 *       local checksum source path (NULL ≡ stdin → cksum_verify skips gracefully).
 *       NOTE: the 8-parameter signature is a frozen extern (called from
 *       copy_block.c) — decomposed body-only, per phase-75 G4.
 */
int
upload_stream_body(const upload_body_ctx *j, pump_src_fn src, void *srcctx,
                   brix_status *st)
{
    const brix_url       *su = j->su;
    const brix_url       *du = j->du;
    const brix_copy_opts *o  = j->o;
    const brix_opts      *co = j->co;
    int64_t               total = j->total;
    brix_conn        c;
    brix_file        f;
    brix_streamset   ss;
    pump_remote_t    sink = {0};
    int              rc;
    int              stall = copy_stall_ms(o, 60000);
    char             opq[80];
    copy_stream_ctx_t ctx = {0};

    ss.n = 0;
    if (brix_connect_resilient(&c, du, co, st) != 0) {
        return -1;
    }

    /* phase-42 W5: request inline write compression when --compress was given —
     * the server decompresses each payload on ingest (brix_file_write compresses
     * transparently once the handle's write_codec is learned).  A server that
     * doesn't support it returns plaintext (write_codec stays 0), so this is safe.
     * Streams are disabled under write compression (the secondaries would carry
     * raw payloads the server can't frame). */
    ctx.c = &c;
    ctx.path = du->path;
    ctx.deadline_ns = brix_mono_ns() + (uint64_t) stall * 1000000ULL;
    if (o->compress != NULL && o->compress[0] != '\0') {
        snprintf(opq, sizeof(opq), "xrootd.compress=%s", o->compress);
        ctx.opaque = opq;
    }
    /* Resilient INITIAL open (retry+reconnect within the stall window). */
    if (upload_open_resilient(&ctx, o->force, o->posc, &f, st) != 0) {
        brix_close(&c);
        return -1;
    }

    /* M8: attach N-1 bound secondary streams to the (post-redirect) session.
     * Skip them when write compression is active (see above). */
    if (f.write_codec == 0) {
        brix_streams_open(&ss, &c, o->streams, st);
    }

    /* local src → remote (EOF-driven), with progress (total = file size or -1).
     * The sink is resilient: a transport sever mid-upload reconnects, reopens the
     * destination IN PLACE (no truncate) and re-issues from the same offset, so an
     * upload survives an nginx restart and resumes from where it left off.  This
     * needs the bytes below the offset to still be on the server: true for a
     * direct-to-final write (default, posc off) and for a server with
     * brix_upload_resume on (deterministic preserved partial).  Re-issuing the
     * same buffer at the same offset is idempotent. */
    sink.c = &c;
    sink.f = &f;
    sink.pgrw = o->pgrw;
    sink.resilient = 1;
    sink.path = du->path;
    sink.posc = o->posc;
    sink.max_stall_ms = copy_stall_ms(o, 60000);
    rc = transfer_pump(src, srcctx, pump_sink_remote, &sink, -1, o, total, st);

    /* Only close the remote file cleanly on success: with POSC, abandoning the
     * handle (connection teardown without close) makes the server discard the
     * partial upload, which is exactly the atomicity we want on error.  The close
     * is the COMMIT, so it is retried resiliently within the stall window. */
    if (rc == 0) {
        rc = upload_close_commit_resilient(&sink, total, st);
    }
    /* The file is persisted after close — verify its checksum now (connection
     * still open), comparing our local source digest against the server's. */
    if (rc == 0 && o->cksum != NULL) {
        rc = upload_reconcile_cksum(&c, su, du, o, st);
    }
    brix_streams_close(&ss);
    brix_close(&c);
    return rc;
}


int
copy_upload(const brix_url *su, const brix_url *du, const brix_copy_opts *o,
            const brix_opts *co, brix_status *st)
{
    if (su->scheme == XRDC_SCHEME_STDIO) {
        /* stdio path: pump from raw STDIN_FILENO; no VFS open */
        int stdinfd = STDIN_FILENO;
        upload_body_ctx uj = { su, du, o, co, -1 /* size unknown */ };
        return upload_stream_body(&uj, pump_src_local, &stdinfd, st);
    }

    /* Local file path: open via VFS (io_uring selection inside the backend) */
    {
        brix_vfs_file     *vf = NULL;
        brix_vfs_open_opts vopts;
        brix_vfs_stat      vst;
        brix_status        tmp_st;
        pump_local_t       lc;
        int64_t            total = -1;
        int                rc;

        vopts.io_uring      = o->io_uring;
        vopts.io_uring_direct = o->io_uring_direct;
        vopts.expected_size = -1;   /* read-only open; hint unused */
        vopts.cred          = NULL;

        if (brix_vfs_open(su->path, XRDC_VFS_READ, &vopts, &vf, st) != 0) {
            return -1;
        }
        brix_status_clear(&tmp_st);
        if (brix_vfs_fstat(vf, &vst, &tmp_st) == 0) {
            total = vst.size;
        }

        lc.vf = vf;
        {
        upload_body_ctx uj = { su, du, o, co, total };
        rc = upload_stream_body(&uj, pump_src_local_vfs, &lc, st);
        }
        brix_vfs_close(vf);
        return rc;
    }
}


/* VFS-backed pull source for an HTTP PUT body: the local source is read through
 * brix_vfs (so its bytes route through the shared SD driver, not a raw fd). */
static ssize_t
web_upload_src_vfs(void *ctx, uint8_t *buf, int64_t off, size_t cap,
                   brix_status *st)
{
    return brix_vfs_pread((brix_vfs_file *) ctx, off, buf, cap, st);
}


int
copy_web_upload(const brix_url *su, const brix_weburl *du, const brix_copy_opts *o,
                const brix_opts *co, brix_status *st)
{
    char               hdrs[8192];
    brix_vfs_file     *vf = NULL;
    brix_vfs_open_opts vopts;
    brix_vfs_stat      vst;
    int                status = 0, rc;

    if (su->scheme == XRDC_SCHEME_STDIO) {
        brix_status_set(st, XRDC_EUSAGE, 0,
                        "web upload needs a regular local file (Content-Length); "
                        "stdin not supported");
        return -1;
    }

    /* Open the local source through the VFS (byte I/O dispatches to the shared
     * SD driver), then fstat it for the Content-Length the PUT must promise. */
    vopts.io_uring      = o ? o->io_uring : 0;
    vopts.io_uring_direct = o ? o->io_uring_direct : 0;
    vopts.expected_size = -1;   /* read-only open; hint unused */
    vopts.cred          = NULL;
    if (brix_vfs_open(su->path, XRDC_VFS_READ, &vopts, &vf, st) != 0) {
        return -1;
    }
    if (brix_vfs_fstat(vf, &vst, st) != 0) {
        brix_vfs_close(vf);
        return -1;
    }
    if (vst.is_dir) {
        /* st_size is only a reliable Content-Length for a non-directory file. */
        brix_vfs_close(vf);
        brix_status_set(st, XRDC_EUSAGE, 0,
                        "web upload source must be a regular file: %s", su->path);
        return -1;
    }
    {
        web_auth_ctx a = { du, "PUT", o, co, st };
        if (web_auth_headers(&a, hdrs, sizeof(hdrs)) != 0) {
            brix_vfs_close(vf);
            return -1;
        }
    }
    {
        /* Resilient by default: Content-Range PUT chunks that reconnect + resume
         * from the server's durable offset, so the upload survives an nginx
         * restart (server brix_webdav_upload_resume).  A plain server commits on
         * the first whole-range chunk, so a single-shot upload still works. */
        int stall = copy_stall_ms(o, XRDC_DEFAULT_MAX_STALL_MS);
        rc = brix_http_upload_resumable(du->host, du->port, du->tls, du->path,
                          hdrs[0] ? hdrs : NULL, web_upload_src_vfs, vf,
                          (long long) vst.size,
                          co ? co->verify_host : 1, co ? co->ca_dir : NULL,
                          XRDC_WEB_TIMEOUT_MS, stall, &status, st);
    }
    brix_vfs_close(vf);
    if (rc == 0 && o && !o->silent) {
        fprintf(stderr, "xrdcp: uploaded %lld bytes (HTTP %d)\n",
                (long long) vst.size, status);
    }
    return rc;
}


/* Dispatch a copy where at least one endpoint is a web URL. */
int
copy_web(const char *src, const char *dst, const brix_copy_opts *o,
         const brix_opts *co, brix_status *st)
{
    int src_web = brix_is_web_url(src);
    int dst_web = brix_is_web_url(dst);

    if (o && o->recursive) {
        brix_status_set(st, XRDC_EUSAGE, 0,
                        "recursive copy is not supported for web (davs/s3) endpoints");
        return -1;
    }
    if (src_web && !dst_web) {                 /* download: web → local/stdout */
        brix_weburl su;
        brix_url    du;
        if (brix_weburl_parse(src, &su) != 0) {
            brix_status_set(st, XRDC_EUSAGE, 0, "bad web source URL");
            return -1;
        }
        if (brix_url_parse(dst, &du, st) != 0) {
            return -1;
        }
        if (du.scheme != XRDC_SCHEME_LOCAL && du.scheme != XRDC_SCHEME_STDIO) {
            brix_status_set(st, XRDC_EUSAGE, 0,
                            "web download destination must be local or '-'");
            return -1;
        }
        {
            web_dl_req rq = { &su, &du, du.scheme == XRDC_SCHEME_STDIO, o, co };
            return copy_web_download(&rq, st);
        }
    }
    if (!src_web && dst_web) {                 /* upload: local → web */
        brix_url    su;
        brix_weburl du;
        if (brix_url_parse(src, &su, st) != 0) {
            return -1;
        }
        if (brix_weburl_parse(dst, &du) != 0) {
            brix_status_set(st, XRDC_EUSAGE, 0, "bad web destination URL");
            return -1;
        }
        if (su.scheme != XRDC_SCHEME_LOCAL && su.scheme != XRDC_SCHEME_STDIO) {
            brix_status_set(st, XRDC_EUSAGE, 0,
                            "web upload source must be a local file");
            return -1;
        }
        return copy_web_upload(&su, &du, o, co, st);
    }
    brix_status_set(st, XRDC_EUSAGE, 0,
                    "web→web copy is not supported (stage via a local file)");
    return -1;
}
