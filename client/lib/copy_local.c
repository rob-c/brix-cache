/*
 * copy_local.c - extracted concern
 * Phase-38 split of copy.c; behavior-identical.
 */
#include "copy_internal.h"


/*
 * Phase 40 (a): build a per-transfer-UNIQUE temp path
 * "<dst>.xrdcp-tmp.<pid>.<seq>". The pid alone is NOT unique under `-j`, whose
 * batch workers are threads sharing one pid — two same-basename sources copied
 * into one directory would otherwise collide on an identical temp name and
 * interleave-corrupt it (then rename a garbage file into place, reported as
 * success). A process-wide atomic sequence makes every concurrent transfer's
 * temp distinct; pids already differ across separate processes. Returns 0, or -1
 * if the composed path would not fit.
 */
int
make_temp_path(const char *dst, char *out, size_t outsz)
{
    static atomic_ulong seq;
    unsigned long s = atomic_fetch_add(&seq, 1ul);
    if ((size_t) snprintf(out, outsz, "%s.xrdcp-tmp.%ld.%lu",
                          dst, (long) getpid(), s) >= outsz) {
        return -1;
    }
    return 0;
}


/*
 * open_download_temp — create a fresh private temp next to `dst` for the
 * download+atomic-rename, and hand back its fd and name.
 *
 * WHY: the temp name is predictable (pid + counter), so an attacker with write
 *      access to the destination directory could pre-create it as a symlink and
 *      redirect our O_TRUNC onto a victim-owned file. O_EXCL refuses a
 *      pre-existing name and O_NOFOLLOW refuses a symlink, closing that race; we
 *      regenerate the name and retry on a stale collision so a leftover temp from
 *      a killed run doesn't wedge the transfer. Returns an fd (caller closes) and
 *      fills tmp[], or -1 with *st set.
 */
int
open_download_temp(const char *dst, char *tmp, size_t tmpsz, brix_status *st)
{
    int attempt;

    for (attempt = 0; attempt < 64; attempt++) {
        int fd;
        if (make_temp_path(dst, tmp, tmpsz) != 0) {
            brix_status_set(st, XRDC_EUSAGE, 0, "destination path too long: %s", dst);
            return -1;
        }
        fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0644);
        if (fd >= 0) {
            return fd;
        }
        if (errno != EEXIST) {
            brix_status_set(st, XRDC_EUSAGE, errno, "open %s: %s",
                            tmp, strerror(errno));
            return -1;
        }
    }
    brix_status_set(st, XRDC_EUSAGE, EEXIST,
                    "could not create a unique temp for %s", dst);
    return -1;
}


/*
 * Commit (or discard) a temp destination: on rc==0 rename `tmp`→`dest`
 * atomically (downgrading rc to -1 with st set if the rename fails); on rc!=0
 * drop the temp. Returns the final rc. Shared by every local-dest writer so the
 * "atomic dest" guarantee lives in one place.
 */
int
atomic_dest_finish(const char *tmp, const char *dest, int rc, brix_status *st)
{
    if (rc == 0) {
        if (rename(tmp, dest) != 0) {
            brix_status_set(st, XRDC_ESOCK, errno, "rename %s -> %s: %s",
                            tmp, dest, strerror(errno));
            unlink(tmp);
            return -1;
        }
        return 0;
    }
    unlink(tmp);   /* drop the partial/cancelled/mismatched temp */
    return rc;
}



/*
 * WHAT: Open the source for read, stream the known-size body to the local sink,
 *       then close the remote handle — the whole "remote file is open" lifetime.
 * WHY:  Confining the open-read handle (and its secondary streams + scratch buf)
 *       to one helper lets the caller stay a flat early-return sequence: the file
 *       is always closed here, on every path, without a shared cleanup jump.
 * HOW:  open_read → streams_open(&ss) → pump(src, sink/sinkctx, si->size) →
 *       file_close.  The caller supplies (sink, sinkctx): either a VFS file via
 *       pump_sink_local_vfs + pump_local_t, or the stdout fd via pump_sink_local.
 *       Returns 0 on a complete transfer, -1 (st set) otherwise.  On open_read
 *       failure the streams are left untouched (ss.n stays 0, so the caller's
 *       streams_close is a no-op) — mirroring the original NULL-init.  The
 *       connection is owned by the caller so it can run the post-transfer checksum
 *       before tearing down.
 */
int
download_stream_body(brix_conn *c, const brix_url *su, const brix_statinfo *si,
                     pump_sink_fn sink, void *sinkctx,
                     const brix_copy_opts *o, brix_streamset *ss,
                     brix_status *st)
{
    brix_file     f;
    pump_remote_t src = {0};
    int           rc;
    char          opq[80];
    const char   *opaque = NULL;

    /* phase-42 W4: request inline read compression when --compress was given.
     * Rides the open opaque; the server confirms via the open reply and
     * brix_file_read transparently inflates.  A server that doesn't support it
     * just returns plaintext (f.read_codec stays 0), so this is always safe. */
    if (o->compress != NULL && o->compress[0] != '\0') {
        snprintf(opq, sizeof(opq), "xrootd.compress=%s", o->compress);
        opaque = opq;
    }
    /* Open the remote handle, retried within max_stall on a transport fault
     * (reconnecting between attempts): the open is the last single-RTT step of
     * setup and is just as sever-prone as connect/stat on a lossy link. */
    {
        int      stall = copy_stall_ms(o, 60000);
        uint64_t deadline = brix_mono_ns() + (uint64_t) stall * 1000000ULL;
        unsigned attempt = 0;
        for (;;) {
            int orc = (opaque != NULL)
                      ? brix_file_open_opaque(c, su->path, opq, 0, 0, 0, &f, st)
                      : brix_file_open_read(c, su->path, &f, st);
            if (orc == 0) {
                break;
            }
            if (!brix_status_retryable(st) || brix_copy_quit_requested()
                || brix_mono_ns() >= deadline) {
                return -1;
            }
            brix_backoff_sleep_fast(attempt++);
            const char *h = (c->home_host[0] != '\0') ? c->home_host : c->host;
            int         p = (c->home_port != 0) ? c->home_port : c->port;
            (void) brix_reconnect(c, h, p, st);   /* re-establish, then reopen */
        }
    }

    /* M8: attach N-1 bound secondary streams to the (post-redirect) session. */
    brix_streams_open(ss, c, o->streams, st);

    /* remote (known si->size) → caller-supplied sink, with progress.  Resilient:
     * a sever mid-read reconnects + reopens at offset and adapts the request size,
     * so a one-shot download rides out a flaky/lossy link. */
    src.c = c;
    src.f = &f;
    src.pgrw = o->pgrw;
    src.resilient = 1;
    src.path = su->path;
    src.opaque = opaque;
    src.max_stall_ms = copy_stall_ms(o, 60000);
    src.cur_chunk = XRDC_COPY_CHUNK;
    rc = transfer_pump(pump_src_remote, &src, sink, sinkctx,
                       si->size, o, si->size, st);

    {
        brix_status throwaway;
        brix_status_clear(&throwaway);
        brix_file_close(c, &f, rc == 0 ? st : &throwaway);
    }
    return rc;
}


int
copy_download(const brix_url *su, const brix_url *du, const brix_copy_opts *o,
              const brix_opts *co, brix_status *st)
{
    brix_conn     c;
    brix_statinfo si;
    brix_streamset ss;
    int            to_stdout = (du->scheme == XRDC_SCHEME_STDIO);
    int            stall = copy_stall_ms(o, 60000);
    int            rc;

    ss.n = 0;   /* so the streams teardown is a no-op if we never bind */
    if (resilient_setup(&c, su, co, &si, stall, st) != 0) {
        return -1;
    }
    if (si.flags & kXR_isDir) {
        brix_status_set(st, XRDC_EUSAGE, 0, "source is a directory (use -r, M5)");
        brix_close(&c);
        return -1;
    }

    if (to_stdout) {
        /* stdio path: pump directly to STDOUT_FILENO — no temp, no VFS, no commit */
        int stdoutfd = STDOUT_FILENO;
        rc = download_stream_body(&c, su, &si, pump_sink_local, &stdoutfd,
                                  o, &ss, st);
        if (rc == 0 && o->cksum != NULL) {
            /* stdout has no on-disk file; cksum_verify skips gracefully on NULL */
            int ck = cksum_verify(&c, su->path, NULL, o->cksum, o->silent, st);
            if (ck == XRDC_CK_MISMATCH) {
                rc = -1;
            } else if (ck == XRDC_CK_UNVERIFIED) {
                if (!o->silent) {
                    fprintf(stderr, "xrdcp: %s downloaded but checksum NOT verified: "
                                    "%s\n", du->path, st->msg);
                }
                brix_status_clear(st);
            }
        }
        brix_streams_close(&ss);
        brix_close(&c);
        return rc;
    }

    /* Local file path: existence-check preserving the original error message,
     * then open via VFS (atomic temp+rename and optional io_uring inside the backend).
     * commit() does fsync+rename; abort() unlinks the temp on any failure or
     * checksum mismatch so the final destination is never a partial/corrupt file. */
    if (!o->force && access(du->path, F_OK) == 0) {
        brix_status_set(st, XRDC_EUSAGE, 0,
                        "destination exists (use -f to overwrite): %s",
                        du->path);
        brix_close(&c);
        return -1;
    }

    {
        brix_vfs_file     *vf = NULL;
        brix_vfs_open_opts vopts;
        pump_local_t       lc;
        int                committed = 0;

        vopts.io_uring      = o->io_uring;
        vopts.expected_size = si.size;
        vopts.cred          = NULL;

        if (brix_vfs_open(du->path,
                          XRDC_VFS_WRITE | (o->force ? XRDC_VFS_FORCE : 0),
                          &vopts, &vf, st) != 0) {
            brix_close(&c);
            return -1;
        }

        lc.vf = vf;
        rc = download_stream_body(&c, su, &si, pump_sink_local_vfs, &lc,
                                  o, &ss, st);

        /* Commit on success (fsync + rename temp→final); only then verify the
         * checksum against the committed file.  A genuine MISMATCH drops the
         * committed file and returns error — it is an integrity failure, not a
         * transient fault.  A query hiccup (UNVERIFIED) keeps the good bytes. */
        if (rc == 0) {
            rc = brix_vfs_commit(vf, st);
            if (rc == 0) {
                committed = 1;
                if (o->cksum != NULL) {
                    int ck = cksum_verify(&c, su->path, du->path,
                                         o->cksum, o->silent, st);
                    if (ck == XRDC_CK_MISMATCH) {
                        unlink(du->path);   /* drop committed-but-bad file */
                        rc = -1;
                    } else if (ck == XRDC_CK_UNVERIFIED) {
                        if (!o->silent) {
                            fprintf(stderr, "xrdcp: %s downloaded but checksum "
                                            "NOT verified: %s\n",
                                    du->path, st->msg);
                        }
                        brix_status_clear(st);
                    }
                }
            }
        }
        if (rc != 0 && !committed) {
            brix_vfs_abort(vf);   /* discard the partial temp */
        }
        brix_vfs_close(vf);
    }

    brix_streams_close(&ss);
    brix_close(&c);
    return rc;
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
 */
int
upload_stream_body(const brix_url *su, const brix_url *du,
                   const brix_copy_opts *o, const brix_opts *co,
                   pump_src_fn src, void *srcctx, int64_t total,
                   brix_status *st)
{
    brix_conn      c;
    brix_file      f;
    brix_streamset ss;
    pump_remote_t  sink = {0};
    int            rc;

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
    {
        char        opq[80];
        const char *copq = NULL;
        if (o->compress != NULL && o->compress[0] != '\0') {
            snprintf(opq, sizeof(opq), "xrootd.compress=%s", o->compress);
            copq = opq;
        }
        /* Resilient INITIAL open: a restart can hit during connect/open, before
         * the write loop's resilient sink is reached.  Retry the open with
         * reconnect within the stall window — nothing is written yet, so a fresh
         * create/truncate retry is safe (matches download_stream_body and
         * brix_rfile_open_write).  Subsequent reopens (pump_sink_reopen) switch
         * to in-place update so resumed bytes are never re-truncated. */
        int      stall = copy_stall_ms(o, 60000);
        uint64_t deadline = brix_mono_ns() + (uint64_t) stall * 1000000ULL;
        unsigned attempt = 0;
        for (;;) {
            int orc = (copq != NULL)
                      ? brix_file_open_opaque(&c, du->path, opq, 1, o->force,
                                              o->posc, &f, st)
                      : brix_file_open_write(&c, du->path, o->force, o->posc,
                                             &f, st);
            if (orc == 0) {
                break;
            }
            if (!brix_status_retryable(st) || brix_copy_quit_requested()
                || brix_mono_ns() >= deadline) {
                brix_close(&c);
                return -1;
            }
            brix_backoff_sleep_fast(attempt++);
            const char *h = (c.home_host[0] != '\0') ? c.home_host : c.host;
            int         p = (c.home_port != 0) ? c.home_port : c.port;
            (void) brix_reconnect(&c, h, p, st);
        }
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
     * partial upload, which is exactly the atomicity we want on error.
     *
     * The close is the COMMIT (it renames the staged partial to the destination),
     * so it must be resilient too: a restart landing on the final close would
     * otherwise leave a fully-written-but-uncommitted partial.  Retry the close
     * within the stall window, reconnecting + reopening IN PLACE between attempts
     * — the bytes are all there, so reopen+close simply commits. */
    if (rc == 0) {
        uint64_t deadline = brix_mono_ns()
                          + (uint64_t) sink.max_stall_ms * 1000000ULL;
        unsigned attempt = 0;
        for (;;) {
            if (brix_file_close(&c, &f, st) == 0) {
                break;
            }
            if (brix_copy_quit_requested() || brix_mono_ns() >= deadline) {
                rc = -1;
                break;
            }
            brix_backoff_sleep_fast(attempt++);
            if (pump_sink_reopen(&sink, st) == 0) {
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
                if (brix_stat(&c, du->path, &si, st) == 0 && si.size == total) {
                    brix_status_clear(st);
                    rc = 0;
                    break;
                }
            }
            if (!brix_status_retryable(st) || brix_mono_ns() >= deadline) {
                rc = -1;
                break;
            }
        }
    }
    /* The file is persisted after close — verify its checksum now (connection
     * still open), comparing our local source digest against the server's.
     * For stdin (XRDC_SCHEME_STDIO) there is no on-disk file; pass NULL so
     * cksum_verify skips gracefully instead of trying to open the path. */
    if (rc == 0 && o->cksum != NULL) {
        const char *ck_local = (su->scheme == XRDC_SCHEME_STDIO) ? NULL : su->path;
        int ck = cksum_verify(&c, du->path, ck_local,
                              o->cksum, o->silent, st);
        if (ck == XRDC_CK_MISMATCH) {
            rc = -1;
        } else if (ck == XRDC_CK_UNVERIFIED) {
            if (!o->silent) {
                fprintf(stderr, "xrdcp: uploaded but checksum NOT verified: %s\n",
                        st->msg);
            }
            brix_status_clear(st);   /* could-not-verify is not a transfer failure */
        }
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
        return upload_stream_body(su, du, o, co, pump_src_local, &stdinfd,
                                  -1 /* size unknown */, st);
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
        rc = upload_stream_body(su, du, o, co, pump_src_local_vfs, &lc,
                                total, st);
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
    if (web_auth_headers(du, "PUT", o, co, hdrs, sizeof(hdrs), st) != 0) {
        brix_vfs_close(vf);
        return -1;
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
        return copy_web_download(&su, &du, du.scheme == XRDC_SCHEME_STDIO, o, co, st);
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
