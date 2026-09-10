/*
 * sd_gsiftp_copy.c — same-origin server copy for the GridFTP backend.
 *
 * WHAT: Fills the driver's `server_copy` slot: copy one object to another path
 *       on the SAME origin without the client in the loop. Until this existed
 *       the slot was NULL, and `brix_vfs_copy_driver` turned every WebDAV COPY
 *       on a gsiftp-backed export into ENOTSUP — the operation was not slow,
 *       it was absent.
 *
 * WHY:  Without the slot a client that wants /a copied to /b has to GET the
 *       whole object and PUT it back, so the bytes cross the client link twice
 *       and the copy is only as durable as that client's connection. Here they
 *       never leave the gateway<->origin link, and the destination appears
 *       whole or not at all.
 *
 * HOW:  ONE control session does both legs — FTP is sequential on the control
 *       channel, so after the source's 226 the same session is idle and ready
 *       to store. The bytes land in a local scratch file between the legs
 *       (tmpfile(), the same spill the staged write path already takes for
 *       every PUT), because gftp_retrieve PUSHES to a sink while gftp_store
 *       PULLS from a source: the two loops cannot drive each other without a
 *       thread, and a thread per copy is a worse trade than a scratch file.
 *       Publication is the driver's existing idiom — STOR to a random temp
 *       name, then RNFR/RNTO — so a failed copy leaves the destination's old
 *       bytes untouched rather than half-replaced.
 *
 *       The size comes from a stat taken BEFORE the transfer and is enforced
 *       after it: gftp_retrieve is a bounded read, so a short origin answer is
 *       a short file, and publishing that would be silent truncation.
 */

#include "sd_gsiftp_internal.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

typedef struct {
    int   fd;
    off_t written;
} sd_gsiftp_copy_sink_t;


/* Land one retrieved span in the scratch file at its own offset. */
static int
sd_gsiftp_copy_sink(void *ctx, off_t offset, const uint8_t *data, size_t len)
{
    sd_gsiftp_copy_sink_t *sink = ctx;
    size_t                 done = 0;

    while (done < len) {
        ssize_t n = pwrite(sink->fd, data + done, len - done, offset + done);

        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        if (n == 0) {
            errno = ENOSPC;
            return -1;
        }
        done += (size_t) n;
    }
    sink->written += (off_t) len;
    return 0;
}


/*
 * Pull the whole source object into `fd`.
 *
 * `size` is both the request and the acceptance test. gftp_retrieve reads a
 * BOUNDED span, so an origin that answers with fewer bytes than it just
 * reported in its own stat produces a shorter file and no error of its own —
 * the mismatch has to be caught here or the truncation gets published.
 */
static int
sd_gsiftp_copy_fetch(gftp_session_t *session, const char *remote_src,
    off_t size, int fd)
{
    sd_gsiftp_copy_sink_t sink;
    size_t                received = 0;

    sink.fd = fd;
    sink.written = 0;

    if (gftp_retrieve(session, remote_src, 0, (size_t) size,
                      sd_gsiftp_copy_sink, &sink, &received) != 0) {
        return -1;
    }
    if ((off_t) received != size || sink.written != size) {
        errno = EIO;
        return -1;
    }
    return 0;
}


/* Read back the scratch file for the store leg. */
static ssize_t
sd_gsiftp_copy_source(void *ctx, uint8_t *data, size_t cap)
{
    sd_gsiftp_copy_sink_t *source = ctx;
    ssize_t                n;

    do {
        n = pread(source->fd, data, cap, source->written);
    } while (n < 0 && errno == EINTR);
    if (n > 0) {
        source->written += n;
    }
    return n;
}


/*
 * Publish the scratch file at `remote_dst` atomically.
 *
 * The temp name is not a nicety: a COPY that overwrites an existing object by
 * STORing straight onto it replaces a whole file with a partial one for the
 * length of the transfer, and leaves it that way if the transfer fails. A
 * failed publish deletes its own temp rather than leaving litter the operator
 * has to recognise as ours.
 */
static int
sd_gsiftp_copy_publish(gftp_session_t *session, const char *remote_dst, int fd)
{
    sd_gsiftp_copy_sink_t source;
    char                  temp_path[GSIFTP_PATH_CAP];
    int                   rc;

    if (sd_gsiftp_temp_path(remote_dst, temp_path) != 0) {
        return -1;
    }
    source.fd = fd;
    source.written = 0;

    rc = gftp_store(session, temp_path, sd_gsiftp_copy_source, &source);
    if (rc == 0) {
        rc = gftp_expect(session, 300, 399, "RNFR %s", temp_path);
    }
    if (rc == 0) {
        rc = gftp_expect(session, 200, 299, "RNTO %s", remote_dst);
    }
    if (rc != 0) {
        (void) gftp_command(session, "DELE %s", temp_path);
        return -1;
    }
    return 0;
}


/*
 * Resolve both ends and refuse the degenerate case.
 *
 * A copy onto its own path is refused rather than performed: the transfer
 * would work — scratch, temp, rename over the original — but it rewrites a
 * healthy object for no gain, and any failure in the middle would damage the
 * only copy of a file the caller never asked to modify.
 */
static int
sd_gsiftp_copy_paths(const sd_gsiftp_state *state, const char *src,
    const char *dst, char remote_src[GSIFTP_PATH_CAP],
    char remote_dst[GSIFTP_PATH_CAP])
{
    if (sd_gsiftp_path(state, src, remote_src) != 0
        || sd_gsiftp_path(state, dst, remote_dst) != 0) {
        return -1;
    }
    if (strcmp(remote_src, remote_dst) == 0) {
        errno = EINVAL;
        return -1;
    }
    return 0;
}


static ngx_int_t
sd_gsiftp_server_copy_impl(brix_sd_instance_t *inst, const char *src,
    const char *dst, off_t *bytes_out, const brix_sd_cred_t *cred)
{
    sd_gsiftp_state *state = inst->state;
    gftp_session_t   session;
    brix_sd_stat_t   source_stat;
    FILE            *scratch;
    char             remote_src[GSIFTP_PATH_CAP];
    char             remote_dst[GSIFTP_PATH_CAP];
    const char      *proxy;
    int              err = 0;
    int              rc;

    if (sd_gsiftp_select_proxy(state, cred, &proxy, &err) != 0
        || sd_gsiftp_copy_paths(state, src, dst, remote_src, remote_dst) != 0) {
        return NGX_ERROR;
    }
    /* Before the scratch file, not after: a copy of a path that is not there
     * should cost one round trip and no local disk. */
    if (sd_gsiftp_stat_impl(inst, src, &source_stat, cred) != NGX_OK) {
        return NGX_ERROR;
    }
    scratch = tmpfile();
    if (scratch == NULL) {
        return NGX_ERROR;
    }
    if (sd_gsiftp_session(&session, state, proxy) != 0) {
        fclose(scratch);
        return NGX_ERROR;
    }
    rc = sd_gsiftp_copy_fetch(&session, remote_src, source_stat.size,
                              fileno(scratch));
    if (rc == 0) {
        rc = sd_gsiftp_copy_publish(&session, remote_dst, fileno(scratch));
    }
    gftp_session_close(&session);
    fclose(scratch);
    if (rc != 0) {
        return NGX_ERROR;
    }
    if (bytes_out != NULL) {
        *bytes_out = source_stat.size;
    }
    return NGX_OK;
}


ngx_int_t
sd_gsiftp_server_copy(brix_sd_instance_t *inst, const char *src,
    const char *dst, off_t *bytes_out)
{
    return sd_gsiftp_server_copy_impl(inst, src, dst, bytes_out, NULL);
}


ngx_int_t
sd_gsiftp_server_copy_cred(brix_sd_instance_t *inst, const char *src,
    const char *dst, off_t *bytes_out, const brix_sd_cred_t *cred)
{
    return sd_gsiftp_server_copy_impl(inst, src, dst, bytes_out, cred);
}
