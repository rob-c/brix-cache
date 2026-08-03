/*
 * cache/origin_ns_dirlist.c — origin-side kXR_dirlist for cache
 * write-through/mirroring, plus the small name-vector container the listing is
 * accumulated into (brix_cache_dirlist_*).
 *
 * Split out of origin_ns.c when that file crossed the 600-line cap
 * (coding-standards §1). The seam is a natural one: every other op in
 * origin_ns.c is a single request/response exchange, while dirlist is the only
 * streaming one — it loops kXR_oksofar frames until a terminating kXR_ok — and
 * it owns a container type nothing else there touches. The one thing the two
 * halves still share, the kXR-error→errno mapping, is declared in
 * origin_ns_internal.h. The public entry points are declared in
 * cache_internal.h.
 */

#include "cache_internal.h"
#include "origin_ns_internal.h"
#include "protocols/root/protocol/bootstrap_pack.h"   /* shared request packers */
#include "protocols/root/protocol/frame_hdr.h"        /* xrd_error_body_decode */
#include <errno.h>
#include <stdlib.h>
#include <string.h>

/* ---- kXR_dirlist: origin directory listing (plain names, no stat) --------- */

/* brix_cache_dirlist_init — zero *dl. See cache_internal.h for the field
 * contract; this only clears the struct, no allocation happens here. */
void
brix_cache_dirlist_init(brix_cache_dirlist_t *dl)
{
    ngx_memzero(dl, sizeof(*dl));
}

/* brix_cache_dirlist_free — release every owned name string plus the array,
 * then reset *dl to the zeroed (empty) state so a second call is a no-op.
 * NULL-safe (mirrors brix_cache_origin_close's idempotence). */
void
brix_cache_dirlist_free(brix_cache_dirlist_t *dl)
{
    size_t i;

    if (dl == NULL) {
        return;
    }
    for (i = 0; i < dl->count; i++) {
        free(dl->names[i]);
    }
    free(dl->names);
    ngx_memzero(dl, sizeof(*dl));
}

/* brix_cache_dirlist_add — append a strdup of name[0, len) to *dl, growing
 * the array (doubling from 16) as needed. Returns 0 on success, -1 (errno
 * ENOMEM) on allocation failure — caller aborts the fetch; the caller-owned
 * dl still holds every name added so far and must still be freed. */
static int
brix_cache_dirlist_add(brix_cache_dirlist_t *dl, const char *name, size_t len)
{
    char *copy;

    if (dl->count == dl->cap) {
        size_t   new_cap = (dl->cap == 0) ? 16 : dl->cap * 2;
        char   **grown = realloc(dl->names, new_cap * sizeof(*grown));

        if (grown == NULL) {
            errno = ENOMEM;
            return -1;
        }
        dl->names = grown;
        dl->cap   = new_cap;
    }

    copy = malloc(len + 1);
    if (copy == NULL) {
        errno = ENOMEM;
        return -1;
    }
    ngx_memcpy(copy, name, len);
    copy[len] = '\0';

    dl->names[dl->count++] = copy;
    return 0;
}

/* brix_cache_dirlist_name_is_dot — 1 iff name (len bytes, not NUL-terminated)
 * is "." or "..". The VFS readdir contract (brix_vfs_readdir, vfs_dir.c)
 * never yields these to a protocol handler, so a remote origin that includes
 * them in its kXR_dirlist body must be filtered here to match every other
 * backend's opendir/readdir behaviour. */
static int
brix_cache_dirlist_name_is_dot(const char *name, size_t len)
{
    return (len == 1 && name[0] == '.')
        || (len == 2 && name[0] == '.' && name[1] == '.');
}

/* brix_cache_dirlist_split — split one response frame's body on '\n' (the
 * kXR_dirlist wire delimiter — src/protocols/root/dirlist/handler.c writes
 * "<name>\n" per entry, plain-names mode has no stat/checksum trailer lines
 * to skip) into individual names, appending each non-dot entry to *dl. A
 * trailing partial name (no terminating '\n' — the final frame's last byte
 * is NUL-terminated by the server, not '\n', per handler.c) is still emitted
 * if non-empty, since it is the last name in the whole listing. Returns 0 on
 * success, -1 (errno set) on an allocation failure partway through. */
static int
brix_cache_dirlist_split(brix_cache_dirlist_t *dl, const u_char *body,
    uint32_t dlen)
{
    size_t start = 0, i;

    for (i = 0; i < dlen; i++) {
        if (body[i] != '\n') {
            continue;
        }
        if (i > start && !brix_cache_dirlist_name_is_dot(
                (const char *) body + start, i - start))
        {
            if (brix_cache_dirlist_add(dl, (const char *) body + start,
                                        i - start) != 0)
            {
                return -1;
            }
        }
        start = i + 1;
    }
    /* Trailing bytes with no '\n' (final frame's NUL-terminated tail, or a
     * lone name with no delimiter at all) — treat as one more name. */
    if (start < dlen && !brix_cache_dirlist_name_is_dot(
            (const char *) body + start, dlen - start))
    {
        if (brix_cache_dirlist_add(dl, (const char *) body + start,
                                    dlen - start) != 0)
        {
            return -1;
        }
    }
    return 0;
}

/* brix_cache_origin_dirlist — kXR_dirlist <path> on the origin: plain name
 * listing (no kXR_dstat/kXR_dcksm — dirlist.c's server handler only needs
 * per-entry stat when a caller explicitly asks for it, and sd_xroot's
 * opendir/readdir only need names, matching every other backend's directory
 * iteration contract). Wire request: kXR_dirlist opcode, body = reserved(15)
 * + options(1) at body[15] (xrdw_dirlist_req_pack; options=0 here — no
 * kXR_dstat/kXR_dcksm/kXR_online), payload = the path (no NUL — dlen is the
 * length, matching kXR_rm/kXR_rmdir's payload framing above). The server
 * streams the listing as kXR_oksofar frames of newline-delimited names,
 * ending with a single kXR_ok frame (src/protocols/root/dirlist/handler.c);
 * this loops brix_cache_read_response until that final kXR_ok, splitting and
 * appending each frame's body into *dl via brix_cache_dirlist_split.
 * Returns 0 (dl populated), or -1 with errno set (dl left however far it
 * got — still owned by the caller). */
int
brix_cache_origin_dirlist(brix_cache_fill_t *t,
    brix_cache_origin_conn_t *oc, const char *path, brix_cache_dirlist_t *dl)
{
    uint8_t   body[XRDW_BODY_LEN];
    size_t    pl = (path != NULL) ? strlen(path) : 0;
    size_t    total = sizeof(ClientRequestHdr) + pl;
    u_char   *buf;
    ClientRequestHdr *req;

    if (pl == 0 || pl > 0x7fff) {
        errno = EINVAL;
        return -1;
    }

    {
        xrdw_dirlist_req_t b = { .options = 0 };   /* plain names, no stat */
        xrdw_dirlist_req_pack(&b, body);
    }

    buf = malloc(total);
    if (buf == NULL) {
        errno = ENOMEM;
        return -1;
    }
    ngx_memzero(buf, sizeof(ClientRequestHdr));
    req = (ClientRequestHdr *) buf;
    req->streamid[1] = 8;                    /* unused stream slot */
    req->requestid   = htons(kXR_dirlist);
    ngx_memcpy(req->body, body, XRDW_BODY_LEN);
    req->dlen = htonl((kXR_int32) pl);
    ngx_memcpy(buf + sizeof(ClientRequestHdr), path, pl);

    if (brix_cache_io_send(oc, buf, total) != 0) {
        free(buf);
        errno = EIO;
        return -1;
    }
    free(buf);

    for (;;) {
        uint16_t  status;
        uint32_t  dlen;
        u_char   *rbody = NULL;

        if (brix_cache_read_response(t, oc, &status, &rbody, &dlen,
                                       BRIX_CACHE_FETCH_CHUNK) != 0)
        {
            errno = EIO;
            return -1;
        }

        if (status == kXR_error) {
            errno = brix_cache_origin_status_errno(status, rbody, dlen);
            free(rbody);
            return -1;
        }

        if (status != kXR_ok && status != kXR_oksofar) {
            free(rbody);
            brix_cache_set_error(t, kXR_ServerError, 0,
                                   "cache origin dirlist returned invalid status");
            errno = EIO;
            return -1;
        }

        if (dlen > 0 && brix_cache_dirlist_split(dl, rbody, dlen) != 0) {
            int saved_errno = errno;

            free(rbody);
            errno = saved_errno;
            return -1;
        }
        free(rbody);

        if (status == kXR_ok) {
            return 0;
        }
    }
}
