#include "ftp_ev.h"

#include "fs/vfs/vfs.h"
#include "fs/vfs/vfs_ops.h"
#include "core/compat/checksum_core.h"

#include <openssl/evp.h>   /* EVP_MAX_MD_SIZE for CKSM digest output */
#include <stdio.h>         /* sscanf/snprintf for CKSM parsing/format */
#include <strings.h>       /* strcasecmp */
#include <time.h>          /* gmtime_r / strftime for MDTM/facts     */

/*
 * ftp_ev_cmd.c — namespace and metadata verbs that complete on the control
 * channel (no data connection): CWD, SIZE, MKD/DELE/RMD, MDTM/MLST/STAT/CKSM,
 * and the RNFR/RNTO rename pair.
 *
 * WHAT: each handler resolves its path argument under the export, performs one
 * VFS operation, and queues a single reply.
 *
 * WHY: these are pure request→reply verbs — no socket I/O beyond the reply — so
 * they carry over from the sync engine essentially unchanged, now writing through
 * the event reply queue instead of a blocking send.  Keeping them out of the
 * dispatcher keeps that file focused on routing.
 *
 * HOW: brix_ftp_ev_resolve() confines the path (INVARIANT 4), brix_ftp_ev_vfs_ctx()
 * builds the identity-bearing context, and the brix_vfs_* seam performs the
 * operation; write verbs gate on conf->allow_write first (INVARIANT 3-adjacent).
 */


/* Format a VFS entry's RFC 3659 facts into `out`; returns the byte count. */
static size_t
ev_fmt_facts(char *out, size_t outsz, const brix_vfs_stat_t *st)
{
    struct tm tm;
    char      mtime[32];
    time_t    t = st->mtime;

    mtime[0] = '\0';
    if (gmtime_r(&t, &tm) == NULL
        || strftime(mtime, sizeof(mtime), "%Y%m%d%H%M%S", &tm) == 0)
    {
        /* strftime leaves the buffer contents indeterminate when it returns 0,
         * so a year gmtime_r accepts but the format cannot render would put
         * uninitialised bytes straight into an MLST fact line.  Re-clamp to
         * empty and emit "modify=" with no value rather than garbage. */
        mtime[0] = '\0';
    }
    return (size_t) snprintf(out, outsz,
        "type=%s;size=%lld;modify=%s;perm=%s;",
        st->is_directory ? "dir" : "file",
        (long long) st->size, mtime,
        st->is_directory ? "el" : "r");
}


ngx_int_t
brix_ftp_ev_cmd_cwd(ftp_ev_t *fc, const char *arg)
{
    char        abs[PATH_MAX];
    char        logical[PATH_MAX];
    size_t      rlen;
    const char *tail;

    if (brix_ftp_ev_resolve(fc, arg, abs, sizeof(abs)) != 0) {
        return brix_ftp_ev_reply(fc, "550 No such directory\r\n");
    }
    /* Re-derive the logical form for display / future joins by stripping the
     * root_canon prefix off `abs`. */
    rlen = ngx_strlen(fc->conf->root_canon);
    tail = abs + rlen;
    if (tail[0] == '\0') {
        tail = "/";
    }
    if (ngx_strlen(tail) >= sizeof(logical)) {
        return brix_ftp_ev_reply(fc, "550 Path too long\r\n");
    }
    ngx_memcpy(fc->cwd, tail, ngx_strlen(tail) + 1);
    return brix_ftp_ev_reply(fc, "250 Directory changed to %s\r\n", fc->cwd);
}


ngx_int_t
brix_ftp_ev_cmd_size(ftp_ev_t *fc, const char *arg)
{
    char            abs[PATH_MAX];
    brix_vfs_ctx_t  vctx;
    brix_vfs_stat_t st;

    if (brix_ftp_ev_resolve(fc, arg, abs, sizeof(abs)) != 0) {
        return brix_ftp_ev_reply(fc, "550 No such file\r\n");
    }
    brix_ftp_ev_vfs_ctx(fc, abs, &vctx);
    if (brix_vfs_stat(&vctx, &st) != NGX_OK || st.is_directory) {
        return brix_ftp_ev_reply(fc, "550 Not a regular file\r\n");
    }
    return brix_ftp_ev_reply(fc, "213 %O\r\n", st.size);
}


/*
 * brix_ftp_ev_cns_note_stored — report a committed STOR/APPE to the CNS manager.
 *
 * Lives here with the namespace verbs rather than in the data-channel teardown
 * that calls it, so every gridftp CNS report is stated in one file.  The caller
 * (brix_ftp_ev_data_finish) is the single event-loop completion for all transfer
 * shapes, and the CMS connection may only be touched from the event loop.
 *
 * The size/mtime come from a probe of the committed path, not from the bytes
 * counted on the wire: the manager serves them to clients verbatim, and a
 * verifying commit can unlink what it just wrote.
 */
void
brix_ftp_ev_cns_note_stored(ftp_ev_t *fc, const char *abs)
{
    brix_vfs_ctx_t  vctx;
    brix_vfs_stat_t st;

    if (!brix_cns_emit_active()) {
        return;
    }

    brix_ftp_ev_vfs_ctx(fc, abs, &vctx);
    if (brix_vfs_probe(&vctx, 1 /* no-follow */, &st) != NGX_OK) {
        return;                  /* unobservable → report nothing over a guess */
    }

    brix_cns_emit_at(fc->conf->root_canon, BRIX_CNS_ADD, abs,
                     (uint64_t) st.size, (uint64_t) st.mtime);
}


/*
 * MKD, DELE and RMD are one transaction with three sets of words: refuse on a
 * read-only export, resolve the argument inside it, run a single namespace op,
 * report the result to the CNS manager, reply.  Table-driven rather than written
 * out three times (coding-standards §8) — only `op`, the CNS op code and the
 * four replies differ.
 *
 * `ok` is applied to `arg` so MKD can echo the created name back per RFC 959
 * §4.2; the two fixed 250s simply consume none of it.  Every string below is a
 * literal — `arg` is client-controlled and must never reach a format position.
 */
typedef struct {
    ngx_int_t  (*op)(brix_vfs_ctx_t *vctx);
    uint32_t     cns_op;
    const char  *denied;        /* export is read-only                       */
    const char  *unresolved;    /* argument would leave the export           */
    const char  *op_failed;     /* the namespace op itself refused           */
    const char  *ok;            /* success reply, formatted against `arg`    */
} ftp_ev_ns_verb_t;


/* Thin adapters so the three ops share one pointer type; the flags are the
 * verbs' historical semantics — MKD does not create parents (RFC 959 has no
 * such verb) and RMD is non-recursive (that is what DELE-per-entry is for). */
static ngx_int_t
ftp_ev_ns_mkdir(brix_vfs_ctx_t *vctx)
{
    return brix_vfs_mkdir(vctx, 0755, 0 /* no parents */);
}


static ngx_int_t
ftp_ev_ns_rmdir(brix_vfs_ctx_t *vctx)
{
    return brix_vfs_rmdir(vctx, 0 /* non-recursive */);
}


static ngx_int_t
ftp_ev_ns_mutate(ftp_ev_t *fc, const char *arg, const ftp_ev_ns_verb_t *v)
{
    char           abs[PATH_MAX];
    brix_vfs_ctx_t vctx;

    if (!fc->conf->allow_write) {
        return brix_ftp_ev_reply(fc, "%s", v->denied);
    }
    if (brix_ftp_ev_resolve(fc, arg, abs, sizeof(abs)) != 0) {
        return brix_ftp_ev_reply(fc, "%s", v->unresolved);
    }
    brix_ftp_ev_vfs_ctx(fc, abs, &vctx);
    if (v->op(&vctx) != NGX_OK) {
        return brix_ftp_ev_reply(fc, "%s", v->op_failed);
    }

    /* phase-97 §5: success path only — a refused mutation may neither seed a
     * phantom entry nor retract a live one. */
    brix_cns_emit_at(fc->conf->root_canon, v->cns_op, abs, 0, 0);
    return brix_ftp_ev_reply(fc, v->ok, arg);
}


ngx_int_t
brix_ftp_ev_cmd_mkd(ftp_ev_t *fc, const char *arg)
{
    static const ftp_ev_ns_verb_t  mkd = {
        ftp_ev_ns_mkdir, BRIX_CNS_MKDIR,
        "550 Permission denied (read-only)\r\n",
        "550 Cannot create directory\r\n",
        "550 Cannot create directory\r\n",
        "257 \"%s\" created\r\n"
    };

    return ftp_ev_ns_mutate(fc, arg, &mkd);
}


ngx_int_t
brix_ftp_ev_cmd_dele(ftp_ev_t *fc, const char *arg)
{
    static const ftp_ev_ns_verb_t  dele = {
        brix_vfs_unlink, BRIX_CNS_DEL,
        "550 Permission denied (read-only)\r\n",
        "550 No such file\r\n",
        "550 Delete failed\r\n",
        "250 File deleted\r\n"
    };

    return ftp_ev_ns_mutate(fc, arg, &dele);
}


ngx_int_t
brix_ftp_ev_cmd_rmd(ftp_ev_t *fc, const char *arg)
{
    static const ftp_ev_ns_verb_t  rmd = {
        ftp_ev_ns_rmdir, BRIX_CNS_RMDIR,
        "550 Permission denied (read-only)\r\n",
        "550 No such directory\r\n",
        "550 Remove directory failed\r\n",
        "250 Directory removed\r\n"
    };

    return ftp_ev_ns_mutate(fc, arg, &rmd);
}


ngx_int_t
brix_ftp_ev_cmd_mdtm(ftp_ev_t *fc, const char *arg)
{
    char            abs[PATH_MAX];
    brix_vfs_ctx_t  vctx;
    brix_vfs_stat_t st;
    struct tm       tm;
    char            ts[32];
    time_t          t;

    if (brix_ftp_ev_resolve(fc, arg, abs, sizeof(abs)) != 0) {
        return brix_ftp_ev_reply(fc, "550 No such file\r\n");
    }
    brix_ftp_ev_vfs_ctx(fc, abs, &vctx);
    if (brix_vfs_stat(&vctx, &st) != NGX_OK || st.is_directory) {
        return brix_ftp_ev_reply(fc, "550 Not a regular file\r\n");
    }
    t = st.mtime;
    if (gmtime_r(&t, &tm) == NULL
        || strftime(ts, sizeof(ts), "%Y%m%d%H%M%S", &tm) == 0)
    {
        return brix_ftp_ev_reply(fc, "550 Cannot format mtime\r\n");
    }
    return brix_ftp_ev_reply(fc, "213 %s\r\n", ts);
}


ngx_int_t
brix_ftp_ev_cmd_mlst(ftp_ev_t *fc, const char *arg)
{
    char            abs[PATH_MAX];
    brix_vfs_ctx_t  vctx;
    brix_vfs_stat_t st;
    char            facts[160];
    const char     *name = (arg != NULL && arg[0] != '\0') ? arg : fc->cwd;

    if (brix_ftp_ev_resolve(fc, arg, abs, sizeof(abs)) != 0) {
        return brix_ftp_ev_reply(fc, "550 No such file or directory\r\n");
    }
    brix_ftp_ev_vfs_ctx(fc, abs, &vctx);
    if (brix_vfs_stat(&vctx, &st) != NGX_OK) {
        return brix_ftp_ev_reply(fc, "550 No such file or directory\r\n");
    }
    (void) ev_fmt_facts(facts, sizeof(facts), &st);
    return brix_ftp_ev_reply(fc, "250-Listing %s\r\n %s %s\r\n250 End\r\n",
                             name, facts, name);
}


ngx_int_t
brix_ftp_ev_cmd_stat(ftp_ev_t *fc, const char *arg)
{
    char            abs[PATH_MAX];
    brix_vfs_ctx_t  vctx;
    brix_vfs_stat_t st;
    char            facts[160];

    if (arg == NULL || arg[0] == '\0') {
        return brix_ftp_ev_reply(fc,
            "211-BriX GridFTP Gateway status\r\n"
            " Connected; TYPE %s; CWD %s\r\n"
            "211 End of status\r\n",
            fc->type_binary ? "I" : "A", fc->cwd);
    }
    if (brix_ftp_ev_resolve(fc, arg, abs, sizeof(abs)) != 0) {
        return brix_ftp_ev_reply(fc, "550 No such file or directory\r\n");
    }
    brix_ftp_ev_vfs_ctx(fc, abs, &vctx);
    if (brix_vfs_stat(&vctx, &st) != NGX_OK) {
        return brix_ftp_ev_reply(fc, "550 No such file or directory\r\n");
    }
    (void) ev_fmt_facts(facts, sizeof(facts), &st);
    return brix_ftp_ev_reply(fc, "213-Status of %s\r\n %s %s\r\n213 End\r\n",
                             arg, facts, arg);
}


/* Map a GridFTP CKSM algorithm token to a BRIX_CK_* kind, or -1 if unknown. */
static int
ev_cksm_kind(const char *algo)
{
    if (strcasecmp(algo, "ADLER32") == 0) { return BRIX_CK_ADLER32; }
    if (strcasecmp(algo, "CRC32")   == 0) { return BRIX_CK_CRC32;   }
    if (strcasecmp(algo, "CRC32C")  == 0) { return BRIX_CK_CRC32C;  }
    if (strcasecmp(algo, "MD5")     == 0) { return BRIX_CK_MD5;     }
    if (strcasecmp(algo, "SHA1")    == 0) { return BRIX_CK_SHA1;    }
    if (strcasecmp(algo, "SHA256")  == 0) { return BRIX_CK_SHA256;  }
    return -1;
}


ngx_int_t
brix_ftp_ev_cmd_cksm(ftp_ev_t *fc, const char *arg)
{
    char             algo[32], abs[PATH_MAX];
    long long        offset, length;
    int              consumed = 0;
    int              kind;
    off_t            start, len;
    const char      *path;
    brix_vfs_ctx_t   vctx;
    brix_vfs_file_t *fh;
    brix_sd_obj_t    obj;
    int              verr = 0;

    if (sscanf(arg, "%31s %lld %lld %n", algo, &offset, &length, &consumed) < 3
        || consumed == 0 || arg[consumed] == '\0')
    {
        return brix_ftp_ev_reply(fc,
            "501 Usage: CKSM <algo> <offset> <length> <path>\r\n");
    }
    path = arg + consumed;

    kind = ev_cksm_kind(algo);
    if (kind < 0) {
        return brix_ftp_ev_reply(fc, "504 Unsupported checksum algorithm %s\r\n",
                                 algo);
    }
    if (offset < 0 || length < -1) {
        return brix_ftp_ev_reply(fc, "501 Invalid CKSM range\r\n");
    }
    start = (off_t) offset;
    len   = (length < 0) ? -1 : (off_t) length;

    if (brix_ftp_ev_resolve(fc, path, abs, sizeof(abs)) != 0) {
        return brix_ftp_ev_reply(fc, "550 No such file\r\n");
    }
    brix_ftp_ev_vfs_ctx(fc, abs, &vctx);
    fh = brix_vfs_open(&vctx, BRIX_VFS_O_READ, &verr);
    if (fh == NULL) {
        return brix_ftp_ev_reply(fc, "550 Cannot open file\r\n");
    }
    brix_vfs_file_sd_obj(fh, &obj);

    if (kind == BRIX_CK_MD5 || kind == BRIX_CK_SHA1 || kind == BRIX_CK_SHA256) {
        unsigned char raw[EVP_MAX_MD_SIZE];
        u_char        hex[2 * EVP_MAX_MD_SIZE + 1];
        unsigned int  rawlen = 0;
        int           ok = brix_cksum_digest_obj_range(kind, &obj, start, len,
                                                       raw, &rawlen);
        brix_vfs_close(fh, fc->c->log);
        if (ok != 0) {
            return brix_ftp_ev_reply(fc, "550 Checksum failed\r\n");
        }
        ngx_hex_dump(hex, raw, rawlen);
        hex[2 * rawlen] = '\0';
        return brix_ftp_ev_reply(fc, "213 %s\r\n", hex);
    } else {
        uint32_t v = 0;
        char     hex[16];
        int      ok = brix_cksum_u32_obj_range(kind, &obj, start, len, &v);
        brix_vfs_close(fh, fc->c->log);
        if (ok != 0) {
            return brix_ftp_ev_reply(fc, "550 Checksum failed\r\n");
        }
        snprintf(hex, sizeof(hex), "%08x", (unsigned) v);
        return brix_ftp_ev_reply(fc, "213 %s\r\n", hex);
    }
}


ngx_int_t
brix_ftp_ev_cmd_rnfr(ftp_ev_t *fc, const char *arg)
{
    char abs[PATH_MAX];

    if (!fc->conf->allow_write) {
        return brix_ftp_ev_reply(fc, "550 Permission denied (read-only)\r\n");
    }
    if (brix_ftp_ev_resolve(fc, arg, abs, sizeof(abs)) != 0) {
        fc->rnfr_set = 0;
        return brix_ftp_ev_reply(fc, "550 No such file or directory\r\n");
    }
    ngx_memcpy(fc->rnfr, abs, ngx_strlen(abs) + 1);
    fc->rnfr_set = 1;
    return brix_ftp_ev_reply(fc, "350 File exists, send RNTO\r\n");
}


ngx_int_t
brix_ftp_ev_cmd_rnto(ftp_ev_t *fc, const char *arg)
{
    char               abs[PATH_MAX];
    brix_vfs_ctx_t     vctx;
    brix_path_result_t dst;

    if (!fc->rnfr_set) {
        return brix_ftp_ev_reply(fc, "503 RNFR required first\r\n");
    }
    fc->rnfr_set = 0;                                /* single-shot pairing    */

    if (!fc->conf->allow_write) {
        return brix_ftp_ev_reply(fc, "550 Permission denied (read-only)\r\n");
    }
    if (brix_ftp_ev_resolve(fc, arg, abs, sizeof(abs)) != 0) {
        return brix_ftp_ev_reply(fc, "550 Cannot rename to target\r\n");
    }

    brix_ftp_ev_vfs_ctx(fc, fc->rnfr, &vctx);        /* source ctx             */
    ngx_memzero(&dst, sizeof(dst));
    dst.is_confined   = 1;
    dst.resolved.data = (u_char *) abs;
    dst.resolved.len  = ngx_strlen(abs);

    if (brix_vfs_rename(&vctx, &dst, 0 /* don't clobber a dir dest */) != NGX_OK) {
        return brix_ftp_ev_reply(fc, "550 Rename failed\r\n");
    }

    /* phase-97 §2: carry the entry across instead of dropping and re-adding it,
     * so a directory rename re-parents its whole subtree in one event.  The
     * size/mtime come from a probe of the destination — the manager serves them
     * verbatim, so a guess would be served to clients as truth. */
    if (brix_cns_emit_active()) {
        brix_vfs_ctx_t  dctx;
        brix_vfs_stat_t st;

        brix_ftp_ev_vfs_ctx(fc, abs, &dctx);
        if (brix_vfs_probe(&dctx, 1 /* no-follow */, &st) == NGX_OK) {
            brix_cns_emit_rename_at(fc->conf->root_canon, fc->rnfr, abs,
                                    (uint64_t) st.size, (uint64_t) st.mtime,
                                    st.is_directory);
        } else {
            /* Unobservable at the destination — retract the source rather than
             * leave the manager pointing at a name that no longer exists. */
            brix_cns_emit_at(fc->conf->root_canon, BRIX_CNS_DEL, fc->rnfr, 0, 0);
        }
    }

    return brix_ftp_ev_reply(fc, "250 Rename successful\r\n");
}
