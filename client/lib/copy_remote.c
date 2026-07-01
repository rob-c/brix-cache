/*
 * copy_remote.c - extracted concern
 * Phase-38 split of copy.c; behavior-identical.
 */
#include "copy_internal.h"


/*
 * Client-mediated remote → remote copy: read from the source server and write to
 * the destination server through this process (two independent sessions). This is
 * NOT server-side third-party copy (kXR_tpc / M8); the bytes transit the client.
 * Both opens go through xrdc_roundtrip, so each side independently follows any
 * cluster redirect to its data server.
 */
/*
 * WHAT: Tear down whatever the remote→remote copy actually acquired, in reverse
 *       order, and return the final rc.
 * WHY:  Both sessions/handles are released the same way from every exit point;
 *       extracting it lets the orchestrator return r2r_teardown(...) directly at
 *       each decision site instead of jumping to a shared label.
 * HOW:  Each `*_up` / `*open` flag gates the matching close so a partially
 *       initialised attempt frees only what it acquired. The destination handle
 *       is closed cleanly only on success (POSC discards a partial upload when the
 *       handle is abandoned on error); the source handle always closes silently.
 */
int
r2r_teardown(xrdc_conn *sc, xrdc_conn *dc, xrdc_file *sf, xrdc_file *df,
             int src_up, int dst_up, int sopen, int dopen, int rc,
             xrdc_status *st)
{
    if (dopen && rc == 0) {
        if (xrdc_file_close(dc, df, st) != 0) {
            rc = -1;
        }
    }
    if (sopen) {
        xrdc_status throwaway;
        xrdc_status_clear(&throwaway);
        xrdc_file_close(sc, sf, &throwaway);
    }
    if (dst_up) {
        xrdc_close(dc);
    }
    if (src_up) {
        xrdc_close(sc);
    }
    return rc;
}


/*
 * WHAT: Stream the source's `si->size` bytes through this process into the open
 *       destination handle. Returns 0 on a complete transfer, -1 (st set) otherwise.
 * WHY:  Isolating the read/write loop (and its scratch buffer) keeps the loop body
 *       free of cleanup jumps — it just reports success/failure to the orchestrator,
 *       which owns the connections and runs the staged teardown.
 * HOW:  malloc one chunk buffer, read from the source and write to the destination
 *       until si->size is reached, then free the buffer on every path.
 */
int
r2r_stream_body(xrdc_conn *sc, xrdc_conn *dc, xrdc_file *sf, xrdc_file *df,
                const xrdc_statinfo *si, const xrdc_copy_opts *o, xrdc_status *st)
{
    pump_remote_t src  = { .c = sc, .f = sf, .pgrw = o->pgrw };
    pump_remote_t sink = { .c = dc, .f = df, .pgrw = o->pgrw };

    /* remote (known si->size) → remote; no progress here (historical). */
    return transfer_pump(pump_src_remote, &src, pump_sink_remote, &sink,
                         si->size, NULL, si->size, st);
}


int
copy_remote_to_remote(const xrdc_url *su, const xrdc_url *du,
                      const xrdc_copy_opts *o, const xrdc_opts *co, xrdc_status *st)
{
    xrdc_conn     sc, dc;
    xrdc_file     sf, df;
    xrdc_statinfo si;
    int           rc;

    if (xrdc_connect(&sc, su, co, st) != 0) {
        return -1;
    }
    if (xrdc_stat(&sc, su->path, &si, st) != 0) {
        return r2r_teardown(&sc, &dc, &sf, &df, 1, 0, 0, 0, -1, st);
    }
    if (si.flags & kXR_isDir) {
        xrdc_status_set(st, XRDC_EUSAGE, 0,
                        "source is a directory (recursive copy unsupported)");
        return r2r_teardown(&sc, &dc, &sf, &df, 1, 0, 0, 0, -1, st);
    }

    if (xrdc_connect(&dc, du, co, st) != 0) {
        return r2r_teardown(&sc, &dc, &sf, &df, 1, 0, 0, 0, -1, st);
    }

    if (xrdc_file_open_read(&sc, su->path, &sf, st) != 0) {
        return r2r_teardown(&sc, &dc, &sf, &df, 1, 1, 0, 0, -1, st);
    }
    if (xrdc_file_open_write(&dc, du->path, o->force, o->posc, &df, st) != 0) {
        return r2r_teardown(&sc, &dc, &sf, &df, 1, 1, 1, 0, -1, st);
    }

    rc = r2r_stream_body(&sc, &dc, &sf, &df, &si, o, st);

    return r2r_teardown(&sc, &dc, &sf, &df, 1, 1, 1, 1, rc, st);
}


/*
 * --cksum handling. `spec` is "<type>[:source|:print|:<value>]". Computes the
 * named checksum over the local file `local_path` (the bytes we actually moved)
 * and then, by mode:
 *   :source / :end2end → query the server (kXR_Qcksum) for `remote_path` on the
 *                        already-open connection `c` and require they match;
 *   :<value>           → require the local digest equals the given hex;
 *   :print / (none)    → print "<type> <digest>" (unless silent).
 * Returns XRDC_CK_OK (matched/printed), XRDC_CK_MISMATCH (digest known and WRONG
 * — caller drops the destination), or XRDC_CK_UNVERIFIED (query/transport/usage
 * error — the digest is UNKNOWN, so the caller keeps the file and only warns;
 * deleting a byte-perfect download because a control-plane query hiccupped would
 * be the inverse footgun).
 */
int
cksum_verify(xrdc_conn *c, const char *remote_path, const char *local_path,
             const char *spec, int silent, xrdc_status *st)
{
    char            algo_name[32];
    char            local_hex[129];
    const char     *colon = strchr(spec, ':');
    const char     *mode = NULL;
    size_t          alen;
    xrdc_cksum_algo algo;
    int             lfd;

    alen = colon ? (size_t) (colon - spec) : strlen(spec);
    if (alen == 0 || alen >= sizeof(algo_name)) {
        xrdc_status_set(st, XRDC_EUSAGE, 0, "bad --cksum type");
        return XRDC_CK_UNVERIFIED;
    }
    memcpy(algo_name, spec, alen);
    algo_name[alen] = '\0';
    mode = colon ? colon + 1 : NULL;

    if (xrdc_cksum_algo_parse(algo_name, &algo) != 0) {
        xrdc_status_set(st, XRDC_EUSAGE, 0,
                        "unsupported --cksum type \"%s\"", algo_name);
        return XRDC_CK_UNVERIFIED;
    }

    if (local_path == NULL) {
        /* stdio endpoint — nothing on disk to digest; skip rather than lie. */
        if (!silent) {
            fprintf(stderr, "xrdcp: --cksum skipped for stdin/stdout\n");
        }
        return XRDC_CK_OK;
    }

    lfd = open(local_path, O_RDONLY);
    if (lfd < 0) {
        xrdc_status_set(st, XRDC_EUSAGE, errno,
                        "open %s for checksum: %s", local_path, strerror(errno));
        return XRDC_CK_UNVERIFIED;
    }
    if (xrdc_cksum_fd(lfd, algo, local_hex, sizeof(local_hex), st) != 0) {
        close(lfd);
        return XRDC_CK_UNVERIFIED;
    }
    close(lfd);

    if (mode != NULL
        && (strcmp(mode, "source") == 0 || strcmp(mode, "end2end") == 0)) {
        char server_hex[129];
        if (remote_path == NULL) {
            xrdc_status_set(st, XRDC_EUSAGE, 0, "--cksum:source has no remote");
            return XRDC_CK_UNVERIFIED;
        }
        if (xrdc_query_cksum(c, remote_path, algo_name,
                             server_hex, sizeof(server_hex), st) != 0) {
            return XRDC_CK_UNVERIFIED;   /* server digest UNKNOWN, not WRONG */
        }
        if (strcasecmp(local_hex, server_hex) != 0) {
            /* A checksum mismatch is a data-integrity failure, not a transient
             * framing fault — classify it non-retryable so no resilient loop
             * spins re-verifying the same bytes. */
            xrdc_status_set(st, XRDC_EINTEGRITY, 0,
                            "%s mismatch: local %s != server %s",
                            algo_name, local_hex, server_hex);
            return XRDC_CK_MISMATCH;
        }
        if (!silent) {
            printf("%s %s OK (matches server)\n", algo_name, local_hex);
        }
        return XRDC_CK_OK;
    }

    if (mode != NULL && strcmp(mode, "print") != 0) {
        /* literal expected value */
        if (strcasecmp(local_hex, mode) != 0) {
            xrdc_status_set(st, XRDC_EINTEGRITY, 0,
                            "%s mismatch: got %s expected %s",
                            algo_name, local_hex, mode);
            return XRDC_CK_MISMATCH;
        }
        if (!silent) {
            printf("%s %s OK\n", algo_name, local_hex);
        }
        return XRDC_CK_OK;
    }

    /* print / no mode */
    if (!silent) {
        printf("%s %s\n", algo_name, local_hex);
    }
    return XRDC_CK_OK;
}


/* Mint a random TPC rendezvous key (hex of 16 /dev/urandom bytes). */
int
gen_tpc_key(char *out, size_t outsz)
{
    uint8_t raw[16];
    int     fd;

    if (outsz < sizeof(raw) * 2 + 1) {
        return -1;
    }
    fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        return -1;
    }
    if (read(fd, raw, sizeof(raw)) != (ssize_t) sizeof(raw)) {
        close(fd);
        return -1;
    }
    close(fd);
    xrootd_hex_encode(raw, sizeof(raw), out);   /* shared lowercase hex */
    return 0;
}


/*
 * Server-side third-party copy (root://), source-first rendezvous:
 *   1. open SRC read with tpc.key=K & tpc.dst=root://dest//dpath  → registers K
 *   2. open DST write with tpc.src=root://src//spath & tpc.key=K  → dest = puller
 *   3. kXR_sync DST (arm "tpc-arm"), then kXR_sync DST again (trigger the pull;
 *      its reply is deferred until the transfer completes).
 * The destination server connects to the source itself and pulls the bytes — no
 * data transits this client (unlike copy_remote_to_remote).
 */
/*
 * WHAT: Tear down whatever the TPC rendezvous acquired — the two opaque request
 *       strings, the source/destination handles, and their connections — and
 *       return the final rc.
 * WHY:  Every exit point releases the same resources the same way; extracting it
 *       lets the orchestrator return tpc_teardown(...) directly at each decision
 *       site instead of jumping to a shared label.
 * HOW:  Each `*open` / `*_up` flag gates the matching close so a partially set-up
 *       rendezvous frees only what it acquired. The destination handle reports its
 *       close error into `st` only on success (so a failed sync's status survives);
 *       the source handle always closes silently. The opaque strings are freed
 *       unconditionally (they are allocated before any session is opened).
 */
int
tpc_teardown(xrdc_conn *sc, xrdc_conn *dc, xrdc_file *sf, xrdc_file *df,
             char *src_opaque, char *dst_opaque,
             int su_up, int du_up, int sopen, int dopen, int rc, xrdc_status *st)
{
    if (dopen) {
        xrdc_status tw; xrdc_status_clear(&tw);
        xrdc_file_close(dc, df, rc == 0 ? st : &tw);
    }
    if (sopen) {
        xrdc_status tw; xrdc_status_clear(&tw);
        xrdc_file_close(sc, sf, &tw);
    }
    if (du_up) { xrdc_close(dc); }
    if (su_up) { xrdc_close(sc); }
    free(src_opaque);
    free(dst_opaque);
    return rc;
}


int
copy_tpc(const xrdc_url *su, const xrdc_url *du, const xrdc_copy_opts *o,
         const xrdc_opts *co, xrdc_status *st)
{
    xrdc_conn   sc, dc;
    xrdc_file   sf, df;
    char        key[40];
    char       *src_opaque = NULL, *dst_opaque = NULL;
    size_t      need;
    const char *tok = (o->tpc_token_mode && o->tpc_token_mode[0])
                      ? o->tpc_token_mode : NULL;

    if (gen_tpc_key(key, sizeof(key)) != 0) {
        xrdc_status_set(st, XRDC_ESOCK, 0, "cannot generate TPC key");
        return -1;
    }
    /* Heap-size the opaque strings to the actual host/path/key/token lengths. */
    need = strlen(su->host) + strlen(su->path) + strlen(du->host)
           + strlen(du->path) + sizeof(key) + (tok ? strlen(tok) : 0) + 128;
    src_opaque = (char *) malloc(need);
    dst_opaque = (char *) malloc(need);
    if (src_opaque == NULL || dst_opaque == NULL) {
        free(src_opaque); free(dst_opaque);
        xrdc_status_set(st, XRDC_EPROTO, 0, "out of memory");
        return -1;
    }
    snprintf(src_opaque, need,
             "tpc.key=%s&tpc.dst=root://%s:%d/%s%s%s", key,
             du->host, du->port, du->path,
             tok ? "&tpc.token_mode=" : "", tok ? tok : "");
    snprintf(dst_opaque, need,
             "tpc.src=root://%s:%d/%s&tpc.key=%s%s%s",
             su->host, su->port, su->path, key,
             tok ? "&tpc.token_mode=" : "", tok ? tok : "");

    if (xrdc_connect(&sc, su, co, st) != 0) {
        return tpc_teardown(&sc, &dc, &sf, &df, src_opaque, dst_opaque,
                            0, 0, 0, 0, -1, st);
    }
    /* The source open is the TPC COORDINATOR: it registers the rendezvous key, and
     * the source defers its open reply (kXR_waitresp) until the pull completes. Let
     * xrdc_recv surface that deferral rather than block — we still have to open the
     * destination and trigger the pull that satisfies this very wait, so blocking
     * here would deadlock the rendezvous. The source connection stays open through
     * the transfer so the registration remains live. */
    sc.tpc_coord_defer = 1;
    if (xrdc_file_open_opaque(&sc, su->path, src_opaque, 0, 0, 0, &sf, st) != 0) {
        return tpc_teardown(&sc, &dc, &sf, &df, src_opaque, dst_opaque,
                            1, 0, 0, 0, -1, st);
    }

    if (xrdc_connect(&dc, du, co, st) != 0) {
        return tpc_teardown(&sc, &dc, &sf, &df, src_opaque, dst_opaque,
                            1, 0, 1, 0, -1, st);
    }
    if (xrdc_file_open_opaque(&dc, du->path, dst_opaque, 1, o->force, o->posc,
                              &df, st) != 0) {
        return tpc_teardown(&sc, &dc, &sf, &df, src_opaque, dst_opaque,
                            1, 1, 1, 0, -1, st);
    }

    if (xrdc_file_sync(&dc, &df, st) != 0) {     /* arm → "tpc-arm" */
        return tpc_teardown(&sc, &dc, &sf, &df, src_opaque, dst_opaque,
                            1, 1, 1, 1, -1, st);
    }
    if (dc.io.timeout_ms < 300000) {
        dc.io.timeout_ms = 300000;               /* 5 min for the deferred pull */
    }
    if (xrdc_file_sync(&dc, &df, st) != 0) {     /* trigger + await completion */
        return tpc_teardown(&sc, &dc, &sf, &df, src_opaque, dst_opaque,
                            1, 1, 1, 1, -1, st);
    }

    return tpc_teardown(&sc, &dc, &sf, &df, src_opaque, dst_opaque,
                        1, 1, 1, 1, 0, st);
}
