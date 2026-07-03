/*
 * copy_remote.c - extracted concern
 * Phase-38 split of copy.c; behavior-identical.
 */
#include "copy_internal.h"


/*
 * Client-mediated remote → remote copy: read from the source server and write to
 * the destination server through this process (two independent sessions). This is
 * NOT server-side third-party copy (kXR_tpc / M8); the bytes transit the client.
 * Both opens go through brix_roundtrip, so each side independently follows any
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
r2r_teardown(brix_conn *sc, brix_conn *dc, brix_file *sf, brix_file *df,
             int src_up, int dst_up, int sopen, int dopen, int rc,
             brix_status *st)
{
    if (dopen && rc == 0) {
        if (brix_file_close(dc, df, st) != 0) {
            rc = -1;
        }
    }
    if (sopen) {
        brix_status throwaway;
        brix_status_clear(&throwaway);
        brix_file_close(sc, sf, &throwaway);
    }
    if (dst_up) {
        brix_close(dc);
    }
    if (src_up) {
        brix_close(sc);
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
r2r_stream_body(brix_conn *sc, brix_conn *dc, brix_file *sf, brix_file *df,
                const brix_statinfo *si, const brix_copy_opts *o, brix_status *st)
{
    pump_remote_t src  = { .c = sc, .f = sf, .pgrw = o->pgrw };
    pump_remote_t sink = { .c = dc, .f = df, .pgrw = o->pgrw };

    /* remote (known si->size) → remote; no progress here (historical). */
    return transfer_pump(pump_src_remote, &src, pump_sink_remote, &sink,
                         si->size, NULL, si->size, st);
}


int
copy_remote_to_remote(const brix_url *su, const brix_url *du,
                      const brix_copy_opts *o, const brix_opts *co, brix_status *st)
{
    brix_conn     sc, dc;
    brix_file     sf, df;
    brix_statinfo si;
    int           rc;

    if (brix_connect(&sc, su, co, st) != 0) {
        return -1;
    }
    if (brix_stat(&sc, su->path, &si, st) != 0) {
        return r2r_teardown(&sc, &dc, &sf, &df, 1, 0, 0, 0, -1, st);
    }
    if (si.flags & kXR_isDir) {
        brix_status_set(st, XRDC_EUSAGE, 0,
                        "source is a directory (recursive copy unsupported)");
        return r2r_teardown(&sc, &dc, &sf, &df, 1, 0, 0, 0, -1, st);
    }

    if (brix_connect(&dc, du, co, st) != 0) {
        return r2r_teardown(&sc, &dc, &sf, &df, 1, 0, 0, 0, -1, st);
    }

    if (brix_file_open_read(&sc, su->path, &sf, st) != 0) {
        return r2r_teardown(&sc, &dc, &sf, &df, 1, 1, 0, 0, -1, st);
    }
    if (brix_file_open_write(&dc, du->path, o->force, o->posc, &df, st) != 0) {
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
cksum_verify(brix_conn *c, const char *remote_path, const char *local_path,
             const char *spec, int silent, brix_status *st)
{
    char            algo_name[32];
    char            local_hex[129];
    const char     *colon = strchr(spec, ':');
    const char     *mode = NULL;
    size_t          alen;
    brix_cksum_algo algo;
    int             lfd;

    alen = colon ? (size_t) (colon - spec) : strlen(spec);
    if (alen == 0 || alen >= sizeof(algo_name)) {
        brix_status_set(st, XRDC_EUSAGE, 0, "bad --cksum type");
        return XRDC_CK_UNVERIFIED;
    }
    memcpy(algo_name, spec, alen);
    algo_name[alen] = '\0';
    mode = colon ? colon + 1 : NULL;

    if (brix_cksum_algo_parse(algo_name, &algo) != 0) {
        brix_status_set(st, XRDC_EUSAGE, 0,
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
        brix_status_set(st, XRDC_EUSAGE, errno,
                        "open %s for checksum: %s", local_path, strerror(errno));
        return XRDC_CK_UNVERIFIED;
    }
    if (brix_cksum_fd(lfd, algo, local_hex, sizeof(local_hex), st) != 0) {
        close(lfd);
        return XRDC_CK_UNVERIFIED;
    }
    close(lfd);

    if (mode != NULL
        && (strcmp(mode, "source") == 0 || strcmp(mode, "end2end") == 0)) {
        char server_hex[129];
        if (remote_path == NULL) {
            brix_status_set(st, XRDC_EUSAGE, 0, "--cksum:source has no remote");
            return XRDC_CK_UNVERIFIED;
        }
        if (brix_query_cksum(c, remote_path, algo_name,
                             server_hex, sizeof(server_hex), st) != 0) {
            return XRDC_CK_UNVERIFIED;   /* server digest UNKNOWN, not WRONG */
        }
        if (strcasecmp(local_hex, server_hex) != 0) {
            /* A checksum mismatch is a data-integrity failure, not a transient
             * framing fault — classify it non-retryable so no resilient loop
             * spins re-verifying the same bytes. */
            brix_status_set(st, XRDC_EINTEGRITY, 0,
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
            brix_status_set(st, XRDC_EINTEGRITY, 0,
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
    brix_hex_encode(raw, sizeof(raw), out);   /* shared lowercase hex */
    return 0;
}


/*
 * Server-side third-party copy (root://) in the STOCK XRootD dialect
 * (XrdOucTPC cgiC2Dst/cgiC2Src + the XrdCl ThirdPartyCopyJob control order),
 * which BOTH a stock XRootD destination and nginx-xrootd accept:
 *   1. connect SRC + kXR_stat  → size for oss.asize; the session has followed
 *      any cluster redirect, so its live host:port names the actual source
 *      data server (the client-side "placement" step).
 *   2. open DST write with  tpc.key=K &tpc.src=<shost:sport> &tpc.lfn=<spath>
 *      &tpc.stage=copy &oss.asize=N &tpc.dlg/spr/tpr/dlgon   → dest = puller
 *   3. kXR_sync DST — rendezvous setup (stock) / arm (nginx).
 *   4. open SRC read with  tpc.key=K &tpc.dst=<dhost> &tpc.stage=copy
 *      → the source authorizes the upcoming pull (stock authQ / nginx SHM
 *      key registry). nginx defers this open's reply until the pull completes
 *      (tpc_coord_defer surfaces the kXR_waitresp); stock replies immediately.
 *   5. kXR_sync DST — trigger the pull and await completion (the reply may be
 *      deferred via kXR_waitresp → kXR_attn(asynresp); brix_recv unwraps it).
 * The destination server connects to the source itself and pulls the bytes — no
 * data transits this client (unlike copy_remote_to_remote).
 *
 * Dialect note: the legacy nginx-only form (tpc.src=root://host:port/path as a
 * full URL, no tpc.lfn/tpc.stage, source opened BEFORE the destination) is NOT
 * emitted any more — a stock destination cannot parse it ("Invalid address"),
 * and a stock source cannot Match() its tpc.dst full-URL against the puller's
 * hostname. nginx-xrootd parses both forms (src/tpc/engine/parse.c normalizes bare
 * host[:port] + tpc.lfn), so the stock dialect is the one that works against
 * every server. tpc.token_mode is an nginx extension; unknown tpc.* keys are
 * ignored by both servers.
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
tpc_teardown(brix_conn *sc, brix_conn *dc, brix_file *sf, brix_file *df,
             char *src_opaque, char *dst_opaque,
             int su_up, int du_up, int sopen, int dopen, int rc, brix_status *st)
{
    if (dopen) {
        brix_status tw; brix_status_clear(&tw);
        brix_file_close(dc, df, rc == 0 ? st : &tw);
    }
    if (sopen) {
        brix_status tw; brix_status_clear(&tw);
        brix_file_close(sc, sf, &tw);
    }
    if (du_up) { brix_close(dc); }
    if (su_up) { brix_close(sc); }
    free(src_opaque);
    free(dst_opaque);
    return rc;
}


int
copy_tpc(const brix_url *su, const brix_url *du, const brix_copy_opts *o,
         const brix_opts *co, brix_status *st)
{
    brix_conn     sc, dc;
    brix_file     sf, df;
    brix_statinfo si;
    char          key[40];
    char          src_hp[XRDC_HOSTPORT_MAX];
    char         *src_opaque = NULL, *dst_opaque = NULL;
    size_t        need;
    const char   *tok = (o->tpc_token_mode && o->tpc_token_mode[0])
                        ? o->tpc_token_mode : NULL;

    if (gen_tpc_key(key, sizeof(key)) != 0) {
        brix_status_set(st, XRDC_ESOCK, 0, "cannot generate TPC key");
        return -1;
    }

    /* 1. Source session + stat: learn the size for oss.asize and let the
     * session follow any cluster redirect so src_hp names the actual source
     * data server (the client-side equivalent of the stock placement step).
     * The stat is BEST-EFFORT, like XrdCl's facultative placement stat — a
     * minimal source that cannot answer kXR_stat must not kill the copy (the
     * pull itself will surface any real problem); only a definitive "no such
     * file" fails fast, before the destination is created. */
    if (brix_connect(&sc, su, co, st) != 0) {
        return -1;
    }
    si.size = -1;
    if (brix_stat(&sc, su->path, &si, st) != 0) {
        if (st->kxr == kXR_NotFound) {
            return tpc_teardown(&sc, &dc, &sf, &df, NULL, NULL,
                                1, 0, 0, 0, -1, st);
        }
        si.size = -1;   /* size unknown → oss.asize omitted below */
    }
    brix_format_host_port(sc.host, (uint16_t) sc.port, src_hp, sizeof(src_hp));

    /* Heap-size the opaque strings to the actual host/path/key/token lengths. */
    need = sizeof(src_hp) + strlen(su->host) + strlen(su->path)
           + strlen(du->host) + strlen(du->path) + sizeof(key)
           + (tok ? strlen(tok) : 0) + 192;
    src_opaque = (char *) malloc(need);
    dst_opaque = (char *) malloc(need);
    if (src_opaque == NULL || dst_opaque == NULL) {
        brix_status_set(st, XRDC_EPROTO, 0, "out of memory");
        return tpc_teardown(&sc, &dc, &sf, &df, src_opaque, dst_opaque,
                            1, 0, 0, 0, -1, st);
    }

    /* 2. Destination open, stock cgiC2Dst field order. tpc.dlg names the
     * originally-requested source endpoint and is inert while tpc.dlgon=0
     * (this client never delegates); emitted for wire parity with XrdCl.
     * oss.asize is only sent when the best-effort stat learned the size. */
    {
        char asize[48];
        asize[0] = '\0';
        if (si.size >= 0) {
            snprintf(asize, sizeof(asize), "&oss.asize=%lld",
                     (long long) si.size);
        }
        snprintf(dst_opaque, need,
                 "tpc.key=%s&tpc.src=%s&tpc.lfn=%s&tpc.dlg=%s:%d&tpc.spr=root"
                 "&tpc.tpr=root&tpc.dlgon=0%s&tpc.stage=copy%s%s",
                 key, src_hp, su->path, su->host, su->port, asize,
                 tok ? "&tpc.token_mode=" : "", tok ? tok : "");
    }

    if (brix_connect(&dc, du, co, st) != 0) {
        return tpc_teardown(&sc, &dc, &sf, &df, src_opaque, dst_opaque,
                            1, 0, 0, 0, -1, st);
    }
    if (brix_file_open_opaque(&dc, du->path, dst_opaque, 1, o->force, o->posc,
                              &df, st) != 0) {
        return tpc_teardown(&sc, &dc, &sf, &df, src_opaque, dst_opaque,
                            1, 1, 0, 0, -1, st);
    }

    if (brix_file_sync(&dc, &df, st) != 0) {     /* rendezvous setup / arm */
        return tpc_teardown(&sc, &dc, &sf, &df, src_opaque, dst_opaque,
                            1, 1, 0, 1, -1, st);
    }

    /* 3. Source open, stock cgiC2Src form (tpc.dst = destination HOSTNAME as
     * the source will see the puller connect — dc.host is the post-redirect
     * endpoint). This registers/authorizes the key at the source. On nginx the
     * source defers this open's reply (kXR_waitresp) until the pull completes;
     * let brix_recv surface that deferral rather than block — the pull that
     * satisfies it is only triggered by the sync below, so blocking here would
     * deadlock the rendezvous. The source connection stays open through the
     * transfer so the registration remains live. */
    snprintf(src_opaque, need, "tpc.key=%s&tpc.dst=%s&tpc.stage=copy%s%s",
             key, dc.host,
             tok ? "&tpc.token_mode=" : "", tok ? tok : "");
    sc.tpc_coord_defer = 1;
    if (brix_file_open_opaque(&sc, su->path, src_opaque, 0, 0, 0, &sf, st) != 0) {
        return tpc_teardown(&sc, &dc, &sf, &df, src_opaque, dst_opaque,
                            1, 1, 0, 1, -1, st);
    }

    if (dc.io.timeout_ms < 300000) {
        dc.io.timeout_ms = 300000;               /* 5 min for the deferred pull */
    }
    if (brix_file_sync(&dc, &df, st) != 0) {     /* trigger + await completion */
        return tpc_teardown(&sc, &dc, &sf, &df, src_opaque, dst_opaque,
                            1, 1, 1, 1, -1, st);
    }

    return tpc_teardown(&sc, &dc, &sf, &df, src_opaque, dst_opaque,
                        1, 1, 1, 1, 0, st);
}
