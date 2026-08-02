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


/*
 * WHAT: The mutable rendezvous state a copy_tpc pass threads through its setup /
 *       run / verify stages: both sessions, both handles, the two opaque strings,
 *       and the acquisition flags that gate teardown.
 * WHY:  copy_tpc was one long procedure whose every step both mutated this state
 *       and, on failure, called tpc_teardown with a hand-maintained flag vector.
 *       Bundling the state lets the stage helpers own their own error-teardown at
 *       the right altitude while the orchestrator stays a flat call sequence.
 * HOW:  `su_up`/`du_up`/`sopen`/`dopen` mirror tpc_teardown's flag arguments;
 *       each stage sets a flag the instant it acquires the matching resource.
 */
typedef struct {
    brix_conn  sc, dc;
    brix_file  sf, df;
    char      *src_opaque, *dst_opaque;
    int        su_up, du_up, sopen, dopen;
} tpc_state_t;


/*
 * WHAT: The read-only inputs a copy_tpc pass shares across its stages: the source
 *       and destination URLs, the transfer/connection option blocks, the minted
 *       rendezvous key, the source's post-redirect host:port, the best-effort
 *       size (-1 = unknown), and the optional tpc.token_mode value (NULL = none).
 * WHY:  These values are computed once (in setup) and then only read by the run
 *       and verify stages; bundling them keeps each stage helper within the 5-arg
 *       budget instead of threading eight loose parameters.
 * HOW:  `key`/`src_hp` are filled by tpc_setup_source; `size`/`tok` likewise; the
 *       four pointers alias the caller's URL/option blocks and are never mutated.
 */
typedef struct {
    const brix_url       *su, *du;
    const brix_copy_opts *o;
    const brix_opts      *co;
    char                  key[40];
    char                  src_hp[XRDC_HOSTPORT_MAX];
    int64_t               size;
    const char           *tok;
} tpc_params_t;


/*
 * WHAT: Release everything `s` acquired via the frozen tpc_teardown extern and
 *       return `rc`.
 * WHY:  Every copy_tpc stage exits through the same teardown; a one-line adapter
 *       from the state struct to the flag-vector extern keeps each call site
 *       readable and the flag order in exactly one place.
 * HOW:  Forward the struct's handles, opaque strings, and acquisition flags to
 *       tpc_teardown unchanged.
 */
static int
tpc_state_teardown(tpc_state_t *s, int rc, brix_status *st)
{
    return tpc_teardown(&s->sc, &s->dc, &s->sf, &s->df,
                        s->src_opaque, s->dst_opaque,
                        s->su_up, s->du_up, s->sopen, s->dopen, rc, st);
}


/*
 * WHAT: Stage 1 (setup) — mint the key, open the source session, best-effort stat
 *       it, and format its post-redirect host:port into `src_hp`. On success sets
 *       `*size` (>=0 known, -1 unknown) and returns 0; on hard failure tears down
 *       and returns -1.
 * WHY:  The placement step mixes key generation, a session open, a facultative
 *       stat, and address formatting; isolating it keeps copy_tpc's top level a
 *       linear setup → run → verify.
 * HOW:  gen_tpc_key → brix_connect (marks su_up) → brix_stat. The stat is
 *       BEST-EFFORT like XrdCl's facultative placement stat: only a definitive
 *       kXR_NotFound fails fast (before the destination exists); any other stat
 *       error just leaves the size unknown so oss.asize is omitted downstream.
 */
static int
tpc_setup_source(tpc_state_t *s, tpc_params_t *p, brix_status *st)
{
    brix_statinfo si;

    if (gen_tpc_key(p->key, sizeof(p->key)) != 0) {
        brix_status_set(st, XRDC_ESOCK, 0, "cannot generate TPC key");
        return -1;
    }

    /* Source session + stat: learn the size for oss.asize and let the session
     * follow any cluster redirect so src_hp names the actual source data
     * server (the client-side equivalent of the stock placement step). */
    if (brix_connect(&s->sc, p->su, p->co, st) != 0) {
        return -1;
    }
    s->su_up = 1;

    si.size = -1;
    if (brix_stat(&s->sc, p->su->path, &si, st) != 0) {
        if (st->kxr == kXR_NotFound) {
            return tpc_state_teardown(s, -1, st);
        }
        si.size = -1;   /* size unknown → oss.asize omitted below */
    }
    p->size = si.size;
    brix_format_host_port(s->sc.host, (uint16_t) s->sc.port,
                          p->src_hp, sizeof(p->src_hp));
    return 0;
}


/*
 * WHAT: Build the destination cgiC2Dst opaque string into `dst_opaque`.
 * WHY:  The stock field order + conditional oss.asize is fiddly formatting; kept
 *       in one helper so the wire layout lives in a single place and copy_tpc's
 *       run stage reads as a sequence of opens.
 * HOW:  Emit tpc.key/src/lfn/dlg/spr/tpr/dlgon/stage in the stock order. tpc.dlg
 *       names the originally-requested source endpoint and is inert while
 *       tpc.dlgon=0 (this client never delegates; emitted for XrdCl wire parity).
 *       oss.asize is appended only when the best-effort stat learned the size.
 */
static void
tpc_build_dst_opaque(char *dst_opaque, size_t need, const tpc_params_t *p)
{
    char asize[48];

    asize[0] = '\0';
    if (p->size >= 0) {
        snprintf(asize, sizeof(asize), "&oss.asize=%lld", (long long) p->size);
    }
    snprintf(dst_opaque, need,
             "tpc.key=%s&tpc.src=%s&tpc.lfn=%s&tpc.dlg=%s:%d&tpc.spr=root"
             "&tpc.tpr=root&tpc.dlgon=0%s&tpc.stage=copy%s%s",
             p->key, p->src_hp, p->su->path, p->su->host, p->su->port, asize,
             p->tok ? "&tpc.token_mode=" : "", p->tok ? p->tok : "");
}


/*
 * WHAT: Stage 2 (run) — allocate the opaque strings, open + arm the destination,
 *       then open the source to register the key. Returns 0 with both handles
 *       live; on any failure tears down and returns -1.
 * WHY:  The rendezvous is a fixed open/sync/open sequence; grouping it keeps
 *       copy_tpc's top level free of the per-step teardown branches.
 * HOW:  Heap-size and build both opaques, connect+open the destination (cgiC2Dst)
 *       and sync it (setup/arm), then open the source (cgiC2Src, tpc.dst =
 *       dc.host, the puller endpoint the source will see). The source open runs
 *       with tpc_coord_defer=1 so brix_recv surfaces the kXR_waitresp deferral
 *       rather than blocking — the pull that satisfies it is only triggered by
 *       the verify-stage sync, so blocking here would deadlock the rendezvous.
 *       The source connection stays open so the registration remains live.
 */
static int
tpc_run_rendezvous(tpc_state_t *s, const tpc_params_t *p, brix_status *st)
{
    /* Heap-size the opaque strings to the actual host/path/key/token lengths. */
    size_t need = XRDC_HOSTPORT_MAX + strlen(p->su->host) + strlen(p->su->path)
                  + strlen(p->du->host) + strlen(p->du->path) + 40
                  + (p->tok ? strlen(p->tok) : 0) + 192;

    s->src_opaque = (char *) malloc(need);
    s->dst_opaque = (char *) malloc(need);
    if (s->src_opaque == NULL || s->dst_opaque == NULL) {
        brix_status_set(st, XRDC_EPROTO, 0, "out of memory");
        return tpc_state_teardown(s, -1, st);
    }

    tpc_build_dst_opaque(s->dst_opaque, need, p);

    if (brix_connect(&s->dc, p->du, p->co, st) != 0) {
        return tpc_state_teardown(s, -1, st);
    }
    s->du_up = 1;
    if (brix_file_open_opaque(&s->dc, p->du->path, s->dst_opaque, 1, p->o->force,
                              p->o->posc, &s->df, st) != 0) {
        return tpc_state_teardown(s, -1, st);
    }
    s->dopen = 1;

    if (brix_file_sync(&s->dc, &s->df, st) != 0) {   /* rendezvous setup / arm */
        return tpc_state_teardown(s, -1, st);
    }

    snprintf(s->src_opaque, need, "tpc.key=%s&tpc.dst=%s&tpc.stage=copy%s%s",
             p->key, s->dc.host,
             p->tok ? "&tpc.token_mode=" : "", p->tok ? p->tok : "");
    s->sc.tpc_coord_defer = 1;
    if (brix_file_open_opaque(&s->sc, p->su->path, s->src_opaque, 0, 0, 0,
                              &s->sf, st) != 0) {
        return tpc_state_teardown(s, -1, st);
    }
    s->sopen = 1;
    return 0;
}


int
copy_tpc(const brix_url *su, const brix_url *du, const brix_copy_opts *o,
         const brix_opts *co, brix_status *st)
{
    tpc_state_t   s = { 0 };
    tpc_params_t  p = {
        .su = su, .du = du, .o = o, .co = co, .size = -1,
        .tok = (o->tpc_token_mode && o->tpc_token_mode[0])
                   ? o->tpc_token_mode : NULL,
    };

    /* 1. Placement: key + source session + best-effort stat. */
    if (tpc_setup_source(&s, &p, st) != 0) {
        return -1;
    }

    /* 2. Rendezvous: open + arm destination, then register the key at source. */
    if (tpc_run_rendezvous(&s, &p, st) != 0) {
        return -1;
    }

    /* 3. Trigger + await completion (reply may be deferred via kXR_waitresp →
     * kXR_attn(asynresp); brix_recv unwraps it). */
    if (s.dc.io.timeout_ms < 300000) {
        s.dc.io.timeout_ms = 300000;             /* 5 min for the deferred pull */
    }
    if (brix_file_sync(&s.dc, &s.df, st) != 0) {
        return tpc_state_teardown(&s, -1, st);
    }

    return tpc_state_teardown(&s, 0, st);
}
