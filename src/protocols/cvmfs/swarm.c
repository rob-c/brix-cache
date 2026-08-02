/* swarm.c — phase-87 G12: P2P swarm cold-start (dynamic mesh membership).
 *
 * WHAT: generalizes the phase-85 F8 sibling mesh from a static
 *       brix_cache_peers ring to gossip-maintained membership: every node
 *       serves its member view at /cvmfs/.swarm/roster, periodically pulls a
 *       random member's roster (the pull doubles as a SWIM-style liveness
 *       probe), merges views, and republishes the live rendezvous ring into
 *       the cache fill spine through brix_sd_cache_ring_swap.
 * WHY:  a batch farm releasing new software cold-starts O(nodes) origin
 *       fetches per object under any static ring that lags reality; with a
 *       converged live ring every object has ONE rendezvous owner that
 *       origin-fills once and feeds every sibling — O(1) origin fetches per
 *       object regardless of farm size, and a dead member is detected and
 *       routed around instead of black-holing its keys.
 * HOW:  registration mirrors the G17 scrub (config-time per-process statics)
 *       but arms in EVERY worker — registry instances are per-worker, so
 *       each worker gossips and swaps its own ring. Seeds come from the
 *       static brix_cache_peers ring (brix_sd_cache_get_peers); a member is
 *       marked dead after 3 consecutive probe misses and spread by gossip
 *       (equal-generation dead beats alive; a node seeing ITSELF dead bumps
 *       its own boot-time generation — the SWIM refutation). The data plane
 *       is untouched F8: the fill spine still runs ONE verified fetch from
 *       the ring owner with origin fallback, so the tamper contract (a lying
 *       sibling raises signal=cvmfs_tamper naming that sibling) carries over
 *       to dynamic membership unchanged.
 *
 *       The roster pull is a bounded plain-socket HTTP GET run on the THREAD
 *       POOL (the RTT probe precedent for protocol-plane sockets — this is
 *       membership traffic, not storage I/O, so the VFS seam does not
 *       apply). Ring caps: membership view 64, published ring 16
 *       (BRIX_SD_CACHE_MAX_PEERS) — overflow logs the drop (no silent caps).
 *       Published rings are immutable and never freed (see
 *       brix_sd_cache_ring_swap); churn leaks ~4.5 KiB per swap by design.
 */
#include "cvmfs.h"
#include "swarm_internal.h"
#include "fs/vfs/vfs_backend_registry.h"

#include <stdio.h>
#include <string.h>

/* Config-time registration table + per-worker contexts — shared with the
 * gossip engine (swarm_gossip.c) through swarm_internal.h. */
cvmfs_swarm_reg_t  cvmfs_swarm_regs[CVMFS_SWARM_MAX_EXPORTS];
ngx_uint_t         cvmfs_swarm_regs_n;

void
brix_cvmfs_swarm_register(const char *root_canon, time_t interval,
    const ngx_str_t *pool_name)
{
    ngx_uint_t         i;
    cvmfs_swarm_reg_t *reg = NULL;

    for (i = 0; i < cvmfs_swarm_regs_n; i++) {
        if (ngx_strcmp(cvmfs_swarm_regs[i].root, root_canon) == 0) {
            reg = &cvmfs_swarm_regs[i];        /* reload: update in place */
            break;
        }
    }
    if (reg == NULL) {
        if (cvmfs_swarm_regs_n >= CVMFS_SWARM_MAX_EXPORTS
            || ngx_strlen(root_canon) >= sizeof(reg->root))
        {
            return;
        }
        reg = &cvmfs_swarm_regs[cvmfs_swarm_regs_n++];
    }
    ngx_cpystrn((u_char *) reg->root, (u_char *) root_canon,
                sizeof(reg->root));
    reg->interval = (interval > 0) ? interval : 3;
    reg->pool[0] = '\0';
    if (pool_name != NULL && pool_name->len > 0
        && pool_name->len < sizeof(reg->pool))
    {
        ngx_memcpy(reg->pool, pool_name->data, pool_name->len);
        reg->pool[pool_name->len] = '\0';
    }
}

/* ---- per-worker membership state (types in swarm_internal.h) ------------ */

cvmfs_swarm_ctx_t  *cvmfs_swarm_ctxs[CVMFS_SWARM_MAX_EXPORTS];

/* Split "host:port" (the F8 label form; IPv6 hosts keep their brackets) at
 * the LAST colon. Returns 0 on success. */
static int
cvmfs_swarm_label_split(const char *label, char *host, size_t hostsz,
    int *port)
{
    const char *colon = strrchr(label, ':');
    size_t      hlen;
    long        p;

    if (colon == NULL || colon == label) {
        return -1;
    }
    p = strtol(colon + 1, NULL, 10);
    if (p <= 0 || p > 65535) {
        return -1;
    }
    hlen = (size_t) (colon - label);
    if (hlen >= hostsz) {
        return -1;
    }
    /* strip IPv6 brackets for the resolver/tier config */
    if (label[0] == '[' && label[hlen - 1] == ']') {
        hlen -= 2;
        ngx_memcpy(host, label + 1, hlen);
    } else {
        ngx_memcpy(host, label, hlen);
    }
    host[hlen] = '\0';
    *port = (int) p;
    return 0;
}

static cvmfs_swarm_member_t *
cvmfs_swarm_member_find(cvmfs_swarm_ctx_t *sw, const char *label)
{
    ngx_uint_t i;

    for (i = 0; i < sw->n_members; i++) {
        if (strcmp(sw->members[i].label, label) == 0) {
            return &sw->members[i];
        }
    }
    return NULL;
}

static cvmfs_swarm_member_t *
cvmfs_swarm_member_add(cvmfs_swarm_ctx_t *sw, const char *label,
    ngx_log_t *log)
{
    cvmfs_swarm_member_t *m;

    if (sw->n_members >= CVMFS_SWARM_MAX_MEMBERS) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
            "cvmfs-swarm (export %s): membership view full (%d) - "
            "dropping learned member %s", sw->reg->root,
            CVMFS_SWARM_MAX_MEMBERS, label);
        return NULL;
    }
    m = &sw->members[sw->n_members];
    ngx_memzero(m, sizeof(*m));
    if (strlen(label) >= sizeof(m->label)
        || cvmfs_swarm_label_split(label, m->host, sizeof(m->host),
                                     &m->port) != 0)
    {
        return NULL;
    }
    ngx_cpystrn((u_char *) m->label, (u_char *) label, sizeof(m->label));
    sw->n_members++;
    return m;
}

/* Seed the membership view from the static brix_cache_peers ring. Lazy —
 * called from both the timer and the roster endpoint, whichever runs
 * first once the backend registry is resolvable. */
void
cvmfs_swarm_seed(cvmfs_swarm_ctx_t *sw, ngx_log_t *log)
{
    brix_sd_instance_t   *inst;
    brix_sd_cache_peer_t  peers[BRIX_SD_CACHE_MAX_PEERS];
    int                   n, self, i;

    if (sw->seeded) {
        return;
    }
    inst = brix_vfs_backend_resolve(sw->reg->root, log);
    if (inst == NULL) {
        return;
    }
    n = brix_sd_cache_get_peers(inst, peers, &self);
    if (n <= 0) {
        return;
    }
    for (i = 0; i < n; i++) {
        cvmfs_swarm_member_t *m =
            cvmfs_swarm_member_add(sw, peers[i].label, log);

        if (m == NULL) {
            continue;
        }
        m->inst = peers[i].inst;           /* reuse the registry's sources */
        if (i == self) {
            sw->self = (int) (m - sw->members);
        }
    }
    if (sw->self < 0) {
        sw->n_members = 0;                 /* self must be identifiable */
        return;
    }
    sw->self_gen = (uint64_t) ngx_time(); /* boot generation: rejoin refutes */
    sw->seeded   = 1;
    ngx_log_error(NGX_LOG_NOTICE, log, 0,
        "cvmfs-swarm (export %s): seeded %ui member(s) from "
        "brix_cache_peers (self=%s, gen=%uL)", sw->reg->root,
        sw->n_members, sw->members[sw->self].label, sw->self_gen);
}

/* ---- roster wire format --------------------------------------------------
 * One member per line: "<label> <alive|dead> <generation>\n". Version tag
 * first so the format can evolve. */

static size_t
cvmfs_swarm_roster_emit(cvmfs_swarm_ctx_t *sw, char *buf, size_t cap)
{
    size_t      off = 0;
    int         n;
    ngx_uint_t  i;

    n = snprintf(buf, cap, "swarm-roster-v1\n");
    if (n < 0 || (size_t) n >= cap) {
        return 0;
    }
    off = (size_t) n;
    for (i = 0; i < sw->n_members; i++) {
        const cvmfs_swarm_member_t *m = &sw->members[i];

        n = snprintf(buf + off, cap - off, "%s %s %llu\n", m->label,
                     ((int) i == sw->self) ? "alive"
                                            : (m->dead ? "dead" : "alive"),
                     (unsigned long long) (((int) i == sw->self)
                                            ? sw->self_gen : m->gen));
        if (n < 0 || (size_t) n >= cap - off) {
            break;                         /* truncated view: still valid  */
        }
        off += (size_t) n;
    }
    return off;
}

/* Adopt a death learned via gossip: flip the bit + NOTICE — a routing-
 * relevant state change must never be silent, and the log line matches the
 * direct probe-miss path so operators (and the dead-member test) see one
 * signature regardless of which node detected the death first. */
static void
cvmfs_swarm_gossip_dead(cvmfs_swarm_ctx_t *sw, cvmfs_swarm_member_t *m,
    ngx_log_t *log)
{
    m->dead = 1;
    ngx_log_error(NGX_LOG_NOTICE, log, 0,
        "cvmfs-swarm (export %s): member %s marked dead via gossip, "
        "its keys route around it", sw->reg->root, m->label);
}

/* Merge a roster line about an already-known member: a HIGHER generation
 * always wins; at EQUAL generation dead beats alive (a death spreads until
 * the member itself refutes with a higher generation). Returns non-zero
 * when the view changed. */
static int
cvmfs_swarm_merge_known(cvmfs_swarm_ctx_t *sw, cvmfs_swarm_member_t *m,
    int dead, uint64_t gen, ngx_log_t *log)
{
    int changed;

    if (gen > m->gen) {
        changed = (m->dead != (dead ? 1u : 0u));
        if (changed && dead) {
            cvmfs_swarm_gossip_dead(sw, m, log);
        }
        m->gen  = gen;
        m->dead = dead ? 1 : 0;
        if (!m->dead) {
            m->miss = 0;
        }
        return changed;
    }
    if (gen == m->gen && dead && !m->dead) {
        cvmfs_swarm_gossip_dead(sw, m, log);
        return 1;
    }
    return 0;
}

/* Merge one parsed roster line: a line about SELF that says dead at >= our
 * generation triggers the SWIM refutation bump; an unknown member is
 * learned; a known member updates via cvmfs_swarm_merge_known. Returns
 * non-zero when the view changed. */
static int
cvmfs_swarm_merge_line(cvmfs_swarm_ctx_t *sw, const char *label, int dead,
    uint64_t gen, ngx_log_t *log)
{
    cvmfs_swarm_member_t *m;

    if (strcmp(label, sw->members[sw->self].label) == 0) {
        if (dead && gen >= sw->self_gen) {
            sw->self_gen = gen + 1;        /* SWIM refutation */
            ngx_log_error(NGX_LOG_NOTICE, log, 0,
                "cvmfs-swarm (export %s): refuting gossip that says "
                "this node is dead (gen -> %uL)", sw->reg->root,
                sw->self_gen);
            return 1;
        }
        return 0;
    }

    m = cvmfs_swarm_member_find(sw, label);
    if (m == NULL) {
        m = cvmfs_swarm_member_add(sw, label, log);
        if (m == NULL) {
            return 0;
        }
        m->gen  = gen;
        m->dead = dead ? 1 : 0;
        ngx_log_error(NGX_LOG_NOTICE, log, 0,
            "cvmfs-swarm (export %s): learned member %s (%s) "
            "via gossip", sw->reg->root, m->label,
            dead ? "dead" : "alive");
        return 1;
    }
    return cvmfs_swarm_merge_known(sw, m, dead, gen, log);
}

int
cvmfs_swarm_roster_merge(cvmfs_swarm_ctx_t *sw, char *text, size_t len,
    ngx_log_t *log)
{
    char *line, *save = NULL;
    int   changed = 0;

    text[len < CVMFS_SWARM_ROSTER_MAX ? len : CVMFS_SWARM_ROSTER_MAX - 1]
        = '\0';
    line = strtok_r(text, "\n", &save);
    if (line == NULL || strcmp(line, "swarm-roster-v1") != 0) {
        return 0;                          /* not a roster — ignore */
    }
    while ((line = strtok_r(NULL, "\n", &save)) != NULL) {
        char                label[CVMFS_SWARM_LABEL_MAX];
        char                state[8];
        unsigned long long  gen = 0;
        int                 dead;

        if (sscanf(line, "%271s %7s %llu", label, state, &gen) != 3) {
            continue;
        }
        dead = (strcmp(state, "dead") == 0);
        if (!dead && strcmp(state, "alive") != 0) {
            continue;
        }
        changed |= cvmfs_swarm_merge_line(sw, label, dead, (uint64_t) gen,
                                            log);
    }
    return changed;
}

/* The probe thread task, ring rebuild + publish, gossip lifecycle timers
 * and brix_cvmfs_swarm_init_worker live in swarm_gossip.c; the shared
 * seam (types, tables, cross-file entry points) is swarm_internal.h. */

/* ---- roster endpoint (request path, pre-classification) ----------------- */

/* Push-pull introduction: a "?from=<label>&gen=<g>" query introduces the
 * CALLER as a live member (a contact is direct proof of life). Without
 * this, pull-only gossip can never spread a new member to nodes that do
 * not already know it. */
static void
cvmfs_swarm_intro_caller(cvmfs_swarm_ctx_t *sw, ngx_http_request_t *r)
{
    char                  qs[CVMFS_SWARM_LABEL_MAX + 64];
    char                  label[CVMFS_SWARM_LABEL_MAX];
    unsigned long long    gen = 0;
    int                   fresh = 0;
    cvmfs_swarm_member_t *m;

    if (r->args.len <= 5 || r->args.len >= sizeof(sw->resp)) {
        return;
    }
    ngx_memcpy(qs, r->args.data,
               r->args.len < sizeof(qs) - 1 ? r->args.len
                                             : sizeof(qs) - 1);
    qs[r->args.len < sizeof(qs) - 1 ? r->args.len : sizeof(qs) - 1] = '\0';
    if (sscanf(qs, "from=%271[^&]&gen=%llu", label, &gen) != 2
        || strcmp(label, sw->members[sw->self].label) == 0)
    {
        return;
    }

    m = cvmfs_swarm_member_find(sw, label);
    if (m == NULL) {
        m = cvmfs_swarm_member_add(sw, label, r->connection->log);
        if (m != NULL) {
            fresh = 1;
            ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
                "cvmfs-swarm (export %s): member %s introduced "
                "itself", sw->reg->root, m->label);
        }
    }
    if (m != NULL && (fresh || m->dead || gen > m->gen)) {
        m->dead = 0;
        m->miss = 0;
        if (gen > m->gen) {
            m->gen = gen;
        }
        cvmfs_swarm_ring_publish(sw, r->connection->log);
    }
}

/* Emit the roster body and send the 200 (plain text, buffered in-memory). */
static ngx_int_t
cvmfs_swarm_send_roster(ngx_http_request_t *r, cvmfs_swarm_ctx_t *sw)
{
    char        *body;
    size_t       len;
    ngx_buf_t   *b;
    ngx_chain_t  out;
    ngx_int_t    rc;

    body = ngx_pnalloc(r->pool, CVMFS_SWARM_ROSTER_MAX);
    if (body == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    len = cvmfs_swarm_roster_emit(sw, body, CVMFS_SWARM_ROSTER_MAX);
    if (len == 0) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    r->headers_out.status           = NGX_HTTP_OK;
    r->headers_out.content_length_n = (off_t) len;
    ngx_str_set(&r->headers_out.content_type, "text/plain");
    r->headers_out.content_type_len = r->headers_out.content_type.len;

    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    b = ngx_calloc_buf(r->pool);
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    b->pos      = (u_char *) body;
    b->last     = (u_char *) body + len;
    b->memory   = 1;
    b->last_buf = 1;
    out.buf  = b;
    out.next = NULL;
    return ngx_http_output_filter(r, &out);
}

/* Serve GET <anything>/.swarm/roster as this worker's membership view.
 * NGX_DECLINED for any other request (the gate then classifies as usual).
 * The roster is membership-plane metadata: world-readable by design (labels
 * and generations only — no credentials, no namespace content). */
ngx_int_t
brix_cvmfs_swarm_roster_serve(ngx_http_request_t *r,
    ngx_http_brix_cvmfs_loc_conf_t *lcf)
{
    static const size_t  tail_len = sizeof(CVMFS_SWARM_ROSTER_TAIL) - 1;
    cvmfs_swarm_ctx_t   *sw = NULL;
    ngx_uint_t           i;

    if (r->method != NGX_HTTP_GET
        || r->uri.len < tail_len
        || ngx_memcmp(r->uri.data + r->uri.len - tail_len,
                      CVMFS_SWARM_ROSTER_TAIL, tail_len) != 0)
    {
        return NGX_DECLINED;
    }
    for (i = 0; i < cvmfs_swarm_regs_n; i++) {
        if (cvmfs_swarm_ctxs[i] != NULL
            && ngx_strcmp(cvmfs_swarm_regs[i].root,
                          lcf->common.root_canon) == 0)
        {
            sw = cvmfs_swarm_ctxs[i];
            break;
        }
    }
    if (sw == NULL) {
        return NGX_HTTP_NOT_FOUND;
    }
    cvmfs_swarm_seed(sw, r->connection->log);
    if (!sw->seeded) {
        return NGX_HTTP_SERVICE_UNAVAILABLE;   /* registry not ready yet */
    }

    cvmfs_swarm_intro_caller(sw, r);

    return cvmfs_swarm_send_roster(r, sw);
}
