/*
 * diag_doctor_recon.c — deep read-only reconnaissance of one endpoint (--deep-recon).
 *
 * WHAT: over one already-open root:// connection, surface the whole read-only
 *       picture an operator might want to eyeball on a server: the operational
 *       counters from `query stats a` (link traffic, xrootd op mix, login
 *       auth/fail, OFS TPC accounting, OSS capacity/inodes, XrdHttp totals), a
 *       full Qconfig key sweep (how many advertised keys the server answers),
 *       the decoded kXR_protocol capability bits, and a bounded list of the
 *       top-level namespace roots our identity is allowed to see.
 * WHY:  --config-audit classifies a handful of VALUES into advice; --deep-recon
 *       is the reconnaissance counterpart — it reports everything, diagnostic
 *       not advisory, so an operator can inspect a remote server's live state in
 *       one pass without shelling in. It reads only what the server volunteers.
 * HOW:  pure composition of the public libbrix API — kXR_QStats + kXR_Qconfig +
 *       a dirlist("/"). The XML/flag parsers are pure over caller buffers and
 *       unit-tested off recorded server output. PII-free: only server-advertised
 *       scalars and top-level path *names* the server itself returns; never a
 *       token, credential, or user path. No goto; early-return.
 */
#include "diag_internal.h"


/* ---- bounded, scoped XML field extraction (pure; unit-tested) ---- */

/*
 * Return a pointer to the inner text of `<stats id="ID" ...>` and its length up
 * to the next `</stats>`, or NULL when the block is absent. The open tag is
 * matched on the exact id (the closing quote is part of the needle, so "oss"
 * never matches "oss.0"), then we advance past the first '>' so any attributes
 * after the id are skipped. No allocation; the span is a view into `xml`.
 */
static const char *
recon_stats_block(const char *xml, const char *id, size_t *blen)
{
    char        open[48];
    const char *p, *gt, *end;

    snprintf(open, sizeof(open), "<stats id=\"%s\"", id);
    p = strstr(xml, open);
    if (p == NULL) {
        return NULL;
    }
    gt = strchr(p, '>');
    if (gt == NULL) {
        return NULL;
    }
    p   = gt + 1;
    end = strstr(p, "</stats>");
    if (end == NULL) {
        return NULL;
    }
    *blen = (size_t) (end - p);
    return p;
}


/*
 * Parse the signed int64 inside the first `<tag>…</tag>` found within the
 * `blen`-bounded block `blk`, or -1 when the tag is absent/empty/non-numeric.
 * strstr scans the whole NUL-terminated buffer, so an offset past `blen` means
 * the match belongs to a later block and is rejected — that is what bounds us.
 */
static int64_t
recon_tag_i64(const char *blk, size_t blen, const char *tag)
{
    char        open[24];
    const char *p, *q;

    snprintf(open, sizeof(open), "<%s>", tag);
    p = strstr(blk, open);
    if (p == NULL || (size_t) (p - blk) >= blen) {
        return -1;
    }
    q = p + strlen(open);
    while (*q == ' ' || *q == '\t') {
        q++;
    }
    if (*q != '-' && (*q < '0' || *q > '9')) {
        return -1;
    }
    return (int64_t) strtoll(q, NULL, 10);
}


/* Return the inner text of a child `<tag>…</tag>` within the bounded block
 * `blk`, or NULL when absent. Used to scope into nested groups (ops/lgn/tpc). */
static const char *
recon_child(const char *blk, size_t blen, const char *tag, size_t *clen)
{
    char        open[24], close[24];
    const char *p, *end;

    snprintf(open,  sizeof(open),  "<%s>",  tag);
    snprintf(close, sizeof(close), "</%s>", tag);
    p = strstr(blk, open);
    if (p == NULL || (size_t) (p - blk) >= blen) {
        return NULL;
    }
    p   = p + strlen(open);
    end = strstr(p, close);
    if (end == NULL) {
        return NULL;
    }
    *clen = (size_t) (end - p);
    return p;
}


/*
 * doctor_recon_xml_i64 — scoped int64 read: the value of top-level <tag> inside
 * `<stats id="ID">`. Exposed for offline unit testing of the extractor spine.
 */
int64_t
doctor_recon_xml_i64(const char *xml, const char *id, const char *tag)
{
    const char *blk;
    size_t      blen;

    if (xml == NULL || id == NULL || tag == NULL) {
        return -1;
    }
    blk = recon_stats_block(xml, id, &blen);
    if (blk == NULL) {
        return -1;
    }
    return recon_tag_i64(blk, blen, tag);
}


/* ---- per-plane stats parsers (each pure over the XML buffer) ---- */

static void
recon_parse_link(const char *xml, doctor_recon *r)
{
    const char *blk;
    size_t      blen;

    blk = recon_stats_block(xml, "link", &blen);
    if (blk == NULL) {
        return;
    }
    r->conns_total = recon_tag_i64(blk, blen, "tot");
    r->bytes_in    = recon_tag_i64(blk, blen, "in");
    r->bytes_out   = recon_tag_i64(blk, blen, "out");
}


static void
recon_parse_xrootd(const char *xml, doctor_recon *r)
{
    const char *blk, *ops, *lgn;
    size_t      blen, sub;

    blk = recon_stats_block(xml, "xrootd", &blen);
    if (blk == NULL) {
        return;
    }
    ops = recon_child(blk, blen, "ops", &sub);
    if (ops != NULL) {
        r->ops_open = recon_tag_i64(ops, sub, "open");
        r->ops_rd   = recon_tag_i64(ops, sub, "rd");
        r->ops_wr   = recon_tag_i64(ops, sub, "wr");
    }
    r->ops_err = recon_tag_i64(blk, blen, "err");
    r->ops_rdr = recon_tag_i64(blk, blen, "rdr");
    r->ops_dly = recon_tag_i64(blk, blen, "dly");
    lgn = recon_child(blk, blen, "lgn", &sub);
    if (lgn != NULL) {
        r->lgn_num = recon_tag_i64(lgn, sub, "num");
        r->lgn_au  = recon_tag_i64(lgn, sub, "au");
        r->lgn_af  = recon_tag_i64(lgn, sub, "af");
    }
}


static void
recon_parse_ofs(const char *xml, doctor_recon *r)
{
    const char *blk, *tpc;
    size_t      blen, sub;

    blk = recon_stats_block(xml, "ofs", &blen);
    if (blk == NULL) {
        return;
    }
    tpc = recon_child(blk, blen, "tpc", &sub);
    if (tpc == NULL) {
        return;
    }
    r->have_tpc  = 1;
    r->tpc_grant = recon_tag_i64(tpc, sub, "grnt");
    r->tpc_deny  = recon_tag_i64(tpc, sub, "deny");
    r->tpc_err   = recon_tag_i64(tpc, sub, "err");
}


static void
recon_parse_oss(const char *xml, doctor_recon *r)
{
    const char *blk;
    size_t      blen;

    blk = recon_stats_block(xml, "oss", &blen);
    if (blk == NULL) {
        return;
    }
    r->oss_total = recon_tag_i64(blk, blen, "tote");
    r->oss_free  = recon_tag_i64(blk, blen, "free");
    r->ino_total = recon_tag_i64(blk, blen, "ino");
    r->ino_free  = recon_tag_i64(blk, blen, "ifr");
}


static void
recon_parse_http(const char *xml, doctor_recon *r)
{
    const char *blk;
    size_t      blen;

    blk = recon_stats_block(xml, "http", &blen);
    if (blk == NULL) {
        return;
    }
    r->have_http     = 1;
    r->http_reqs     = recon_tag_i64(blk, blen, "requests");
    r->http_in       = recon_tag_i64(blk, blen, "bytes_in");
    r->http_out      = recon_tag_i64(blk, blen, "bytes_out");
    r->http_tpc_pull = recon_tag_i64(blk, blen, "tpc_pull");
    r->http_tpc_push = recon_tag_i64(blk, blen, "tpc_push");
}


/* Parse every plane we care about out of a `query stats a` reply. */
void
doctor_recon_parse_stats(const char *xml, doctor_recon *r)
{
    if (xml == NULL || r == NULL) {
        return;
    }
    recon_parse_link(xml, r);
    recon_parse_xrootd(xml, r);
    recon_parse_ofs(xml, r);
    recon_parse_oss(xml, r);
    recon_parse_http(xml, r);
}


/* ---- capability-flag decode (pure; unit-tested) ---- */

/*
 * doctor_recon_caps_str — render the set kXR_protocol capability bits of `f`
 * as a comma-separated name list into out[osz]; returns the count named. The
 * bit→name table is the same vocabulary conn_explain.c narrates, compacted for
 * a single reconnaissance line and machine consumption.
 */
int
doctor_recon_caps_str(unsigned f, char *out, size_t osz)
{
    static const struct { unsigned bit; const char *name; } M[] = {
        { kXR_isServer,      "server" },
        { kXR_isManager,     "manager" },
        { kXR_attrCache,     "cache" },
        { kXR_attrMeta,      "meta" },
        { kXR_attrProxy,     "proxy" },
        { kXR_attrSuper,     "supervisor" },
        { kXR_attrVirtRdr,   "virt-redirector" },
        { kXR_recoverWrts,   "recover-writes" },
        { kXR_collapseRedir, "collapse-redir" },
        { kXR_ecRedir,       "ec-redir" },
        { kXR_haveTLS,       "tls-available" },
        { kXR_gotoTLS,       "tls-required" },
        { kXR_tlsLogin,      "tls-login" },
        { kXR_anongpf,       "anon-gpf" },
        { kXR_supgpf,        "gpf" },
        { kXR_suppgrw,       "pgrw" },
        { kXR_supposc,       "posc" },
    };
    size_t i, used = 0;
    int    cnt = 0;

    if (osz > 0) {
        out[0] = '\0';
    }
    for (i = 0; i < sizeof(M) / sizeof(M[0]); i++) {
        if (!(f & M[i].bit)) {
            continue;
        }
        used += (size_t) snprintf(out + used, used < osz ? osz - used : 0,
                                  "%s%s", cnt ? "," : "", M[i].name);
        cnt++;
    }
    return cnt;
}


/* ---- wire scrape (kXR_QStats / kXR_Qconfig / dirlist) ---- */

/*
 * Fetch one Qconfig key's value-line into out (may be NULL to only test
 * support). Returns 1 when the server answered with a real value, 0 when the
 * key is unsupported (echoed verbatim) or unanswered — the echo-suppression
 * rule doctor_scrape_config/xrd_probe_caps use.
 */
static int
recon_qkey(brix_conn *c, const char *key, char *out, size_t osz)
{
    char        reply[256], *nl, *eq;
    const char *val;
    brix_status st;

    if (out != NULL) {
        out[0] = '\0';
    }
    brix_status_clear(&st);
    if (brix_query(c, kXR_Qconfig, key, reply, sizeof(reply), &st) != 0) {
        return 0;
    }
    if ((nl = strchr(reply, '\n')) != NULL) {
        *nl = '\0';
    }
    eq  = strchr(reply, '=');
    val = (eq != NULL) ? eq + 1 : reply;
    if (strcmp(val, key) == 0) {          /* echo == key ⇒ unsupported/absent */
        return 0;
    }
    if (out != NULL && osz > 0) {
        snprintf(out, osz, "%.*s", (int) osz - 1, val);
    }
    return 1;
}


/* The full Qconfig key sweep. Counts how many advertised keys this server
 * actually answers (a fingerprint of build/config surface) and captures the two
 * cluster-identity values worth surfacing directly. PII-free. */
static void
recon_sweep_config(brix_conn *c, doctor_recon *r)
{
    static const char *KEYS[] = {
        "version", "role", "sitename", "chksum", "tpc", "tpcdlg", "pgread",
        "bind_max", "pio_max", "poscmax", "readv_ior_max", "readv_iov_max",
        "window", "wan_port", "wan_window", "cid", "cms", "start", "dlgctm",
        "fslib", "ofslib", "oidc", "xrdfs.ext", "oss.cgroup", "tpcprot",
    };
    size_t i;

    r->cfg_probed = (int) (sizeof(KEYS) / sizeof(KEYS[0]));
    for (i = 0; i < sizeof(KEYS) / sizeof(KEYS[0]); i++) {
        char  *dst = NULL;   /* capture cid/cms directly; test-only otherwise */
        size_t dsz = 0;

        if (strcmp(KEYS[i], "cid") == 0) {
            dst = r->cid; dsz = sizeof(r->cid);
        } else if (strcmp(KEYS[i], "cms") == 0) {
            dst = r->cms; dsz = sizeof(r->cms);
        }
        if (recon_qkey(c, KEYS[i], dst, dsz)) {
            r->cfg_supported++;
        }
    }
}


/* Bounded authorized-root discovery: a single dirlist of "/". A refusal (not
 * authorized) simply leaves roots_listed=0 — never an error. Only top-level
 * entry NAMES are recorded (never a full path), capped at RECON_MAX_ROOTS. */
static void
recon_list_roots(brix_conn *c, doctor_recon *r)
{
    brix_dirent *ents = NULL;
    size_t       count = 0, i;
    brix_status  st;

    brix_status_clear(&st);
    if (brix_dirlist(c, "/", 0 /*no stat*/, &ents, &count, &st) != 0) {
        return;
    }
    r->roots_listed = 1;
    for (i = 0; i < count; i++) {
        if (ents[i].name[0] == '\0' || strcmp(ents[i].name, ".") == 0
            || strcmp(ents[i].name, "..") == 0) {
            continue;
        }
        if (r->nroots >= RECON_MAX_ROOTS) {
            r->roots_more = 1;
            break;
        }
        snprintf(r->roots[r->nroots], sizeof(r->roots[0]), "%.*s",
                 (int) sizeof(r->roots[0]) - 1, ents[i].name);
        r->nroots++;
    }
    free(ents);
}


/* Set every numeric field to the "-1 = not reported" sentinel; string/flag
 * fields start zeroed by the caller's memset. */
static void
recon_init(doctor_recon *r, unsigned caps)
{
    r->probed = 1;
    r->caps   = caps;
    r->conns_total = r->bytes_in = r->bytes_out = -1;
    r->ops_open = r->ops_rd = r->ops_wr = -1;
    r->ops_err = r->ops_rdr = r->ops_dly = -1;
    r->lgn_num = r->lgn_au = r->lgn_af = -1;
    r->tpc_grant = r->tpc_deny = r->tpc_err = -1;
    r->oss_total = r->oss_free = r->ino_total = r->ino_free = -1;
    r->http_reqs = r->http_in = r->http_out = -1;
    r->http_tpc_pull = r->http_tpc_push = -1;
}


/*
 * doctor_recon_probe — fill e->recon over the live connection `c`. Best-effort:
 * each leg (stats / config sweep / root list) is independent, so a server that
 * denies one still yields the others. PII-free and read-only throughout.
 */
void
doctor_recon_probe(const diag_args *a, brix_conn *c, doctor_ep *e)
{
    doctor_recon *r = &e->recon;
    char          xml[16384];
    brix_status   st;

    (void) a;
    recon_init(r, e->caps);

    brix_status_clear(&st);
    if (brix_query(c, kXR_QStats, "a", xml, sizeof(xml), &st) == 0
        && xml[0] != '\0') {
        doctor_recon_parse_stats(xml, r);
    }
    recon_sweep_config(c, r);
    recon_list_roots(c, r);
}


/* ---- renderers (text + JSON) ---- */

/* Print " label=<v>" only when the server reported the field (v >= 0). */
static void
recon_num(const char *label, int64_t v)
{
    if (v >= 0) {
        printf(" %s=%lld", label, (long long) v);
    }
}


/* Traffic/op/login/tpc panel lines. */
static void
recon_report_activity(const doctor_recon *r)
{
    if (r->conns_total >= 0 || r->bytes_in >= 0) {
        printf("  recon link:");
        recon_num("conns", r->conns_total);
        recon_num("bytes_in", r->bytes_in);
        recon_num("bytes_out", r->bytes_out);
        printf("\n");
    }
    if (r->ops_open >= 0 || r->ops_err >= 0) {
        printf("  recon ops:");
        recon_num("open", r->ops_open);
        recon_num("rd", r->ops_rd);
        recon_num("wr", r->ops_wr);
        recon_num("err", r->ops_err);
        recon_num("rdr", r->ops_rdr);
        recon_num("dly", r->ops_dly);
        printf("\n");
    }
    if (r->lgn_num >= 0) {
        printf("  recon logins:");
        recon_num("total", r->lgn_num);
        recon_num("authed", r->lgn_au);
        recon_num("failed", r->lgn_af);
        printf("\n");
    }
    if (r->have_tpc) {
        printf("  recon tpc:");
        recon_num("grant", r->tpc_grant);
        recon_num("deny", r->tpc_deny);
        recon_num("err", r->tpc_err);
        printf("\n");
    }
}


/* Storage/http/roots panel lines. */
static void
recon_report_storage(const doctor_recon *r)
{
    int i;

    if (r->oss_total >= 0 || r->ino_total >= 0) {
        printf("  recon oss:");
        recon_num("bytes_total", r->oss_total);
        recon_num("bytes_free", r->oss_free);
        recon_num("inodes_total", r->ino_total);
        recon_num("inodes_free", r->ino_free);
        printf("\n");
    }
    if (r->have_http) {
        printf("  recon http:");
        recon_num("reqs", r->http_reqs);
        recon_num("bytes_in", r->http_in);
        recon_num("bytes_out", r->http_out);
        recon_num("tpc_pull", r->http_tpc_pull);
        recon_num("tpc_push", r->http_tpc_push);
        printf("\n");
    }
    if (r->roots_listed) {
        printf("  recon roots (%d%s):", r->nroots, r->roots_more ? "+" : "");
        for (i = 0; i < r->nroots; i++) {
            printf(" /%s", r->roots[i]);
        }
        printf("\n");
    }
}


void
doctor_report_recon(const doctor_ep *e)
{
    const doctor_recon *r = &e->recon;
    char                caps[256];

    if (!r->probed) {
        return;
    }
    printf("  recon: qconfig %d/%d keys answered", r->cfg_supported, r->cfg_probed);
    if (r->cid[0]) {
        printf(" cid=%s", r->cid);
    }
    if (r->cms[0]) {
        printf(" cms=%s", r->cms);
    }
    printf("\n");
    if (doctor_recon_caps_str(r->caps, caps, sizeof(caps)) > 0) {
        printf("  recon caps: %s\n", caps);
    }
    recon_report_activity(r);
    recon_report_storage(r);
}


/* Append a ,"recon":{...} object to the endpoint's JSON (nothing if unprobed). */
void
doctor_emit_recon_json(const doctor_ep *e, FILE *out)
{
    const doctor_recon *r = &e->recon;
    char                caps[256];
    int                 i;

    if (!r->probed) {
        return;
    }
    doctor_recon_caps_str(r->caps, caps, sizeof(caps));
    fprintf(out, ",\"recon\":{\"caps\":");
    fjson_str(out, caps);
    fprintf(out, ",\"cid\":");
    fjson_str(out, r->cid);
    fprintf(out, ",\"cms\":");
    fjson_str(out, r->cms);
    fprintf(out, ",\"cfg_probed\":%d,\"cfg_supported\":%d"
            ",\"conns_total\":%lld,\"bytes_in\":%lld,\"bytes_out\":%lld"
            ",\"ops\":{\"open\":%lld,\"rd\":%lld,\"wr\":%lld,\"err\":%lld,"
            "\"rdr\":%lld,\"dly\":%lld}"
            ",\"logins\":{\"total\":%lld,\"authed\":%lld,\"failed\":%lld}"
            ",\"tpc\":{\"grant\":%lld,\"deny\":%lld,\"err\":%lld}"
            ",\"oss\":{\"bytes_total\":%lld,\"bytes_free\":%lld,"
            "\"inodes_total\":%lld,\"inodes_free\":%lld}"
            ",\"http\":{\"reqs\":%lld,\"bytes_in\":%lld,\"bytes_out\":%lld,"
            "\"tpc_pull\":%lld,\"tpc_push\":%lld}",
            r->cfg_probed, r->cfg_supported,
            (long long) r->conns_total, (long long) r->bytes_in,
            (long long) r->bytes_out,
            (long long) r->ops_open, (long long) r->ops_rd, (long long) r->ops_wr,
            (long long) r->ops_err, (long long) r->ops_rdr, (long long) r->ops_dly,
            (long long) r->lgn_num, (long long) r->lgn_au, (long long) r->lgn_af,
            (long long) r->tpc_grant, (long long) r->tpc_deny, (long long) r->tpc_err,
            (long long) r->oss_total, (long long) r->oss_free,
            (long long) r->ino_total, (long long) r->ino_free,
            (long long) r->http_reqs, (long long) r->http_in, (long long) r->http_out,
            (long long) r->http_tpc_pull, (long long) r->http_tpc_push);
    fprintf(out, ",\"roots\":[");
    for (i = 0; i < r->nroots; i++) {
        if (i) {
            fprintf(out, ",");
        }
        fjson_str(out, r->roots[i]);
    }
    fprintf(out, "],\"roots_more\":%s}", r->roots_more ? "true" : "false");
}
