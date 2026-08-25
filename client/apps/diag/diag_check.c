/*
 * diag_check.c - extracted concern
 * Phase-38 split of xrddiag.c; behavior-identical.
 */
#include "diag_internal.h"
#include "cli/jsonout.h"


/* check — protocol-correctness probes                                 */

/*
 * emit_json_bool_or_null — write "key":bool or "key":null + optional comma.
 *
 * WHAT: helper for optional probe fields in do_check's JSON block.
 * WHY:  distinguishes untested probes (null) from tested-and-failed (false) —
 *       null tells the consumer "we never ran this probe", false says "ran + failed".
 * HOW:  writes directly to out; used only in the JSON emit block of do_check.
 */
static void
emit_json_bool_or_null(FILE *out, const char *k, int tested, int v, int comma)
{
    brix_json_fputs(out, k);
    if (tested) {
        fprintf(out, ":%s%s", v ? "true" : "false", comma ? "," : "");
    } else {
        fprintf(out, ":null%s", comma ? "," : "");
    }
}


/*
 * chk_acc — accumulators shared across the do_check probe helpers.
 *
 * WHAT: the JSON-mode result state that each probe writes its outcome into.
 * WHY:  the probes were extracted from one large function; passing this struct
 *       by pointer keeps their data flow explicit with no new globals.
 * HOW:  zero-init in do_check (bools default false, counts 0); each probe sets
 *       its own fields and bumps `fails` on a failure — same semantics as the
 *       original inline locals.
 */
typedef struct {
    int       fails;
    int       auth_ok, tls_active, tls_required;
    int       confinement_ok, dirlist_ok;
    int       dstat_tested, dstat_ok;
    int       cksum_tested, cksum_ok;
    int       pgread_tested, pgread_ok;
    int       posc_tested, posc_ok;
    int       hlim_tested, hlim_ok;
    long long dirlist_count;
    char      auth_proto[64];
    char      tls_ver[32];
} chk_acc;


/* (1) auth-as-advertised: the driver's chosen protocol must be anon (no &P=)
 *     or appear in the server's advertised security list. */
static void
chk_probe_auth(const diag_args *a, const brix_conn *c, chk_acc *acc)
{
    int ok;
    if (c->sec_list[0] == '\0') {
        ok = (c->diag.chosen_auth == NULL);
    } else {
        ok = (c->diag.chosen_auth != NULL) &&
             (strstr(c->sec_list, c->diag.chosen_auth) != NULL);
    }
    acc->auth_ok = ok;
    if (!ok) { acc->fails++; }
    if (c->diag.chosen_auth != NULL) {
        snprintf(acc->auth_proto, sizeof(acc->auth_proto), "%s", c->diag.chosen_auth);
    }
    if (!a->json) {
        if (c->sec_list[0] == '\0') {
            probe("auth-as-advertised", ok,
                  c->diag.chosen_auth == NULL ? "anonymous (no &P= offered)"
                                             : "client used %s but server offered none",
                  c->diag.chosen_auth ? c->diag.chosen_auth : "");
        } else {
            probe("auth-as-advertised", ok, "chose %s from \"%s\"",
                  c->diag.chosen_auth ? c->diag.chosen_auth : "(none)", c->sec_list);
        }
    }
}


/* (2) no-silent-TLS-downgrade: gotoTLS advertised ⇒ session must be TLS. */
static void
chk_probe_tls(const diag_args *a, brix_conn *c, chk_acc *acc)
{
    unsigned    f = (unsigned) c->server_flags;
    const char *v = NULL, *cf = NULL;
    int         tls_active = brix_tls_info(c, &v, &cf);
    acc->tls_active   = tls_active;
    acc->tls_required = (f & kXR_gotoTLS) ? 1 : 0;
    if (v != NULL) {
        snprintf(acc->tls_ver, sizeof(acc->tls_ver), "%s", v);
    }
    /* count as a failure only when the server demanded TLS but we got cleartext */
    if (acc->tls_required && !tls_active) { acc->fails++; }
    if (!a->json) {
        if (f & kXR_gotoTLS) {
            probe("no-tls-downgrade", tls_active,
                  tls_active ? "gotoTLS honored (%s)" : "gotoTLS advertised but cleartext!",
                  v ? v : "");
        } else {
            note("no-tls-downgrade", tls_active ? "TLS active" : "cleartext (gotoTLS not required)");
        }
    }
}


/* (3) path-confinement: an escape attempt must be refused, never served. */
static void
chk_probe_confinement(const diag_args *a, brix_conn *c, chk_acc *acc)
{
    brix_statinfo esc;
    brix_status   est;
    int           rc;
    brix_status_clear(&est);
    rc = brix_stat(c, "/../../../../../../etc/passwd", &esc, &est);
    acc->confinement_ok = (rc != 0);
    if (!acc->confinement_ok) { acc->fails++; }
    if (!a->json) {
        probe("path-confinement", rc != 0,
              rc != 0 ? "escape refused (%s)" : "ESCAPE SERVED — confinement broken!",
              rc != 0 ? brix_kxr_name(est.kxr) : "");
    }
}


/* (4) dirlist works + (7) dirlist-dstat == stat for the first entry. */
static void
chk_probe_dirlist(const diag_args *a, brix_conn *c, chk_acc *acc)
{
    brix_dirent *ents = NULL;
    size_t       n = 0;
    brix_status  dst;
    brix_status_clear(&dst);
    if (brix_dirlist(c, "/", 1, &ents, &n, &dst) != 0) {
        acc->dirlist_ok = 0;
        acc->fails++;
        if (!a->json) { probe("dirlist", 0, "%s", dst.msg); }
        return;
    }
    acc->dirlist_ok     = 1;
    acc->dirlist_count  = (long long) n;
    if (!a->json) { probe("dirlist", 1, "%zu entries under /", n); }
    /* find a regular file entry with a stat and cross-check it */
    for (size_t i = 0; i < n; i++) {
        if (ents[i].have_stat && !(ents[i].st.flags & kXR_isDir)) {
            char         p[XRDC_PATH_MAX];
            brix_statinfo s2;
            brix_status   s2st;
            snprintf(p, sizeof(p), "/%s", ents[i].name);
            brix_status_clear(&s2st);
            if (brix_stat(c, p, &s2, &s2st) == 0) {
                int ok = (s2.size == ents[i].st.size);
                acc->dstat_tested = 1;
                acc->dstat_ok     = ok;
                if (!ok) { acc->fails++; }
                if (!a->json) {
                    probe("dstat==stat", ok,
                          "%s size dstat=%lld stat=%lld", ents[i].name,
                          (long long) ents[i].st.size, (long long) s2.size);
                }
            }
            break;
        }
    }
    free(ents);
}


/* (5) checksum-works: server digest == local digest of the downloaded bytes. */
static void
chk_probe_checksum(const diag_args *a, brix_conn *c, const char *target, chk_acc *acc)
{
    char        srv[160], loc[160];
    brix_status qst, lst;
    int         tmpfd;
    char        tmpl[] = "/tmp/xrddiag.XXXXXX";

    brix_status_clear(&qst);
    if (brix_query_cksum(c, target, "adler32", srv, sizeof(srv), &qst) != 0) {
        if (!a->json) {
            note("checksum-works", "server has no adler32 (%s)", qst.msg);
        }
        return;
    }
    tmpfd = mkstemp(tmpl);
    if (tmpfd < 0) {
        if (!a->json) { note("checksum-works", "mkstemp failed"); }
        return;
    }
    {
        int64_t got = 0;
        brix_status_clear(&lst);
        if (download_to_fd(c, target, tmpfd, &got, &lst) == 0 &&
            brix_cksum_fd(tmpfd, XRDC_CK_ADLER32, loc, sizeof(loc), &lst) == 0) {
            int ok = (strcmp(srv, loc) == 0);
            acc->cksum_tested = 1;
            acc->cksum_ok     = ok;
            if (!ok) { acc->fails++; }
            if (!a->json) {
                probe("checksum-works", ok,
                      "%s server=%s local=%s", target, srv, loc);
            }
        } else {
            acc->cksum_tested = 1;
            acc->cksum_ok     = 0;
            acc->fails++;
            if (!a->json) { probe("checksum-works", 0, "%s", lst.msg); }
        }
        close(tmpfd);
        unlink(tmpl);
    }
}


/* (6) pgread-integrity: pgread self-validates per-page CRC32c. */
static void
chk_probe_pgread(const diag_args *a, brix_conn *c, const char *target, chk_acc *acc)
{
    char        buf[8192];
    brix_file   f;
    brix_status pst;
    brix_status_clear(&pst);
    if (brix_file_open_read(c, target, &f, &pst) != 0) {
        acc->pgread_tested = 1;
        acc->pgread_ok     = 0;
        acc->fails++;
        if (!a->json) { probe("pgread-integrity", 0, "open: %s", pst.msg); }
        return;
    }
    {
        ssize_t r = brix_file_pgread(c, &f, 0, buf, sizeof(buf), &pst);
        acc->pgread_tested = 1;
        acc->pgread_ok     = (r >= 0);
        if (!acc->pgread_ok) { acc->fails++; }
        if (!a->json) {
            probe("pgread-integrity", r >= 0,
                  r >= 0 ? "%zd bytes, all page CRC32c verified" : "%s",
                  r >= 0 ? (size_t) r : 0, r >= 0 ? "" : pst.msg);
        }
        brix_file_close(c, &f, &pst);
    }
}


/* (8) POSC-atomicity: a non-finalized POSC upload must leave NO file. Open a
 *     SECOND connection, posc-open + partial write, then ABANDON it (close the
 *     socket without kXR_close) and confirm the path is absent on the main conn. */
static void
chk_probe_posc(const diag_args *a, brix_conn *c, const brix_url *u, chk_acc *acc)
{
    brix_conn   pc;
    brix_status pst;
    brix_file   pf;
    char        ppath[64];
    snprintf(ppath, sizeof(ppath), "/_xrddiag_posc_%d.tmp", (int) getpid());
    brix_status_clear(&pst);
    if (brix_connect(&pc, u, &a->conn, &pst) != 0) {
        if (!a->json) {
            note("posc-atomicity", "skipped — 2nd connect: %s", pst.msg);
        }
        return;
    }
    if (brix_file_open_write(&pc, ppath, 1, 1, &pf, &pst) != 0) {
        if (!a->json) {
            note("posc-atomicity", "skipped — posc open: %s (read-only export?)",
                 pst.msg);
        }
        brix_close(&pc);
        return;
    }
    {
        brix_statinfo si;
        brix_status   s2;
        int           visible;
        (void) brix_file_write(&pc, &pf, 0, "partial", 7, &pst);
        /* ABANDON: drop the socket with no kXR_close → server discards POSC. */
        if (pc.io.fd >= 0) { close(pc.io.fd); pc.io.fd = -1; }
        brix_close(&pc);
        brix_status_clear(&s2);
        visible          = (brix_stat(c, ppath, &si, &s2) == 0);
        acc->posc_tested = 1;
        acc->posc_ok     = !visible;
        if (visible) { acc->fails++; }
        if (!a->json) {
            probe("posc-atomicity", !visible,
                  visible ? "PARTIAL FILE VISIBLE after abandoned upload!"
                          : "abandoned upload left no file (%s)",
                  visible ? "" : brix_kxr_name(s2.kxr));
        }
        if (visible) { brix_rm(c, ppath, &s2); }   /* clean up the leak */
    }
}


/* (9) handle-limits: opening files past the server cap must fail GRACEFULLY
 *     (a clean kXR_* error, not a crash/hang) and the connection survive. */
static void
chk_probe_handle_limits(const diag_args *a, brix_conn *c, const char *target, chk_acc *acc)
{
    brix_file   fhs[64];
    brix_status hst;
    int         opened = 0, i, graceful;
    for (i = 0; i < 64; i++) {
        brix_status_clear(&hst);
        if (brix_file_open_read(c, target, &fhs[opened], &hst) != 0) {
            break;
        }
        opened++;
    }
    graceful = (opened < 64);   /* hit a cap with a clean error */
    {
        brix_statinfo si;
        brix_status   s2;
        int           alive;
        brix_status_clear(&s2);
        alive = (brix_stat(c, "/", &si, &s2) == 0) || (s2.kxr > 0);
        if (graceful) {
            acc->hlim_tested = 1;
            acc->hlim_ok     = alive;
            if (!alive) { acc->fails++; }
            if (!a->json) {
                probe("handle-limits", alive, "capped at %d open (%s), conn alive",
                      opened, brix_kxr_name(hst.kxr));
            }
        } else {
            if (!a->json) {
                note("handle-limits", "no cap hit (opened %d), conn %s", opened,
                     alive ? "alive" : "DEAD");
            }
        }
    }
    for (i = 0; i < opened; i++) {
        brix_status cs;
        brix_status_clear(&cs);
        brix_file_close(c, &fhs[i], &cs);
    }
}


/* (10) credential validity / clock-skew: surface env-credential expiry (the
 *      actionable client-side signal — see also `xrdfs explain`). */
static void
chk_probe_cred_validity(void)
{
    char       *tok = brix_token_discover();
    const char *proxy = getenv("X509_USER_PROXY");
    if (tok != NULL || (proxy != NULL && proxy[0] != '\0')) {
        printf("Credential validity:\n");
        if (tok != NULL) { brix_token_explain(tok, stdout); free(tok); }
        if (proxy != NULL && proxy[0] != '\0') {
            brix_gsi_cert_explain(proxy, stdout);
        }
    } else {
        note("cred-validity", "anonymous — no credential expiry to check");
    }
}


/* chk_emit_json — write the single JSON result object; returns the exit code. */
static int
chk_emit_json(const diag_args *a, const chk_acc *acc)
{
    printf("{");
    brix_json_kv_str(stdout,  "url",                  a->url,               1);
    brix_json_kv_bool(stdout, "connect_ok",           1,                    1);
    brix_json_kv_str(stdout,  "auth_proto",           acc->auth_proto,      1);
    brix_json_kv_bool(stdout, "auth_ok",              acc->auth_ok,         1);
    brix_json_kv_bool(stdout, "tls_required",         acc->tls_required,    1);
    brix_json_kv_bool(stdout, "tls_active",           acc->tls_active,      1);
    brix_json_kv_str(stdout,  "tls_ver",              acc->tls_ver,         1);
    brix_json_kv_bool(stdout, "path_confinement_ok",  acc->confinement_ok,  1);
    brix_json_kv_bool(stdout, "dirlist_ok",           acc->dirlist_ok,      1);
    brix_json_kv_ll(stdout,   "dirlist_count",        acc->dirlist_count,   1);
    emit_json_bool_or_null(stdout, "dstat_ok",        acc->dstat_tested,  acc->dstat_ok,  1);
    emit_json_bool_or_null(stdout, "checksum_ok",     acc->cksum_tested,  acc->cksum_ok,  1);
    emit_json_bool_or_null(stdout, "pgread_ok",       acc->pgread_tested, acc->pgread_ok, 1);
    emit_json_bool_or_null(stdout, "posc_ok",         acc->posc_tested,   acc->posc_ok,   1);
    emit_json_bool_or_null(stdout, "handle_ok",       acc->hlim_tested,   acc->hlim_ok,   1);
    brix_json_kv_ll(stdout,   "failures",             (long long) acc->fails, 0);
    printf("}\n");
    return acc->fails ? 1 : 0;
}


/*
 * do_check — protocol-correctness and security probes against a live endpoint.
 *
 * WHAT: connects, runs a battery of functional and security probes, then
 *       outputs either a human-readable report or (--json) a single JSON object.
 * WHY:  JSON mode lets CI/CD pipelines and monitoring scripts consume results
 *       without parsing prose; the machine-readable path mirrors the human one 1:1.
 * HOW:  each probe runs regardless of output mode; outcomes accumulate in `acc`.
 *       Human path (probe/note/printf) is guarded by !a->json throughout.
 *       JSON is emitted once at the very end — never partial, never on early error.
 */
int
do_check(const diag_args *a)
{
    brix_url      u;
    brix_conn     c;
    brix_status   st;
    brix_statinfo sti;
    char          target[XRDC_PATH_MAX];
    int           have_file;
    /* JSON-mode accumulators — zero-init: bools default false, counts 0 */
    chk_acc       acc = { 0 };
    snprintf(acc.auth_proto, sizeof(acc.auth_proto), "%s", "anon");

    int dial = diag_dial(a, &u, &c, &st);
    if (dial != 0) {
        return dial;
    }

    if (!a->json) {
        printf("Session facts:\n");
        brix_explain_conn(&c, &a->conn, stdout);
        printf("Probes:\n");
    }

    chk_probe_auth(a, &c, &acc);
    chk_probe_tls(a, &c, &acc);
    chk_probe_confinement(a, &c, &acc);
    chk_probe_dirlist(a, &c, &acc);

    /* Resolve a file for the integrity probes (skip cleanly if none). */
    have_file = (resolve_target(&c, &u, target, sizeof(target), &sti, &st) == 0);
    if (!have_file && !a->json) {
        note("checksum/pgread", "skipped — %s", st.msg);
    }

    if (have_file) {
        chk_probe_checksum(a, &c, target, &acc);
        chk_probe_pgread(a, &c, target, &acc);
        chk_probe_posc(a, &c, &u, &acc);
        chk_probe_handle_limits(a, &c, target, &acc);
    }

    if (!a->json) {
        chk_probe_cred_validity();
    }

    brix_close(&c);

    if (a->json) {
        return chk_emit_json(a, &acc);
    }

    printf("Result: %d failure(s)\n", g_fails);
    return g_fails ? 1 : 0;
}
