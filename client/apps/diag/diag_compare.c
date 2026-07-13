/*
 * diag_compare.c - extracted concern
 * Phase-38 split of xrddiag.c; behavior-identical.
 */
#include "diag_internal.h"

void
probe(const char *name, int ok, const char *fmt, ...)
{
    char    detail[256];
    va_list ap;

    va_start(ap, fmt);
    vsnprintf(detail, sizeof(detail), fmt, ap);
    va_end(ap);

    if (!ok) {
        g_fails++;
    }
    printf("  [%s] %-22s %s\n", ok ? "PASS" : "FAIL", name, detail);
}


/* compare — root-vs-reference (size + dirlist set + md5)              */

/* md5 of a remote file fetched over conn c, into hex[hexsz]. 0 / -1. */
int
remote_md5(brix_conn *c, const char *path, char *hex, size_t hexsz, brix_status *st)
{
    char    tmpl[] = "/tmp/xrddiag-cmp.XXXXXX";
    int     fd = mkstemp(tmpl);
    int64_t got = 0;
    int     rc;

    if (fd < 0) {
        brix_status_set(st, XRDC_ESOCK, 0, "mkstemp failed");
        return -1;
    }
    rc = download_to_fd(c, path, fd, &got, st);
    if (rc == 0) {
        rc = brix_cksum_fd(fd, XRDC_CK_MD5, hex, hexsz, st);
    }
    close(fd);
    unlink(tmpl);
    return rc;
}


/*
 * §15.6 cross-protocol consistency oracle: read the SAME object via root:// and
 * cleartext WebDAV (HTTP GET) and assert size + MD5 agree. The capability no
 * upstream client has — this project unifies the planes over one VFS, so a
 * divergence here is a real cross-protocol bug. S3 (SigV4) and HTTPS-davs
 * (TLS+chunked) planes are deferred — noted, not implemented.
 */
int
do_compare_davs(const diag_args *a)
{
    brix_url      ua;
    brix_conn     ca;
    brix_status   st;
    char          dhost[256];
    int           dport;
    char          root_md5[64], davs_md5[64];
    char         *body;
    size_t        blen = 0;
    int           http = 0, fd;
    char          tmpl[] = "/tmp/xrddiag-davs.XXXXXX";

    brix_status_clear(&st);
    if (brix_endpoint_parse(a->url, &ua, &st) != 0) {
        fprintf(stderr, "xrddiag: %s\n", st.msg);
        return 50;
    }
    if (ua.path[0] == '\0' || strcmp(ua.path, "/") == 0) {
        fprintf(stderr, "xrddiag: compare --davs needs a file path in the URL\n");
        return 50;
    }
    parse_http_hostport(a->davs, dhost, sizeof(dhost), &dport);
    printf("Cross-protocol compare %s\n  root:// %s:%d   davs(http) %s:%d   path %s\n",
           a->url, ua.host, ua.port, dhost, dport, ua.path);

    if (brix_connect(&ca, &ua, &a->conn, &st) != 0) {
        fprintf(stderr, "xrddiag: connect %s:%d: %s\n", ua.host, ua.port, st.msg);
        return brix_shellcode(&st);
    }
    if (remote_md5(&ca, ua.path, root_md5, sizeof(root_md5), &st) != 0) {
        probe("root-read", 0, "%s", st.msg);
        brix_close(&ca);
        return 1;
    }
    brix_close(&ca);

    /* WebDAV plane: cleartext HTTP GET of the same logical path (binary-safe). */
    body = (char *) malloc(1u << 20);
    if (body == NULL) {
        fprintf(stderr, "xrddiag: out of memory\n");
        return 51;
    }
    brix_status_clear(&st);
    if (brix_http_get(dhost, dport, ua.path, 5000, &http, body, 1u << 20, &blen,
                      &st) != 0) {
        probe("davs-http", 0, "GET %s:%d%s: %s", dhost, dport, ua.path, st.msg);
        free(body);
        return 1;
    }
    probe("davs-http", http == 200, "HTTP %d for %s", http, ua.path);
    if (http != 200) {
        free(body);
        printf("Result: %d difference(s)\n", g_fails);
        return 1;
    }
    fd = mkstemp(tmpl);
    if (fd < 0 || (size_t) write(fd, body, blen) != blen
        || brix_cksum_fd(fd, XRDC_CK_MD5, davs_md5, sizeof(davs_md5), &st) != 0) {
        probe("davs-md5", 0, "local md5 failed");
        if (fd >= 0) { close(fd); unlink(tmpl); }
        free(body);
        return 1;
    }
    close(fd);
    unlink(tmpl);
    free(body);

    probe("davs-md5", strcmp(root_md5, davs_md5) == 0,
          "root=%s davs=%s", root_md5, davs_md5);
    note("s3 / https-davs", "deferred (needs SigV4 / HTTPS+chunked)");
    printf("Result: %d difference(s)\n", g_fails);
    return g_fails ? 1 : 0;
}


/*
 * WHAT: Parse both compare URLs, validate the A-side path, and open both
 *       connections (`ca`, `cb`).
 * WHY:  Isolates the argument/URL validation + dual-connect prologue (with its
 *       exact error strings and exit codes) from the actual comparison so the
 *       orchestrator reads as a flat setup → compare → teardown.
 * HOW:  Reject a missing reference, a parse failure, or a bare/empty A path; then
 *       connect A and connect B (closing A if B fails). On success fills `ua`/`ub`
 *       and the open `ca`/`cb`. Returns 0 on success; on failure returns the exact
 *       exit code the inline code used (50 / brix_shellcode). No behavior change.
 */
static int
compare_setup(const diag_args *a, brix_url *ua, brix_url *ub,
              brix_conn *ca, brix_conn *cb)
{
    brix_status st;

    if (a->ref_url == NULL) {
        fprintf(stderr, "xrddiag: compare needs --vs-reference <url>\n");
        return 50;
    }
    brix_status_clear(&st);
    if (brix_endpoint_parse(a->url, ua, &st) != 0 ||
        brix_endpoint_parse(a->ref_url, ub, &st) != 0) {
        fprintf(stderr, "xrddiag: %s\n", st.msg);
        return 50;
    }
    if (ua->path[0] == '\0' || strcmp(ua->path, "/") == 0) {
        fprintf(stderr, "xrddiag: compare needs a file/dir path in the URL\n");
        return 50;
    }
    if (brix_connect(ca, ua, &a->conn, &st) != 0) {
        fprintf(stderr, "xrddiag: connect A %s:%d: %s\n", ua->host, ua->port, st.msg);
        return brix_shellcode(&st);
    }
    if (brix_connect(cb, ub, &a->conn, &st) != 0) {
        fprintf(stderr, "xrddiag: connect B %s:%d: %s\n", ub->host, ub->port, st.msg);
        brix_close(ca);
        return brix_shellcode(&st);
    }
    return 0;
}

/*
 * WHAT: Compare two directories by their dirlist name-set (order-independent).
 * WHY:  Keeps the O(n*m) set-equality probe out of the orchestrator's compare
 *       block so the file-vs-dir branch stays a one-line dispatch.
 * HOW:  List both dirs; if either fails, emit a "dirlist-set" fail probe. Else
 *       equal iff counts match and every A name appears in B; emit the probe with
 *       the entry counts. Side effect: probe() output only. No behavior change.
 */
static void
compare_dirs(brix_conn *ca, brix_conn *cb, const char *pa, const char *pb)
{
    brix_dirent *ea = NULL, *eb = NULL;
    size_t       na = 0, nb = 0;
    int          eq = 1;
    brix_status  sta, stb;

    brix_status_clear(&sta);
    brix_status_clear(&stb);
    if (brix_dirlist(ca, pa, 0, &ea, &na, &sta) == 0 &&
        brix_dirlist(cb, pb, 0, &eb, &nb, &stb) == 0) {
        if (na != nb) {
            eq = 0;
        } else {
            for (size_t i = 0; i < na && eq; i++) {
                int hit = 0;
                for (size_t j = 0; j < nb; j++) {
                    if (strcmp(ea[i].name, eb[j].name) == 0) { hit = 1; break; }
                }
                if (!hit) { eq = 0; }
            }
        }
        probe("dirlist-set", eq, "A=%zu B=%zu entries", na, nb);
    } else {
        probe("dirlist-set", 0, "list failed");
    }
    free(ea);
    free(eb);
}

/*
 * WHAT: Compare two files by their remote MD5 digests.
 * WHY:  Confines the dual remote_md5 fetch + compare (and its failure-status
 *       formatting) to one helper mirroring compare_dirs.
 * HOW:  Fetch MD5 of both paths; on both-OK emit an "md5" probe of the string
 *       compare, else a fail probe carrying whichever side reported an error.
 *       Side effect: probe() output only. No behavior change.
 */
static void
compare_files(brix_conn *ca, brix_conn *cb, const char *pa, const char *pb)
{
    char        ha[64], hb[64];
    brix_status ma, mb;

    brix_status_clear(&ma);
    brix_status_clear(&mb);
    if (remote_md5(ca, pa, ha, sizeof(ha), &ma) == 0 &&
        remote_md5(cb, pb, hb, sizeof(hb), &mb) == 0) {
        probe("md5", strcmp(ha, hb) == 0, "A=%s B=%s", ha, hb);
    } else {
        probe("md5", 0, "A:%s B:%s",
              ma.kxr ? ma.msg : "ok", mb.kxr ? mb.msg : "ok");
    }
}

/*
 * WHAT: Stat both paths, probe size equality, then dispatch to the dir- or
 *       file-comparison helper.
 * WHY:  Splits the comparison body from setup/teardown; returns whether any early
 *       exit (stat failure) occurred so the orchestrator can short-circuit.
 * HOW:  Stat A and B; on either failure emit a "stat" probe and return 1 (caller
 *       returns 1). Else probe "size", then compare_dirs / compare_files per
 *       kXR_isDir. Returns 0 to continue. No behavior change.
 */
static int
compare_probe(brix_conn *ca, brix_conn *cb, const brix_url *ua, const brix_url *ub)
{
    brix_statinfo sa, sb;
    brix_status   sta, stb;
    const char   *pa = ua->path;
    const char   *pb = (ub->path[0] && strcmp(ub->path, "/")) ? ub->path : ua->path;
    int           oka, okb;

    brix_status_clear(&sta);
    brix_status_clear(&stb);
    oka = brix_stat(ca, pa, &sa, &sta) == 0;
    okb = brix_stat(cb, pb, &sb, &stb) == 0;
    if (!oka || !okb) {
        probe("stat", 0, "A:%s B:%s", oka ? "ok" : sta.msg, okb ? "ok" : stb.msg);
        return 1;
    }
    probe("size", sa.size == sb.size, "A=%lld B=%lld",
          (long long) sa.size, (long long) sb.size);

    if (sa.flags & kXR_isDir) {
        compare_dirs(ca, cb, pa, pb);
    } else {
        compare_files(ca, cb, pa, pb);
    }
    return 0;
}

int
do_compare(const diag_args *a)
{
    brix_url  ua = {0}, ub = {0};
    brix_conn ca, cb;
    int       rc;

    if (a->davs != NULL) {
        return do_compare_davs(a);
    }

    rc = compare_setup(a, &ua, &ub, &ca, &cb);
    if (rc != 0) {
        return rc;
    }

    printf("Compare %s  vs  %s\n", a->url, a->ref_url);

    if (compare_probe(&ca, &cb, &ua, &ub) != 0) {
        brix_close(&ca);
        brix_close(&cb);
        return 1;
    }

    brix_close(&ca);
    brix_close(&cb);
    printf("Result: %d difference(s)\n", g_fails);
    return g_fails ? 1 : 0;
}
