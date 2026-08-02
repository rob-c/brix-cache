/*
 * storascan_scan.c — xrdstorascan server-engine modes over the /scan endpoint.
 *
 * WHAT: the dump/verify/fill/compare/inspect/health/inventory/drift modes that
 *       drive the server-side scan engine through the /brix/api/v1/scan admin
 *       HTTP endpoint (NDJSON in, TSV/JSON/summary out).
 * WHY:  these modes are an HTTP client with no libbrix wire I/O; splitting them
 *       from the client-side verify/bench keeps every subcommand within the
 *       Phase-38 size budget and off the storascan_core math surface.
 * HOW:  password login → session cookie → authenticated GET, then a per-record
 *       NDJSON renderer. No goto; a minimal field extractor over controlled
 *       server output (no full JSON parser needed).
 */
#include "storascan_internal.h"
#include "brix.h"
#include "brix_net.h"
#include "core/progname.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    int  tls;
    char host[256];
    int  port;
} scan_ep;

/*
 * scan_args_t — decoded engine-mode (dump/verify/fill/…) command line.
 * WHY: one state block for parse → fetch → render instead of seven loose
 *      locals, and it carries the auth pair (password/insecure) that
 *      scan_login needs without pushing its signature over the arg gate.
 */
typedef struct {
    const char *url;          /* http(s):// dashboard base                  */
    const char *path;         /* --path subtree (default "/")               */
    const char *alg;          /* --algo checksum name (default adler32)     */
    const char *password;     /* --password / $XRDSTORASCAN_PASSWORD        */
    int         insecure;     /* --insecure: skip TLS peer verification     */
    int         as_json;      /* --json: raw NDJSON passthrough             */
    int         summary_only; /* --summary: print only the summary line     */
} scan_args_t;

/* Parse http(s)://host[:port][/...] — only scheme/host/port are used. */
static int
scan_parse_url(const char *url, scan_ep *ep)
{
    const char *p, *slash, *colon;
    size_t      hlen;

    if (strncmp(url, "https://", 8) == 0) {
        ep->tls = 1; p = url + 8; ep->port = 443;
    } else if (strncmp(url, "http://", 7) == 0) {
        ep->tls = 0; p = url + 7; ep->port = 80;
    } else {
        return -1;
    }
    slash = strchr(p, '/');
    colon = strchr(p, ':');
    if (colon != NULL && (slash == NULL || colon < slash)) {
        hlen = (size_t) (colon - p);
        ep->port = atoi(colon + 1);
    } else {
        hlen = slash ? (size_t) (slash - p) : strlen(p);
    }
    if (hlen == 0 || hlen >= sizeof(ep->host) || ep->port <= 0) {
        return -1;
    }
    memcpy(ep->host, p, hlen);
    ep->host[hlen] = '\0';
    return 0;
}

/* POST /brix/login (password) → capture the session cookie. 0 / -1. */
static int
scan_login(const scan_ep *ep, const scan_args_t *sa,
           char *cookie, size_t cksz, brix_status *st)
{
    brix_http_resp resp;
    char           body[256];
    char           sc[512];
    int            n, ok;

    n = snprintf(body, sizeof(body), "password=%s", sa->password);
    if (brix_http_req(ep->host, ep->port, ep->tls, "POST", "/brix/login",
                      "Content-Type: application/x-www-form-urlencoded\r\n",
                      body, (size_t) n, 15000, sa->insecure ? 0 : 1, NULL,
                      &resp, st) != 0)
    {
        return -1;
    }
    cookie[0] = '\0';
    if (brix_http_header(&resp, "Set-Cookie", sc, sizeof(sc))) {
        char *semi = strchr(sc, ';');
        if (semi != NULL) {
            *semi = '\0';
        }
        snprintf(cookie, cksz, "%s", sc);
    }
    ok = (resp.status == 200 || resp.status == 302) && cookie[0] != '\0';
    brix_http_resp_free(&resp);
    if (!ok) {
        brix_status_set(st, XRDC_EAUTH, 0, "dashboard login failed (bad password?)");
        return -1;
    }
    return 0;
}

/* Minimal JSON field extractor over one controlled NDJSON line: copies the value
 * of "key" into out[outsz]. Strings are returned without surrounding quotes (no
 * unescaping — values here are paths/hex/short tokens). 1 found, 0 absent. */
static int
scan_json_field(const char *line, const char *key, char *out, size_t outsz)
{
    char   pat[48];
    const char *p;
    size_t o = 0;

    snprintf(pat, sizeof(pat), "\"%s\":", key);
    p = strstr(line, pat);
    if (p == NULL) {
        return 0;
    }
    p += strlen(pat);
    if (*p == '"') {
        p++;
        while (*p != '\0' && *p != '"' && o + 1 < outsz) {
            if (*p == '\\' && p[1] != '\0') {
                p++;   /* keep the escaped char verbatim */
            }
            out[o++] = *p++;
        }
    } else {
        while (*p != '\0' && *p != ',' && *p != '}' && o + 1 < outsz) {
            out[o++] = *p++;
        }
    }
    out[o] = '\0';
    return 1;
}

/*
 * scan_render_summary — print the summary record; return its mismatch count.
 * WHY: the summary line both renders AND yields the verify/compare exit
 *      signal, so it is the one record type with a return value.
 * HOW: raw passthrough in --json/--summary mode, otherwise the frozen
 *      "# files=… ok=…" counter line.
 */
static long
scan_render_summary(const char *buf, int as_json, int summary_only)
{
    char mm[24] = "0";

    scan_json_field(buf, "mismatch", mm, sizeof(mm));
    if (as_json || summary_only) {
        printf("%s\n", buf);
    } else {
        char files[24] = "0", ok[24] = "0", miss[24] = "0",
             un[24] = "0";
        scan_json_field(buf, "files", files, sizeof(files));
        scan_json_field(buf, "ok", ok, sizeof(ok));
        scan_json_field(buf, "missing", miss, sizeof(miss));
        scan_json_field(buf, "unreadable", un, sizeof(un));
        printf("# files=%s ok=%s mismatch=%s missing=%s unreadable=%s\n",
               files, ok, mm, miss, un);
    }
    return atol(mm);
}

/*
 * scan_render_inspect — TSV line for one "inspect" record.
 * WHY/HOW: pulls the frozen field set out of the NDJSON line and prints the
 *      frozen backend/size/path row.
 */
static void
scan_render_inspect(const char *buf)
{
    char path[1024] = "", backend[24] = "-", src[24] = "-",
         size[24] = "0", cons[8] = "-";

    scan_json_field(buf, "path", path, sizeof(path));
    scan_json_field(buf, "backend", backend, sizeof(backend));
    scan_json_field(buf, "stored_src", src, sizeof(src));
    scan_json_field(buf, "size", size, sizeof(size));
    scan_json_field(buf, "namespace_consistent", cons, sizeof(cons));
    printf("%-8s %-12s %s\tstored_src=%s consistent=%s\n",
           backend, size, path, src, cons);
}

/*
 * scan_render_health — TSV line for one "health" record.
 * WHY/HOW: frozen backend capacity line (total/used/free bytes).
 */
static void
scan_render_health(const char *buf)
{
    char backend[24] = "-", total[24] = "0", freeb[24] = "0",
         used[24] = "0";

    scan_json_field(buf, "backend", backend, sizeof(backend));
    scan_json_field(buf, "total_bytes", total, sizeof(total));
    scan_json_field(buf, "free_bytes", freeb, sizeof(freeb));
    scan_json_field(buf, "used_bytes", used, sizeof(used));
    printf("backend=%s total=%s used=%s free=%s\n",
           backend, total, used, freeb);
}

/*
 * scan_render_object — TSV line for one "object" (inventory) record.
 * WHY/HOW: frozen size/path/key row; a pathless object prints "(orphan)".
 */
static void
scan_render_object(const char *buf)
{
    char key[1024] = "", path[1024] = "", size[24] = "0",
         orphan[8] = "-";

    scan_json_field(buf, "key", key, sizeof(key));
    scan_json_field(buf, "path", path, sizeof(path));
    scan_json_field(buf, "size", size, sizeof(size));
    scan_json_field(buf, "orphan", orphan, sizeof(orphan));
    printf("%-12s %s\tkey=%s orphan=%s\n",
           size, path[0] ? path : "(orphan)", key, orphan);
}

/*
 * scan_render_drift — TSV line for one "drift" record.
 * WHY/HOW: frozen class/size/key/path row.
 */
static void
scan_render_drift(const char *buf)
{
    char cls[24] = "-", key[1024] = "", path[1024] = "",
         size[24] = "0";

    scan_json_field(buf, "class", cls, sizeof(cls));
    scan_json_field(buf, "key", key, sizeof(key));
    scan_json_field(buf, "path", path, sizeof(path));
    scan_json_field(buf, "size", size, sizeof(size));
    printf("%-14s %-12s key=%s path=%s\n", cls, size, key, path);
}

/*
 * scan_render_file — TSV line for one "file" (checksum) record.
 * WHY/HOW: frozen status/size/path row with stored vs computed hex.
 */
static void
scan_render_file(const char *buf)
{
    char path[1024] = "", status[24] = "-", stored[136] = "-",
         computed[136] = "-", size[24] = "0";

    scan_json_field(buf, "path", path, sizeof(path));
    scan_json_field(buf, "status", status, sizeof(status));
    scan_json_field(buf, "size", size, sizeof(size));
    scan_json_field(buf, "stored", stored, sizeof(stored));
    scan_json_field(buf, "computed", computed, sizeof(computed));
    printf("%-10s %-12s %s\tstored=%s computed=%s\n",
           status, size, path, stored, computed);
}

/*
 * scan_render_row — route one non-summary NDJSON record to its printer.
 * WHY: keeps the per-record formatting knowledge out of the body walker.
 * HOW: raw passthrough in --json mode, nothing in --summary mode, otherwise
 *      dispatch on the record's "t" tag ("file" is the default shape).
 */
static void
scan_render_row(const char *buf, const char *t, int as_json, int summary_only)
{
    if (as_json) {
        if (!summary_only) {
            printf("%s\n", buf);
        }
    } else if (summary_only) {
        /* nothing: only the summary line is printed in summary mode */
    } else if (strcmp(t, "inspect") == 0) {
        scan_render_inspect(buf);
    } else if (strcmp(t, "health") == 0) {
        scan_render_health(buf);
    } else if (strcmp(t, "object") == 0) {
        scan_render_object(buf);
    } else if (strcmp(t, "drift") == 0) {
        scan_render_drift(buf);
    } else {   /* "file" */
        scan_render_file(buf);
    }
}

/* Render the NDJSON body: TSV (default), raw json, or summary-only. Returns the
 * mismatch count seen in the summary (for the verify/compare exit code). */
static long
scan_render(const char *body, int as_json, int summary_only)
{
    const char *line = body;
    long        mismatch = 0;

    while (line != NULL && *line != '\0') {
        const char *nl = strchr(line, '\n');
        size_t      len = nl ? (size_t) (nl - line) : strlen(line);
        char        buf[4096];
        char        t[16];

        if (len >= sizeof(buf)) {
            len = sizeof(buf) - 1;
        }
        memcpy(buf, line, len);
        buf[len] = '\0';

        if (scan_json_field(buf, "t", t, sizeof(t))) {
            if (strcmp(t, "summary") == 0) {
                mismatch = scan_render_summary(buf, as_json, summary_only);
            } else {
                scan_render_row(buf, t, as_json, summary_only);
            }
        }
        line = nl ? nl + 1 : NULL;
    }
    return mismatch;
}

/* URL-encode a query value (conservative: keep unreserved + '/'). */
static void
scan_qencode(const char *in, char *out, size_t outsz)
{
    static const char hex[] = "0123456789ABCDEF";
    size_t o = 0;

    for (; *in != '\0' && o + 4 < outsz; in++) {
        unsigned char c = (unsigned char) *in;
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
            || (c >= '0' && c <= '9') || c == '/' || c == '.' || c == '-'
            || c == '_' || c == '~')
        {
            out[o++] = (char) c;
        } else {
            out[o++] = '%';
            out[o++] = hex[c >> 4];
            out[o++] = hex[c & 0xf];
        }
    }
    out[o] = '\0';
}

/* Parse cmd_scan's flag ladder into `sa`. WHAT: --path/--algo/--password/
 * --insecure/--json/--summary plus the single positional dashboard URL.
 * WHY: cmd_scan's parse half is independent of the fetch/render halves; the
 * decoded scan_args_t is what scan_login and the fetch consume.
 * HOW: same first-match ladder as before; unknown dash-word or a second
 * positional → -1 (caller emits usage). */
static int
scan_parse_scan_args(int argc, char **argv, scan_args_t *sa)
{
    int i;

    for (i = 0; i < argc; i++) {
        const char *a = argv[i];
        if (strcmp(a, "--path") == 0 && i + 1 < argc) {
            sa->path = argv[++i];
        } else if (strcmp(a, "--algo") == 0 && i + 1 < argc) {
            sa->alg = argv[++i];
        } else if (strcmp(a, "--password") == 0 && i + 1 < argc) {
            sa->password = argv[++i];
        } else if (strcmp(a, "--insecure") == 0) {
            sa->insecure = 1;
        } else if (strcmp(a, "--json") == 0) {
            sa->as_json = 1;
        } else if (strcmp(a, "--summary") == 0) {
            sa->summary_only = 1;
        } else if (a[0] == '-') {
            return -1;
        } else if (sa->url == NULL) {
            sa->url = a;
        } else {
            return -1;
        }
    }
    return 0;
}

/* Run the authenticated GET against /brix/api/v1/scan. WHAT: builds the
 * mode/path/alg query + Cookie header and fetches into *resp.
 * WHY: the network half of cmd_scan, split from parse and render.
 * HOW: query-encodes path/alg, formats the request, maps transport failure
 * to the shell code and a non-200 to SX_ERROR with the same hints. */
static int
scan_fetch(const char *mode, const scan_ep *ep, const scan_args_t *sa,
           const char *cookie, brix_http_resp *resp)
{
    char        epath[2048], ealg[64], query[2240], hdr[640];
    char        fullpath[2304];
    brix_status st;

    brix_status_clear(&st);
    scan_qencode(sa->path, epath, sizeof(epath));
    scan_qencode(sa->alg, ealg, sizeof(ealg));
    snprintf(query, sizeof(query), "mode=%s&path=%s&alg=%s", mode, epath, ealg);
    snprintf(hdr, sizeof(hdr), "Cookie: %s\r\n", cookie);

    snprintf(fullpath, sizeof(fullpath), "/brix/api/v1/scan?%s", query);
    if (brix_http_req(ep->host, ep->port, ep->tls, "GET", fullpath, hdr,
                      NULL, 0, 120000, sa->insecure ? 0 : 1, NULL, resp, &st) != 0)
    {
        fprintf(stderr, "xrdstorascan: %s: %s\n", mode, st.msg);
        return brix_shellcode(&st);
    }
    if (resp->status != 200) {
        fprintf(stderr, "xrdstorascan: %s: server returned HTTP %d%s\n",
                mode, resp->status,
                resp->status == 404 ? " (scan disabled? — set brix_scan_root)"
                : resp->status == 401 ? " (auth — check password)" : "");
        brix_http_resp_free(resp);
        return SX_ERROR;
    }
    return SX_OK;
}

int
cmd_scan(const char *mode, int argc, char **argv, const char *prog)
{
    scan_args_t    sa = { NULL, "/", "adler32", NULL, 0, 0, 0 };
    scan_ep        ep;
    char           cookie[512] = "";
    brix_http_resp resp;
    brix_status    st;
    long           mismatch;
    int            rc;

    sa.password = getenv("XRDSTORASCAN_PASSWORD");

    /* --help as the first subcommand arg → print this mode's usage to stdout
     * and exit cleanly (WS-2). */
    if (argc >= 1 && strcmp(argv[0], "--help") == 0) {
        printf("usage: %s %s <dashboard-url> [--path P] [--algo A]\n"
               "                    [--password PW] [--insecure] [--json|--summary]\n"
               "    Server-side scan over the /brix/api/v1/scan admin endpoint.\n"
               "    auth via --password or $XRDSTORASCAN_PASSWORD\n",
               prog, mode);
        brix_usage_footer(stdout, prog);
        return SX_OK;
    }

    if (scan_parse_scan_args(argc, argv, &sa) != 0 || sa.url == NULL) {
        return usage(prog, SX_USAGE);
    }
    if (scan_parse_url(sa.url, &ep) != 0) {
        fprintf(stderr, "xrdstorascan: %s needs an http(s):// dashboard URL\n", mode);
        return SX_USAGE;
    }
    if (sa.password == NULL) {
        fprintf(stderr, "xrdstorascan: %s needs --password or $XRDSTORASCAN_PASSWORD\n",
                mode);
        return SX_USAGE;
    }

    brix_status_clear(&st);
    if (scan_login(&ep, &sa, cookie, sizeof(cookie), &st) != 0) {
        fprintf(stderr, "xrdstorascan: %s\n", st.msg);
        return brix_shellcode(&st);
    }

    rc = scan_fetch(mode, &ep, &sa, cookie, &resp);
    if (rc != SX_OK) {
        return rc;
    }

    mismatch = scan_render(resp.body ? resp.body : "", sa.as_json,
                           sa.summary_only);
    brix_http_resp_free(&resp);

    /* verify/compare: corruption found ⇒ non-zero for scripting */
    if ((strcmp(mode, "verify") == 0 || strcmp(mode, "compare") == 0)
        && mismatch > 0)
    {
        return SX_MISMATCH;
    }
    return SX_OK;
}
