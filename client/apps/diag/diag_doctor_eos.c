/*
 * diag_doctor_eos.c — EOS-dialect topology enrichment for `xrddiag --map`.
 *
 * The XRootD mesh (kXR_locate / CMSD) is structurally blind to an EOS FST farm:
 * an EOS MGM answers kXR_locate for ANY path with *itself* plus the aggregate
 * space report, revealing the storage nodes only at open/redirect time. To draw
 * the real cluster we speak EOS's own out-of-band command channel: the client
 * opens a magic path `/proc/{user,admin}/` with the command in the CGI opaque
 * (e.g. `?mgm.cmd=version`) and reads the reply envelope
 *   mgm.proc.stdout=<data>&mgm.proc.stderr=<err>&mgm.proc.retc=<N>
 *
 *   - `/proc/user/?mgm.cmd=version`                         → detect EOS + banner
 *   - `/proc/admin/?mgm.cmd=fs&mgm.subcmd=ls&mgm.outformat=m` → enumerate the FSTs
 *
 * `fs ls` is admin-gated. An identity without admin rights (e.g. one nginx maps
 * to `nobody`) fails the /proc/admin/ open with NotAuthorized — recognised, not
 * unknown — so we mark the MGM `gated` and degrade gracefully rather than error.
 *
 * The transport (doctor_eos_proc / doctor_eos_map) is the only wire code; every
 * parser below (stdout/kv/retc/version/fs) is pure over a caller-supplied buffer
 * and unit-tested off recorded EOS output. Renderers are pure over doctor_ep.
 */
#include "diag_internal.h"

#include "brix_ops.h"

/* ---- pure parsers ------------------------------------------------------- */

/* 1 when `p` (a strstr hit for a klen-byte key inside `rec`) sits on a token
 * boundary and is immediately followed by '=' — i.e. it is a whole key. */
static int
eos_kv_at(const char *rec, const char *p, size_t klen)
{
    char before = (p == rec) ? ' ' : p[-1];

    return (before == ' ' || before == '\t' || before == '\n' || before == '\r')
           && p[klen] == '=';
}


/* Copy one value, which runs from `v` to the next space/tab/newline/&/nul.
 * `v[j] != '\0'` is tested first, so the separator set is never searched for a
 * NUL (strchr would report a spurious hit on the terminator). */
static void
eos_kv_copy(const char *v, char *out, size_t osz)
{
    size_t j = 0;

    while (v[j] != '\0' && strchr(" \t\n\r&", v[j]) == NULL && j < osz - 1) {
        out[j] = v[j];
        j++;
    }
    out[j] = '\0';
}

/* Extract the value of an exact key from an EOS record. The key must sit on a
 * token boundary (start-of-record or preceding whitespace) and be immediately
 * followed by '='; the value runs to the next space/&/newline/nul. This exact-
 * boundary match is what keeps `host` from matching inside `hostport`/`stat.host`
 * and makes the parser tolerant of unknown extra keys and key-order changes.
 * Returns 0 with `out` filled (NUL-terminated) on a hit, -1 otherwise. */
int
doctor_eos_kv(const char *rec, const char *key, char *out, size_t osz)
{
    size_t      klen;
    const char *p;

    if (out == NULL || osz == 0) { return -1; }
    out[0] = '\0';
    if (rec == NULL || key == NULL) { return -1; }
    klen = strlen(key);
    if (klen == 0) { return -1; }

    for (p = rec; (p = strstr(p, key)) != NULL; p += klen) {
        if (eos_kv_at(rec, p, klen)) {
            eos_kv_copy(p + klen + 1, out, osz);
            return 0;
        }
    }
    return -1;
}

/* Locate the `mgm.proc.stdout=` payload span inside a proc reply envelope. The
 * value ends at the next envelope key (`&mgm.proc.stderr=` / `&mgm.proc.retc=`)
 * or end-of-buffer. Returns 0 with [*start,*start+*len) set, -1 if absent. */
int
doctor_eos_stdout(const char *body, const char **start, int *len)
{
    const char *s, *e;

    if (body == NULL || start == NULL || len == NULL) { return -1; }
    s = strstr(body, "mgm.proc.stdout=");
    if (s == NULL) { return -1; }
    s += strlen("mgm.proc.stdout=");
    e = strstr(s, "&mgm.proc.stderr=");
    if (e == NULL) { e = strstr(s, "&mgm.proc.retc="); }
    if (e == NULL) { e = s + strlen(s); }
    *start = s;
    *len = (int) (e - s);
    return 0;
}

/* The command return code from a proc reply. Handles both the line envelope
 * (`mgm.proc.retc=N`) and the JSON envelope (`"retc" : N`). -1 = not present. */
int
doctor_eos_retc(const char *body)
{
    const char *p;

    if (body == NULL) { return -1; }
    p = strstr(body, "mgm.proc.retc=");
    if (p != NULL) { return atoi(p + strlen("mgm.proc.retc=")); }
    p = strstr(body, "\"retc\"");
    if (p != NULL) {
        p = strchr(p, ':');
        if (p != NULL) {
            p++;
            while (*p == ' ' || *p == '"') { p++; }
            return atoi(p);
        }
    }
    return -1;
}

/* Parse `mgm.cmd=version` output into the MGM banner. The stdout payload is
 * `EOS_INSTANCE=... EOS_SERVER_VERSION=... ...`; because the first token abuts
 * the `stdout=` separator we copy the span into a local buffer so the boundary
 * rule in doctor_eos_kv sees it at start-of-record. Returns 1 if this endpoint
 * is an EOS MGM (EOS_INSTANCE present), 0 otherwise. */
int
doctor_eos_parse_version(const char *body, doctor_eos *eos)
{
    const char *s;
    int         len;
    char        buf[512];
    char        v[64];

    if (eos == NULL) { return 0; }
    if (doctor_eos_stdout(body, &s, &len) != 0 || len <= 0) { return 0; }
    if (len > (int) sizeof(buf) - 1) { len = (int) sizeof(buf) - 1; }
    memcpy(buf, s, (size_t) len);
    buf[len] = '\0';

    if (doctor_eos_kv(buf, "EOS_INSTANCE", v, sizeof(v)) != 0) { return 0; }
    eos->kind = DOC_EOS_MGM;
    snprintf(eos->instance, sizeof(eos->instance), "%.*s",
             (int) sizeof(eos->instance) - 1, v);
    if (doctor_eos_kv(buf, "EOS_SERVER_VERSION", v, sizeof(v)) == 0) {
        snprintf(eos->version, sizeof(eos->version), "%.*s",
                 (int) sizeof(eos->version) - 1, v);
    }
    return 1;
}

/* Copy the record starting at sout[*i] (up to the next newline, which is
 * consumed) into `rec`, truncating at the buffer. Returns the record length. */
static int
eos_next_record(const char *sout, int len, int *i, char *rec, size_t rsz)
{
    int j = 0;

    while (*i < len && sout[*i] != '\n') {
        if (j < (int) rsz - 1) {
            rec[j++] = sout[*i];
        }
        (*i)++;
    }
    rec[j] = '\0';
    if (*i < len) {
        (*i)++;                             /* consume the newline */
    }
    return j;
}


/* Project one `fs ls -m` record onto an endpoint slot: address, EOS facts, and
 * the derived cfg/CMS views. `host` is the already-extracted host key and may
 * carry an embedded :port, which is used when no `port=` key is present. */
static void
eos_fill_fst(const char *rec, char *host, doctor_ep *e)
{
    char  port[16], val[64];
    char *colon;

    memset(e, 0, sizeof(*e));
    e->proto = DXP_ROOT;

    colon = strrchr(host, ':');
    if (doctor_eos_kv(rec, "port", port, sizeof(port)) == 0) {
        e->port = atoi(port);
    } else if (colon != NULL) {
        *colon = '\0';
        e->port = atoi(colon + 1);
    }
    if (e->port == 0) { e->port = 1095; }   /* the FST default port */
    snprintf(e->host, sizeof(e->host), "%s", host);

    e->eos.kind = DOC_EOS_FST;
    doctor_eos_kv(rec, "stat.geotag", e->eos.geotag, sizeof(e->eos.geotag));
    doctor_eos_kv(rec, "configstatus", e->eos.cfgstatus,
                  sizeof(e->eos.cfgstatus));
    if (doctor_eos_kv(rec, "stat.boot", val, sizeof(val)) == 0) {
        e->eos.booted = (strcmp(val, "booted") == 0);
    }
    if (doctor_eos_kv(rec, "stat.active", val, sizeof(val)) == 0) {
        e->eos.active = (strcmp(val, "online") == 0);
    }
    if (doctor_eos_kv(rec, "stat.statfs.capacity", val, sizeof(val)) == 0) {
        e->eos.cap_bytes = strtoll(val, NULL, 10);
    }
    if (doctor_eos_kv(rec, "stat.statfs.freebytes", val, sizeof(val)) == 0) {
        e->eos.free_bytes = strtoll(val, NULL, 10);
    }

    /* Mirror capacity into cfg so the shared "NN% free" renderer works, and
     * type the FST on the CMS plane (a data server; rw/ro from configstatus)
     * so the mesh map colours it consistently with located holders. */
    e->cfg.space_total = e->eos.cap_bytes;
    e->cfg.space_free = e->eos.free_bytes;
    if (e->eos.cap_bytes > 0) { e->cfg.scraped = 1; }
    e->cms.reported = 1;
    e->cms.role = DOC_CMS_SERVER;
    e->cms.write = (strstr(e->eos.cfgstatus, "rw") != NULL);
}


/* Parse `fs ls -m` (monitoring) output — one filesystem per line — appending an
 * FST endpoint per record into arr[start..cap). A record is a filesystem iff it
 * carries a `host=` (fs ls) or `hostport=` (node ls) key. Returns the count of
 * endpoints appended. Pure: no allocation, no wire. */
int
doctor_eos_parse_fs(const char *sout, int len, doctor_ep *arr, int cap, int start)
{
    int  i = 0, n = start, added = 0;
    char rec[4096], host[256];

    if (sout == NULL || arr == NULL) { return 0; }

    while (i < len && n < cap) {
        if (eos_next_record(sout, len, &i, rec, sizeof(rec)) == 0) {
            continue;                       /* blank line */
        }
        if (doctor_eos_kv(rec, "host", host, sizeof(host)) != 0
            || host[0] == '\0') {
            if (doctor_eos_kv(rec, "hostport", host, sizeof(host)) != 0) {
                continue;                   /* not a filesystem/node record */
            }
        }

        eos_fill_fst(rec, host, &arr[n]);
        n++;
        added++;
    }
    return added;
}

/* ---- wire transport ----------------------------------------------------- */

/* Run one EOS /proc command: open the magic path with the command as the CGI
 * opaque, read the whole reply (proc replies stat as size 0, so grow-read until
 * EOF), close. Returns a malloc'd NUL-terminated body via *out (caller frees),
 * or -1 — an open failure (NotAuthorized on an admin-gated command) included. */
int
doctor_eos_proc(brix_conn *c, const char *dir, const char *cmd,
                char **out, brix_status *st)
{
    brix_file f;
    char     *buf = NULL;
    size_t    cap = 0, len = 0;
    int64_t   off = 0;

    memset(&f, 0, sizeof(f));
    if (brix_file_open_opaque(c, dir, cmd, 0, 0, 0, &f, st) != 0) {
        return -1;
    }
    for (;;) {
        ssize_t r;
        if (len + 65536 + 1 > cap) {
            size_t ncap = cap ? cap * 2 : 131072;
            char  *nb = realloc(buf, ncap);
            if (nb == NULL) {
                free(buf);
                brix_file_close(c, &f, st);
                return -1;
            }
            buf = nb;
            cap = ncap;
        }
        r = brix_file_read(c, &f, off, buf + len, 65536, st);
        if (r < 0) {
            free(buf);
            brix_file_close(c, &f, st);
            return -1;
        }
        if (r == 0) { break; }
        len += (size_t) r;
        off += r;
    }
    brix_file_close(c, &f, st);

    if (buf == NULL) {
        buf = malloc(1);
        if (buf == NULL) { return -1; }
    }
    buf[len] = '\0';
    *out = buf;
    return 0;
}

/* Admin plane: an `fs ls -m` answer enumerates the whole FST farm. Replaces the
 * located self-node with arr[1..]. Returns 1 when the farm hit the array cap. */
static int
eos_map_admin(const char *body, doctor_ep *arr, int cap, int *n)
{
    const char *sout;
    int         slen, added;

    if (doctor_eos_stdout(body, &sout, &slen) != 0) {
        return 0;
    }
    added = doctor_eos_parse_fs(sout, slen, arr, cap, 1);
    *n = 1 + added;                         /* drop the CMS self-node */
    arr[0].eos.fst_count = added;
    return added >= cap - 1;
}


/* Admin-gated (NotAuthorized) or command error: fall back to the unprivileged
 * user-plane path — sample real files and union the FSTs their `fileinfo`
 * replica tables name. Partial coverage, but real. */
static int
eos_map_fileinfo(const diag_args *a, brix_conn *c, doctor_ep *arr, int cap,
                 int *n, brix_status *st)
{
    char path[XRDC_PATH_MAX];
    int  added;

    arr[0].eos.gated = 1;
    doctor_eos_url_path(a->urls[0], path, sizeof(path));
    brix_status_clear(st);
    added = doctor_eos_discover_fileinfo(c, path, arr, cap, 1, n, st);
    if (added <= 0) {
        return 0;
    }
    arr[0].eos.sampled   = 1;
    arr[0].eos.fst_count = added;
    return *n >= cap;
}


/* Enrich the fan-out array with the EOS view of urls[0]: detect the MGM via the
 * version banner and, if enumerable, replace the CMS self-node with the real FST
 * farm (arr[1..]). Only runs for `--map`. Returns 1 if FSTs were truncated. */
int
doctor_eos_map(const diag_args *a, doctor_ep *arr, int cap, int *n)
{
    brix_url    u;
    brix_conn   c;
    brix_status st;
    char       *body = NULL;
    int         trunc = 0;

    if (a == NULL || arr == NULL || n == NULL) { return 0; }
    if (!a->map || *n < 1 || cap < 2) { return 0; }

    brix_status_clear(&st);
    if (brix_endpoint_parse(a->urls[0], &u, &st) != 0) { return 0; }
    if (brix_connect(&c, &u, &a->conn, &st) != 0) { return 0; }
    c.io.timeout_ms = a->probe_timeout_ms > 0 ? a->probe_timeout_ms : 8000;

    brix_status_clear(&st);
    if (doctor_eos_proc(&c, "/proc/user/", "mgm.cmd=version", &body, &st) != 0
        || !doctor_eos_parse_version(body, &arr[0].eos)) {
        free(body);
        brix_close(&c);
        return 0;                           /* not an EOS MGM — mesh untouched */
    }
    free(body);
    body = NULL;
    brix_status_clear(&st);
    if (doctor_eos_proc(&c, "/proc/admin/",
                        "mgm.cmd=fs&mgm.subcmd=ls&mgm.outformat=m",
                        &body, &st) == 0
        && doctor_eos_retc(body) == 0) {
        trunc = eos_map_admin(body, arr, cap, n);
    } else {
        trunc = eos_map_fileinfo(a, &c, arr, cap, n, &st);
    }
    free(body);
    brix_close(&c);
    return trunc;
}

/* ---- renderers (pure over doctor_ep) ------------------------------------ */

/* Health of an FST for colouring: green booted+online, red neither, else yellow.
 * Shared verdict word so ASCII/text/graph agree. */
static const char *
doctor_eos_fst_health(const doctor_eos *x)
{
    if (x->booted && x->active) { return "GREEN"; }
    if (x->booted || x->active) { return "YELLOW"; }
    return "RED";
}

/* Text-report line for an enumerated FST. Returns 1 if it printed (this ep is an
 * FST), 0 otherwise so the caller can fall through to the generic renderer. */
int
doctor_eos_report_fst(const doctor_ep *e)
{
    int pct;

    if (e->eos.kind != DOC_EOS_FST) { return 0; }
    pct = doctor_cfg_capacity_pct(e->cfg.space_total, e->cfg.space_free);

    printf("\n[%s] EOS FST %s:%d\n", doctor_eos_fst_health(&e->eos),
           e->host, e->port);
    printf("  eos: geo=%s  %s  %s  cfg=%s",
           e->eos.geotag[0] ? e->eos.geotag : "?",
           e->eos.booted ? "booted" : "not-booted",
           e->eos.active ? "online" : "offline",
           e->eos.cfgstatus[0] ? e->eos.cfgstatus : "?");
    if (pct >= 0) { printf("  %d%% free", pct); }
    printf(" (%s)\n", e->eos.sampled ? "via fileinfo replica sampling"
                                      : "from MGM fs ls");
    return 1;
}

/* Extra `eos:` line under an MGM's report, noting the enumeration outcome. */
void
doctor_eos_report_mgm(const doctor_ep *e)
{
    if (e->eos.kind != DOC_EOS_MGM) { return; }
    printf("  eos: EOS MGM %s v%s", e->eos.instance,
           e->eos.version[0] ? e->eos.version : "?");
    if (e->eos.fst_count > 0 && e->eos.sampled) {
        printf(" (%d FST%s via fileinfo replica sampling — partial, admin fs ls gated)\n",
               e->eos.fst_count, e->eos.fst_count == 1 ? "" : "s");
    } else if (e->eos.fst_count > 0) {
        printf(" (%d FST%s enumerated)\n", e->eos.fst_count,
               e->eos.fst_count == 1 ? "" : "s");
    } else if (e->eos.gated) {
        printf(" (FST inventory admin-gated — not enumerable with this identity)\n");
    } else {
        printf("\n");
    }
}

/* Per-endpoint `"eos":{...}` object for the --json report (leading comma; only
 * emitted for MGM/FST endpoints). Instance/version/geotag/configstatus come from
 * a constrained charset (host-token/version), escaped defensively all the same. */
void
doctor_eos_emit_json(const doctor_ep *e, FILE *out)
{
    const doctor_eos *x = &e->eos;

    if (x->kind == DOC_EOS_MGM) {
        fprintf(out, ",\"eos\":{\"kind\":\"mgm\",\"instance\":");
        fjson_str(out, x->instance);
        fprintf(out, ",\"version\":");
        fjson_str(out, x->version);
        fprintf(out, ",\"fst_count\":%d,\"gated\":%s,\"sampled\":%s}",
                x->fst_count, x->gated ? "true" : "false",
                x->sampled ? "true" : "false");
    } else if (x->kind == DOC_EOS_FST) {
        fprintf(out, ",\"eos\":{\"kind\":\"fst\",\"geotag\":");
        fjson_str(out, x->geotag);
        fprintf(out, ",\"configstatus\":");
        fjson_str(out, x->cfgstatus);
        fprintf(out, ",\"booted\":%s,\"active\":%s,"
                "\"capacity\":%lld,\"free\":%lld}",
                x->booted ? "true" : "false", x->active ? "true" : "false",
                (long long) x->cap_bytes, (long long) x->free_bytes);
    }
}
