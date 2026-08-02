/*
 * brix_fault_proxy_json.c — optional JSON front-end over the control grammar.
 *
 * WHAT: a tiny, dependency-free JSON request/response layer for the control
 *       port (feature-expansion plan A2 + A4).  A control line whose first
 *       non-space byte is '{' is parsed here; every other line falls through to
 *       the newline grammar in brix_fault_proxy_control.c unchanged.
 *
 * WHY:  callers previously had to regex the human `status` string and had no
 *       language bindings.  A JSON in/out shape (mirroring Toxiproxy's API)
 *       gives scripts a stable machine oracle without a JSON dependency in the
 *       ngx-free client tree.
 *
 * HOW:  the scanner is deliberately minimal — it extracts the `cmd`, optional
 *       `dir`, and the numeric scalars a verb needs, then REPROJECTS the request
 *       to the existing verb string and calls `apply_command()`.  So JSON is a
 *       thin front-end over the one grammar: no lever logic is duplicated here,
 *       so the two surfaces cannot drift.  `status` is answered directly with a
 *       serialised snapshot (A4).  Malformed input yields
 *       `{"ok":false,"error":"parse"}` and never wedges the parser.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "brix_fault_proxy_internal.h"

/* Locate the value start for `"key"` in a flat JSON object (requests are flat,
 * so no nesting handling is needed). Returns the first non-space byte after the
 * ':' or NULL if the key is absent / not followed by a colon. */
static const char *
json_val(const char *s, const char *key)
{
    char pat[40];
    snprintf(pat, sizeof pat, "\"%s\"", key);
    const char *p = strstr(s, pat);
    if (p == NULL) {
        return NULL;
    }
    p += strlen(pat);
    while (*p == ' ' || *p == '\t') p++;
    if (*p != ':') {
        return NULL;
    }
    p++;
    while (*p == ' ' || *p == '\t') p++;
    return p;
}

/* Copy the string value of `key` into `out` (NUL-terminated). Returns 1 only if
 * a properly closed "..." value was found. */
static int
json_str(const char *s, const char *key, char *out, size_t n)
{
    const char *p = json_val(s, key);
    if (p == NULL || *p != '"') {
        return 0;
    }
    p++;
    size_t i = 0;
    while (*p != '\0' && *p != '"' && i + 1 < n) {
        out[i++] = *p++;
    }
    out[i] = '\0';
    return *p == '"';
}

/* Read the numeric value of `key` into `*v`. Returns 1 if a number was parsed. */
static int
json_num(const char *s, const char *key, double *v)
{
    const char *p = json_val(s, key);
    if (p == NULL) {
        return 0;
    }
    char *end;
    double d = strtod(p, &end);
    if (end == p) {
        return 0;
    }
    *v = d;
    return 1;
}

/* Reproject a JSON request to the newline verb string in `out`. Byte/count
 * fields are emitted as integers (never `%g`, which would switch to scientific
 * notation on large byte counts and defeat the verb-side atol). Returns 1 if a
 * `cmd` was present (even if unknown — apply_command reports the error). */
static int
reproject(const char *line, char *out, size_t osz)
{
    char cmd[32] = "";
    if (!json_str(line, "cmd", cmd, sizeof cmd)) {
        return 0;
    }
    char dir[8] = "";
    json_str(line, "dir", dir, sizeof dir);
    const char *d = dir[0] ? dir : "both";
    double a = 0, b = 0;

    if (!strcmp(cmd, "corrupt") || !strcmp(cmd, "lossy")
        || !strcmp(cmd, "dup") || !strcmp(cmd, "toxicity")) {
        json_num(line, "pct", &a);
        snprintf(out, osz, "%s %g %s", cmd, a, d);
    } else if (!strcmp(cmd, "latency") || !strcmp(cmd, "jitter")
               || !strcmp(cmd, "slow-close")) {
        json_num(line, "ms", &a);
        snprintf(out, osz, "%s %ld %s", cmd, (long) a, d);
    } else if (!strcmp(cmd, "chunk")) {
        json_num(line, "bytes", &a);
        snprintf(out, osz, "chunk %ld %s", (long) a, d);
    } else if (!strcmp(cmd, "rate")) {
        if (!json_num(line, "kbps", &a)) json_num(line, "rate", &a);
        snprintf(out, osz, "rate %ld %s", (long) a, d);
    } else if (!strcmp(cmd, "burst")) {
        json_num(line, "bytes", &a);
        snprintf(out, osz, "burst %ld %s", (long) a, d);
    } else if (!strcmp(cmd, "drip")) {
        json_num(line, "bytes", &a);
        json_num(line, "ms", &b);
        snprintf(out, osz, "drip %ld %ld %s", (long) a, (long) b, d);
    } else if (!strcmp(cmd, "reorder")) {
        json_num(line, "pct", &a);
        json_num(line, "ms", &b);
        snprintf(out, osz, "reorder %g %ld %s", a, (long) b, d);
    } else if (!strcmp(cmd, "truncate-at")) {
        if (!json_num(line, "at", &a)) json_num(line, "bytes", &a);
        snprintf(out, osz, "truncate-at %ld %s", (long) a, d);
    } else if (!strcmp(cmd, "refuse")) {
        json_num(line, "pct", &a);
        snprintf(out, osz, "refuse %g", a);
    } else if (!strcmp(cmd, "connect-delay") || !strcmp(cmd, "accept-delay")) {
        json_num(line, "ms", &a);
        snprintf(out, osz, "%s %ld", cmd, (long) a);
    } else if (!strcmp(cmd, "fail-nth")) {
        json_num(line, "n", &a);
        snprintf(out, osz, "fail-nth %ld", (long) a);
    } else if (!strcmp(cmd, "heal-after")) {
        json_num(line, "ms", &a);
        snprintf(out, osz, "heal-after %ld", (long) a);
    } else if (!strcmp(cmd, "abortive")) {
        json_num(line, "n", &a);
        snprintf(out, osz, "abortive %ld", (long) a);
    } else if (!strcmp(cmd, "latency-dist")) {
        char mode[16] = "";
        json_str(line, "mode", mode, sizeof mode);
        json_num(line, "mean", &a);
        if (json_num(line, "sigma", &b)) {
            snprintf(out, osz, "latency-dist %s %ld %ld %s", mode, (long) a, (long) b, d);
        } else {
            snprintf(out, osz, "latency-dist %s %ld %s", mode, (long) a, d);
        }
    } else {
        /* argument-less verbs (drop/reset/half-close/hang/unhang/block/unblock/
         * one-shot/clear/metrics) and unknown verbs: pass the bare verb. */
        snprintf(out, osz, "%s", cmd);
    }
    return 1;
}

/* Serialise the full lever + flag + counter snapshot as a JSON object (A4).
 * Percentages match the human status line (ppm/10000). */
void
brix_fp_json_status(char *out, size_t osz)
{
    if (out == NULL || osz == 0) {
        return;
    }
    snprintf(out, osz,
"{\"up\":{\"latency_ms\":%d,\"jitter_ms\":%d,\"corrupt_pct\":%.4f,\"lossy_pct\":%.4f,"
"\"dup_pct\":%.4f,\"slow_close_ms\":%d,\"dist\":%d},"
"\"down\":{\"latency_ms\":%d,\"jitter_ms\":%d,\"corrupt_pct\":%.4f,\"lossy_pct\":%.4f,"
"\"dup_pct\":%.4f,\"slow_close_ms\":%d,\"dist\":%d},"
"\"flags\":{\"blocked\":%s,\"hang\":%s,\"abortive\":%s,\"one_shot\":%s,"
"\"fail_nth\":%d,\"refuse_pct\":%.4f,\"connect_delay_ms\":%d,\"epoch\":%u},"
"\"counters\":{\"conns\":%lu,\"active\":%lu,\"up_bytes\":%lu,\"down_bytes\":%lu,"
"\"severs\":%lu,\"corrupt\":%lu,\"dups\":%lu,\"refused\":%lu}}\n",
        g_up.latency_ms, g_up.jitter_ms, g_up.corrupt_ppm / 10000.0,
        g_up.lossy_ppm / 10000.0, g_up.dup_ppm / 10000.0, g_up.slow_close_ms, g_up.lat_dist,
        g_down.latency_ms, g_down.jitter_ms, g_down.corrupt_ppm / 10000.0,
        g_down.lossy_ppm / 10000.0, g_down.dup_ppm / 10000.0, g_down.slow_close_ms, g_down.lat_dist,
        g_blocked ? "true" : "false", g_hang ? "true" : "false",
        g_abortive ? "true" : "false", g_one_shot ? "true" : "false",
        g_fail_nth, g_refuse_ppm / 10000.0, g_connect_delay_ms, g_drop_epoch,
        C.conns, C.active, C.up_bytes, C.down_bytes,
        C.severs, C.corrupt, C.dups, C.refused);
}

/* Handle one control line as JSON. Returns 0 (not JSON — caller uses the verb
 * grammar) if the first non-space byte is not '{'. Otherwise writes a JSON
 * response into `out` and returns 1. Reprojects to the verb grammar and calls
 * apply_command() so there is a single source of lever truth. */
int
brix_fp_json_request(const char *line, char *out, size_t osz)
{
    const char *p = line;
    while (*p == ' ' || *p == '\t') p++;
    if (*p != '{') {
        return 0;
    }
    char cmd[32] = "";
    if (!json_str(line, "cmd", cmd, sizeof cmd)) {
        snprintf(out, osz, "{\"ok\":false,\"error\":\"parse\"}\n");
        return 1;
    }
    if (!strcmp(cmd, "status")) {
        brix_fp_json_status(out, osz);
        return 1;
    }
    char verb[256];
    reproject(line, verb, sizeof verb);
    char reply[256];
    apply_command(verb, reply, sizeof reply);
    if (!strncmp(reply, "err", 3)) {
        snprintf(out, osz, "{\"ok\":false,\"error\":\"unknown command\"}\n");
    } else {
        snprintf(out, osz, "{\"ok\":true}\n");
    }
    return 1;
}
