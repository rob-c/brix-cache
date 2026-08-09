/* brix_fault_cmd_json.c — the JSON control dialect and the Prometheus metrics
 * readback for brix-fault-proxy.
 *
 * WHAT: `apply_json_command` (the two coexisting JSON dialects over the ONE verb
 *       grammar), its typed-status / verb-line helpers, and `cmd_metrics_report`
 *       (D1 Prometheus text-exposition of the traffic counters).
 *
 * WHY:  Split out of brix_fault_report.c, which crossed the 600-line cap
 *       (coding-standards §1) once the JSON reply dialect and metrics landed.
 *       The bare-verb scanner lives in the decoupled brix_fault_proxy_json.c;
 *       this TU is the CORE-side dialect logic that reads live lever/counter
 *       state and re-runs commands through apply_command, so it belongs with the
 *       core rather than the dependency-free scanner module.
 *
 * HOW:  Include after the core state header.  The JSON reply layer answers the
 *       structured dialect with {"ok":...} objects and the legacy {"cmd","args"}
 *       dialect with the verb's own plain reply; a command is never defined
 *       twice — both paths run through apply_command(). */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "brix_fault_proxy_state.h"
#include "brix_fault_proxy_mods.h"
#include "brix_fault_buf.h"
#include <stdio.h>
#include <string.h>

/* Prometheus text-exposition of the traffic/fault counters (D1).  A read-only
 * projection of `C` — no new wire surface, no grammar broadening. */
void
cmd_metrics_report(char *reply, size_t rsz)
{
    if (!reply || !rsz) {
        return;
    }
    snprintf(reply, rsz,
"# HELP brix_fault_proxy_conns_total Connections accepted.\n"
"# TYPE brix_fault_proxy_conns_total counter\n"
"brix_fault_proxy_conns_total %lu\n"
"# HELP brix_fault_proxy_active Currently active relays.\n"
"# TYPE brix_fault_proxy_active gauge\n"
"brix_fault_proxy_active %lu\n"
"# HELP brix_fault_proxy_bytes_total Bytes relayed per direction.\n"
"# TYPE brix_fault_proxy_bytes_total counter\n"
"brix_fault_proxy_bytes_total{dir=\"up\"} %lu\n"
"brix_fault_proxy_bytes_total{dir=\"down\"} %lu\n"
"# HELP brix_fault_proxy_severs_total Streams severed by a fault.\n"
"# TYPE brix_fault_proxy_severs_total counter\n"
"brix_fault_proxy_severs_total %lu\n"
"# HELP brix_fault_proxy_corrupt_total Bytes corrupted.\n"
"# TYPE brix_fault_proxy_corrupt_total counter\n"
"brix_fault_proxy_corrupt_total %lu\n"
"# HELP brix_fault_proxy_refused_total Connections refused.\n"
"# TYPE brix_fault_proxy_refused_total counter\n"
"brix_fault_proxy_refused_total %lu\n",
        C.conns, C.active, C.up_bytes, C.down_bytes,
        C.severs, C.corrupt, C.refused);
}

/* Typed status snapshot for the JSON control path (A4): up/down lever fractions
 * and the connection flags as native JSON numbers/booleans. */
static void
json_status_typed(char *reply, size_t rsz)
{
    snprintf(reply, rsz,
"{\"up\":{\"latency_ms\":%d,\"corrupt_pct\":%g,\"lossy_pct\":%g,\"dup_pct\":%g,"
"\"rate_kbps\":%d,\"trunc\":%ld},"
"\"down\":{\"latency_ms\":%d,\"corrupt_pct\":%g,\"lossy_pct\":%g,\"dup_pct\":%g,"
"\"rate_kbps\":%d,\"trunc\":%ld},"
"\"flags\":{\"blocked\":%s,\"hang\":%s,\"abortive\":%s,\"epoch\":%u},"
"\"text\":\"blocked=%d hang=%d abortive=%d epoch=%u\"}\n",
        g_up.latency_ms, g_up.corrupt_ppm / 10000.0, g_up.lossy_ppm / 10000.0,
        g_up.dup_ppm / 10000.0, g_up.rate_kbps, g_up.truncate_at,
        g_down.latency_ms, g_down.corrupt_ppm / 10000.0, g_down.lossy_ppm / 10000.0,
        g_down.dup_ppm / 10000.0, g_down.rate_kbps, g_down.truncate_at,
        g_blocked ? "true" : "false", g_hang ? "true" : "false",
        g_abortive ? "true" : "false", g_drop_epoch,
        g_blocked, g_hang, g_abortive, g_drop_epoch);
}

/* Build a "<cmd> [operand] [dir]" verb line from a flat JSON command object.
 * The operand is the first present of args/pct/at/value/ms/bytes/kbps (a number
 * is copied verbatim so a large byte count never becomes %g scientific
 * notation).  Returns 0 on success, -1 if "cmd" is absent/malformed. */
static int
json_build_verb(const char *json, char *out, size_t outsz)
{
    char cmd[64] = "", dir[16] = "", operand[1024] = "";
    if (fp_json_get(json, "cmd", cmd, sizeof cmd) != 1 || cmd[0] == '\0') {
        return -1;
    }
    static const char *const OPKEYS[] = {
        "args", "pct", "at", "value", "ms", "bytes", "kbps", NULL };
    for (int i = 0; OPKEYS[i] != NULL; i++) {
        if (fp_json_get(json, OPKEYS[i], operand, sizeof operand) == 1) {
            break;
        }
        operand[0] = '\0';
    }
    (void) fp_json_get(json, "dir", dir, sizeof dir);
    int n = snprintf(out, outsz, "%s%s%s%s%s", cmd,
                     operand[0] ? " " : "", operand,
                     dir[0] ? " " : "", dir);
    return (n < 0 || (size_t) n >= outsz) ? -1 : 0;
}

/* JSON control input, two coexisting dialects over the ONE verb grammar.  The
 * legacy dialect is marked by an "args" string; everything else is structured:
 *   * legacy   ({"cmd":..,"args":".."}): reprojected onto the verb line and
 *     answered with the verb's own plain reply ("ok" / "err: ...").
 *   * structured ({"cmd":..[,"pct"/"at"/"value"/"dir"/"format":..]}): answered
 *     with a JSON result {"ok":true|false,...}; a status query returns the typed
 *     snapshot (which also carries a "text" line for substring readers).
 * A command is never defined twice — both dialects run through apply_command. */
void
apply_json_command(const char *json, char *reply, size_t rsz)
{
    char tmp[8];
    int  has_args = fp_json_get(json, "args", tmp, sizeof tmp) == 1;
    char cmd[64]  = "";
    int  have_cmd = fp_json_get(json, "cmd", cmd, sizeof cmd) == 1 && cmd[0] != '\0';

    if (!has_args && have_cmd) {
        if (strcmp(cmd, "status") == 0) {
            json_status_typed(reply, rsz);
            return;
        }
        char verbline[2000];
        if (json_build_verb(json, verbline, sizeof verbline) != 0) {
            fp_reply(reply, rsz, "{\"ok\":false,\"error\":\"parse\"}\n");
            return;
        }
        char scratch[2048] = "";
        apply_command(verbline, scratch, sizeof scratch);
        if (strncmp(scratch, "err", 3) == 0) {
            fp_reply(reply, rsz, "{\"ok\":false,\"error\":\"unknown command\"}\n");
        } else {
            fp_reply(reply, rsz, "{\"ok\":true}\n");
        }
        return;
    }
    /* Legacy string dialect: reproject to a verb line and run it verbatim. */
    char verbline[2000];
    if (fp_json_to_verb(json, verbline, sizeof verbline) == 0) {
        apply_command(verbline, reply, rsz);
        return;
    }
    /* Reprojection failed.  A CLOSED object that names cmd/args (bad value or
     * missing cmd) is a legacy command error; an UNCLOSED / unreadable object is
     * a JSON parse error. */
    if (strchr(json, '}') != NULL &&
        (strstr(json, "\"cmd\"") != NULL || strstr(json, "\"args\"") != NULL)) {
        fp_reply(reply, rsz, "err: bad json command\n");
    } else {
        fp_reply(reply, rsz, "{\"ok\":false,\"error\":\"parse\"}\n");
    }
}
