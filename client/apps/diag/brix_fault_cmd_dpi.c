/* brix_fault_cmd_dpi.c — control verbs for the Phase-99 DPI / middlebox
 * pathology levers (docs/refactor/phase-99-dpi-middlebox-pathology-levers.md).
 *
 * WHAT: the root-free "shitty middlebox" family — idle-flow reaping, HTTP
 *       100-continue swallowing, classify-and-kill guillotines, asymmetric
 *       teardown, volume slow-lanes, FTP/GridFTP ALG payload rewriting, oversized
 *       TLS ClientHello resets, and SYN-drop connection loss.
 *
 * WHY:  these compose from primitives the relay already owns; the parsing/gating
 *       lives here so brix_fault_cmd_attack.c stays under the 600-line cap.
 *
 * HOW:  each verb sets a global lever read lock-free by the relay pump / accept
 *       loop; the ALG rewriter installs an FTP-comma find/replace pair into the
 *       existing mutation buffers under g_ext_lock.  clear_all() resets it all. */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "brix_fault_proxy_state.h"
#include <unistd.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Render "a.b.c.d:port" as the FTP PASV "a,b,c,d,p1,p2" byte form into `out`.
 * Returns the length, or 0 if the endpoint does not parse as IPv4:port. */
static int
ftp_comma_form(const char *ep, unsigned char *out, size_t cap)
{
    unsigned a, b, c, d, port;
    if (sscanf(ep, "%u.%u.%u.%u:%u", &a, &b, &c, &d, &port) != 5 ||
        a > 255 || b > 255 || c > 255 || d > 255 || port > 65535) {
        return 0;
    }
    int n = snprintf((char *) out, cap, "%u,%u,%u,%u,%u,%u",
                     a, b, c, d, port >> 8, port & 0xff);
    return (n > 0 && (size_t) n < cap) ? n : 0;
}

/* alg-rewrite <src ip:port> <dst ip:port> [up|down] — model an FTP/GridFTP ALG
 * that rewrites the endpoint embedded in a PASV reply, installed as a find/
 * replace pair on the selected direction (default down: the 227 response). */
static int
dpi_alg_rewrite(char *args, char *reply, size_t rsz)
{
    char *src = strtok(args, " ");
    char *dst = strtok(NULL, " ");
    char *dir = strtok(NULL, " ");
    if (!src || !dst) {
        snprintf(reply, rsz, "err: alg-rewrite <src ip:port> <dst ip:port> "
                             "[up|down]\n");
        return 1;
    }
    unsigned char fbuf[64], rbuf[64];
    int fl = ftp_comma_form(src, fbuf, sizeof(fbuf));
    int rl = ftp_comma_form(dst, rbuf, sizeof(rbuf));
    if (fl == 0 || rl == 0) {
        snprintf(reply, rsz, "err: alg-rewrite endpoints must be IPv4:port\n");
        return 1;
    }
    struct fp_mutbuf *M = (dir && strcmp(dir, "up") == 0) ? &g_up_mut : &g_down_mut;
    pthread_mutex_lock(&g_ext_lock);
    memcpy(M->find, fbuf, (size_t) fl); M->find_len = fl;
    memcpy(M->repl, rbuf, (size_t) rl); M->repl_len = rl;
    pthread_mutex_unlock(&g_ext_lock);
    return 1;
}

/* drop-fin [up|down|both|off] — swallow a direction's EOF (asymmetric teardown).*/
static void
dpi_drop_fin(char *args)
{
    if (strstr(args, "off")) {
        g_drop_fin_up = 0; g_drop_fin_down = 0;
        return;
    }
    int d = dir_of(args);                 /* 0 both / 1 up / 2 down */
    if (d != 2) { g_drop_fin_up = 1; }
    if (d != 1) { g_drop_fin_down = 1; }
}

/* Dispatch a Phase-99 verb. Returns 1 once one is claimed, else 0. */
int
cmd_set_dpi(const char *verb, char *args, char *reply, size_t rsz)
{
    if (strcmp(verb, "idle-reap") == 0) {
        int ms = atoi(args);
        g_idle_reap_ms  = ms;
        g_idle_reap_rst = strstr(args, "rst") ? 1 : 0;
    } else if (strcmp(verb, "eat-100-continue") == 0) {
        g_eat_100 = strstr(args, "off") ? 0 : 1;
    } else if (strcmp(verb, "rst-after") == 0) {
        g_rst_after_ms       = atol(args);
        g_rst_after_abortive = 1;         /* forged RST */
    } else if (strcmp(verb, "max-bytes") == 0) {
        g_rst_after_bytes    = atol(args);
        g_rst_after_abortive = strstr(args, "rst") ? 1 : 0;  /* default clean FIN */
    } else if (strcmp(verb, "drop-fin") == 0) {
        dpi_drop_fin(args);
    } else if (strcmp(verb, "classify-throttle") == 0) {
        long b = 0; int k = 0;
        sscanf(args, "%ld %d", &b, &k);
        g_classify_bytes = b; g_classify_kbps = k;
    } else if (strcmp(verb, "hello-split-reset") == 0) {
        g_hello_reset_thresh = atoi(args);
    } else if (strcmp(verb, "syn-drop") == 0) {
        int ppm = atoi(args);
        g_syn_drop_ppm = ppm < 0 ? 0 : (ppm > 1000000 ? 1000000 : ppm);
    } else if (strcmp(verb, "alg-rewrite") == 0) {
        return dpi_alg_rewrite(args, reply, rsz);
    } else {
        return 0;
    }
    return 1;
}


/* Aggregate token-bucket gate: pace this segment against a single uplink ceiling
 * shared across ALL relays (simulates a saturated shared link / upstream link).
 * Briefly holds g_gr_lock to update the shared tokens, then sleeps unlocked.
 * (Lives here rather than in the relay TU only to keep that file under the
 * 600-line cap; it is a relay data-path helper, declared in the state header.) */
void
global_rate_gate(ssize_t seg)
{
    int kbps = g_global_rate_kbps;
    if (kbps <= 0) {
        return;
    }
    double rate = (double) kbps * 1024.0;   /* bytes / second */
    pthread_mutex_lock(&g_gr_lock);
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    if (!g_gr_init) {
        g_gr_last = now;
        g_gr_tokens = 0.0;
        g_gr_init = 1;
    }
    double elapsed = (now.tv_sec - g_gr_last.tv_sec)
                   + (now.tv_nsec - g_gr_last.tv_nsec) / 1e9;
    g_gr_tokens += elapsed * rate;
    if (g_gr_tokens > rate) {
        g_gr_tokens = rate;   /* cap the burst at ~1s of credit */
    }
    g_gr_last = now;
    g_gr_tokens -= (double) seg;
    double deficit = g_gr_tokens < 0.0 ? -g_gr_tokens : 0.0;
    pthread_mutex_unlock(&g_gr_lock);
    if (deficit > 0.0) {
        usleep((useconds_t) (deficit / rate * 1e6));
    }
}
