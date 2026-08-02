/*
 * brix_fault_proxy_toxic.c — named, stackable, individually-removable toxics (C1).
 *
 * WHAT: a small fixed-capacity table of named "toxics" — each one a single fault
 *       lever (latency/corrupt/rate/…) bound to a direction — that operators add,
 *       remove and list at runtime.  They layer ON TOP of the flat g_up/g_down
 *       default levers, which remain the implicit default toxic, so nothing that
 *       pre-dates C1 changes behaviour.
 *
 * WHY:  the flat lever model holds exactly one field per fault type, so you cannot
 *       stack two of a kind, nor remove one leaving the others.  Toxiproxy models a
 *       *list* of named toxics per direction; this table restores that without
 *       malloc on the hot path (a fixed FP_MAX_TOXICS array) and without touching
 *       the fast path when the table is empty — the relay checks g_ntoxics==0 and
 *       composes nothing.
 *
 * HOW:  fp_toxic_compose() folds every active toxic for a direction into the
 *       per-read lever snapshot the relay already takes: delays and probabilities
 *       add (probabilities clamped to 100%), bandwidth / chunk / drip / truncate
 *       take the tightest (min non-zero) bound.  One mutex serialises all table
 *       mutation and composition; the relay only locks when g_ntoxics>0, so the
 *       existing single-lever users pay nothing.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "brix_fault_proxy_internal.h"

fp_toxic g_toxics[FP_MAX_TOXICS];
int      g_ntoxics = 0;

static pthread_mutex_t g_toxic_mu = PTHREAD_MUTEX_INITIALIZER;

/* Toxic type tags — one per composable fault field. */
enum {
    FP_TX_LATENCY, FP_TX_JITTER, FP_TX_SLOWCLOSE, FP_TX_CHUNK, FP_TX_RATE,
    FP_TX_DRIP, FP_TX_LOSSY, FP_TX_CORRUPT, FP_TX_DUP, FP_TX_REORDER,
    FP_TX_TRUNCATE, FP_TX__N
};
static const char *TX_NAME[FP_TX__N] = {
    "latency", "jitter", "slow-close", "chunk", "rate",
    "drip", "lossy", "corrupt", "dup", "reorder", "truncate"
};
static const char *DIR_NAME[3] = { "both", "up", "down" };

/* Reply helper: write only when the caller wants a reply (script replay passes
 * reply==NULL — the mutation must still happen, just without an answer). */
#define TXR(...) do { if (reply && rsz) snprintf(reply, rsz, __VA_ARGS__); } while (0)

/* Fill tx->type + tx->vals from a type keyword and its parameter string.
 * ppm fields reuse the control-plane convention: a percentage → ppm (1% = 10000).
 * Returns 0 on success, -1 for an unknown type keyword. */
static int
tx_parse(const char *type, const char *p, fp_toxic *tx)
{
    if (!strcmp(type, "latency")) {
        tx->type = FP_TX_LATENCY;   tx->vals.latency_ms = atoi(p);
    } else if (!strcmp(type, "jitter")) {
        tx->type = FP_TX_JITTER;    tx->vals.jitter_ms = atoi(p);
    } else if (!strcmp(type, "slow-close")) {
        tx->type = FP_TX_SLOWCLOSE; tx->vals.slow_close_ms = atoi(p);
    } else if (!strcmp(type, "chunk")) {
        tx->type = FP_TX_CHUNK;     tx->vals.chunk_bytes = atoi(p);
    } else if (!strcmp(type, "rate")) {
        tx->type = FP_TX_RATE;      tx->vals.rate_kbps = atoi(p);
    } else if (!strcmp(type, "drip")) {
        int b = 0, m = 0; sscanf(p, "%d %d", &b, &m);
        tx->type = FP_TX_DRIP;      tx->vals.drip_bytes = b; tx->vals.drip_ms = m;
    } else if (!strcmp(type, "lossy")) {
        tx->type = FP_TX_LOSSY;     tx->vals.lossy_ppm   = (int)(strtod(p, NULL) * 10000.0 + 0.5);
    } else if (!strcmp(type, "corrupt")) {
        tx->type = FP_TX_CORRUPT;   tx->vals.corrupt_ppm = (int)(strtod(p, NULL) * 10000.0 + 0.5);
    } else if (!strcmp(type, "dup")) {
        tx->type = FP_TX_DUP;       tx->vals.dup_ppm     = (int)(strtod(p, NULL) * 10000.0 + 0.5);
    } else if (!strcmp(type, "reorder")) {
        double pr = 0; int m = -1; sscanf(p, "%lf %d", &pr, &m);
        tx->type = FP_TX_REORDER;
        tx->vals.reorder_ppm = (int)(pr * 10000.0 + 0.5);
        tx->vals.reorder_ms  = (m >= 0) ? m : 50;
    } else if (!strcmp(type, "truncate") || !strcmp(type, "truncate-at")) {
        tx->type = FP_TX_TRUNCATE;  tx->vals.truncate_at = atol(p);
    } else {
        return -1;
    }
    return 0;
}

/* Fold one toxic's single field into the effective lever `e`. */
static void
tx_fold(lever_t *e, const fp_toxic *t)
{
    const lever_t *v = &t->vals;
    switch (t->type) {
    case FP_TX_LATENCY:   e->latency_ms    += v->latency_ms;    break;
    case FP_TX_JITTER:    e->jitter_ms     += v->jitter_ms;     break;
    case FP_TX_SLOWCLOSE: e->slow_close_ms += v->slow_close_ms; break;
    case FP_TX_LOSSY:     e->lossy_ppm     += v->lossy_ppm;     break;
    case FP_TX_CORRUPT:   e->corrupt_ppm   += v->corrupt_ppm;   break;
    case FP_TX_DUP:       e->dup_ppm       += v->dup_ppm;       break;
    case FP_TX_REORDER:
        e->reorder_ppm += v->reorder_ppm;
        if (v->reorder_ms > 0) e->reorder_ms = v->reorder_ms;
        break;
    case FP_TX_DRIP:
        if (v->drip_bytes > 0 && (e->drip_bytes == 0 || v->drip_bytes < e->drip_bytes))
            e->drip_bytes = v->drip_bytes;
        e->drip_ms += v->drip_ms;
        break;
    case FP_TX_CHUNK:
        if (v->chunk_bytes > 0 && (e->chunk_bytes == 0 || v->chunk_bytes < e->chunk_bytes))
            e->chunk_bytes = v->chunk_bytes;
        break;
    case FP_TX_RATE:
        if (v->rate_kbps > 0 && (e->rate_kbps == 0 || v->rate_kbps < e->rate_kbps))
            e->rate_kbps = v->rate_kbps;
        break;
    case FP_TX_TRUNCATE:
        if (v->truncate_at > 0 && (e->truncate_at == 0 || v->truncate_at < e->truncate_at))
            e->truncate_at = v->truncate_at;
        break;
    default: break;
    }
}

/* Fold every active toxic for direction dir_i (0 = up, 1 = down) into `eff`,
 * the relay's per-read lever snapshot, then clamp summed probabilities. */
void
fp_toxic_compose(lever_t *eff, int dir_i)
{
    int up = (dir_i == 0);
    pthread_mutex_lock(&g_toxic_mu);
    for (int k = 0; k < g_ntoxics; k++) {
        const fp_toxic *t = &g_toxics[k];
        if (!t->active) continue;
        if (!(t->dir == 0 || (t->dir == 1 && up) || (t->dir == 2 && !up))) continue;
        tx_fold(eff, t);
    }
    pthread_mutex_unlock(&g_toxic_mu);
    if (eff->lossy_ppm   > 1000000) eff->lossy_ppm   = 1000000;
    if (eff->corrupt_ppm > 1000000) eff->corrupt_ppm = 1000000;
    if (eff->dup_ppm     > 1000000) eff->dup_ppm     = 1000000;
    if (eff->reorder_ppm > 1000000) eff->reorder_ppm = 1000000;
}

void
fp_toxic_clear(void)
{
    pthread_mutex_lock(&g_toxic_mu);
    g_ntoxics = 0;
    pthread_mutex_unlock(&g_toxic_mu);
}

/* toxic add <name> <type> <params…> [up|down|both] */
static void
tx_add(char *rest, char *reply, size_t rsz)
{
    int  dir = dir_of(rest);   /* strips a trailing up|down|both token */
    char name[32] = "", type[24] = "", params[96] = "";
    int  m = sscanf(rest, "%31s %23s %95[^\n]", name, type, params);
    if (m < 2) { TXR("err: usage: toxic add <name> <type> <params> [dir]\n"); return; }

    fp_toxic tx;
    memset(&tx, 0, sizeof tx);
    if (tx_parse(type, params, &tx) != 0) { TXR("err: unknown toxic type\n"); return; }

    int rc = 0;   /* 0 ok · 1 duplicate name · 2 table full */
    pthread_mutex_lock(&g_toxic_mu);
    for (int k = 0; k < g_ntoxics; k++)
        if (strcmp(g_toxics[k].name, name) == 0) { rc = 1; break; }
    if (rc == 0 && g_ntoxics >= FP_MAX_TOXICS) rc = 2;
    if (rc == 0) {
        snprintf(tx.name, sizeof tx.name, "%s", name);
        tx.dir    = dir;
        tx.active = 1;
        g_toxics[g_ntoxics] = tx;   /* publish entry BEFORE bumping the count */
        g_ntoxics++;
    }
    pthread_mutex_unlock(&g_toxic_mu);

    if      (rc == 1) TXR("err: exists\n");
    else if (rc == 2) TXR("err: too many toxics\n");
    else              TXR("ok: added %s\n", name);
}

/* toxic remove <name> — compacts the array so live toxics stay dense. */
static void
tx_remove(char *rest, char *reply, size_t rsz)
{
    char name[32] = "";
    if (sscanf(rest, "%31s", name) < 1) { TXR("err: usage: toxic remove <name>\n"); return; }

    int found = 0;
    pthread_mutex_lock(&g_toxic_mu);
    for (int k = 0; k < g_ntoxics; k++) {
        if (strcmp(g_toxics[k].name, name) == 0) {
            for (int j = k; j < g_ntoxics - 1; j++) g_toxics[j] = g_toxics[j + 1];
            g_ntoxics--;
            found = 1;
            break;
        }
    }
    pthread_mutex_unlock(&g_toxic_mu);

    if (found) TXR("ok: removed %s\n", name);
    else       TXR("err: no such toxic\n");
}

/* Bounded cursor append: never advances `*off` past `rsz`. */
static void
tx_appendf(char *buf, size_t *off, size_t rsz, const char *fmt, ...)
{
    if (*off >= rsz) return;
    va_list ap;
    va_start(ap, fmt);
    int r = vsnprintf(buf + *off, rsz - *off, fmt, ap);
    va_end(ap);
    if (r < 0) return;
    *off += (size_t) r;
    if (*off >= rsz) *off = rsz - 1;   /* clamp; buffer already NUL-terminated */
}

/* toxic list [json] */
static void
tx_list(char *rest, char *reply, size_t rsz)
{
    if (!reply || !rsz) return;
    int    json = (strncmp(rest, "json", 4) == 0);
    size_t off  = 0;

    pthread_mutex_lock(&g_toxic_mu);
    if (json) {
        tx_appendf(reply, &off, rsz, "{\"toxics\":[");
        for (int k = 0; k < g_ntoxics; k++) {
            const fp_toxic *t = &g_toxics[k];
            tx_appendf(reply, &off, rsz,
                "%s{\"name\":\"%s\",\"type\":\"%s\",\"dir\":\"%s\"}",
                k ? "," : "", t->name,
                (t->type >= 0 && t->type < FP_TX__N) ? TX_NAME[t->type] : "?",
                DIR_NAME[t->dir % 3]);
        }
        tx_appendf(reply, &off, rsz, "]}\n");
    } else {
        tx_appendf(reply, &off, rsz, "toxics=%d\n", g_ntoxics);
        for (int k = 0; k < g_ntoxics; k++) {
            const fp_toxic *t = &g_toxics[k];
            tx_appendf(reply, &off, rsz, "  %s %s %s\n", t->name,
                (t->type >= 0 && t->type < FP_TX__N) ? TX_NAME[t->type] : "?",
                DIR_NAME[t->dir % 3]);
        }
    }
    pthread_mutex_unlock(&g_toxic_mu);
}

void
fp_toxic_cmd(char *args, char *reply, size_t rsz)
{
    char sub[16] = "";
    int  off = 0;
    if (sscanf(args, "%15s %n", sub, &off) < 1) {
        if (reply && rsz) snprintf(reply, rsz, "err: usage: toxic add|remove|list\n");
        return;
    }
    char *rest = args + off;
    if      (!strcmp(sub, "add"))    tx_add(rest, reply, rsz);
    else if (!strcmp(sub, "remove")) tx_remove(rest, reply, rsz);
    else if (!strcmp(sub, "list"))   tx_list(rest, reply, rsz);
    else if (reply && rsz) snprintf(reply, rsz, "err: unknown toxic subcommand\n");
}
