/*
 * brix_fault_toxic.c — named, stackable, per-direction fault toxics (C1).
 *
 * WHAT: a table of named single-effect toxics (`toxic add <name> <type> <value>
 *       [dir]`), each a per-direction fault that composes on top of the core's
 *       base levers.  `toxic remove <name>` drops one by name, the core `clear`
 *       verb empties the table, and `toxic list [json]` reports them.
 *
 * WHY:  the base g_up/g_down levers are a single blended knob-set — you cannot
 *       add "100 ms latency" and later remove exactly that without remembering
 *       and undoing the delta.  Named toxics make each discrete effect
 *       independently addressable (the Toxiproxy model), which is what a test
 *       harness wants when it layers and peels faults around a scenario; two of
 *       a kind STACK, where the flat single-field lever held exactly one.
 *
 * HOW:  a fixed-size table under one mutex.  A lock-free atomic direction mask
 *       (g_dir_mask) lets the per-buffer relay hot path skip composition entirely
 *       when nothing targets its direction; only when a toxic is present does
 *       fp_toxic_compose take the lock and fold the active toxics into the
 *       caller's snapshot.  Composition rules are fixed and documented below so a
 *       stack of toxics has one well-defined meaning.
 */
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "brix_fault_toxic.h"
#include "brix_fault_buf.h"

#define FP_TOXIC_MAX  16
#define FP_TOXIC_NAME 32
#define FP_TOXIC_TYPE 24

/* dir: 1 = up (client→upstream), 2 = down (upstream→client), 3 = both. */
struct fp_toxic {
    char    name[FP_TOXIC_NAME];
    char    type[FP_TOXIC_TYPE];    /* the effect keyword, echoed back verbatim */
    int     dir;
    lever_t lv;                     /* exactly one field set; the rest are neutral */
    int     in_use;
};

static struct fp_toxic  g_toxics[FP_TOXIC_MAX];
static pthread_mutex_t   g_toxic_lock = PTHREAD_MUTEX_INITIALIZER;

/* Union of the dir masks of all live toxics (bit0=up, bit1=down).  Read lock-free
 * by the hot path; only ever written under g_toxic_lock. */
static volatile int      g_dir_mask = 0;

/* Recompute g_dir_mask from the table.  Caller holds g_toxic_lock. */
static void
recalc_mask(void)
{
    int m = 0;
    for (int i = 0; i < FP_TOXIC_MAX; i++) {
        if (g_toxics[i].in_use) {
            m |= g_toxics[i].dir;
        }
    }
    __atomic_store_n(&g_dir_mask, m, __ATOMIC_RELEASE);
}

/* Map a direction token to a mask (1/2/3); default to both (3) when absent or
 * unrecognised — the direction is an optional trailing token. */
static int
dir_mask_of(const char *tok)
{
    if (strcmp(tok, "up") == 0)   return 1;
    if (strcmp(tok, "down") == 0) return 2;
    return 3;
}

static const char *
dir_name(int mask)
{
    static const char *dn[4] = { "both", "up", "down", "both" };
    return dn[mask & 3];
}

/* The settable lever fields, as a descriptor table rather than a strcmp ladder
 * (coding-standards §8.6): a toxic type is a name, a slot, and how to read its
 * operand.  Adding a lever field is one row here and nothing else. */
enum { FLD_INT, FLD_PPM, FLD_LONG };

static const struct {
    const char *name;
    size_t      off;
    int         kind;
} TOXIC_FIELDS[] = {
    { "latency",    offsetof(lever_t, latency_ms),    FLD_INT  },
    { "jitter",     offsetof(lever_t, jitter_ms),     FLD_INT  },
    { "chunk",      offsetof(lever_t, chunk_bytes),   FLD_INT  },
    { "rate",       offsetof(lever_t, rate_kbps),     FLD_INT  },
    { "drip_bytes", offsetof(lever_t, drip_bytes),    FLD_INT  },
    { "drip_ms",    offsetof(lever_t, drip_ms),       FLD_INT  },
    { "reorder_ms", offsetof(lever_t, reorder_ms),    FLD_INT  },
    { "delayfirst", offsetof(lever_t, delayfirst_ms), FLD_INT  },
    { "truncate",   offsetof(lever_t, truncate_at),   FLD_LONG },
    { "lossy",      offsetof(lever_t, lossy_ppm),     FLD_PPM  },
    { "corrupt",    offsetof(lever_t, corrupt_ppm),   FLD_PPM  },
    { "dup",        offsetof(lever_t, dup_ppm),       FLD_PPM  },
    { "reorder",    offsetof(lever_t, reorder_ppm),   FLD_PPM  },
    { "drop",       offsetof(lever_t, drop_ppm),      FLD_PPM  },
    { "repeat",     offsetof(lever_t, repeat_ppm),    FLD_PPM  },
};

/* Set the single field named by `type` on `lv` to `value`.  Probability types
 * take a percent string (× 10000 → ppm), matching the core's lever grammar.
 * Returns 0 on success, -1 if the type name is unknown. */
static int
set_field(lever_t *lv, const char *type, const char *value)
{
    for (size_t i = 0; i < sizeof(TOXIC_FIELDS) / sizeof(TOXIC_FIELDS[0]); i++) {
        if (strcmp(type, TOXIC_FIELDS[i].name) != 0) {
            continue;
        }
        void *slot = (char *) lv + TOXIC_FIELDS[i].off;
        switch (TOXIC_FIELDS[i].kind) {
        case FLD_LONG:
            *(volatile long *) slot = atol(value);
            break;
        case FLD_PPM:   /* operator writes a percentage; the lever holds ppm */
            *(volatile int *) slot = (int) (strtod(value, NULL) * 10000.0 + 0.5);
            break;
        default:
            *(volatile int *) slot = atoi(value);
            break;
        }
        return 0;
    }
    return -1;   /* unknown toxic type */
}

/* Find a live toxic by name, or -1.  Caller holds g_toxic_lock. */
static int
find_toxic(const char *name)
{
    for (int i = 0; i < FP_TOXIC_MAX; i++) {
        if (g_toxics[i].in_use && strcmp(g_toxics[i].name, name) == 0) {
            return i;
        }
    }
    return -1;
}

static void
reply_set(char *reply, size_t rsz, const char *msg)
{
    fp_reply(reply, rsz, "%s", msg);
}

/* toxic add <name> <type> <value> [dir] */
static int
toxic_add(char *rest, char *reply, size_t rsz)
{
    char name[FP_TOXIC_NAME] = "", type[FP_TOXIC_TYPE] = "";
    char value[32] = "", dir[8] = "";
    int  nf = sscanf(rest, "%31s %23s %31s %7s", name, type, value, dir);
    if (nf < 3) {
        reply_set(reply, rsz, "err: usage: toxic add <name> <type> <value> [up|down|both]\n");
        return 1;
    }

    /* Validate the effect type before touching the table (so a bad type never
     * displaces a duplicate-name or capacity verdict). */
    lever_t lv;
    memset(&lv, 0, sizeof lv);
    if (set_field(&lv, type, value) != 0) {
        reply_set(reply, rsz, "err: unknown toxic type\n");
        return 1;
    }
    int dm = (nf >= 4) ? dir_mask_of(dir) : 3;

    pthread_mutex_lock(&g_toxic_lock);
    if (find_toxic(name) >= 0) {
        pthread_mutex_unlock(&g_toxic_lock);
        reply_set(reply, rsz, "err: exists\n");
        return 1;
    }
    int slot = -1;
    for (int i = 0; i < FP_TOXIC_MAX; i++) {
        if (!g_toxics[i].in_use) { slot = i; break; }
    }
    if (slot < 0) {
        pthread_mutex_unlock(&g_toxic_lock);
        reply_set(reply, rsz, "err: too many toxics\n");
        return 1;
    }
    snprintf(g_toxics[slot].name, FP_TOXIC_NAME, "%s", name);
    snprintf(g_toxics[slot].type, FP_TOXIC_TYPE, "%s", type);
    g_toxics[slot].dir    = dm;
    g_toxics[slot].lv     = lv;
    g_toxics[slot].in_use = 1;
    recalc_mask();
    pthread_mutex_unlock(&g_toxic_lock);

    fp_reply(reply, rsz, "added %s\n", name);
    return 1;
}

/* toxic remove <name> */
static int
toxic_remove(char *rest, char *reply, size_t rsz)
{
    char name[FP_TOXIC_NAME] = "";
    if (sscanf(rest, "%31s", name) != 1) {
        reply_set(reply, rsz, "err: usage: toxic remove <name>\n");
        return 1;
    }
    pthread_mutex_lock(&g_toxic_lock);
    int slot = find_toxic(name);
    if (slot >= 0) {
        g_toxics[slot].in_use = 0;
        recalc_mask();
    }
    pthread_mutex_unlock(&g_toxic_lock);
    if (slot < 0) {
        reply_set(reply, rsz, "err: no such toxic\n");
    } else fp_reply(reply, rsz, "removed %s\n", name);
    return 1;
}

/* toxic list [json] — human head line is "toxics=N"; json is the machine form. */
static int
toxic_list(char *rest, char *reply, size_t rsz)
{
    if (!reply || !rsz) {
        return 1;
    }
    int want_json = (strncmp(rest, "json", 4) == 0);

    pthread_mutex_lock(&g_toxic_lock);
    size_t o = 0;
    if (want_json) {
        o += (size_t) snprintf(reply + o, rsz - o, "{\"toxics\":[");
        int first = 1;
        for (int i = 0; i < FP_TOXIC_MAX && o < rsz; i++) {
            if (!g_toxics[i].in_use) continue;
            o += (size_t) snprintf(reply + o, rsz - o,
                                   "%s{\"name\":\"%s\",\"type\":\"%s\",\"dir\":\"%s\"}",
                                   first ? "" : ",",
                                   g_toxics[i].name, g_toxics[i].type,
                                   dir_name(g_toxics[i].dir));
            first = 0;
        }
        if (o < rsz) o += (size_t) snprintf(reply + o, rsz - o, "]}\n");
    } else {
        int n = 0;
        for (int i = 0; i < FP_TOXIC_MAX; i++) {
            if (g_toxics[i].in_use) n++;
        }
        o += (size_t) snprintf(reply + o, rsz - o, "toxics=%d\n", n);
        for (int i = 0; i < FP_TOXIC_MAX && o < rsz; i++) {
            if (!g_toxics[i].in_use) continue;
            o += (size_t) snprintf(reply + o, rsz - o, "  %s %s %s\n",
                                   g_toxics[i].name, g_toxics[i].type,
                                   dir_name(g_toxics[i].dir));
        }
    }
    pthread_mutex_unlock(&g_toxic_lock);
    return 1;
}

int
fp_toxic_cmd(char *args, char *reply, size_t rsz)
{
    char sub[16] = "";
    int  off = 0;
    sscanf(args, "%15s %n", sub, &off);
    char *rest = args + off;

    if (strcmp(sub, "add") == 0)    return toxic_add(rest, reply, rsz);
    if (strcmp(sub, "remove") == 0) return toxic_remove(rest, reply, rsz);
    if (strcmp(sub, "list") == 0)   return toxic_list(rest, reply, rsz);

    reply_set(reply, rsz, "err: unknown toxic subcommand\n");
    return 1;
}

int
fp_toxic_active(int is_up)
{
    int m = __atomic_load_n(&g_dir_mask, __ATOMIC_ACQUIRE);
    return (m & (is_up ? 1 : 2)) != 0;
}

/* Additive stack for delays/probabilities; tightest-wins for bottleneck fields. */
static void
compose_one(lever_t *s, const lever_t *t)
{
    s->latency_ms    += t->latency_ms;
    s->jitter_ms     += t->jitter_ms;
    s->drip_ms       += t->drip_ms;
    s->delayfirst_ms += t->delayfirst_ms;
    if (t->reorder_ms > 0) {
        s->reorder_ms += t->reorder_ms;
    }

#define ADD_PPM(f) do { long v = (long) s->f + t->f; s->f = v > 1000000 ? 1000000 : (int) v; } while (0)
    ADD_PPM(lossy_ppm);
    ADD_PPM(corrupt_ppm);
    ADD_PPM(dup_ppm);
    ADD_PPM(reorder_ppm);
    ADD_PPM(drop_ppm);
    ADD_PPM(repeat_ppm);
#undef ADD_PPM

    /* Bottleneck / fragmentation: the tightest non-zero value wins. */
#define TIGHTEN(f) do { if (t->f > 0 && (s->f == 0 || t->f < s->f)) s->f = t->f; } while (0)
    TIGHTEN(rate_kbps);
    TIGHTEN(chunk_bytes);
    TIGHTEN(drip_bytes);
#undef TIGHTEN
    if (t->truncate_at > 0 && (s->truncate_at == 0 || t->truncate_at < s->truncate_at)) {
        s->truncate_at = t->truncate_at;
    }
}

void
fp_toxic_compose(int is_up, lever_t *snap)
{
    int want = is_up ? 1 : 2;
    pthread_mutex_lock(&g_toxic_lock);
    for (int i = 0; i < FP_TOXIC_MAX; i++) {
        if (g_toxics[i].in_use && (g_toxics[i].dir & want)) {
            compose_one(snap, &g_toxics[i].lv);
        }
    }
    pthread_mutex_unlock(&g_toxic_lock);
}

void
fp_toxic_reset(void)
{
    pthread_mutex_lock(&g_toxic_lock);
    for (int i = 0; i < FP_TOXIC_MAX; i++) {
        g_toxics[i].in_use = 0;
    }
    __atomic_store_n(&g_dir_mask, 0, __ATOMIC_RELEASE);
    pthread_mutex_unlock(&g_toxic_lock);
}
