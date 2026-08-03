/* brix_fault_cmd_attack.c — control commands for the attack-mock levers.
 *
 * WHAT: The named-preset table and the verbs behind the topple-a-server toolkit:
 *       content triggers, length-prefix mangling, attack levers, TLS record
 *       surgery, HTTP smuggling, and session record/replay.
 *
 * WHY:  Split out of brix_fault_proxy.c, which was far over the 600-line cap
 *       (coding-standards §1). The program's shared lever state stayed where
 *       it was defined; see brix_fault_proxy_state.h for the seam.
 *
 * HOW:  Same behaviour as before the split — this is a pure move. Levers are
 *       read lock-free; wide config is snapshotted under g_ext_lock. */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "brix_fault_proxy_state.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* Named real-world + attack profiles: each expands to a list of control commands
 * applied in order. NULL-terminated command arrays. */
static const struct { const char *name; const char *cmds[6]; } PRESETS[] = {
    /* realism */
    {"satellite",     {"latency 600 both", "jitter 40", "lossy 1", NULL}},
    {"hotel-wifi",    {"jitter 300", "reorder 20 60", "lossy 2", "rate 400", NULL}},
    {"3g-lossy",      {"latency 200", "jitter 120", "corrupt 0.1", "reorder 15 80", NULL}},
    {"transoceanic",  {"latency 150", "jitter 20", NULL}},
    {"congested",     {"rate 128", "drip 4096 40", NULL}},
    {"bufferbloat",   {"latency 50", "rate 256", "jitter 200", NULL}},
    /* attacks — designed to topple a server */
    {"slowloris",     {"drip 1 800 up", "delay-first 2000 up", NULL}},
    {"slowread",      {"drip 1 800 down", "rcvbuf 512", NULL}},
    {"rst-flood",     {"abortive 1", "lossy 100", NULL}},
    {"truncate-bomb", {"truncate-at 4096 down", NULL}},
    {"corrupt-storm", {"corrupt 5", NULL}},
    {"pool-exhaust",  {"fanout 8", "hang", NULL}},
    {"smuggle",       {"inject str:0\\r\\n\\r\\nGET /x HTTP/1.1\\r\\nHost: h\\r\\n\\r\\n up", NULL}},
    {"black-hole",    {"hang", NULL}},
    {"lb-flap",       {"flap 500 500", NULL}},
};

/* Apply a named preset, or list them on `list`/empty. Returns 1 (handled). */
int
cmd_preset(char *args, char *reply, size_t rsz)
{
    char *name = strtok(args, " ");
    size_t n = sizeof(PRESETS) / sizeof(PRESETS[0]);
    if (!name || strcmp(name, "list") == 0) {
        char *w = reply; int left = (int) rsz;
        int k = snprintf(w, left, "presets:");
        w += k; left -= k;
        for (size_t i = 0; i < n && left > 1; i++) {
            int m = snprintf(w, left, " %s", PRESETS[i].name);
            w += m; left -= m;
        }
        snprintf(w, left > 0 ? left : 0, "\n");
        return 1;
    }
    for (size_t i = 0; i < n; i++) {
        if (strcmp(name, PRESETS[i].name) != 0) {
            continue;
        }
        for (int c = 0; PRESETS[i].cmds[c] != NULL; c++) {
            char buf[256];
            snprintf(buf, sizeof(buf), "%s", PRESETS[i].cmds[c]);
            apply_command(buf, NULL, 0);
        }
        snprintf(reply, rsz, "ok (preset %s)\n", name);
        return 1;
    }
    snprintf(reply, rsz, "err: unknown preset (try 'preset list')\n");
    return 1;
}

/* Arm a content trigger: `trigger[-once] <dir> <payload> <command...>`. */
int
cmd_trigger(int once, char *args, char *reply, size_t rsz)
{
    char *dirtok = strtok(args, " ");
    if (dirtok && strcmp(dirtok, "off") == 0) {
        pthread_mutex_lock(&g_ext_lock);
        g_trig_up.pat_len = 0; g_trig_up.fired = 0;
        g_trig_down.pat_len = 0; g_trig_down.fired = 0;
        pthread_mutex_unlock(&g_ext_lock);
        return 1;
    }
    char *pay = strtok(NULL, " ");
    char *cmd = strtok(NULL, "");
    int   d = 0;
    if (dirtok && strcmp(dirtok, "up") == 0)   d = 1;
    else if (dirtok && strcmp(dirtok, "down") == 0) d = 2;
    if (!dirtok || !pay || !cmd) {
        snprintf(reply, rsz, "err: trigger <up|down|both> <payload> <command>\n");
        return 1;
    }
    unsigned char pat[128];
    int pl = fp_ext_parse_payload(pay, pat, sizeof(pat));
    if (pl <= 0) {
        snprintf(reply, rsz, "err: bad trigger payload (hex:.. or str:..)\n");
        return 1;
    }
    pthread_mutex_lock(&g_ext_lock);
    struct fp_trigger *set[2] = { NULL, NULL };
    if (d != 2) { set[0] = &g_trig_up; }
    if (d != 1) { set[1] = &g_trig_down; }
    for (int j = 0; j < 2; j++) {
        if (!set[j]) {
            continue;
        }
        memcpy(set[j]->pat, pat, (size_t) pl);
        set[j]->pat_len = pl;
        snprintf(set[j]->cmd, sizeof(set[j]->cmd), "%s", cmd);
        set[j]->once = once;
        set[j]->fired = 0;
    }
    pthread_mutex_unlock(&g_ext_lock);
    return 1;
}

/* set|add|sub -> 0|1|2; -1 names no mangle op. */
static int
mangle_op_of(const char *tok)
{
    if (strcmp(tok, "set") == 0) { return 0; }
    if (strcmp(tok, "add") == 0) { return 1; }
    if (strcmp(tok, "sub") == 0) { return 2; }
    return -1;
}

/* Leading direction token: up|down, anything else meaning both. Unlike dir_of()
 * this one reads a *leading* token and does not rewrite `args`. */
static int
mangle_dir_of(const char *tok)
{
    if (strcmp(tok, "up") == 0)   { return 1; }
    if (strcmp(tok, "down") == 0) { return 2; }
    return 0;
}

/* Arm the length-mangler on the selected direction(s). */
static void
mangle_arm(int d, long offset, int op, long val)
{
    struct fp_mangle *set[2] = { NULL, NULL };
    if (d != 2) { set[0] = &g_mangle_up; }
    if (d != 1) { set[1] = &g_mangle_down; }
    for (int j = 0; j < 2; j++) {
        if (!set[j]) {
            continue;
        }
        set[j]->offset = offset;
        set[j]->op = op;
        set[j]->val = val;
        set[j]->active = 1;
    }
}

/* `mangle-len <up|down|both> <offset> <set|add|sub> <val>` (or `off`). */
int
cmd_mangle(char *args, char *reply, size_t rsz)
{
    char *dirtok = strtok(args, " ");
    if (dirtok && strcmp(dirtok, "off") == 0) {
        g_mangle_up.active = 0; g_mangle_down.active = 0;
        return 1;
    }
    char *offt = strtok(NULL, " ");
    char *opt  = strtok(NULL, " ");
    char *valt = strtok(NULL, " ");
    if (!dirtok || !offt || !opt || !valt) {
        snprintf(reply, rsz, "err: mangle-len <dir> <offset> <set|add|sub> <val>\n");
        return 1;
    }
    int op = mangle_op_of(opt);
    if (op < 0) {
        snprintf(reply, rsz, "err: mangle op must be set|add|sub\n");
        return 1;
    }
    mangle_arm(mangle_dir_of(dirtok), atol(offt), op, atol(valt));
    return 1;
}

/* `flap [<up_ms> <down_ms>|off]` — bounce the listener on a duty cycle. Every
 * arm bumps g_flap_gen so the previously-detached thread retires itself. */
static void
attack_flap(const char *args)
{
    if (strcmp(args, "off") == 0 || args[0] == '\0') {
        __atomic_add_fetch(&g_flap_gen, 1, __ATOMIC_SEQ_CST);
        g_flap_on = 0;
        return;
    }
    int up = 0, down = 0;
    sscanf(args, "%d %d", &up, &down);
    g_flap_up_ms = up; g_flap_down_ms = down;
    unsigned gen = __atomic_add_fetch(&g_flap_gen, 1, __ATOMIC_SEQ_CST);
    pthread_t th;
    if (pthread_create(&th, NULL, flap_thread, (void *) (uintptr_t) gen) == 0) {
        pthread_detach(th);
        g_flap_on = 1;
    }
}

/* `ramp <lever> <start> <end> <ms>` — sweep one lever over a window in a
 * detached thread. 0 on a usage error (the arg is owned by the thread on 1). */
static int
attack_ramp(const char *args)
{
    struct ramp_arg *r = calloc(1, sizeof(*r));
    if (!r) {
        return 0;
    }
    if (sscanf(args, "%23s %lf %lf %d", r->lever, &r->start, &r->end, &r->ms) != 4) {
        free(r);
        return 0;
    }
    r->gen = __atomic_load_n(&g_ramp_gen, __ATOMIC_SEQ_CST);
    pthread_t th;
    if (pthread_create(&th, NULL, ramp_thread, r) != 0) {
        free(r);
    } else {
        pthread_detach(th);
    }
    return 1;
}

/* Attack-mocking control verbs (topple-a-server toolkit). Returns 1 if handled. */
int
cmd_set_attack(const char *verb, char *args, char *reply, size_t rsz)
{
    if (strcmp(verb, "preset") == 0) {
        cmd_preset(args, reply, rsz);
    } else if (strcmp(verb, "trigger") == 0) {
        cmd_trigger(0, args, reply, rsz);
    } else if (strcmp(verb, "trigger-once") == 0) {
        cmd_trigger(1, args, reply, rsz);
    } else if (strcmp(verb, "mangle-len") == 0) {
        cmd_mangle(args, reply, rsz);
    } else if (strcmp(verb, "accept-pause") == 0) {
        g_accept_pause_ms = atoi(args);
    } else if (strcmp(verb, "fanout") == 0) {
        g_fanout = atoi(args);
    } else if (strcmp(verb, "global-rate") == 0) {
        g_global_rate_kbps = atoi(args);
        g_gr_init = 0;   /* re-prime the shared bucket */
    } else if (strcmp(verb, "flap") == 0) {
        attack_flap(args);
    } else if (strcmp(verb, "ramp") == 0) {
        if (!attack_ramp(args)) {
            snprintf(reply, rsz, "err: ramp <lever> <start> <end> <ms>\n");
        }
    } else {
        return 0;
    }
    return 1;
}

/* --- TLS record surgery control (`tls <sub> ...`) ------------------------- */

/* Apply integer `v` to field `F` of the selected direction(s) TLS config.
 * d: 0 both / 1 up / 2 down. */
#define TLS_SET(d, F, v) do {                      \
    if ((d) != 2) g_tls_up.F   = (v);              \
    if ((d) != 1) g_tls_down.F = (v);              \
} while (0)

int
cmd_set_tls(char *args, char *reply, size_t rsz)
{
    char *sub = strtok(args, " ");
    char *rest = strtok(NULL, "");
    char  rbuf[64] = "";
    if (rest) {
        snprintf(rbuf, sizeof(rbuf), "%s", rest);
    }
    int d = dir_of(rbuf);
    pthread_mutex_lock(&g_ext_lock);
    if (!sub || strcmp(sub, "off") == 0) {
        fp_tls_cfg_init(&g_tls_up);
        fp_tls_cfg_init(&g_tls_down);
    } else if (strcmp(sub, "fragment") == 0) {
        TLS_SET(d, frag_max, atoi(rbuf));
    } else if (strcmp(sub, "set-type") == 0) {
        TLS_SET(d, set_type, atoi(rbuf));
    } else if (strcmp(sub, "drop-type") == 0) {
        TLS_SET(d, drop_type, atoi(rbuf));
    } else if (strcmp(sub, "inflate") == 0) {
        TLS_SET(d, inflate_len, atoi(rbuf));
    } else if (strcmp(sub, "flip") == 0) {
        TLS_SET(d, flip_payload, 1);
    } else if (strcmp(sub, "set-version") == 0) {
        int maj = 3, min = 3;
        sscanf(rbuf, "%d %d", &maj, &min);
        TLS_SET(d, set_ver_major, maj);
        TLS_SET(d, set_ver_minor, min);
    } else if (strcmp(sub, "alert") == 0) {
        int lvl = 2, desc = 0;
        sscanf(rbuf, "%d %d", &lvl, &desc);
        TLS_SET(d, alert_level, lvl);
        TLS_SET(d, alert_desc, desc);
    } else {
        pthread_mutex_unlock(&g_ext_lock);
        snprintf(reply, rsz, "err: tls <fragment|set-type|drop-type|inflate|flip|"
                             "set-version|alert|off> ...\n");
        return 1;
    }
    pthread_mutex_unlock(&g_ext_lock);
    return 1;
}

/* --- HTTP smuggling control (`http <sub> ...`) ---------------------------- */

/* Every `http` sub-verb yields one of three outcomes, and the caller reports a
 * different error for each — so they are named rather than left as bare ints. */
#define HTTP_UNKNOWN (-1)   /* `sub` names no lever          */
#define HTTP_BADARG    0    /* lever exists, argument is bad */
#define HTTP_OK        1

/* The scalar smuggling levers: each is "set fields from a number", identical for
 * every selected direction, so one direction's config is all this needs.
 * HTTP_OK if `sub` named one of them, HTTP_UNKNOWN otherwise. */
static int
http_lever_scalar(fp_http_cfg *h, const char *sub, const char *rbuf)
{
    if (strcmp(sub, "cl-te") == 0) {
        h->add_cl = 1; h->cl_val = atol(rbuf); h->add_te = 1;
    } else if (strcmp(sub, "te-cl") == 0) {
        h->add_te = 1; h->add_cl = 1; h->cl_val = atol(rbuf);
    } else if (strcmp(sub, "dup-cl") == 0) {
        h->dup_cl = 1; h->dup_cl_val = atol(rbuf);
    } else if (strcmp(sub, "obfuscate-te") == 0) {
        int m = atoi(rbuf);
        h->obfuscate_te = (m < 1 || m > 3) ? 1 : m;
    } else if (strcmp(sub, "naked-lf") == 0) {
        h->naked_lf = 1;
    } else {
        return HTTP_UNKNOWN;
    }
    return HTTP_OK;
}

/* Apply a scalar lever to every selected direction. */
static int
http_lever_scalar_all(fp_http_cfg *H[2], const char *sub, const char *rbuf)
{
    int rc = HTTP_UNKNOWN;
    for (int j = 0; j < 2; j++) {
        if (H[j]) {
            rc = http_lever_scalar(H[j], sub, rbuf);
        }
    }
    return rc;
}

/* `inject-header <name> <value>`. strtok mutates rbuf, so the split happens once
 * here and both directions share the result. */
static int
http_lever_inject(fp_http_cfg *H[2], char *rbuf)
{
    char *nm = strtok(rbuf, " ");
    char *vl = strtok(NULL, "");
    if (!nm || !vl) {
        return HTTP_BADARG;
    }
    int rc = HTTP_OK;
    for (int j = 0; j < 2; j++) {
        if (!H[j]) {
            continue;
        }
        H[j]->inj_name_len = (int) snprintf((char *) H[j]->inj_name,
            sizeof(H[j]->inj_name), "%s", nm);
        H[j]->inj_val_len = fp_ext_parse_payload(vl, H[j]->inj_val,
            sizeof(H[j]->inj_val));
        if (H[j]->inj_val_len < 0) { H[j]->inj_val_len = 0; rc = HTTP_BADARG; }
    }
    return rc;
}

/* `append <payload>` — raw bytes glued onto the far end of the stream. */
static int
http_lever_append(fp_http_cfg *H[2], const char *rbuf)
{
    int rc = HTTP_OK;
    for (int j = 0; j < 2; j++) {
        if (!H[j]) {
            continue;
        }
        int n = fp_ext_parse_payload(rbuf, H[j]->append, sizeof(H[j]->append));
        H[j]->append_len = n > 0 ? n : 0;
        if (n <= 0) { rc = HTTP_BADARG; }
    }
    return rc;
}

/* Dispatch one `http` sub-verb. Caller holds g_ext_lock. */
static int
http_apply(const char *sub, char *rbuf, int d)
{
    fp_http_cfg *H[2] = { NULL, NULL };
    if (d != 2) { H[0] = &g_http_up; }
    if (d != 1) { H[1] = &g_http_down; }

    if (!sub || strcmp(sub, "off") == 0) {
        memset(&g_http_up, 0, sizeof(g_http_up));
        memset(&g_http_down, 0, sizeof(g_http_down));
        return HTTP_OK;
    }
    if (strcmp(sub, "inject-header") == 0) {
        return http_lever_inject(H, rbuf);
    }
    if (strcmp(sub, "append") == 0) {
        return http_lever_append(H, rbuf);
    }
    return http_lever_scalar_all(H, sub, rbuf);
}

int
cmd_set_http(char *args, char *reply, size_t rsz)
{
    char *sub = strtok(args, " ");
    char *rest = strtok(NULL, "");
    char  rbuf[512] = "";
    if (rest) {
        snprintf(rbuf, sizeof(rbuf), "%s", rest);
    }
    int d = dir_of(rbuf);   /* strips the direction token before any sub parses */

    pthread_mutex_lock(&g_ext_lock);
    int rc = http_apply(sub, rbuf, d);
    pthread_mutex_unlock(&g_ext_lock);

    if (rc == HTTP_UNKNOWN) {
        snprintf(reply, rsz, "err: http <cl-te|te-cl|dup-cl|obfuscate-te|naked-lf|"
                             "inject-header|append|off> ...\n");
    } else if (rc == HTTP_BADARG) {
        snprintf(reply, rsz, "err: bad http argument (payload hex:/str:)\n");
    }
    return 1;
}

/* --- Session record / replay control -------------------------------------- */
int
cmd_set_replay(const char *verb, char *args, char *reply, size_t rsz)
{
    if (strcmp(verb, "record") == 0) {
        if (strcmp(args, "off") == 0 || args[0] == '\0') {
            fp_replay_record_stop();
            snprintf(reply, rsz, "ok (recording stopped)\n");
        } else if (fp_replay_record_start(args) == 0) {
            snprintf(reply, rsz, "ok (recording to %s)\n", args);
        } else {
            snprintf(reply, rsz, "err: cannot open record file\n");
        }
        return 1;
    }
    if (strcmp(verb, "replay") == 0) {
        char *sub = strtok(args, " ");
        if (!sub || strcmp(sub, "off") == 0) {
            g_replay_active = 0;
            snprintf(reply, rsz, "ok (replay off)\n");
            return 1;
        }
        if (strcmp(sub, "dir") == 0) {
            char *d = strtok(NULL, " ");
            g_replay_updir = (d && strcmp(d, "up") == 0) ? 1 : 0;
            return 1;
        }
        if (g_replay_active) {
            snprintf(reply, rsz, "err: replay already active (replay off first)\n");
            return 1;
        }
        fp_replay_free(&g_replay_store);
        if (fp_replay_load(sub, &g_replay_store) != 0) {
            snprintf(reply, rsz, "err: cannot load capture (missing / bad magic)\n");
            return 1;
        }
        g_replay_active = 1;
        snprintf(reply, rsz, "ok (replaying %zu records from %s)\n",
                 g_replay_store.n, sub);
        return 1;
    }
    return 0;
}
