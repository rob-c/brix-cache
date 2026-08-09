/*
 * brix_fault_proxy_mods.h — first-party optional modules that bolt onto the
 * brix-fault-proxy core (brix_fault_proxy.c) without reaching into its private
 * fault-lever state.  Each module is a self-contained translation unit; the core
 * calls these entry points and nothing else crosses the boundary.
 *
 *   ctl        — a built-in control-port client subcommand (`brix-fault-proxy
 *                ctl <host:port> "<cmd>"`), replacing the external `nc` that
 *                operators and tests used to shell out to.
 *   event-log  — an optional append-only JSONL trail of discrete fault events
 *                (sever, refuse), giving per-event provenance the point-in-time
 *                `status`/metrics aggregates cannot.
 *
 * These are deliberately decoupled from the core's static lever_t / counters:
 * the event sink takes only plain scalars, so it links against no core symbol
 * and the core only ever calls brix_fp_event() / fp_event_open().
 */
#ifndef BRIX_FAULT_PROXY_MODS_H
#define BRIX_FAULT_PROXY_MODS_H

#include <stddef.h>

/* --- ctl client subcommand (brix_fault_proxy_ctl.c) --- */

/* Dispatched from main() when argv[1] == "ctl".  Dials the control port, sends
 * the request (argv[3], or stdin when "-"), prints the reply, and maps it to a
 * scriptable exit code (0 ok/status · 3 err reply · 4 connect failure ·
 * 2 usage).  Never returns to the proxy run path. */
int fp_ctl_main(int argc, char **argv);

/* --- optional JSONL fault-event log (brix_fault_proxy_event.c) --- */

/* Open (or replace) the append-only event sink.  Returns 0 on success, -1 if
 * `path` cannot be opened for append (caller fails closed). */
int fp_event_open(const char *path);

/* 1 when a log is configured — lets hot callers skip building event strings. */
int fp_event_enabled(void);

/* Append one JSONL event.  `dir`/`reason`/`numkey` are optional (NULL omits the
 * field); `numval` is emitted only when `numkey` is non-NULL.  No relayed
 * payload bytes are ever written — only structural metadata.  A best-effort
 * write: a full or failing log never disrupts the relay. */
void brix_fp_event(unsigned long conn, const char *dir, const char *event,
                   const char *reason, const char *numkey, long numval);

/* Override the "route" field of subsequent events on THIS thread (route accept
 * threads name their own route; unset / "" restores the default "default"). */
void fp_event_set_route(const char *name);

/* --- optional JSON control-input front-end (brix_fault_proxy_json.c) --- */

/* Reproject a flat JSON command object — {"cmd":"<verb>","args":"<args>"} — onto
 * a "<verb> <args>" line for the core command parser.  Returns 0 on success
 * (NUL-terminated `out`), -1 on a malformed object or a missing "cmd".  Touches
 * no lever state: a pure string transform so JSON input cannot drift from the
 * one command grammar. */
int fp_json_to_verb(const char *json, char *out, size_t outsz);

/* Fetch one top-level key's value (string decoded, or a bare number/bool token
 * copied verbatim). Returns 1 (filled `out`), 0 (absent), -1 (malformed). */
int fp_json_get(const char *json, const char *key, char *out, size_t outsz);

#endif /* BRIX_FAULT_PROXY_MODS_H */
