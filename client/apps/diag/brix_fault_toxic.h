/*
 * brix_fault_toxic.h — named, stackable, per-direction fault toxics (C1).
 *
 * The core owns the two live base levers (g_up/g_down); this module holds a
 * separately addressable table of *named* single-effect toxics that compose ON
 * TOP of that base into the relay's per-buffer snapshot.  Naming lets an operator
 * or test add and remove one discrete effect at a time — `toxic add slow
 * latency 100 up`, `toxic remove slow` — without disturbing the base levers or
 * the other toxics, exactly the Toxiproxy model.  Grammar:
 *   toxic add <name> <type> <value> [up|down|both]   (dir optional, default both)
 *   toxic remove <name>
 *   toxic list [json]
 * The core `clear` verb empties the whole table (via fp_toxic_reset).
 */
#ifndef BRIX_FAULT_TOXIC_H
#define BRIX_FAULT_TOXIC_H

#include <stddef.h>

#include "brix_fault_lever.h"

/* Handle a `toxic <sub> ...` control command (add / remove / list).  `args`
 * is the text after the "toxic" verb (mutated).  Always writes a reply; returns
 * 1 (the verb is always consumed here once the core has matched "toxic"). */
int fp_toxic_cmd(char *args, char *reply, size_t rsz);

/* Fast-path gate: 1 if any toxic could affect this direction (is_up != 0 ⇒ the
 * client→upstream leg).  Lock-free so the zero-toxic relay path pays nothing. */
int fp_toxic_active(int is_up);

/* Compose every active toxic for this direction onto `*snap` (a caller-owned
 * copy of the base levers — never the live levers).  Delays stack additively,
 * probabilities add (capped), and bottleneck fields take the tightest value. */
void fp_toxic_compose(int is_up, lever_t *snap);

/* Drop every toxic (hooked into the core's clear_all). */
void fp_toxic_reset(void);

#endif /* BRIX_FAULT_TOXIC_H */
