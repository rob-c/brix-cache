/*
 * brix_fault_lever.h — the per-direction fault-lever record shared between the
 * brix-fault-proxy core (brix_fault_proxy.c) and the optional named-toxic module
 * (brix_fault_toxic.c).
 *
 * The core owns the two live instances (`g_up` / `g_down`) and every field's
 * semantics; the toxic module only ever *composes* a stack of named toxics into
 * a caller-owned snapshot copy (never the live levers), so the type — not the
 * state — is what crosses the boundary.  Kept header-only and dependency-free so
 * both translation units agree on the layout with no other coupling.
 */
#ifndef BRIX_FAULT_LEVER_H
#define BRIX_FAULT_LEVER_H

/* Per-direction fault levers.  0 = off (reorder_ms defaults to 50). */
typedef struct {
    volatile int latency_ms;
    volatile int jitter_ms;
    volatile int chunk_bytes;
    volatile int drip_bytes;
    volatile int drip_ms;
    volatile int rate_kbps;      /* bandwidth ceiling, KB/s (paced) */
    volatile int lossy_ppm;      /* per-chunk sever probability, ppm (1% = 10000) */
    volatile int reorder_ppm;    /* per-chunk hold-back probability, ppm */
    volatile int reorder_ms;     /* hold-back delay applied to a reordered chunk */
    volatile int corrupt_ppm;    /* per-byte bit-flip probability, ppm */
    volatile int dup_ppm;        /* per-chunk duplicate-delivery probability, ppm */
    volatile int drop_ppm;       /* per-byte DELETE probability, ppm (framing desync) */
    volatile int repeat_ppm;     /* per-byte duplicate probability, ppm (length inflate) */
    volatile int delayfirst_ms;  /* delay ONLY the first forwarded chunk this direction */
    volatile long truncate_at;   /* sever after this many bytes this direction; 0=off */
    /* Phase-B fidelity levers (per-direction). */
    volatile int slow_close_ms;  /* delay the FIN by this many ms after EOF/sever */
    volatile int burst_bytes;    /* token-bucket depth for rate_kbps; 0 => 1 MTU */
    volatile int lat_dist;       /* jitter shape: 0 uniform, 1 normal */
    volatile int lat_sigma_ms;   /* normal-distribution sigma for the jitter sample */
} lever_t;

#endif /* BRIX_FAULT_LEVER_H */
