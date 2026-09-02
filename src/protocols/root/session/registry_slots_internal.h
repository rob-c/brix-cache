/*
 * registry_slots_internal.h — the slot-mechanics seam between registry.c
 * (public session API, owns brix_session_mutex and the SHM zone) and
 * registry_slots.c (per-slot helpers: quota key, table scan, LRU reap,
 * fill, find, self-eviction). Every helper here either is pure or takes the
 * table explicitly, and NONE locks: the caller in registry.c holds
 * brix_session_mutex around each call (finish_eviction is the one exception —
 * it must run AFTER the mutex is released; see its comment).
 */
#ifndef BRIX_SESSION_REGISTRY_SLOTS_INTERNAL_H
#define BRIX_SESSION_REGISTRY_SLOTS_INTERNAL_H

#include "registry.h"

/* Slot-selection candidates gathered in one table pass. */
typedef struct {
    ngx_uint_t free_slot;     /* first free slot, or capacity if none */
    ngx_uint_t lru_slot;      /* global LRU occupied slot (F4), capacity if none */
    ngx_msec_t lru_seen;
    ngx_uint_t src_count;     /* live slots owned by the registrant's src_key */
    ngx_uint_t src_lru_slot;  /* LRU among the registrant's OWN slots (W5) */
    ngx_msec_t src_lru_seen;
} brix_session_scan_t;

void brix_session_src_key(const char *dn, ngx_uint_t token_auth,
    char out[BRIX_SESSION_SRC_KEY_LEN]);
int brix_session_scan(brix_session_table_t *tbl,
    const u_char sessid[BRIX_SESSION_ID_LEN], ngx_msec_t now,
    const char *src_key, brix_session_scan_t *sc);
int brix_session_reap_lru(brix_session_table_t *tbl, ngx_msec_t now,
    ngx_uint_t lru_slot, ngx_msec_t lru_seen,
    ngx_uint_t *free_slot_out, u_char victim[BRIX_SESSION_ID_LEN]);
void brix_session_fill_slot(brix_session_table_t *tbl, ngx_uint_t slot,
    const u_char sessid[BRIX_SESSION_ID_LEN],
    const char *dn, const char *vo_list, ngx_uint_t token_auth,
    const char *src_key, ngx_msec_t now);
brix_session_entry_t *brix_session_find_locked(brix_session_table_t *tbl,
    const u_char sessid[BRIX_SESSION_ID_LEN]);
int brix_session_src_cap_evict(brix_session_table_t *tbl,
    ngx_uint_t src_lru_slot, ngx_uint_t *free_slot_out,
    u_char victim[BRIX_SESSION_ID_LEN]);
void brix_session_finish_eviction(const u_char victim[BRIX_SESSION_ID_LEN]);

#endif /* BRIX_SESSION_REGISTRY_SLOTS_INTERNAL_H */
