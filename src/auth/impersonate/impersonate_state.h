/*
 * impersonate_state.h — encapsulated state for impersonation subsystem.
 *
 * WHAT: Centralized state container replacing scattered module-level globals.
 * WHY: Improves testability, enables future multi-instance support, eliminates
 *   implicit dependencies, and satisfies code quality requirement for module
 *   globals encapsulation (100/100 code quality initiative).
 * HOW: Single state struct with accessor functions — no direct global access.
 */
#ifndef BRIX_IMPERSONATE_STATE_H
#define BRIX_IMPERSONATE_STATE_H

#include "impersonate.h"
#include <sys/types.h>

/*
 * brix_imp_state_t — runtime state for impersonation broker.
 *
 * Fields:
 *   broker_allow_uid: UID allowed to connect to broker (0 = disabled)
 *   base_uid: Base UID for impersonation operations
 *   base_gid: Base GID for impersonation operations
 *   base_groups: Supplementary group array
 *   base_ngroups: Count of supplementary groups
 *   self_uid: Service user's own UID (for restore operations)
 *   initialized: Flag indicating state has been initialized
 */
typedef struct {
    uid_t  broker_allow_uid;
    uid_t  base_uid;
    gid_t  base_gid;
    gid_t  base_groups[BRIX_IDMAP_MAXGROUPS];
    int    base_ngroups;
    uid_t  self_uid;
    int    initialized;
} brix_imp_state_t;

/*
 * brix_idmap_state_t — runtime state for identity mapping.
 *
 * Fields:
 *   min_uid: Minimum UID allowed for impersonation (security floor)
 *   primary_only: Flag — only use primary group (ignore supplementary)
 *   gate_loaded: Flag — gate map file present and loaded
 *   initialized: Flag indicating state has been initialized
 */
typedef struct {
    uid_t  min_uid;
    int    primary_only;
    int    gate_loaded;
    int    initialized;
} brix_idmap_state_t;

/* Global state instances (singletons for now) */
extern brix_imp_state_t   brix_imp_state;
extern brix_idmap_state_t brix_idmap_state;

/*
 * Accessor functions for brix_imp_state_t.
 * These provide controlled access to impersonation broker state.
 */

/* Broker allow UID accessor */
uid_t brix_imp_get_broker_allow_uid(void);
void  brix_imp_set_broker_allow_uid(uid_t uid);

/* Base UID accessor */
uid_t brix_imp_get_base_uid(void);
void  brix_imp_set_base_uid(uid_t uid);

/* Base GID accessor */
gid_t brix_imp_get_base_gid(void);
void  brix_imp_set_base_gid(gid_t gid);

/* Base groups accessor */
const gid_t* brix_imp_get_base_groups(void);
int          brix_imp_get_base_ngroups(void);
void         brix_imp_set_base_groups(const gid_t *groups, int ngroups);

/* Self UID accessor */
uid_t brix_imp_get_self_uid(void);
void  brix_imp_set_self_uid(uid_t uid);

/* Initialization check */
int brix_imp_is_initialized(void);
void brix_imp_mark_initialized(void);

/*
 * Accessor functions for brix_idmap_state_t.
 * These provide controlled access to identity mapping state.
 */

/* Minimum UID accessor */
uid_t brix_idmap_get_min_uid(void);
void  brix_idmap_set_min_uid(uid_t uid);

/* Primary-only flag accessor */
int  brix_idmap_get_primary_only(void);
void brix_idmap_set_primary_only(int on);

/* Gate loaded flag accessor */
int  brix_idmap_is_gate_loaded(void);
void brix_idmap_set_gate_loaded(int loaded);

/* Initialization check */
int brix_idmap_is_initialized(void);
void brix_idmap_mark_initialized(void);

/*
 * Initialization functions.
 * Call these during module initialization to set up state.
 */
void brix_imp_state_init(void);
void brix_idmap_state_init(void);

#endif /* BRIX_IMPERSONATE_STATE_H */
