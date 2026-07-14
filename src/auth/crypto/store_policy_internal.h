/*
 * store_policy_internal.h — private glue shared across the store_policy.c
 * translation units (store_policy.c / store_policy_conformance.c /
 * store_policy_store.c).  Declares only symbols defined in one of those
 * files and referenced from another; nothing here is part of the public
 * store_policy.h contract.
 */
#ifndef BRIX_CRYPTO_STORE_POLICY_INTERNAL_H
#define BRIX_CRYPTO_STORE_POLICY_INTERNAL_H

#include "auth/crypto/store_policy.h"

/*
 * Thin wrapper over the caller-supplied log callback: a no-op when fn is NULL.
 * Defined in store_policy.c; also called from the store-configuration path in
 * store_policy_store.c.
 */
void sp_log(void *log, brix_sp_log_fn fn, int level, const char *msg);

#endif /* BRIX_CRYPTO_STORE_POLICY_INTERNAL_H */
