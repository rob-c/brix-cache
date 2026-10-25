/*
 * Bounded native TPC endpoint and observation helpers.
 * Requires no prior includes; shared execution types are provided below.
 */
#pragma once
#include "xrd_conform_internal.h"

int xrd_conform_tpc_unsigned(const char *value, unsigned long long *number);
int xrd_conform_tpc_query(brix_conn *connection, unsigned long long *value,
    brix_status *status);
