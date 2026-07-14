/*
 * tpc_token_internal.h — declarations shared between the two halves of the TPC
 * outbound delegated-token fetcher after the phase-79 file-size split.
 *
 * WHAT: Cross-declares the two functions that call across the tpc_token.c /
 *       tpc_token_exchange.c file boundary.
 * WHY:  tpc_token.c (dispatcher + oidc-agent path + shared parse helper) and
 *       tpc_token_exchange.c (RFC 8693 token-exchange path) were one 632-line
 *       file; splitting keeps each focused and under the 500-line cap. The
 *       dispatcher in tpc_token.c calls tpc_token_rfc8693 (now in the exchange
 *       file), and the exchange path calls the shared JSON parser that stays in
 *       tpc_token.c — so exactly those two functions become non-static.
 * HOW:  Both translation units include this header; neither symbol is exported
 *       beyond the outbound TPC module.
 */
#ifndef BRIX_TPC_OUTBOUND_TPC_TOKEN_INTERNAL_H
#define BRIX_TPC_OUTBOUND_TPC_TOKEN_INTERNAL_H

#include "tpc/engine/tpc_internal.h"   /* brix_tpc_pull_t */
#include <stddef.h>                     /* size_t */

/* Defined in tpc_token.c; called by the RFC 8693 exchange path. Parses an
 * OAuth2 JSON reply body ({"access_token":"..."}) into out; returns 0 / -1. */
int tpc_token_parse_access_token(const char *json, char *out, size_t out_sz);

/* Defined in tpc_token_exchange.c; called by tpc_fetch_delegated_token. Fetches
 * a delegated token via an RFC 8693 token-exchange POST; returns 0 / -1 with
 * t->err_msg / t->xrd_error set on failure. */
int tpc_token_rfc8693(brix_tpc_pull_t *t, char *token_out, size_t token_out_sz);

#endif /* BRIX_TPC_OUTBOUND_TPC_TOKEN_INTERNAL_H */
