/*
 * ratelimit_keys_internal.h — cross-file glue for the ratelimit_keys.c split.
 *
 * The directive-parsing plane is split across ratelimit_keys_parse.c (the value
 * primitives) and ratelimit_keys_rules.c (the shared rule builders).  The four
 * value parsers below are defined once in ratelimit_keys_parse.c and referenced
 * from the rule builders; declaring them here keeps them a single definition
 * without exposing them in the public ratelimit.h.
 */
#ifndef BRIX_RATELIMIT_KEYS_INTERNAL_H
#define BRIX_RATELIMIT_KEYS_INTERNAL_H

#include "ratelimit.h"

/* Parse "key=<type>[:<prefix>]" into rule->key_type / rule->key_match. */
ngx_int_t rl_parse_key(ngx_conf_t *cf, ngx_str_t *v, brix_rl_rule_t *rule);

/* Parse "<N>r/s" → requests/s (returns the integer N, or NGX_ERROR). */
ngx_int_t rl_parse_req_rate(ngx_str_t *v);

/* Parse "<N>[k|m|g]/s" → bytes/s.  Returns NGX_ERROR on bad input. */
ssize_t rl_parse_bw_rate(ngx_str_t *v);

/* Parse "<N>[k|m|g]" → bytes (burst). */
ssize_t rl_parse_size(ngx_str_t *v);

#endif /* BRIX_RATELIMIT_KEYS_INTERNAL_H */
