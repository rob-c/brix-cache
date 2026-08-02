/*
 * auth_sigv4_canonical_standalone.h — nginx-free shims for fuzzing the SigV4
 * canonical query-string builder.
 *
 * WHAT: the three nginx aliases auth_sigv4_canonical.c uses (ngx_flag_t,
 *       ngx_strcmp, ngx_memcpy), defined against libc, so the file can be
 *       compiled standalone under a libFuzzer harness.
 * WHY:  build_canonical_qs() is already a pure (bytes, len) → canonical-bytes
 *       transform over attacker-controlled S3 query strings (pre-auth,
 *       hyper-hardening C-1 target 5), but its TU hard-includes s3.h (→
 *       ngx_http.h) purely for those three aliases. This header lets the harness
 *       substitute them without pulling the full nginx stack, and without any
 *       change to the production build path (which still includes s3.h when
 *       BRIX_SIGV4_STANDALONE is undefined).
 * HOW:  define BRIX_SIGV4_STANDALONE before including auth_sigv4_canonical.c;
 *       the file includes this header instead of s3.h. The aliases below mirror
 *       nginx's own definitions (ngx_config.h / ngx_string.h) exactly.
 */
#ifndef BRIX_SIGV4_CANONICAL_STANDALONE_H
#define BRIX_SIGV4_CANONICAL_STANDALONE_H

#include <stdint.h>
#include <string.h>
#include <sys/types.h>   /* u_char */

typedef intptr_t ngx_flag_t;                         /* nginx: ngx_config.h */

#define ngx_strcmp(s1, s2)   strcmp((const char *) s1, (const char *) s2)
#define ngx_memcpy(dst, src, n)   (void) memcpy(dst, src, n)

#endif /* BRIX_SIGV4_CANONICAL_STANDALONE_H */
