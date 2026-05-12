#ifndef TOKEN_B64URL_H
#define TOKEN_B64URL_H
#include <stddef.h>
#include <stdint.h>
#if !defined(_SSIZE_T_DEFINED) && !defined(__ssize_t_defined) && !defined(__ssize_t)
# if defined(_WIN32) || defined(_WIN64)
typedef long ssize_t;
# else
#  include <sys/types.h>
# endif
#endif
ssize_t b64url_decode(const char *in, size_t in_len, uint8_t *out, size_t out_max);
#endif // TOKEN_B64URL_H
