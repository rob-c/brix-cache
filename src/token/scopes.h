#ifndef TOKEN_SCOPES_H
#define TOKEN_SCOPES_H
#include <limits.h>
#include <stddef.h>

#ifndef XROOTD_SCOPE_PATH_MAX
#define XROOTD_SCOPE_PATH_MAX  256
#endif

#ifndef XROOTD_TOKEN_SCOPE_T_DEFINED
#define XROOTD_TOKEN_SCOPE_T_DEFINED
typedef struct {
    char          path[XROOTD_SCOPE_PATH_MAX];
    unsigned int  read   : 1;
    unsigned int  write  : 1;
    unsigned int  create : 1;
    unsigned int  modify : 1;
} xrootd_token_scope_t;
#endif

int xrootd_token_parse_scopes(const char *scope_str,
    xrootd_token_scope_t *scopes, int max_scopes);
int xrootd_token_check_read(const xrootd_token_scope_t *scopes,
    int scope_count, const char *path);
int xrootd_token_check_write(const xrootd_token_scope_t *scopes,
    int scope_count, const char *path);

#endif /* TOKEN_SCOPES_H */
