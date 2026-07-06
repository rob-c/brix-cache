#ifndef TOKEN_SCOPES_H
#define TOKEN_SCOPES_H
/* Token scope parsing and path-checking helpers for WLCG JWT bearer tokens.
 * Defines brix_token_scope_t struct with read/write/create/modify flags
 * per scope entry. Declarations: parse_scopes, check_read, check_write. */
#include <limits.h>
#include <stddef.h>

#ifndef BRIX_SCOPE_PATH_MAX
#define BRIX_SCOPE_PATH_MAX  256
#endif

#ifndef BRIX_TOKEN_SCOPE_T_DEFINED
#define BRIX_TOKEN_SCOPE_T_DEFINED
typedef struct {
    char          path[BRIX_SCOPE_PATH_MAX];
    unsigned int  read   : 1;
    unsigned int  write  : 1;
    unsigned int  create : 1;
    unsigned int  modify : 1;
} brix_token_scope_t;
#endif

/* WHAT: Test whether scope_path covers request_path using prefix + boundary rules.
* WHY: Prevents "/data" from matching "/database" — callers (check_read/check_write and issuer_registry.c)
*      reuse this single boundary-checked implementation rather than duplicating the prefix logic.
* HOW: Returns 1 if scope "/" (root), or scope_path is a proper prefix of request_path where the
*      next char is '/' or NUL; returns 0 otherwise.
*/
int brix_token_scope_path_matches(const char *scope_path,
    const char *request_path);

/* WHAT: Parse space-separated WLCG "permission:path" scope claim into structured brix_token_scope_t entries.
* WHY: WLCG tokens encode authorization as space-separated scope claims (e.g., "storage.read:/atlas/reco"). This extracts permission and path components for downstream access control decisions.
* HOW: Tokenizes input on spaces → splits each entry on ":" separator → copies path component with default "/" if empty → sets read/write/create/modify flags via exact-length memcmp. Returns count of parsed scope entries written to scopes[].
*/
int brix_token_parse_scopes(const char *scope_str,
    brix_token_scope_t *scopes, int max_scopes);
/* WHAT: Test whether any scope grants storage.read access to the given path.
* WHY: Access control decision function used by validate.c and s3/auth.c to enforce read permission against parsed WLCG scopes with path prefix matching.
* HOW: Iterates over scopes[0..scope_count-1], checks each scope's read flag combined with scope_path_matches() prefix comparison (boundary check prevents "/data" from matching "/database"). Returns 1 if any scope grants access, 0 if denied.
*/
int brix_token_check_read(const brix_token_scope_t *scopes,
    int scope_count, const char *path);
/* WHAT: Test whether any scope grants storage.write or storage.create access to the given path.
* WHY: Access control decision function used by validate.c and s3/auth.c — both write and create permissions are treated as sufficient for write ops per WLCG token profile intent where "create" is a write-like capability restricted to new objects.
* HOW: Iterates over scopes[0..scope_count-1], checks (write || create) flag combined with scope_path_matches() prefix comparison. Returns 1 if any scope grants access, 0 if denied.
*/
int brix_token_check_write(const brix_token_scope_t *scopes,
    int scope_count, const char *path);

#endif /* TOKEN_SCOPES_H */
