#ifndef TOKEN_JSON_H
#define TOKEN_JSON_H
#include <stddef.h>
#include <stdint.h>

#if defined(_WIN32) || defined(_WIN64)
# include <BaseTsd.h>
typedef SSIZE_T ssize_t;
#else
# include <sys/types.h>
#endif

const char *json_skip_ws(const char *p, const char *end);
const char *json_skip_value(const char *p, const char *end);
const char *json_find_key(const char *json, const char *end,
    const char *key, const char **val_end);
ssize_t json_get_string(const char *json, size_t json_len, const char *key,
    char *out, size_t out_max);
int json_get_string_array(const char *json, size_t json_len, const char *key,
    char out[][256], int max_items);
int json_get_int64(const char *json, size_t json_len, const char *key, int64_t *out);

#endif /* TOKEN_JSON_H */
