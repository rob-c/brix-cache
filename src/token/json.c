#include "json.h"

#include <string.h>
#include <stdint.h>
#include <stdlib.h>


const char *
json_skip_ws(const char *cursor, const char *end)
{
    while (cursor < end
           && (*cursor == ' ' || *cursor == '\t'
               || *cursor == '\n' || *cursor == '\r'))
    {
        cursor++;
    }

    return cursor;
}


static const char *
json_string_end(const char *cursor, const char *end)
{
    while (cursor < end) {
        if (*cursor == '\\') {
            cursor++;
            if (cursor >= end) {
                return NULL;
            }
            cursor++;
            continue;
        }

        if (*cursor == '"') {
            return cursor;
        }

        cursor++;
    }

    return NULL;
}


static const char *
json_skip_string(const char *cursor, const char *end)
{
    const char *quote;

    if (cursor >= end || *cursor != '"') {
        return NULL;
    }

    quote = json_string_end(cursor + 1, end);
    return quote == NULL ? NULL : quote + 1;
}


static const char *
json_skip_compound(const char *cursor, const char *end, char open, char close)
{
    int depth;

    if (cursor >= end || *cursor != open) {
        return NULL;
    }

    depth = 1;
    cursor++;

    while (cursor < end && depth > 0) {
        if (*cursor == '"') {
            cursor = json_skip_string(cursor, end);
            if (cursor == NULL) {
                return NULL;
            }
            continue;
        }

        if (*cursor == '{' && open != '{') {
            cursor = json_skip_compound(cursor, end, '{', '}');
            if (cursor == NULL) {
                return NULL;
            }
            continue;
        }

        if (*cursor == '[' && open != '[') {
            cursor = json_skip_compound(cursor, end, '[', ']');
            if (cursor == NULL) {
                return NULL;
            }
            continue;
        }

        if (*cursor == open) {
            depth++;
        } else if (*cursor == close) {
            depth--;
        }

        cursor++;
    }

    return depth == 0 ? cursor : NULL;
}


const char *
json_skip_value(const char *cursor, const char *end)
{
    cursor = json_skip_ws(cursor, end);
    if (cursor >= end) {
        return NULL;
    }

    if (*cursor == '"') {
        return json_skip_string(cursor, end);
    }

    if (*cursor == '{') {
        return json_skip_compound(cursor, end, '{', '}');
    }

    if (*cursor == '[') {
        return json_skip_compound(cursor, end, '[', ']');
    }

    while (cursor < end
           && *cursor != ',' && *cursor != '}'
           && *cursor != ']' && *cursor != ' '
           && *cursor != '\t' && *cursor != '\n'
           && *cursor != '\r')
    {
        cursor++;
    }

    return cursor;
}


const char *
json_find_key(const char *json, const char *end, const char *key,
    const char **val_end)
{
    const char *cursor;
    size_t      key_len;

    key_len = strlen(key);
    cursor = json_skip_ws(json, end);
    if (cursor >= end || *cursor != '{') {
        return NULL;
    }

    cursor++;
    while (cursor < end) {
        const char *key_start;
        const char *key_end;
        const char *value_start;
        const char *value_end;
        size_t      parsed_key_len;

        cursor = json_skip_ws(cursor, end);
        if (cursor >= end || *cursor == '}') {
            return NULL;
        }
        if (*cursor != '"') {
            return NULL;
        }

        key_start = cursor + 1;
        cursor = json_skip_string(cursor, end);
        if (cursor == NULL) {
            return NULL;
        }
        key_end = cursor - 1;

        cursor = json_skip_ws(cursor, end);
        if (cursor >= end || *cursor != ':') {
            return NULL;
        }

        cursor++;
        value_start = json_skip_ws(cursor, end);
        value_end = json_skip_value(value_start, end);
        if (value_end == NULL) {
            return NULL;
        }

        parsed_key_len = (size_t) (key_end - key_start);
        if (parsed_key_len == key_len
            && memcmp(key_start, key, key_len) == 0)
        {
            if (val_end != NULL) {
                *val_end = value_end;
            }
            return value_start;
        }

        cursor = json_skip_ws(value_end, end);
        if (cursor < end && *cursor == ',') {
            cursor++;
        }
    }

    return NULL;
}


ssize_t
json_get_string(const char *json, size_t json_len, const char *key,
    char *out, size_t out_max)
{
    const char *end;
    const char *value;
    const char *value_end;
    const char *string_end;
    size_t      copy_len;

    if (out_max == 0) {
        return -1;
    }

    end = json + json_len;
    value = json_find_key(json, end, key, &value_end);
    if (value == NULL || *value != '"') {
        return -1;
    }

    string_end = json_string_end(value + 1, value_end);
    if (string_end == NULL) {
        return -1;
    }

    copy_len = (size_t) (string_end - (value + 1));
    if (copy_len >= out_max) {
        copy_len = out_max - 1;
    }

    memcpy(out, value + 1, copy_len);
    out[copy_len] = '\0';

    return (ssize_t) copy_len;
}


int
json_get_string_array(const char *json, size_t json_len, const char *key,
    char out[][256], int max_items)
{
    const char *end;
    const char *array_end;
    const char *cursor;
    int         count;

    if (max_items <= 0) {
        return 0;
    }

    end = json + json_len;
    cursor = json_find_key(json, end, key, &array_end);
    if (cursor == NULL || *cursor != '[') {
        return 0;
    }

    count = 0;
    cursor++;

    while (cursor < array_end && count < max_items) {
        cursor = json_skip_ws(cursor, array_end);
        if (cursor >= array_end || *cursor == ']') {
            break;
        }

        if (*cursor == '"') {
            const char *string_start;
            const char *string_end;
            size_t      copy_len;

            string_start = cursor + 1;
            string_end = json_string_end(string_start, array_end);
            if (string_end == NULL) {
                break;
            }

            copy_len = (size_t) (string_end - string_start);
            if (copy_len > 255) {
                copy_len = 255;
            }

            memcpy(out[count], string_start, copy_len);
            out[count][copy_len] = '\0';
            count++;
            cursor = string_end + 1;
        } else {
            cursor = json_skip_value(cursor, array_end);
            if (cursor == NULL) {
                break;
            }
        }

        cursor = json_skip_ws(cursor, array_end);
        if (cursor < array_end && *cursor == ',') {
            cursor++;
        }
    }

    return count;
}


int
json_get_int64(const char *json, size_t json_len, const char *key,
    int64_t *out)
{
    char        numbuf[32];
    char       *parse_end;
    const char *end;
    const char *value;
    const char *value_end;
    size_t      value_len;

    end = json + json_len;
    value = json_find_key(json, end, key, &value_end);
    if (value == NULL) {
        return -1;
    }
    if (*value != '-' && (*value < '0' || *value > '9')) {
        return -1;
    }

    value_len = (size_t) (value_end - value);
    if (value_len >= sizeof(numbuf)) {
        return -1;
    }

    memcpy(numbuf, value, value_len);
    numbuf[value_len] = '\0';

    *out = strtoll(numbuf, &parse_end, 10);
    return (*parse_end == '\0') ? 0 : -1;
}
