#include "../../src/token/json.h"
#include <stdio.h>
#include <string.h>

int main() {
    const char *json = "{\"foo\":\"bar\",\"num\":42}";
    const char *escaped_json = "{\"foo\":\"line\\nnext\",\"num\":-17,"
                               "\"wlcg.groups\":[\"/cms\",\"/atlas\\u002dprod\"]}";
    const char *groups_json = "{\"wlcg.groups\":[\"/cms\",\"/atlas\"]}";
    char out[16];
    char groups[2][256];
    int64_t num = 0;
    int group_count;
    if (json_get_string(json, strlen(json), "foo", out, sizeof(out)) < 0 || strcmp(out, "bar") != 0) {
        printf("json_get_string failed\n");
        return 1;
    }
    if (json_get_int64(json, strlen(json), "num", &num) != 0 || num != 42) {
        printf("json_get_int64 failed\n");
        return 1;
    }
    group_count = json_get_string_array(groups_json, strlen(groups_json), "wlcg.groups", groups, 2);
    if (group_count != 2 || strcmp(groups[0], "/cms") != 0 || strcmp(groups[1], "/atlas") != 0) {
        printf("json_get_string_array failed\n");
        return 1;
    }
    if (json_get_string(escaped_json, strlen(escaped_json), "foo", out, sizeof(out)) < 0) {
        printf("json_get_string escaped failed\n");
        return 1;
    }
    if (strcmp(json_backend_name(), "jansson") == 0) {
        if (strcmp(out, "line\nnext") != 0) {
            printf("jansson escaped string decode failed\n");
            return 1;
        }
    } else if (strcmp(out, "line\\nnext") != 0) {
        printf("fallback escaped string preservation failed\n");
        return 1;
    }
    if (json_get_int64(escaped_json, strlen(escaped_json), "num", &num) != 0 || num != -17) {
        printf("json_get_int64 negative failed\n");
        return 1;
    }
    group_count = json_get_string_array(escaped_json, strlen(escaped_json),
                                        "wlcg.groups", groups, 2);
    if (group_count != 2 || strcmp(groups[0], "/cms") != 0) {
        printf("json escaped array failed\n");
        return 1;
    }
    if (strcmp(json_backend_name(), "jansson") == 0
        && strcmp(groups[1], "/atlas-prod") != 0)
    {
        printf("jansson unicode array decode failed: %s\n", groups[1]);
        return 1;
    }
    printf("json helpers passed using %s\n", json_backend_name());
    return 0;
}
