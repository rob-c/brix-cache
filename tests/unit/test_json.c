#include "../../src/token/json.h"
#include <stdio.h>
#include <string.h>

int main() {
    const char *json = "{\"foo\":\"bar\",\"num\":42}";
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
    printf("json helpers passed\n");
    return 0;
}
