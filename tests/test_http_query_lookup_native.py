"""Singleton value and presence checks share exactly one ambiguity rule."""

import subprocess

import pytest

from test_platform_linux_native import native_compile
from cmdscripts.object_unit_layout import NGX_SRC


@pytest.fixture(scope="module")
def query_lookup_driver(native_compile):
    """Compile the real lookup implementation and nginx's string comparator."""
    strings = NGX_SRC / "src/core/ngx_string.c"
    assert strings.is_file(), f"selected SDK lacks {strings}"
    return native_compile("query-singleton", _DRIVER,
                          ["src/core/http/http_query_parsed.c", str(strings)],
                          ["-ffunction-sections", "-fdata-sections",
                           "-Wl,--gc-sections"])


@pytest.mark.parametrize("case", ["success", "error", "negative"])
def test_singleton_lookup_and_presence_contract(query_lookup_driver, case):
    """Valid singleton, invalid state and duplicate routing retain their verdicts."""
    result = subprocess.run([str(query_lookup_driver), case], capture_output=True,
                            text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr


_DRIVER = r'''
#include "core/http/http_query.h"
#include <assert.h>
#include <string.h>

int main(int argc, char **argv)
{
    brix_http_query_param_t parameters[2] = {
        { .name = ngx_string("mode"), .value = ngx_string("read"), .has_value = 1 },
        { .name = ngx_string("MODE"), .value = ngx_string("write"), .has_value = 1 },
    };
    brix_http_query_t query = { .params = parameters, .count = 1, .parsed = 1 };
    ngx_str_t value = ngx_string("stale");
    assert(argc == 2);
    if (strcmp(argv[1], "success") == 0) {
        assert(brix_http_query_parsed_value(&query, "mode", &value, 0) == 1);
        assert(value.len == 4 && memcmp(value.data, "read", 4) == 0);
        assert(brix_http_query_parsed_has(&query, "mode", BRIX_HTTP_QUERY_HAS_VALUE_OK) == 1);
        assert(brix_http_query_parsed_has(&query, "absent", 0) == 0);
    } else if (strcmp(argv[1], "error") == 0) {
        query.parsed = 0;
        assert(brix_http_query_parsed_value(&query, "mode", &value, 0) == -1);
        assert(brix_http_query_parsed_has(&query, "mode", 0) == -1);
        query.parsed = 1;
        assert(brix_http_query_parsed_value(&query, "mode", NULL, 0) == -1);
        assert(brix_http_query_parsed_has(&query, NULL, 0) == -1);
    } else {
        unsigned flags = BRIX_HTTP_QUERY_CASE_INSENSITIVE;
        assert(strcmp(argv[1], "negative") == 0);
        query.count = 2;
        assert(brix_http_query_parsed_value(&query, "mode", &value, flags) == BRIX_HTTP_QUERY_DUPLICATE);
        assert(value.data == NULL && value.len == 0);
        assert(brix_http_query_parsed_has(&query, "mode", flags) == BRIX_HTTP_QUERY_DUPLICATE);
        parameters[1].name = parameters[0].name;
        assert(brix_http_query_parsed_has(&query, "mode", 0) == BRIX_HTTP_QUERY_DUPLICATE);
    }
    return 0;
}
'''
