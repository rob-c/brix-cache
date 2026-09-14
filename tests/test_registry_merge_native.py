"""Native checks for registry declarations/state and CMS parser merge repairs.

Use BRIX_NGINX_BUILD_DIR=build/alma9-merged with pytest --noconftest. The shared
compiler fixture links production functions against configured nginx headers;
unused nginx runtime sections are discarded, so these checks start no fleet.
"""

import os
from pathlib import Path
import subprocess

import pytest

from test_platform_linux_native import native_compile  # shared SDK fixture


@pytest.fixture(scope='module')
def policy_binary(native_compile):
    """Compile the real registry owner and its read-only policy accessor."""
    return native_compile('registry-policy', r'''
#include <assert.h>
#include <stddef.h>
#include <string.h>
#include "net/manager/registry_internal.h"
int main(int argc, char **argv) {
    assert(argc == 2);
    assert(brix_srv_state()->registry_nslots == BRIX_SRV_REGISTRY_SLOTS);
    assert(offsetof(brix_srv_table_t, lock) == 0);
    assert(sizeof(((brix_srv_entry_t *)0)->paths) == BRIX_SRV_MAX_PATHS);
    assert(sizeof(brix_srv_snapshot_entry_t) > 0);
    assert(brix_srv_get_shm_zone() == NULL);
    assert(brix_srv_get_mutex() != NULL);
    assert(brix_srv_get_mutex() == brix_srv_get_mutex());
    brix_srv_set_stale_after(2500);
    brix_srv_set_registry_slots(256);
    assert(brix_srv_state()->stale_after_ms == 2500);
    assert(brix_srv_state()->registry_nslots == 256);
    if (strcmp(argv[1], "reset") == 0) {
        brix_srv_sched_t schedule = {.cpu = 10, .io = 20};
        brix_srv_space_t space = {.enforce = 1, .hwm_mb = 128};
        brix_srv_set_sched(&schedule);
        brix_srv_set_space(&space);
        brix_srv_set_sched(NULL);
        brix_srv_set_space(NULL);
        brix_srv_set_stale_after(0);
        assert(brix_srv_state()->sched.cpu == 0);
        assert(brix_srv_state()->sched.io == 0);
        assert(brix_srv_state()->space.enforce == 0);
        assert(brix_srv_state()->space.hwm_mb == 0);
        assert(brix_srv_state()->stale_after_ms == 0);
    } else if (strcmp(argv[1], "oversized") == 0) {
        brix_srv_sched_t schedule = {.cpu = (ngx_uint_t)-1, .fuzz = 101};
        brix_srv_set_sched(&schedule);
        brix_srv_set_load_weight((ngx_uint_t)-1);
        assert(brix_srv_state()->sched.cpu == 100);
        assert(brix_srv_state()->sched.fuzz == 100);
        assert(brix_srv_state()->load_weight == 100);
    }
    return 0;
}
''', ['src/net/manager/registry.c', 'src/net/manager/registry_policy.c'],
        ['-ffunction-sections', '-fdata-sections', '-Wl,--gc-sections'])


def _run(executable, case):
    """Retain native assertion failures in pytest diagnostics."""
    result = subprocess.run([str(executable), case], capture_output=True,
                            text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize('case', ['set', 'reset', 'oversized'])
def test_registry_policy_contract(policy_binary, case):
    """Keep state updates, reset behavior, and out-of-range clamping intact."""
    _run(policy_binary, case)


@pytest.fixture(scope='module')
def parser_binary(native_compile):
    """Compile the CMS percentage parser whose renamed bound was undefined."""
    return native_compile('cms-perf-parser', r'''
#include <assert.h>
#include "net/cms/perf_pgm.c"
int main(int argc, char **argv) {
    assert(argc == 2);
    uint8_t values[5] = {7, 7, 7, 7, 7};
    const char *line;
    if (strcmp(argv[1], "success") == 0) {
        line = "10 20 30 40 1000";
        assert(perf_parse_line((const u_char *)line, strlen(line), values) == 0);
        assert(values[0] == 10 && values[1] == 20 && values[2] == 30);
        assert(values[3] == 40 && values[4] == 100);
    } else {
        line = strcmp(argv[1], "malformed") == 0 ? "x 0 0 0 0" :
            "9999999999999999999999999999999 0 0 0 0";
        assert(perf_parse_line((const u_char *)line, strlen(line), values) == -1);
        assert(values[0] == 7);
    }
    return 0;
}
''', extra=['-ffunction-sections', '-fdata-sections', '-Wl,--gc-sections'])


@pytest.mark.parametrize('case', ['success', 'malformed', 'overflow'])
def test_cms_percentage_bound(parser_binary, case):
    """Accept valid monitor values and reject malformed or excessive input."""
    _run(parser_binary, case)


@pytest.fixture(scope='module')
def location_binary(native_compile):
    """Exercise real location-cache expiry using a private in-memory table."""
    root = Path(__file__).resolve().parents[1]
    build = Path(os.environ.get('BRIX_NGINX_BUILD_DIR', root / 'build/alma9-merged')).resolve()
    return native_compile('location-cache', r'''
#include <assert.h>
#include "net/manager/loc_cache.c"
volatile ngx_msec_t ngx_current_msec = 1000;
/* This fixture has no threads; nginx's real string copier is linked below. */
void ngx_shmtx_lock(ngx_shmtx_t *mutex) { (void)mutex; }
void ngx_shmtx_unlock(ngx_shmtx_t *mutex) { (void)mutex; }
int main(int argc, char **argv) {
    assert(argc == 2);
    char host[256];
    uint16_t port = 0;
    assert(brix_loc_cache_lookup("/file", host, sizeof(host), &port) == 0);
    brix_loc_table_t *table = calloc(1, sizeof(*table));
    assert(table != NULL);
    ngx_shm_zone_t zone;
    memset(&zone, 0, sizeof(zone));
    zone.data = table;
    loc_cache_state.shm_zone = &zone;
    ngx_msec_t lifetime = BRIX_LOC_CACHE_TTL_MS;
    if (strcmp(argv[1], "override") == 0) {
        lifetime = 250;
        brix_loc_cache_set_ttl(lifetime);
    } else if (strcmp(argv[1], "invalid") == 0) {
        brix_loc_cache_set_ttl(0);
        brix_loc_cache_insert("/file", "", 1094);
        assert(brix_loc_cache_lookup("/file", host, sizeof(host), &port) == 0);
    }
    brix_loc_cache_insert("/file", "cache.fixture.invalid", 1094);
    assert(brix_loc_cache_lookup("/file", host, sizeof(host), &port) == 1);
    assert(strcmp(host, "cache.fixture.invalid") == 0 && port == 1094);
    ngx_current_msec += lifetime - 1;
    assert(brix_loc_cache_lookup("/file", host, sizeof(host), &port) == 1);
    ngx_current_msec++;
    assert(brix_loc_cache_lookup("/file", host, sizeof(host), &port) == 0);
    free(table);
    return 0;
}
''', extra=['-ffunction-sections', '-fdata-sections', '-Wl,--gc-sections',
            str(build / 'nginx-src/src/core/ngx_string.c')])


@pytest.mark.parametrize('case', ['default', 'override', 'invalid'])
def test_location_cache_lifetime(location_binary, case):
    """Retain the 30-second default, honor overrides, and reject empty hosts."""
    _run(location_binary, case)
