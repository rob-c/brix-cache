"""Verify native latency recording and Prometheus export without a server."""

import math
import re
import subprocess

import pytest

from test_platform_linux_native import native_compile


@pytest.fixture(scope='module')
def latency_binary(native_compile):
    """Compile actual tables, recorder and exporter; adapt only SHM and output."""
    return native_compile('io-latency', r'''
#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include "observability/metrics/unified_export_io.c"

ngx_shm_zone_t *brix_metrics_get_shm_zone(void) {
    static ngx_shm_zone_t zone;
    return &zone;
}

ngx_int_t mw_printf(metrics_writer_t *writer, const char *format, ...) {
    va_list arguments;
    (void)writer;
    va_start(arguments, format);
    int length = vprintf(format, arguments);
    va_end(arguments);
    return length >= 0 ? NGX_OK : NGX_ERROR;
}

int main(int argc, char **argv) {
    assert(argc == 2);
    ngx_brix_metrics_t *metrics = calloc(1, sizeof(*metrics));
    metrics_writer_t writer = {0};
    ngx_shm_zone_t *zone = brix_metrics_get_shm_zone();
    assert(metrics != NULL);
    zone->data = metrics;
    if (strcmp(argv[1], "observed") == 0) {
        const ngx_msec_t samples[] = {0, 1000, 1001, 5000, 1000000, 5000001};
        for (size_t index = 0; index < sizeof(samples) / sizeof(samples[0]); index++) {
            brix_metric_op_latency(BRIX_PROTO_ROOT, BRIX_METRIC_OP_READ,
                                   samples[index]);
        }
    } else if (strcmp(argv[1], "detached") == 0) {
        zone->data = NULL;
        brix_metric_op_latency(BRIX_PROTO_ROOT, BRIX_METRIC_OP_READ, 1000);
        zone->data = (void *)1;
        brix_metric_op_latency(BRIX_PROTO_ROOT, BRIX_METRIC_OP_READ, 1000);
    } else {
        brix_metric_op_latency(BRIX_PROTO_COUNT, BRIX_METRIC_OP_READ, 1000);
        brix_metric_op_latency(BRIX_PROTO_ROOT, BRIX_METRIC_OP_COUNT, 1000);
    }
    unified_emit_io_latency_series(&writer, metrics, BRIX_PROTO_ROOT,
                                   BRIX_METRIC_OP_READ);
    free(metrics);
    zone->data = NULL;
    return 0;
}
''', ['src/observability/metrics/unified.c',
      'src/observability/metrics/unified_record.c'],
        ['-ffunction-sections', '-fdata-sections', '-Wl,--gc-sections'])


def _assert_histogram(output, samples):
    """Check the established bounds, cumulative counts and seconds-valued sum."""
    buckets = re.findall(r'_bucket\{[^\n]*le="([^"]+)"\} ([0-9]+)', output)
    limits = [float(limit) for limit, _ in buckets]
    assert limits == [.001, .005, .01, .05, .1, .5, 1, 5, math.inf]
    counts = [int(count) for _, count in buckets]
    assert counts == _cumulative_counts(samples, limits)
    _assert_histogram_totals(output, samples, counts[-1])


def _cumulative_counts(samples, limits):
    """Reference each bucket against all observations at or below its bound."""
    return [sum(sample <= limit for sample in samples) for limit in limits]


def _assert_histogram_totals(output, samples, infinite_count):
    """The infinite bucket equals the count, and the sum is in seconds."""
    count = re.search(r'_count\{[^\n]+\} ([0-9]+)', output)
    total = re.search(r'_sum\{[^\n]+\} ([0-9.]+)', output)
    assert count and int(count[1]) == len(samples) == infinite_count
    assert total and float(total[1]) == pytest.approx(sum(samples))


@pytest.mark.parametrize('case', ['observed', 'detached', 'invalid-index'])
def test_io_latency_histogram(latency_binary, case):
    """Render real observations; missing SHM and invalid indexes add no samples."""
    result = subprocess.run([str(latency_binary), case], capture_output=True,
                            text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr
    samples = [0, .001, .001001, .005, 1, 5.000001] if case == 'observed' else []
    _assert_histogram(result.stdout, samples)
