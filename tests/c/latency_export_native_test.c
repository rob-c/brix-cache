/* Render the actual latency exporter through a stdout-only writer boundary. */
#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include "observability/metrics/unified_export_io.c"

ngx_int_t
mw_printf(metrics_writer_t *writer, const char *format, ...)
{
    va_list arguments;
    int result;

    (void) writer;
    va_start(arguments, format);
    result = vprintf(format, arguments);
    va_end(arguments);
    assert(result >= 0);
    return NGX_OK;
}

int
main(int argc, char **argv)
{
    ngx_brix_metrics_t *metrics = calloc(1, sizeof(*metrics));
    unsigned long usec;
    unsigned long bucket;

    assert(argc == 3 && metrics != NULL);
    assert(BRIX_PPM_MULTIPLIER == 1000000);
    usec = strtoul(argv[1], NULL, 10);
    bucket = strtoul(argv[2], NULL, 10);
    assert(bucket < BRIX_IO_LATENCY_BUCKETS);
    metrics->unified.io_latency_bucket[BRIX_PROTO_ROOT][BRIX_METRIC_OP_READ][bucket] = 1;
    metrics->unified.io_latency_sum_usec[BRIX_PROTO_ROOT][BRIX_METRIC_OP_READ] = usec;
    metrics->unified.io_latency_count[BRIX_PROTO_ROOT][BRIX_METRIC_OP_READ] = 1;
    unified_emit_io_latency_series(NULL, metrics, BRIX_PROTO_ROOT, BRIX_METRIC_OP_READ);
    free(metrics);
    return 0;
}
