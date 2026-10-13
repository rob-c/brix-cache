/* Internal renderer contract shared only inside client/lib/conform. */
#pragma once

#include "conform/report.h"

void brix_conform_json_string(FILE *out, const char *value);
void brix_conform_report_json(FILE *out,
    const brix_conform_report_meta *meta,
    const brix_conform_run_results *results);
void brix_conform_report_sarif(FILE *out,
    const brix_conform_report_meta *meta,
    const brix_conform_run_results *results);
void brix_conform_report_ecs(FILE *out,
    const brix_conform_report_meta *meta,
    const brix_conform_run_results *results);
void brix_conform_report_diff_json(FILE *out,
    const brix_conform_report_meta *meta,
    const brix_conform_run_results *results);
void brix_conform_report_html(FILE *out,
    const brix_conform_report_meta *meta,
    const brix_conform_run_results *results);
