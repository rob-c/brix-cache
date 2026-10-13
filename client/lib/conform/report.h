/*
 * Phase-118 conformance report rendering contract.
 *
 * Requires: conform/run.h before use.
 */
#pragma once

#include "conform/run.h"

#include <stdio.h>

typedef struct {
    const char *target;
    const char *const *also_targets;
    size_t      also_target_count;
    const char *profile;
    const char *shape;
    const char *budget;
    const char *reference;
    const char *run_key;
    const char *timestamp;
    const char *tool_version;
    const char *const *negative_verify;
    size_t      negative_verify_count;
    int         negative_verify_passed;
    unsigned    requests;
    unsigned long long bytes;
    unsigned    request_limit;
    unsigned long long byte_limit;
    unsigned    wall_seconds;
} brix_conform_report_meta;

typedef struct {
    uint16_t       sid;
    uint16_t       code;
    const uint8_t *wire;
    uint32_t       wire_length;
} brix_conform_reproducer_frame;

void brix_conform_report_terminal(FILE *out,
    const brix_conform_report_meta *meta,
    const brix_conform_run_results *results);
int brix_conform_report_bundle(const char *out_dir,
    const brix_conform_report_meta *meta,
    const brix_conform_run_results *results, char *error, size_t error_size);
int brix_conform_capture_artifacts(const char *out_dir, const char *raw_capture,
    const brix_conform_run_results *results, char *error, size_t error_size);
int brix_conform_capture_reproducer(const char *out_dir, const char *clause_id,
    const brix_conform_reproducer_frame *frames, size_t frame_count,
    char *error, size_t error_size);
int brix_conform_capture_is_scrubbed(const char *path, char *error,
    size_t error_size);
