/* Offline success, error, and security-negative checks for xrd conform M1. */
#include "brix.h"
#include "conform/conform.h"
#include "conform/model.h"
#include "conform/run.h"
#include "conform/report.h"
#include "core/compat/crypto.h"

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static void
test_prf_and_random_access(void)
{
    brix_conform_key key;
    brix_conform_key parsed;
    uint8_t          data[33];
    char             hex[BRIX_CONFORM_KEY_SIZE * 2U + 1U];
    uint64_t         bad = 0;
    size_t           i;

    for (i = 0; i < sizeof(key.bytes); i++) key.bytes[i] = (uint8_t) i;
    brix_conform_key_format(&key, hex);
    assert(strcmp(hex, "000102030405060708090a0b0c0d0e0f") == 0);
    assert(brix_conform_key_parse(hex, &parsed) == 0);
    assert(memcmp(parsed.bytes, key.bytes, sizeof(key.bytes)) == 0);
    assert(brix_conform_key_parse("00010203", &parsed) == -1);
    assert(brix_conform_key_parse("000102030405060708090a0b0c0d0e0x", &parsed)
        == -1);
    assert(brix_conform_prf64(&key, UINT64_C(0x0706050403020100))
        == UINT64_C(0x93f5f5799a932462));
    brix_conform_fill(&key, 4093, data, sizeof(data));
    assert(brix_conform_verify(&key, 4093, data, sizeof(data), &bad) == 0);
    data[17] ^= 0x80U;
    assert(brix_conform_verify(&key, 4093, data, sizeof(data), &bad) == -1);
    assert(bad == 4110);
}

static void
test_expected_answers(void)
{
    brix_conform_read_answer answer;
    brix_conform_page_answer page;

    answer = brix_conform_read_expected(4097, 4096, 4096);
    assert(!answer.invalid && answer.expected_len == 1);
    answer = brix_conform_read_expected(4097, 4097, 1);
    assert(!answer.invalid && answer.expected_len == 0);
    answer = brix_conform_read_expected(4097, -1, 1);
    assert(answer.invalid);
    answer = brix_conform_read_expected(4097, 0, -1);
    assert(answer.invalid);

    page = brix_conform_page_expected(4095, 4098);
    assert(page.first_bytes == 1);
    assert(page.full_pages == 1);
    assert(page.last_bytes == 1);
    assert(page.units == 3);
    page = brix_conform_page_expected(0, 0);
    assert(page.units == 0);
}

static int
contains(const int64_t *values, size_t count, int64_t wanted)
{
    size_t i;

    for (i = 0; i < count; i++) {
        if (values[i] == wanted) return 1;
    }
    return 0;
}

static void
test_catalogue_axes_and_budgets(void)
{
    const brix_conform_object *objects;
    brix_conform_budget        budget;
    int64_t                    values[BRIX_CONFORM_AXIS_MAX];
    size_t                     count;
    size_t                     object_count;

    objects = brix_conform_objects(&object_count);
    assert(object_count == 12);
    assert(strcmp(objects[0].name, "Z") == 0 && objects[0].size == 0);
    assert(strcmp(objects[11].name, "L") == 0 && objects[11].large);

    count = brix_conform_offsets(4097, values, BRIX_CONFORM_AXIS_MAX);
    assert(count > 20 && contains(values, count, -1));
    assert(contains(values, count, 4096));
    assert(contains(values, count, 4097));
    assert(contains(values, count, 4098));
    assert(contains(values, count, INT64_MIN));

    count = brix_conform_lengths(4097, 4096, values,
        BRIX_CONFORM_AXIS_MAX);
    assert(contains(values, count, 0));
    assert(contains(values, count, 1));
    assert(contains(values, count, 2));
    assert(contains(values, count, -1));

    assert(brix_conform_budget_parse("pairwise", &budget) == 0);
    assert(budget == BRIX_CONFORM_PAIRWISE);
    assert(brix_conform_budget_parse("unknown", &budget) == -1);
    assert(brix_conform_case_selected(BRIX_CONFORM_EXHAUSTIVE,
        0, 12, 3, 30, 4, 20, 37, 91, 4097));
    assert(brix_conform_case_selected(BRIX_CONFORM_BOUNDARY,
        0, 12, 3, 30, 4, 20, 4095, 37, 4097));
    assert(!brix_conform_case_selected(BRIX_CONFORM_BOUNDARY,
        0, 12, 3, 30, 4, 20, 37, 91, 4097));
}

static void
test_option_and_limit_axes(void)
{
    uint64_t values[70];
    size_t   count;

    count = brix_conform_option_masks(UINT64_C(0x0b), values, 70);
    assert(count == 6);
    assert(values[0] == 0);
    assert(values[1] == 1 && values[2] == 2 && values[3] == 8);
    assert(values[4] == UINT64_C(0x0b));
    assert(values[5] == UINT64_C(0x0f));
    assert(brix_conform_option_masks(UINT64_MAX, values, 70) == 66);
    assert(brix_conform_option_masks(1, NULL, 0) == 3);

    count = brix_conform_limit_values(1024, values, 3);
    assert(count == 3 && values[0] == 1023 && values[1] == 1024
        && values[2] == 1025);
    assert(brix_conform_limit_values(0, values, 3) == 2);
    assert(brix_conform_limit_values(UINT64_MAX, values, 3) == 2);
    assert(brix_conform_limit_values(16, NULL, 0) == 3);
}

static void
test_page_shape_generator(void)
{
    brix_conform_page_case cases[BRIX_CONFORM_SHAPE_MAX];
    size_t exhaustive;
    size_t pairwise;
    size_t boundary;
    size_t i;

    exhaustive = brix_conform_page_cases(BRIX_CONFORM_EXHAUSTIVE, cases,
        BRIX_CONFORM_SHAPE_MAX);
    assert(exhaustive == 80);
    for (i = 0; i < exhaustive; i++) {
        brix_conform_page_answer answer = brix_conform_page_expected(
            cases[i].offset, cases[i].length);

        assert(cases[i].first_page_off < BRIX_CONFORM_PAGE_SIZE);
        assert(cases[i].last_page_bytes < BRIX_CONFORM_PAGE_SIZE);
        assert(answer.full_pages == cases[i].full_pages);
        assert(answer.last_bytes == cases[i].last_page_bytes);
    }
    pairwise = brix_conform_page_cases(BRIX_CONFORM_PAIRWISE, cases,
        BRIX_CONFORM_SHAPE_MAX);
    boundary = brix_conform_page_cases(BRIX_CONFORM_BOUNDARY, cases,
        BRIX_CONFORM_SHAPE_MAX);
    assert(pairwise < exhaustive && pairwise >= 20);
    assert(boundary < exhaustive && boundary > 0);
    assert(brix_conform_page_cases(BRIX_CONFORM_PAIRWISE, NULL, 0)
        == pairwise);
}

static int
vector_pair_seen(const brix_conform_vector_case *cases, size_t count,
    unsigned left, uint32_t left_value, unsigned right, uint32_t right_value)
{
    size_t i;

    for (i = 0; i < count; i++) {
        const uint32_t values[] = { cases[i].element_count,
            cases[i].element_size, cases[i].total_bytes,
            (uint32_t) cases[i].geometry, cases[i].handle_count };

        if (values[left] == left_value && values[right] == right_value) return 1;
    }
    return 0;
}

static void
test_vector_pairwise_generator(void)
{
    static const uint32_t axis0[] = { 0, 1, 2, 1023, 1024, 1025 };
    static const uint32_t axis1[] = { 0, 1, 4096, 2048, 2097136 };
    static const uint32_t axis2[] = { 2097135, 2097136, 2097137 };
    static const uint32_t axis3[] = { 0, 1, 2, 3, 4, 5, 6, 7, 8 };
    static const uint32_t axis4[] = { 1, 3, 2 };
    const uint32_t *axes[] = { axis0, axis1, axis2, axis3, axis4 };
    const size_t sizes[] = { 6, 5, 3, 9, 3 };
    brix_conform_vector_case cases[BRIX_CONFORM_SHAPE_MAX];
    size_t count;
    size_t left;

    count = brix_conform_vector_cases(BRIX_CONFORM_PAIRWISE, cases,
        BRIX_CONFORM_SHAPE_MAX);
    assert(count > 0 && count < 2430);
    for (left = 0; left < 5; left++) {
        size_t right;

        for (right = left + 1; right < 5; right++) {
            size_t li;

            for (li = 0; li < sizes[left]; li++) {
                size_t ri;

                for (ri = 0; ri < sizes[right]; ri++) {
                    assert(vector_pair_seen(cases, count, (unsigned) left,
                        axes[left][li], (unsigned) right, axes[right][ri]));
                }
            }
        }
    }
    assert(strcmp(brix_conform_vector_geometry_name(
        BRIX_CONFORM_VECTOR_EOF_STRADDLING), "eof-straddling") == 0);
    assert(strcmp(brix_conform_vector_geometry_name(
        (brix_conform_vector_geometry) 99), "unknown") == 0);
}

static void
test_http_range_generator(void)
{
    const brix_conform_http_range_case *cases;
    size_t count;
    size_t i;
    int invalid = 0;
    int over_limit = 0;

    cases = brix_conform_http_range_cases(BRIX_CONFORM_EXHAUSTIVE, &count);
    assert(count == 22);
    for (i = 0; i < count; i++) {
        invalid |= cases[i].kind == BRIX_CONFORM_HTTP_RANGE_INVALID;
        over_limit |= cases[i].kind == BRIX_CONFORM_HTTP_RANGE_OVER_LIMIT;
    }
    assert(invalid && over_limit);
    cases = brix_conform_http_range_cases(BRIX_CONFORM_BOUNDARY, &count);
    assert(count == 9);
    assert(strcmp(cases[0].expression, "bytes=0-0") == 0);
}

static void
test_clause_registry_and_vocabularies(void)
{
    const brix_conform_clause *clauses;
    const brix_conform_clause *row;
    size_t count;
    size_t index;

    clauses = brix_conform_clauses(&count);
    assert(clauses != NULL);
    assert(count == 527);
    assert(strcmp(clauses[0].id, "FRM-001") == 0);
    assert(strcmp(clauses[count - 1].id, "ADV-010") == 0);
    for (index = 0; index < count; index++) {
        assert(clauses[index].negative_fixture != NULL);
        assert(clauses[index].negative_fixture[0] != '\0');
        if (strncmp(clauses[index].text, "Retracted:", 10) != 0)
            assert(strncmp(clauses[index].negative_fixture,
                "not-applicable/", 15) != 0);
    }
    assert(strcmp(brix_conform_clause_find("ADV-007")->negative_fixture,
        "fault-proxy/hostile-input-liveness/ADV-007") == 0);
    assert(strcmp(brix_conform_clause_find("ADV-010")->negative_fixture,
        "fault-proxy/hostile-input-liveness/ADV-010") == 0);
    assert(strcmp(brix_conform_clause_find("PGR-027")->negative_fixture,
        "not-applicable/retracted/PGR-027") == 0);
    row = brix_conform_clause_find("PGR-019");
    assert(row != NULL);
    assert(strcmp(row->family, "PGR") == 0);
    assert((row->oracles & BRIX_CONFORM_ORACLE_O1) != 0);
    assert(row->probe_class == BRIX_CONFORM_PROBE_READ);
    assert(brix_conform_clause_find("OPN-001")->probe_class
        == BRIX_CONFORM_PROBE_READ);
    assert(brix_conform_clause_find("OPN-009")->probe_class
        == BRIX_CONFORM_PROBE_MUTATE);
    assert(brix_conform_clause_find("OPN-032")->probe_class
        == BRIX_CONFORM_PROBE_DISRUPT);
    assert(brix_conform_clause_find("HTC-001")->probe_class
        == BRIX_CONFORM_PROBE_MUTATE);
    assert(brix_conform_clause_find("DAV-001")->probe_class
        == BRIX_CONFORM_PROBE_READ);
    assert(brix_conform_clause_find("DAV-006")->probe_class
        == BRIX_CONFORM_PROBE_MUTATE);
    assert(brix_conform_clause_find("CAC-009")->probe_class
        == BRIX_CONFORM_PROBE_DISRUPT);
    assert(brix_conform_clause_find("PGR-999") == NULL);
    assert(strcmp(brix_conform_verdict_name(
        BRIX_CONFORM_VERDICT_INCONCLUSIVE), "inconclusive") == 0);
    assert(strcmp(brix_conform_reference_name(BRIX_CONFORM_REF_CONS),
        "cons") == 0);
    assert(strcmp(brix_conform_probe_class_name(
        BRIX_CONFORM_PROBE_MUTATE), "mutate") == 0);
}

static void
test_scope_and_scratch_security(void)
{
    const brix_conform_clause *read_clause;
    const brix_conform_clause *write_clause;
    const brix_conform_clause *disrupt_clause;
    brix_conform_run_config config;
    char reason[BRIX_CONFORM_REASON_MAX];
    char path[128];

    memset(&config, 0, sizeof(config));
    config.target = "root://localhost//data";
    config.profile = "full";
    read_clause = brix_conform_clause_find("RD-001");
    write_clause = brix_conform_clause_find("WRT-001");
    disrupt_clause = brix_conform_clause_find("ADV-001");
    assert(brix_conform_clause_selected(read_clause, &config, reason,
        sizeof(reason)) == 1);
    config.profile = "manager,http";
    assert(brix_conform_clause_selected(read_clause, &config, reason,
        sizeof(reason)) == 0);
    assert(brix_conform_clause_selected(brix_conform_clause_find("HTR-001"),
        &config, reason, sizeof(reason)) == 1);
    assert(brix_conform_clause_selected(brix_conform_clause_find("CMS-001"),
        &config, reason, sizeof(reason)) == 1);
    config.profile = "full";
    assert(brix_conform_clause_selected(write_clause, &config, reason,
        sizeof(reason)) == 0);
    assert(strcmp(reason, "no-scratch-prefix") == 0);
    write_clause = brix_conform_clause_find("OPN-009");
    assert(brix_conform_clause_selected(write_clause, &config, reason,
        sizeof(reason)) == 0);
    assert(strcmp(reason, "no-scratch-prefix") == 0);
    config.scratch = "/conform/run";
    config.allow_mutate = 1;
    assert(brix_conform_clause_selected(write_clause, &config, reason,
        sizeof(reason)) == 1);
    disrupt_clause = brix_conform_clause_find("OPN-032");
    config.allow_disrupt = 1;
    config.confirm_target = "root://other//data";
    assert(brix_conform_clause_selected(disrupt_clause, &config, reason,
        sizeof(reason)) == 0);
    config.confirm_target = config.target;
    assert(brix_conform_clause_selected(disrupt_clause, &config, reason,
        sizeof(reason)) == 1);
    disrupt_clause = brix_conform_clause_find("ADV-010");
    config.allow_mutate = 0;
    assert(brix_conform_clause_selected(disrupt_clause, &config, reason,
        sizeof(reason)) == 0);
    assert(strcmp(reason, "probe-class-disabled:mutate") == 0);
    config.allow_mutate = 1;
    config.scratch = NULL;
    assert(brix_conform_clause_selected(disrupt_clause, &config, reason,
        sizeof(reason)) == 0);
    assert(strcmp(reason, "no-scratch-prefix") == 0);
    config.scratch = "/conform/run";
    assert(brix_conform_clause_selected(disrupt_clause, &config, reason,
        sizeof(reason)) == 1);

    assert(brix_conform_scratch_path("/safe/root", "object.bin", path,
        sizeof(path)) == 0);
    assert(strcmp(path, "/safe/root/object.bin") == 0);
    assert(brix_conform_scratch_path("/safe/root", "../escape", path,
        sizeof(path)) == -1);
    assert(brix_conform_scratch_path("/safe/root", "a//b", path,
        sizeof(path)) == -1);
    assert(brix_conform_scratch_path("relative", "file", path,
        sizeof(path)) == -1);
    assert(brix_conform_scratch_control_path("/safe/root", "dir/a\nname", '\n',
        path, sizeof(path)) == 0);
    assert(strcmp(path, "/safe/root/dir/a\nname") == 0);
    assert(brix_conform_scratch_control_path("/safe/root", "dir/plain", '\n',
        path, sizeof(path)) == -1);
    assert(brix_conform_scratch_control_path("/safe/root", "../a\nname", '\n',
        path, sizeof(path)) == -1);
    assert(brix_conform_scratch_control_path("/safe/root", "dir/a\n\tname", '\n',
        path, sizeof(path)) == -1);
    assert(brix_conform_scratch_control_path("/safe/root", "bad\nparent/name", '\n',
        path, sizeof(path)) == -1);
}

static void
test_exit_policy(void)
{
    brix_conform_run_config config;
    brix_conform_result rows[4];
    brix_conform_run_results results;

    memset(&config, 0, sizeof(config));
    memset(rows, 0, sizeof(rows));
    memset(&results, 0, sizeof(results));
    rows[0].verdict = BRIX_CONFORM_VERDICT_CONFORMANT;
    rows[1].verdict = BRIX_CONFORM_VERDICT_SKIPPED;
    rows[2].verdict = BRIX_CONFORM_VERDICT_INCONCLUSIVE;
    rows[3].verdict = BRIX_CONFORM_VERDICT_CONFORMANT;
    results.results = rows;
    results.count = 4;
    brix_conform_run_results_count(&results);
    assert(results.conformant == 2 && results.skipped == 1
        && results.inconclusive == 1 && results.divergent == 0);
    config.fail_mode = BRIX_CONFORM_FAIL_DIVERGENT;
    assert(brix_conform_run_exit_code(&config, &results) == 0);
    config.fail_mode = BRIX_CONFORM_FAIL_ANY;
    assert(brix_conform_run_exit_code(&config, &results) == 2);
    rows[0].verdict = BRIX_CONFORM_VERDICT_DIVERGENT;
    brix_conform_run_results_count(&results);
    assert(brix_conform_run_exit_code(&config, &results) == 1);
}

static void
test_reference_projection(void)
{
    brix_conform_run_config config;
    brix_conform_result rows[3];
    brix_conform_run_results results;

    memset(&config, 0, sizeof(config));
    memset(rows, 0, sizeof(rows));
    memset(&results, 0, sizeof(results));
    rows[0].clause = brix_conform_clause_find("RDV-009");
    rows[0].verdict = BRIX_CONFORM_VERDICT_CONFORMANT;
    rows[1].clause = brix_conform_clause_find("RDV-010");
    rows[1].verdict = BRIX_CONFORM_VERDICT_DIVERGENT;
    rows[2].clause = brix_conform_clause_find("RD-001");
    rows[2].verdict = BRIX_CONFORM_VERDICT_CONFORMANT;
    results.results = rows;
    results.count = 3;
    config.reference_mode = BRIX_CONFORM_REFERENCE_BOTH;
    brix_conform_apply_reference_mode(&config, &results);
    assert(rows[0].ecosystem_verdict == BRIX_CONFORM_VERDICT_CONFORMANT);
    assert(rows[0].strict_verdict == BRIX_CONFORM_VERDICT_DIVERGENT);
    assert(rows[0].verdict == BRIX_CONFORM_VERDICT_DIVERGENT);
    assert(rows[1].strict_verdict == BRIX_CONFORM_VERDICT_INCONCLUSIVE);
    assert(rows[2].strict_verdict == BRIX_CONFORM_VERDICT_CONFORMANT);
    assert(strstr(rows[0].strict_reason, "de-facto-answer") != NULL);
}

/* WHAT: Read and close one report stream into bounded test storage.
 * WHY: Every output format must apply the same read-error and terminator checks.
 * HOW: Assert the stream, read at most capacity-1 bytes, terminate and close.
 */
static void
read_report_stream(FILE *stream, char *body, size_t capacity)
{
    size_t count;
    assert(stream != NULL && capacity > 0);
    count = fread(body, 1, capacity - 1, stream);
    assert(!ferror(stream));
    body[count] = '\0';
    assert(fclose(stream) == 0);
}

/* WHAT: Load one named bundle artifact through the common stream contract.
 * WHY: All report formats need identical bounds and open-failure handling.
 * HOW: Form a bounded path, open it, then delegate read/close ownership. */
static void
read_report_file(const char *directory, const char *name, char *body, size_t capacity)
{
    char path[256];
    int length = snprintf(path, sizeof(path), "%s/%s", directory, name);
    assert(length >= 0 && (size_t) length < sizeof(path));
    read_report_stream(fopen(path, "r"), body, capacity);
}

static void
test_report_bundle_and_symlink_refusal(void)
{
    brix_conform_result rows[2];
    brix_conform_run_results results;
    brix_conform_report_meta meta;
    char template[] = "/tmp/brix-conform-report.XXXXXX";
    char *dir;
    char path[256];
    char error[256];
    FILE *stream;
    char body[2048];

    memset(rows, 0, sizeof(rows));
    memset(&results, 0, sizeof(results));
    memset(&meta, 0, sizeof(meta));
    rows[0].clause = brix_conform_clause_find("RD-001");
    rows[0].verdict = BRIX_CONFORM_VERDICT_CONFORMANT;
    rows[0].changed = 1;
    rows[1].clause = brix_conform_clause_find("RD-002");
    rows[1].verdict = BRIX_CONFORM_VERDICT_SKIPPED;
    rows[1].changed = 1;
    snprintf(rows[1].reason, sizeof(rows[1].reason), "no-planted-object");
    results.results = rows;
    results.count = 2;
    brix_conform_run_results_count(&results);
    meta.target = "root://localhost//fixture";
    {
        static const char *const also[] = {
            "https://localhost/fixture", "s3://localhost/fixture"
        };

        meta.also_targets = also;
        meta.also_target_count = sizeof(also) / sizeof(also[0]);
    }
    meta.profile = "data";
    meta.shape = "accept";
    meta.budget = "boundary";
    meta.reference = "ecosystem";
    meta.run_key = "000102030405060708090a0b0c0d0e0f";
    meta.timestamp = "2026-10-04T00:00:00Z";
    meta.tool_version = "test-version";
    meta.requests = 7;
    meta.bytes = 4096;
    meta.request_limit = 100;
    meta.byte_limit = 65536;
    meta.wall_seconds = 30;
    dir = mkdtemp(template);
    assert(dir != NULL);
    assert(brix_conform_report_bundle(dir, &meta, &results, error,
        sizeof(error)) == 0);
    read_report_file(dir, "report.json", body, sizeof(body));
    assert(strstr(body, "\"schema\":\"brix.conform.v1\"") != NULL);
    assert(strstr(body, "\"tool_version\":\"test-version\"") != NULL);
    assert(strstr(body, "\"requests\":7,\"bytes\":4096") != NULL);
    assert(strstr(body, "\"targets\":[\"root://localhost//fixture\","
        "\"https://localhost/fixture\",\"s3://localhost/fixture\"]") != NULL);
    assert(strstr(body, "\"skipped\":1") != NULL);
    assert(strstr(body, "\"negative_fixture\":") != NULL);
    read_report_file(dir, "report.complete.json", body, sizeof(body));
    assert(strstr(body, "\"schema\":\"brix.conform.bundle.v1\"")
        != NULL);
    assert(strstr(body, "\"timestamp\":\"2026-10-04T00:00:00Z\"")
        != NULL);
    read_report_file(dir, "report.md", body, sizeof(body));
    assert(strstr(body, "- Also: https://localhost/fixture") != NULL);
    assert(strstr(body, "Negative fixture") != NULL);
    read_report_file(dir, "report.html", body, sizeof(body));
    assert(strstr(body, "<!doctype html>") != NULL);
    assert(strstr(body, "<th>Ecosystem</th><th>Strict</th>") != NULL);
    assert(strstr(body, "<th>Negative fixture</th>") != NULL);
    stream = tmpfile(); assert(stream != NULL);
    brix_conform_report_terminal(stream, &meta, &results);
    rewind(stream);
    read_report_stream(stream, body, sizeof(body));
    assert(strstr(body, "xrd conform also=s3://localhost/fixture") != NULL);
    snprintf(path, sizeof(path), "%s/report.json", dir);
    assert(brix_conform_apply_baseline(path, &results, error,
        sizeof(error)) == 0);
    brix_conform_run_results_count(&results);
    assert(results.baseline_applied == 1 && results.changed == 0);
    rows[0].verdict = BRIX_CONFORM_VERDICT_DIVERGENT;
    assert(brix_conform_apply_baseline(path, &results, error,
        sizeof(error)) == 0);
    brix_conform_run_results_count(&results);
    assert(results.changed == 1);

    snprintf(path, sizeof(path), "%s/report.json", dir);
    unlink(path);
    assert(symlink("/tmp/brix-conform-must-not-write", path) == 0);
    assert(brix_conform_report_bundle(dir, &meta, &results, error,
        sizeof(error)) == -1);
    snprintf(path, sizeof(path), "%s/report.complete.json", dir);
    assert(access(path, F_OK) != 0);
    snprintf(path, sizeof(path), "%s/report.json", dir);
    unlink(path);
    snprintf(path, sizeof(path), "%s/report.md", dir); unlink(path);
    snprintf(path, sizeof(path), "%s/report.html", dir); unlink(path);
    snprintf(path, sizeof(path), "%s/report.sarif", dir); unlink(path);
    snprintf(path, sizeof(path), "%s/report.ecs.jsonl", dir); unlink(path);
    snprintf(path, sizeof(path), "%s/report.diff.json", dir); unlink(path);
    assert(rmdir(dir) == 0);
}

static void
test_put_u16(FILE *stream, uint16_t value)
{
    fputc((int) (value >> 8), stream);
    fputc((int) (value & 0xffU), stream);
}

static void
test_put_u32(FILE *stream, uint32_t value)
{
    fputc((int) (value >> 24), stream);
    fputc((int) ((value >> 16) & 0xffU), stream);
    fputc((int) ((value >> 8) & 0xffU), stream);
    fputc((int) (value & 0xffU), stream);
}

static void
test_capture_frame(FILE *stream, int direction, int request, uint16_t sid,
    uint16_t code, const char *wire)
{
    size_t length = strlen(wire);

    fputc('F', stream); fputc(direction, stream); fputc(request, stream);
    test_put_u16(stream, sid); test_put_u16(stream, code);
    test_put_u32(stream, (uint32_t) length);
    assert(fwrite(wire, 1, length, stream) == length);
}

static void
test_capture_scrub_security(void)
{
    brix_conform_result row;
    brix_conform_run_results results;
    char template[] = "/tmp/brix-conform-cap.XXXXXX";
    char raw[256], scrubbed[256], error[256];
    char *dir = mkdtemp(template);
    FILE *stream;

    assert(dir != NULL);
    snprintf(raw, sizeof(raw), "%s/raw.xrdcap", dir);
    stream = fopen(raw, "wb");
    assert(stream != NULL);
    assert(fwrite("XRDCAP1\n", 1, 8, stream) == 8);
    fputc('M', stream); fputc(5, stream); fwrite("token", 1, 5, stream);
    test_put_u16(stream, 6); fwrite("secret", 1, 6, stream);
    test_capture_frame(stream, '>', 1, 7, kXR_auth, "credential-bytes");
    test_capture_frame(stream, '<', 0, 7, kXR_ok, "auth-response");
    test_capture_frame(stream, '>', 1, 8, kXR_read, "ordinary-read-frame");
    assert(fclose(stream) == 0);

    memset(&row, 0, sizeof(row));
    memset(&results, 0, sizeof(results));
    row.clause = brix_conform_clause_find("RD-001");
    row.verdict = BRIX_CONFORM_VERDICT_DIVERGENT;
    results.results = &row;
    results.count = 1;
    assert(brix_conform_capture_is_scrubbed(raw, error, sizeof(error)) == 0);
    assert(brix_conform_capture_artifacts(dir, raw, &results, error,
        sizeof(error)) == 0);
    snprintf(scrubbed, sizeof(scrubbed), "%s/RD-001.xrdcap", dir);
    assert(brix_conform_capture_is_scrubbed(scrubbed, error,
        sizeof(error)) == 1);
    errno = 0;
    assert(brix_conform_capture_artifacts(dir, raw, &results, error,
        sizeof(error)) == -1);
    assert(errno == EEXIST);
    assert(brix_conform_capture_is_scrubbed(scrubbed, error,
        sizeof(error)) == 1);
    stream = fopen(scrubbed, "rb");
    assert(stream != NULL);
    {
        char body[256];
        size_t got = fread(body, 1, sizeof(body), stream);

        assert(memmem(body, got, "secret", 6) == NULL);
        assert(memmem(body, got, "credential", 10) == NULL);
        assert(memmem(body, got, "ordinary-read-frame", 19) != NULL);
    }
    fclose(stream);
    stream = fopen(raw, "wb");
    assert(stream != NULL);
    assert(fwrite("not-a-capture", 1, 13, stream) == 13);
    assert(fclose(stream) == 0);
    row.clause = brix_conform_clause_find("RD-002");
    errno = 0;
    assert(brix_conform_capture_artifacts(dir, raw, &results, error,
        sizeof(error)) == -1);
    assert(errno == EBADMSG);
    assert(strstr(error, strerror(EBADMSG)) != NULL);
    snprintf(scrubbed, sizeof(scrubbed), "%s/RD-002.xrdcap", dir);
    assert(access(scrubbed, F_OK) != 0);
    snprintf(scrubbed, sizeof(scrubbed), "%s/RD-001.xrdcap", dir);
    unlink(scrubbed); unlink(raw); assert(rmdir(dir) == 0);
}

static void
test_capture_reproducer_security(void)
{
    char template[] = "/tmp/brix-conform-repro.XXXXXX";
    char path[256], error[256];
    const uint8_t wire[] = { 0x61, 0x02, 0x0b, 0xd8 };
    brix_conform_reproducer_frame frame = {
        0x6102, 3032, wire, sizeof(wire)
    };
    char *dir = mkdtemp(template);

    assert(dir != NULL);
    assert(brix_conform_capture_reproducer(dir, "ADV-008", &frame, 1,
        error, sizeof(error)) == 0);
    snprintf(path, sizeof(path), "%s/ADV-008.xrdcap", dir);
    assert(brix_conform_capture_is_scrubbed(path, error, sizeof(error)) == 1);
    errno = 0;
    assert(brix_conform_capture_reproducer(dir, "ADV-008", &frame, 1,
        error, sizeof(error)) == -1);
    assert(errno == EEXIST);
    unlink(path);
    frame.code = kXR_auth;
    errno = 0;
    assert(brix_conform_capture_reproducer(dir, "ADV-008", &frame, 1,
        error, sizeof(error)) == -1);
    assert(access(path, F_OK) != 0);
    assert(rmdir(dir) == 0);
}

static void
test_s3_signing_lifecycle(void)
{
    char headers[2048];
    char query[4096];
    char repeated[4096];
    time_t instant = (time_t) 1700000000;

    brix_crypto_cleanup();
    assert(brix_crypto_init() == 1);
    assert(brix_crypto_init() == 1);
    assert(brix_s3_sign_v4("HEAD", "127.0.0.1:10065", "/bucket/object",
        "test-access-key", "test-secret-key", "us-east-1",
        "UNSIGNED-PAYLOAD", headers, sizeof(headers)) == 0);
    assert(strstr(headers, "Authorization: AWS4-HMAC-SHA256 ") != NULL);
    assert(strstr(headers,
        "x-amz-content-sha256: UNSIGNED-PAYLOAD\r\n") != NULL);
    assert(brix_s3_presign_v4_at("GET", "127.0.0.1:10065",
        "/bucket/object", "test-access-key", "test-secret-key", "us-east-1",
        instant, 300, query, sizeof(query)) == 0);
    assert(strstr(query, "X-Amz-Algorithm=AWS4-HMAC-SHA256&") == query);
    assert(strstr(query, "X-Amz-Expires=300&X-Amz-SignedHeaders=host&")
        != NULL);
    assert(strstr(query, "&X-Amz-Signature=") != NULL);
    assert(brix_s3_presign_v4_at("GET", "127.0.0.1:10065",
        "/bucket/object", "test-access-key", "test-secret-key", "us-east-1",
        instant, 300, repeated, sizeof(repeated)) == 0);
    assert(strcmp(query, repeated) == 0);
    assert(brix_s3_presign_v4_at("GET", "127.0.0.1:10065",
        "/bucket/object", "test-access-key", "test-secret-key", "us-east-1",
        instant, 0, query, sizeof(query)) != 0);
    assert(brix_s3_presign_v4_at("GET", "127.0.0.1:10065",
        "/bucket/object", "test-access-key", "test-secret-key", "us-east-1",
        instant, 604801, query, sizeof(query)) != 0);
    assert(brix_s3_presign_v4_at("GET", "127.0.0.1:10065",
        "/bucket/object", "test-access-key", "test-secret-key", "us-east-1",
        instant, 300, query, 16) != 0);
    brix_crypto_cleanup();
    assert(brix_s3_sign_v4("HEAD", "127.0.0.1:10065", "/bucket/object",
        "test-access-key", "test-secret-key", "us-east-1",
        "UNSIGNED-PAYLOAD", headers, sizeof(headers)) != 0);
}

static void
test_handle_query_argument_refusal(void)
{
    brix_conn connection;
    brix_file file;
    brix_status status;
    char output[8];

    memset(&connection, 0, sizeof(connection));
    memset(&file, 0, sizeof(file));
    brix_status_clear(&status);
    assert(brix_query_file(&connection, NULL, kXR_Qvisa, NULL, 0, output,
        sizeof(output), &status) == -1);
    assert(status.kxr == XRDC_EUSAGE);
    brix_status_clear(&status);
    assert(brix_query_file(&connection, &file, kXR_Qvisa, NULL, 1, output,
        sizeof(output), &status) == -1);
    assert(status.kxr == XRDC_EUSAGE);
#if SIZE_MAX > UINT32_MAX
    brix_status_clear(&status);
    assert(brix_query_file(&connection, &file, kXR_Qvisa, output,
        (size_t) UINT32_MAX + 1U, output, sizeof(output), &status) == -1);
    assert(status.kxr == XRDC_EUSAGE);
#endif
}

int
main(void)
{
    test_prf_and_random_access();
    test_expected_answers();
    test_catalogue_axes_and_budgets();
    test_option_and_limit_axes();
    test_page_shape_generator();
    test_vector_pairwise_generator();
    test_http_range_generator();
    test_clause_registry_and_vocabularies();
    test_scope_and_scratch_security();
    test_exit_policy();
    test_reference_projection();
    test_report_bundle_and_symlink_refusal();
    test_capture_scrub_security();
    test_capture_reproducer_security();
    test_s3_signing_lifecycle();
    test_handle_query_argument_refusal();
    return 0;
}
