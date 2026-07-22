/*
 * post_policy_conditions.c - extracted concern
 * Phase-38 split of post_object.c; further split from post_policy.c;
 * behavior-identical. POST-policy condition evaluation + document validation.
 */
#include "s3_post_internal.h"


/*
 * WHAT: Convert a proleptic-Gregorian civil date (y, m, d) to a day count
 *       relative to the Unix epoch (1970-01-01 == 0).
 * WHY:  Policy expiry must be compared against ngx_time() without depending on
 *       the host timezone, so we compute a UTC epoch directly rather than via
 *       mktime() (which is local-time and not async-signal-safe).
 * HOW:  Howard Hinnant's well-known days_from_civil algorithm. It shifts the
 *       year so March is month 1 (Feb's leap day lands at year-end), groups
 *       years into 400-year "eras" (each exactly 146097 days), then offsets by
 *       719468 to re-anchor era day 0 onto the Unix epoch. Constants are exact,
 *       not approximations. Reference: howardhinnant.github.io/date_algorithms.html
 * Returns signed days since 1970-01-01 (negative for pre-epoch dates).
 */
int64_t
s3_post_days_from_civil(int y, unsigned m, unsigned d)
{
    int64_t   era;
    unsigned  yoe, doy, doe;
    int       mp;

    y -= m <= 2;                                /* Jan/Feb count to prior year */
    era = (y >= 0 ? y : y - 399) / 400;         /* 400-year era index */
    yoe = (unsigned) (y - era * 400);           /* year-of-era [0, 399] */
    mp = (int) m + (m > 2 ? -3 : 9);            /* month, March=0 .. Feb=11 */
    doy = (153 * (unsigned) mp + 2) / 5 + d - 1;/* day-of-year, March 1 == 0 */
    doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;/* day-of-era [0, 146096] */

    return era * 146097 + (int64_t) doe - 719468;
}


/*
 * WHAT: Parse an ISO 8601 UTC timestamp "YYYY-MM-DDTHH:MM:SSZ" to a time_t.
 * WHY:  POST policy "expiration" is given in this exact UTC form; we need it as
 *       an epoch seconds value to compare against ngx_time(). HOW: strict
 *       sscanf with field widths, range-check each component (se <= 60 allows a
 *       leap second), then combine the civil-day count with the time-of-day.
 * Returns NGX_OK with *out set, or NGX_ERROR on a malformed/out-of-range value.
 */
ngx_int_t
s3_post_parse_iso8601(const char *s, time_t *out)
{
    int y, mo, d, h, mi, se;

    if (sscanf(s, "%4d-%2d-%2dT%2d:%2d:%2dZ",
               &y, &mo, &d, &h, &mi, &se) != 6)
    {
        return NGX_ERROR;
    }

    if (y < 1970 || mo < 1 || mo > 12 || d < 1 || d > 31
        || h < 0 || h > 23 || mi < 0 || mi > 59 || se < 0 || se > 60)
    {
        return NGX_ERROR;
    }

    /* epoch = (whole days since 1970) * 86400 + seconds within the day. */
    *out = (time_t) (s3_post_days_from_civil(y, (unsigned) mo, (unsigned) d)
                     * 86400 + h * 3600 + mi * 60 + se);
    return NGX_OK;
}


/*
 * WHAT: Exact-match a submitted field value against a policy-required value.
 * Returns NGX_OK on match, NGX_DECLINED on mismatch or a missing value.
 */
ngx_int_t
s3_post_check_field_eq(const char *actual, const char *expected)
{
    if (actual == NULL || expected == NULL || strcmp(actual, expected) != 0) {
        return NGX_DECLINED;
    }
    return NGX_OK;
}


/*
 * WHAT: Evaluate the object-form of a POST-policy condition
 *       {"field":"value", ...} — implicit "equals" for every key/value pair.
 * WHY:  The AWS object shape means every listed field must match exactly; the
 *       special "bucket" key is not a form field but the configured bucket name.
 * HOW:  Iterate each member, reject non-string values as malformed, compare
 *       "bucket" against cf->bucket and all other keys against the form value.
 * Returns NGX_OK if every pair matches, NGX_DECLINED on the first mismatch,
 * NGX_ERROR if a value is not a string (malformed condition).
 */
static ngx_int_t
s3_post_cond_object(ngx_http_s3_loc_conf_t *cf, const s3_post_form_t *form,
    json_t *cond)
{
    const char *key;
    json_t     *value;

    json_object_foreach(cond, key, value) {
        const char *expected;
        const char *actual;

        if (!json_is_string(value)) {
            return NGX_ERROR;
        }

        expected = json_string_value(value);
        /* "bucket" is not a form field — match the configured bucket name. */
        if (strcmp(key, "bucket") == 0) {
            if (cf->bucket.len != strlen(expected)
                || ngx_strncmp(cf->bucket.data, (u_char *) expected,
                               cf->bucket.len) != 0)
            {
                return NGX_DECLINED;
            }
            continue;
        }

        actual = s3_post_field_value(form, key);
        if (s3_post_check_field_eq(actual, expected) != NGX_OK) {
            return NGX_DECLINED;
        }
    }
    return NGX_OK;
}


/*
 * WHAT: Evaluate the content-length-range array condition
 *       ["content-length-range", min, max] against the uploaded file size.
 * WHY:  This is the only array operator whose arguments are integers; it bounds
 *       how large the uploaded body may be.
 * HOW:  Require exactly three integer-typed elements, then range-check
 *       form->file_len inclusively.
 * Returns NGX_OK if the size is within [min, max], NGX_DECLINED if outside,
 * NGX_ERROR if the argument shapes are malformed.
 */
static ngx_int_t
s3_post_cond_length_range(const s3_post_form_t *form, json_t *cond)
{
    json_int_t minv, maxv;

    if (json_array_size(cond) != 3
        || !json_is_integer(json_array_get(cond, 1))
        || !json_is_integer(json_array_get(cond, 2)))
    {
        return NGX_ERROR;
    }

    minv = json_integer_value(json_array_get(cond, 1));
    maxv = json_integer_value(json_array_get(cond, 2));
    if ((json_int_t) form->file_len < minv
        || (json_int_t) form->file_len > maxv)
    {
        return NGX_DECLINED;
    }
    return NGX_OK;
}


/*
 * WHAT: Evaluate a string-valued array condition ["op", field, value] where op
 *       is "eq" (exact match) or "starts-with" (prefix match).
 * WHY:  These two operators share identical argument shapes and differ only in
 *       the final comparison, so one helper covers both.
 * HOW:  Require three string-typed elements; resolve the form value; an absent
 *       field is a violation. For "eq" compare the whole string, for
 *       "starts-with" compare the expected-length prefix (empty value => any).
 * Returns NGX_OK if satisfied, NGX_DECLINED if violated, NGX_ERROR if the
 * argument shapes are malformed.
 */
static ngx_int_t
s3_post_cond_string_op(const s3_post_form_t *form, json_t *cond, const char *op)
{
    const char *field;
    const char *expected;
    const char *actual;

    if (json_array_size(cond) != 3
        || !json_is_string(json_array_get(cond, 1))
        || !json_is_string(json_array_get(cond, 2)))
    {
        return NGX_ERROR;
    }

    field = json_string_value(json_array_get(cond, 1));
    expected = json_string_value(json_array_get(cond, 2));
    actual = s3_post_field_value(form, field);

    if (actual == NULL) {
        return NGX_DECLINED;
    }

    if (strcmp(op, "eq") == 0) {
        return strcmp(actual, expected) == 0 ? NGX_OK : NGX_DECLINED;
    }

    return strncmp(actual, expected, strlen(expected)) == 0
           ? NGX_OK : NGX_DECLINED;
}


/*
 * Descriptor for one array-form operator: its literal name and the evaluator
 * that checks a condition of that operator. `wants_string_args` selects the
 * shared string-op evaluator (eq / starts-with) versus the integer-argument
 * content-length-range evaluator; both signatures are unified behind the
 * dispatcher below.
 */
typedef struct {
    const char *op;
    ngx_int_t (*eval)(const s3_post_form_t *form, json_t *cond, const char *op);
} s3_post_op_desc_t;


/*
 * WHAT: Thin adapter so content-length-range shares the operator-table signature.
 * WHY:  s3_post_cond_length_range takes no op string; the table's function
 *       pointer type passes one uniformly. HOW: ignore the op argument and
 *       forward to the range evaluator.
 * Returns whatever s3_post_cond_length_range returns.
 */
static ngx_int_t
s3_post_cond_length_range_adapter(const s3_post_form_t *form, json_t *cond,
    const char *op)
{
    (void) op;
    return s3_post_cond_length_range(form, cond);
}


/*
 * Array-form operator table (INVARIANT 6: S3 SigV4/policy logic, not shared with
 * token auth). Append-only; the dispatcher scans it linearly. "eq" and
 * "starts-with" share one evaluator, "content-length-range" its own adapter.
 */
static const s3_post_op_desc_t s3_post_ops[] = {
    { "eq",                   s3_post_cond_string_op },
    { "starts-with",          s3_post_cond_string_op },
    { "content-length-range", s3_post_cond_length_range_adapter },
};


/*
 * WHAT: Evaluate the array-form of a condition ["op", arg1, arg2].
 * WHY:  Element 0 names the comparison; the remaining elements are its operands.
 * HOW:  Require a string operator, then look it up in s3_post_ops and delegate
 *       to the matching evaluator.
 * Returns the evaluator's verdict, or NGX_ERROR if the operator is not a string
 * or is unknown.
 */
static ngx_int_t
s3_post_cond_array(const s3_post_form_t *form, json_t *cond)
{
    const char *op;
    ngx_uint_t  i;

    if (!json_is_string(json_array_get(cond, 0))) {
        return NGX_ERROR;
    }

    op = json_string_value(json_array_get(cond, 0));

    for (i = 0; i < sizeof(s3_post_ops) / sizeof(s3_post_ops[0]); i++) {
        if (strcmp(op, s3_post_ops[i].op) == 0) {
            return s3_post_ops[i].eval(form, cond, op);
        }
    }

    return NGX_ERROR;
}


/*
 * WHAT: Evaluate a single POST-policy condition against the submitted form.
 * WHY:  This is the access-control core: a signed policy lists conditions the
 *       upload must satisfy; if any fails the upload is rejected even though the
 *       signature is valid. Two JSON shapes occur (AWS spec):
 *         - Object  {"field":"value", ...}  : every field must equal exactly
 *           (the special "bucket" key is matched against the configured bucket).
 *         - Array   ["op", "field|$field", "value"] : op is "eq", "starts-with",
 *           or "content-length-range" (which bounds the file size).
 * HOW:  Dispatch on JSON type to the object-form or array-form evaluator.
 * Returns NGX_OK if the condition is satisfied, NGX_DECLINED if it is violated,
 * NGX_ERROR if the condition itself is malformed (unknown shape/op/types).
 */
ngx_int_t
s3_post_policy_condition(ngx_http_request_t *r, ngx_http_s3_loc_conf_t *cf,
    const s3_post_form_t *form, json_t *cond)
{
    (void) r;

    /* Object form: implicit "equals" for every key/value pair. */
    if (json_is_object(cond)) {
        return s3_post_cond_object(cf, form, cond);
    }

    /* Array form: ["op", arg1, arg2] — element 0 selects the comparison. */
    if (json_is_array(cond) && json_array_size(cond) >= 3) {
        return s3_post_cond_array(form, cond);
    }

    return NGX_ERROR;
}


/*
 * WHAT: Parse the base64-decoded POST policy JSON and enforce all of it.
 * WHY:  The policy document is what the signature actually covers; once the
 *       signature is verified we must (a) confirm the policy has not expired and
 *       (b) confirm every listed condition holds for this upload. The upload is
 *       only authorised if BOTH hold.
 * HOW:  Load JSON, check "expiration" against ngx_time(), then evaluate each
 *       entry of "conditions" via s3_post_policy_condition().
 * Ownership: `root` is jansson-refcounted; every early-return path json_decref()s
 *       it exactly once to avoid leaking the parse tree.
 * Returns NGX_OK (allow), NGX_DECLINED (expired or a condition failed -> 403),
 * NGX_ERROR (document malformed -> treated as invalid policy).
 */
ngx_int_t
s3_post_validate_policy_json(ngx_http_request_t *r,
    ngx_http_s3_loc_conf_t *cf, const s3_post_form_t *form,
    u_char *policy_json, size_t policy_len)
{
    json_error_t  jerr;
    json_t       *root;
    json_t       *expiration;
    json_t       *conditions;
    size_t        i;
    time_t        exp;

    root = json_loadb((const char *) policy_json, policy_len, 0, &jerr);
    if (root == NULL || !json_is_object(root)) {
        if (root != NULL) {
            json_decref(root);          /* decref only if a tree was built */
        }
        return NGX_ERROR;
    }

    /* "expiration" must be present, parseable, and not in the past. */
    expiration = json_object_get(root, "expiration");
    if (!json_is_string(expiration)
        || s3_post_parse_iso8601(json_string_value(expiration), &exp)
           != NGX_OK
        || ngx_time() > exp)
    {
        json_decref(root);
        return NGX_DECLINED;
    }

    conditions = json_object_get(root, "conditions");
    if (!json_is_array(conditions)) {
        json_decref(root);
        return NGX_ERROR;
    }

    /* Every condition must pass; the first non-OK result short-circuits and is
     * propagated (DECLINED = violated, ERROR = malformed condition). */
    for (i = 0; i < json_array_size(conditions); i++) {
        ngx_int_t rc;

        rc = s3_post_policy_condition(r, cf, form,
                                      json_array_get(conditions, i));
        if (rc != NGX_OK) {
            json_decref(root);
            return rc;
        }
    }

    json_decref(root);
    return NGX_OK;
}
