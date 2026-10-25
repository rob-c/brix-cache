/*
 * Ordered metadata emission shared by the HTML and Markdown renderers.
 * Each renderer supplies its own unchanged text escaper and literal prefixes;
 * this module never interprets untrusted values as report markup.
 */
#include "conform/report_fields.h"

/* ---- Emit an ordered list of escaped metadata values ----
 * WHAT: Write each literal prefix followed by its format-specific escaped value.
 * WHY: Human-readable reports share ordering, but not markup or escaping rules.
 * HOW: 1. Walk the caller's fixed field list. 2. Emit prefixes. 3. Call its escaper.
 */
void
brix_conform_report_fields(FILE *out, const brix_conform_report_field *fields,
    size_t count, void (*emit_text)(FILE *, const char *))
{
    size_t index;

    for (index = 0; index < count; index++) {
        fputs(fields[index].prefix, out);
        emit_text(out, fields[index].value);
    }
}
