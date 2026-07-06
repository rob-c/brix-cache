/* xferjournal_unit.c — batch resume journal: load, lookup, append, hostile input. */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "brix.h"
#include "cli/xferjournal.h"

static const char *PATH = "/tmp/xferjournal_unit.journal";

/* JOURNAL_LINE_MAX is internal to xferjournal.c; mirror the same value here so
 * boundary tests stay in sync with the implementation constant. */
#define JOURNAL_LINE_MAX_MIRROR 4096

static void test_roundtrip(void)                 /* success */
{
    brix_status   st;
    brix_journal *j;
    unlink(PATH);
    brix_status_clear(&st);
    j = brix_journal_open(PATH, &st);
    assert(j != NULL);
    assert(brix_journal_has(j, "root://h//a") == 0);
    assert(brix_journal_mark(j, "root://h//a") == 0);
    brix_journal_close(j);
    j = brix_journal_open(PATH, &st);            /* reload: entry persisted */
    assert(j != NULL);
    assert(brix_journal_has(j, "root://h//a") == 1);
    assert(brix_journal_has(j, "root://h//b") == 0);
    brix_journal_close(j);
}

static void test_open_error(void)                /* error */
{
    brix_status st;
    brix_status_clear(&st);
    assert(brix_journal_open("/nonexistent-dir/x.journal", &st) == NULL);
    assert(st.msg[0] != '\0');
}

static void test_hostile_entries(void)           /* security-negative */
{
    brix_status   st;
    brix_journal *j;
    FILE         *f;
    unlink(PATH);
    /* Hand-craft a journal with a malformed + an oversized line: both must be
     * skipped without crashing, and valid lines around them still load. */
    f = fopen(PATH, "w");
    fprintf(f, "ok good1\n");
    fprintf(f, "garbage-no-prefix\n");
    fprintf(f, "ok ");
    for (int i = 0; i < 9000; i++) { fputc('x', f); }
    fprintf(f, "\nok good2\n");
    fclose(f);
    brix_status_clear(&st);
    j = brix_journal_open(PATH, &st);
    assert(j != NULL);
    assert(brix_journal_has(j, "good1") == 1);
    assert(brix_journal_has(j, "good2") == 1);
    assert(brix_journal_has(j, "garbage-no-prefix") == 0);
    /* Newline injection must be refused (would forge a second entry). */
    assert(brix_journal_mark(j, "evil\nok forged") == -1);
    brix_journal_close(j);
    j = brix_journal_open(PATH, &st);
    assert(brix_journal_has(j, "forged") == 0);
    brix_journal_close(j);
    unlink(PATH);
}

/* WHAT: verify the mark→close→open→has roundtrip at the maximum valid src length,
 *       and that one byte longer is refused before touching the file.
 * WHY:  "ok <src>\n" must fit in journal_load's fgets buffer (JOURNAL_LINE_MAX
 *       bytes).  Max src = JOURNAL_LINE_MAX-5 chars (line = JOURNAL_LINE_MAX-1
 *       chars including '\n', which is the most fgets can deliver in one call).
 *       One byte longer (JOURNAL_LINE_MAX-4 chars) produces a JOURNAL_LINE_MAX-char
 *       line whose '\n' is left in the stream, causing load() to misread it as
 *       oversized — the mark() check must reject it before writing.
 * HOW:  build strings of exactly the two boundary lengths, exercise both paths. */
static void test_boundary(void)
{
    brix_status   st;
    brix_journal *j;
    /* Max valid src: JOURNAL_LINE_MAX - 5 chars
     * ("ok " + src + "\n" = JOURNAL_LINE_MAX - 1 chars, fits in buffer). */
    const size_t  max_len = JOURNAL_LINE_MAX_MIRROR - 5;
    const size_t  too_len = JOURNAL_LINE_MAX_MIRROR - 4;
    char         *max_src = malloc(max_len + 1);
    char         *too_src = malloc(too_len + 1);
    assert(max_src != NULL && too_src != NULL);
    memset(max_src, 'a', max_len);  max_src[max_len] = '\0';
    memset(too_src, 'b', too_len);  too_src[too_len] = '\0';

    unlink(PATH);
    brix_status_clear(&st);
    j = brix_journal_open(PATH, &st);
    assert(j != NULL);
    /* At exactly the boundary: mark() accepts, entry survives reload. */
    assert(brix_journal_mark(j, max_src) == 0);
    /* One char over: mark() refuses (line would overflow the load buffer). */
    assert(brix_journal_mark(j, too_src) == -1);
    brix_journal_close(j);

    j = brix_journal_open(PATH, &st);
    assert(j != NULL);
    assert(brix_journal_has(j, max_src) == 1);  /* survives reload */
    assert(brix_journal_has(j, too_src) == 0);  /* was never written */
    brix_journal_close(j);
    unlink(PATH);
    free(max_src);
    free(too_src);
}

int main(void)
{
    test_roundtrip();
    test_open_error();
    test_hostile_entries();
    test_boundary();
    printf("xferjournal_unit: ALL PASS\n");
    return 0;
}
