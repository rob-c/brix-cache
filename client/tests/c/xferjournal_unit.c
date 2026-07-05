/* xferjournal_unit.c — batch resume journal: load, lookup, append, hostile input. */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "brix.h"
#include "cli/xferjournal.h"

static const char *PATH = "/tmp/xferjournal_unit.journal";

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

int main(void)
{
    test_roundtrip();
    test_open_error();
    test_hostile_entries();
    printf("xferjournal_unit: ALL PASS\n");
    return 0;
}
