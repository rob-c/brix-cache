#ifndef BRIX_CLI_XFERJOURNAL_H
#define BRIX_CLI_XFERJOURNAL_H
#include "brix.h"

/* WHAT: persistent completion journal for batch copies (xrdcp --from/--resume).
 * WHY:  a 10k-file manifest killed at file 8k must resume without recopying;
 *       the journal records each completed source, one line: "ok <src>\n".
 * HOW:  loaded once into a qsort'ed array (bsearch lookups), appended+flushed
 *       under a mutex so -j worker threads can share one handle. */
typedef struct brix_journal brix_journal;

brix_journal *brix_journal_open(const char *path, brix_status *st);
int           brix_journal_has(const brix_journal *j, const char *src);
int           brix_journal_mark(brix_journal *j, const char *src);
void          brix_journal_close(brix_journal *j);

#endif
