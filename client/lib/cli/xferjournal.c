/* xferjournal.c — batch-copy resume journal (see xferjournal.h). */
#include "cli/xferjournal.h"
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define JOURNAL_LINE_MAX 4096   /* longer lines are hostile/corrupt: skipped */

struct brix_journal {
    FILE            *fp;      /* append stream */
    pthread_mutex_t  lock;
    char           **done;    /* sorted array of completed sources */
    size_t           n, cap;
};

static int
cmp_str(const void *a, const void *b)
{
    return strcmp(*(const char *const *) a, *(const char *const *) b);
}

/* Append one strdup'd entry to j->done (unsorted; caller sorts). 0/-1. */
static int
done_append(brix_journal *j, const char *s)
{
    if (j->n == j->cap) {
        size_t nc = j->cap ? j->cap * 2 : 64;
        char **na = (char **) realloc(j->done, nc * sizeof(char *));
        if (na == NULL) { return -1; }
        j->done = na;
        j->cap = nc;
    }
    j->done[j->n] = strdup(s);
    if (j->done[j->n] == NULL) { return -1; }
    j->n++;
    return 0;
}

/* Load existing "ok <src>" lines; malformed/oversized lines are skipped
 * (a corrupt journal must degrade to "recopy", never to a crash). 0/-1. */
static int
journal_load(brix_journal *j, const char *path)
{
    FILE *f = fopen(path, "r");
    char  line[JOURNAL_LINE_MAX];

    if (f == NULL) {
        return 0;   /* no journal yet — nothing completed */
    }
    while (fgets(line, sizeof(line), f) != NULL) {
        size_t len = strlen(line);
        if (len > 0 && line[len - 1] != '\n' && !feof(f)) {
            int ch;                                   /* oversized: drain + skip */
            while ((ch = fgetc(f)) != EOF && ch != '\n') { }
            continue;
        }
        while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r')) {
            line[--len] = '\0';
        }
        if (strncmp(line, "ok ", 3) != 0 || line[3] == '\0') {
            continue;
        }
        if (done_append(j, line + 3) != 0) {
            fclose(f);
            return -1;
        }
    }
    fclose(f);
    if (j->n > 1) {
        qsort(j->done, j->n, sizeof(char *), cmp_str);
    }
    return 0;
}

brix_journal *
brix_journal_open(const char *path, brix_status *st)
{
    brix_journal *j = (brix_journal *) calloc(1, sizeof(*j));

    if (j == NULL) {
        brix_status_set(st, XRDC_EPROTO, 0, "journal: out of memory");
        return NULL;
    }
    if (journal_load(j, path) != 0) {
        brix_status_set(st, XRDC_EPROTO, 0, "journal: out of memory loading %s", path);
        brix_journal_close(j);
        return NULL;
    }
    j->fp = fopen(path, "a");
    if (j->fp == NULL) {
        brix_status_set(st, XRDC_ESOCK, errno, "journal: cannot open %s: %s",
                        path, strerror(errno));
        brix_journal_close(j);
        return NULL;
    }
    pthread_mutex_init(&j->lock, NULL);
    return j;
}

int
brix_journal_has(const brix_journal *j, const char *src)
{
    if (j == NULL || j->n == 0) {
        return 0;
    }
    return bsearch(&src, j->done, j->n, sizeof(char *), cmp_str) != NULL;
}

int
brix_journal_mark(brix_journal *j, const char *src)
{
    int rc;

    if (j == NULL || j->fp == NULL || src == NULL || src[0] == '\0'
        || strpbrk(src, "\n\r") != NULL || strlen(src) + 4 > JOURNAL_LINE_MAX) {
        return -1;   /* newline injection would forge entries — refuse */
    }
    pthread_mutex_lock(&j->lock);
    rc = (fprintf(j->fp, "ok %s\n", src) > 0 && fflush(j->fp) == 0) ? 0 : -1;
    pthread_mutex_unlock(&j->lock);
    return rc;
}

void
brix_journal_close(brix_journal *j)
{
    size_t i;

    if (j == NULL) {
        return;
    }
    if (j->fp != NULL) {
        fclose(j->fp);
        pthread_mutex_destroy(&j->lock);
    }
    for (i = 0; i < j->n; i++) { free(j->done[i]); }
    free(j->done);
    free(j);
}
