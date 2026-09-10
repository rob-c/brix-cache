/*
 * cta_queue.c — CTA request-queue state machine. See cta_queue.h.
 */

#include "cta_queue.h"
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/*
 * Journal record grammar sizes. A field's escaped form is at most twice its
 * source (every byte escapable), so these are derived from the struct widths
 * rather than guessed: owner[64] -> 127+NUL, req.path[1024] -> 2047+NUL. The
 * line buffer holds a whole worst-case record — three numeric fields, four
 * tabs, both escaped fields and the newline — with room to spare, because a
 * line that does NOT fit is precisely the case the replay path must be able to
 * recognise and discard whole.
 */
#define CTA_JOURNAL_OWNER_ESC   128
#define CTA_JOURNAL_PATH_ESC    2048
#define CTA_JOURNAL_LINE_MAX    4096

/*
 * Escape one text field into the journal's record grammar.
 *
 * WHAT: copies `in` to `out`, replacing the two bytes the grammar reserves —
 *       tab (field separator) and newline (record separator) — and the escape
 *       byte itself with two-character sequences.
 *
 * WHY:  SECURITY. `req.path` is `Notification.file.lpath` straight off the
 *       wire, up to 1023 bytes chosen by whoever submitted the request. Written
 *       raw, a path containing a newline FORGES A SECOND RECORD, and replay
 *       believes it — including its `owner` field, which is the principal
 *       cta_queue_cancel() checks. A submitter could therefore plant a queue
 *       entry owned by somebody else, or restate a real id under a different
 *       owner, and the forgery only takes effect after a restart, where nobody
 *       is watching the request that planted it. A tab is the same attack one
 *       field narrower: it shifts every later field left. `owner` is escaped
 *       too — it is an identity string rather than a wire field, but a grammar
 *       that holds only for the fields we currently believe are safe is not a
 *       grammar.
 *
 * HOW:  '\\' -> "\\\\", '\t' -> "\\t", '\n' -> "\\n", '\r' -> "\\r"; every other
 *       byte verbatim. Returns 0, or -1 when the escaped form does not fit —
 *       the caller then writes NO record, because a truncated one re-parses as
 *       a different (and attacker-chosen) record rather than as an error.
 */
static int
journal_escape(const char *in, char *out, size_t cap)
{
    size_t o = 0;
    size_t i;

    for (i = 0; in[i] != '\0'; i++) {
        char esc = 0;

        switch (in[i]) {
        case '\\': esc = '\\'; break;
        case '\t': esc = 't';  break;
        case '\n': esc = 'n';  break;
        case '\r': esc = 'r';  break;
        default:   break;
        }
        if (esc == 0) {
            if (o + 1 >= cap) { return -1; }
            out[o++] = in[i];
            continue;
        }
        if (o + 2 >= cap) { return -1; }
        out[o++] = '\\';
        out[o++] = esc;
    }
    out[o] = '\0';
    return 0;
}


/*
 * The exact inverse of journal_escape, bounded by `cap`.
 *
 * An UNKNOWN escape ("\\x") yields 'x' and a trailing lone '\\' is dropped:
 * replay reads a file an operator may have hand-edited and an attacker may have
 * reached through the hole this pair of functions closes, so a malformed input
 * must produce a harmless field — never a parse that resynchronises onto
 * attacker-chosen bytes, and never a write past `out`.
 */
static void
journal_unescape(const char *in, char *out, size_t cap)
{
    size_t o = 0;
    size_t i;

    for (i = 0; in[i] != '\0' && o + 1 < cap; i++) {
        char c = in[i];

        if (c != '\\') {
            out[o++] = c;
            continue;
        }
        if (in[i + 1] == '\0') {
            break;              /* trailing lone escape: drop it */
        }
        i++;
        switch (in[i]) {
        case 't': out[o++] = '\t'; break;
        case 'n': out[o++] = '\n'; break;
        case 'r': out[o++] = '\r'; break;
        default:  out[o++] = in[i]; break;
        }
    }
    out[o] = '\0';
}


/*
 * True when `line` (as returned by fgets) is a WHOLE record.
 *
 * A record whose escaped form still exceeds the line buffer cannot be a record
 * this code wrote, so it is either corruption or a hand edit. fgets would hand
 * back its head and then its tail as if the tail were a record of its own —
 * letting a long field resynchronise the parser onto bytes chosen by whoever
 * supplied it. Draining to the next newline denies that: the whole line is
 * discarded, or nothing is. A final line with no newline is complete (EOF),
 * not truncated.
 */
static int
journal_line_whole(FILE *f, const char *line)
{
    int c;

    if (strchr(line, '\n') != NULL || feof(f)) {
        return 1;
    }
    while ((c = fgetc(f)) != EOF && c != '\n') {
        /* discard the remainder of the over-long line */
    }
    return 0;
}


/* Append one entry's current state to the journal (tab-delimited record). */
/*
 * Append one entry's current state to the journal, as ONE record.
 *
 * The record is built whole and emitted with a SINGLE write(2) on an O_APPEND
 * descriptor, rather than with fprintf + fflush. That is not a style choice:
 * every worker inherits this one descriptor from the master, so the journal is
 * written concurrently by the whole worker set, and only a single append of a
 * complete record keeps two workers' records from interleaving into a third
 * record that neither wrote. stdio promises no such thing about where its
 * buffer boundaries fall.
 */
static void
journal_append(brix_cta_queue_t *q, const cta_req_t *e)
{
    char    rec[CTA_JOURNAL_LINE_MAX];
    char    owner[CTA_JOURNAL_OWNER_ESC];
    char    path[CTA_JOURNAL_PATH_ESC];
    ssize_t written;
    int     n;

    if (q->journal_fd < 0) {
        return;
    }
    if (journal_escape(e->owner, owner, sizeof(owner)) != 0
        || journal_escape(e->req.path, path, sizeof(path)) != 0)
    {
        return;   /* see journal_escape: never write a truncated record */
    }
    n = snprintf(rec, sizeof(rec), "%llu\t%d\t%d\t%s\t%s\n",
                 (unsigned long long) e->id, (int) e->req.op, (int) e->state,
                 owner, path);
    if (n <= 0 || (size_t) n >= sizeof(rec)) {
        return;   /* same rule as a field that will not fit */
    }
    /* Best-effort journal: a failed write only degrades crash-replay fidelity;
     * the in-memory queue stays authoritative, so there is no error to
     * propagate from an append. */
    written = write(q->journal_fd, rec, (size_t) n);
    (void) written;
}

/* Legal transitions, table-driven. A request may advance SUBMITTED→QUEUED→ACTIVE
 * →COMPLETE, fail from ACTIVE, or be cancelled from any non-terminal state. */
static int
transition_ok(cta_state_t from, cta_state_t to)
{
    switch (from) {
    case CTA_ST_SUBMITTED:
        return to == CTA_ST_QUEUED || to == CTA_ST_CANCELED;
    case CTA_ST_QUEUED:
        return to == CTA_ST_ACTIVE || to == CTA_ST_CANCELED ||
               to == CTA_ST_FAILED;
    case CTA_ST_ACTIVE:
        return to == CTA_ST_COMPLETE || to == CTA_ST_FAILED ||
               to == CTA_ST_CANCELED;
    case CTA_ST_COMPLETE:
    case CTA_ST_FAILED:
    case CTA_ST_CANCELED:
        return 0;   /* terminal */
    }
    return 0;
}

static int
is_terminal(cta_state_t s)
{
    return s == CTA_ST_COMPLETE || s == CTA_ST_FAILED || s == CTA_ST_CANCELED;
}

void
cta_queue_init(brix_cta_queue_t *q)
{
    memset(q, 0, sizeof(*q));
    q->next_id = 1;
    q->journal_fd = -1;
}


brix_cta_queue_t *
cta_queue_create(void)
{
    brix_cta_queue_t *q = malloc(sizeof(*q));
    if (q != NULL) {
        cta_queue_init(q);
    }
    return q;
}

void
cta_queue_destroy(brix_cta_queue_t *q)
{
    if (q != NULL && q->journal_fd >= 0) {
        /* Teardown path: every append was a single unbuffered write, so a
         * close error carries no unwritten data and there is no caller to
         * report it to. */
        (void) close(q->journal_fd);
    }
    free(q);
}

/* Find an existing slot for id, or claim a free one (replay only). */
static cta_req_t *
replay_slot(brix_cta_queue_t *q, uint64_t id)
{
    int i, free_slot = -1;

    for (i = 0; i < CTA_QUEUE_MAX; i++) {
        if (q->slots[i].in_use && q->slots[i].id == id) {
            return &q->slots[i];
        }
        if (!q->slots[i].in_use && free_slot < 0) {
            free_slot = i;
        }
    }
    if (free_slot < 0) {
        return NULL;
    }
    memset(&q->slots[free_slot], 0, sizeof(q->slots[free_slot]));
    q->slots[free_slot].in_use = 1;
    q->slots[free_slot].id     = id;
    return &q->slots[free_slot];
}

int
cta_queue_open_journal(brix_cta_queue_t *q, const char *path)
{
    FILE *f = fopen(path, "r");   /* replay cursor, separate from the append fd */
    char  line[CTA_JOURNAL_LINE_MAX];
    int   fd;

    while (f != NULL && fgets(line, sizeof(line), f) != NULL) {
        unsigned long long id;
        int        op = 0, state = 0;
        char       owner_esc[CTA_JOURNAL_OWNER_ESC] = "";
        char       path_esc[CTA_JOURNAL_PATH_ESC] = "";
        char       owner[64] = "", pathbuf[1024] = "";
        cta_req_t *e;

        if (!journal_line_whole(f, line)) {
            continue;   /* over-long: see journal_line_whole */
        }
        /* "id\top\tstate\towner\tpath" — the text fields are escaped
         * (journal_escape), so a raw tab or newline can no longer occur INSIDE
         * one and this split stays exact. Either may be empty, in which case
         * its conversion fails harmlessly and the "" initialiser stands. */
        if (sscanf(line, "%llu\t%d\t%d\t%127[^\t]\t%2047[^\n]",
                   &id, &op, &state, owner_esc, path_esc) < 3) {
            continue;   /* need at least id/op/state */
        }
        journal_unescape(owner_esc, owner, sizeof(owner));
        journal_unescape(path_esc, pathbuf, sizeof(pathbuf));

        e = replay_slot(q, (uint64_t) id);
        if (e == NULL) {
            break;
        }
        e->req.op = (cta_op_t) op;
        e->state  = (cta_state_t) state;
        snprintf(e->owner, sizeof(e->owner), "%s", owner);
        snprintf(e->req.path, sizeof(e->req.path), "%s", pathbuf);
        if ((uint64_t) id >= q->next_id) {
            q->next_id = (uint64_t) id + 1;
        }
    }
    if (f != NULL) {
        fclose(f);
    }
    /*
     * The append descriptor. Opened here — which, for the shared queue, means
     * in the MASTER during zone init, before fork — so every worker inherits
     * this same open file description and its shared O_APPEND offset. One
     * journal, one cursor, no per-worker files to reconcile on replay.
     */
    fd = open(path, O_WRONLY | O_CREAT | O_APPEND, 0600);
    if (fd < 0) {
        return -1;
    }
    q->journal_fd = fd;
    return 0;
}

cta_req_t *
cta_queue_submit(brix_cta_queue_t *q, const cta_request_t *r, const char *owner)
{
    int i;

    for (i = 0; i < CTA_QUEUE_MAX; i++) {
        if (!q->slots[i].in_use) {
            cta_req_t *e = &q->slots[i];
            memset(e, 0, sizeof(*e));
            e->req    = *r;
            e->state  = CTA_ST_SUBMITTED;
            e->id     = q->next_id++;
            e->in_use = 1;
            if (owner != NULL) {
                size_t n = strlen(owner);
                if (n >= sizeof(e->owner)) {
                    n = sizeof(e->owner) - 1;
                }
                memcpy(e->owner, owner, n);
                e->owner[n] = '\0';
            }
            journal_append(q, e);
            return e;
        }
    }
    return NULL;   /* full */
}

cta_req_t *
cta_queue_find(brix_cta_queue_t *q, uint64_t id)
{
    int i;

    for (i = 0; i < CTA_QUEUE_MAX; i++) {
        if (q->slots[i].in_use && q->slots[i].id == id) {
            return &q->slots[i];
        }
    }
    return NULL;
}

int
cta_queue_transition(brix_cta_queue_t *q, cta_req_t *e, cta_state_t to)
{
    if (!transition_ok(e->state, to)) {
        return -1;
    }
    e->state = to;
    journal_append(q, e);
    return 0;
}

int
cta_queue_cancel(brix_cta_queue_t *q, uint64_t id, const char *requester,
                 int is_admin)
{
    cta_req_t *e = cta_queue_find(q, id);

    if (e == NULL) {
        return CTA_QUEUE_ENOENT;
    }
    if (!is_admin && (requester == NULL || strcmp(requester, e->owner) != 0)) {
        return CTA_QUEUE_EACCES;
    }
    return cta_queue_transition(q, e, CTA_ST_CANCELED);
}

int
cta_queue_active_count(const brix_cta_queue_t *q)
{
    int i, n = 0;

    for (i = 0; i < CTA_QUEUE_MAX; i++) {
        if (q->slots[i].in_use && !is_terminal(q->slots[i].state)) {
            n++;
        }
    }
    return n;
}
