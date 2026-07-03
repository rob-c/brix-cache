/*
 * ssi_service_unittest.c — standalone unit test for the SSI service registry +
 * built-in handlers, driven through a recording responder.
 *
 *   gcc -Wall -Wextra -Werror -I src -o /tmp/ssi_service_ut \
 *       src/ssi/ssi_service_unittest.c src/ssi/ssi_service.c && /tmp/ssi_service_ut
 */

#include "ssi_service.h"

#include <stdio.h>
#include <string.h>

static int g_fail;
#define CHECK(cond) do { \
    if (!(cond)) { printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
                   g_fail++; } \
} while (0)

/* recording responder */typedef struct {
    unsigned char md[256];   size_t md_len;   int md_set;
    unsigned char data[256]; size_t data_len; int last; int resp_set;
    int err_code; const char *err_text; int err_set;
} rec_t;

static void rec_md(brix_ssi_responder_t *r, const unsigned char *md, size_t n)
{ rec_t *x = r->state; memcpy(x->md, md, n); x->md_len = n; x->md_set = 1; }
static void rec_resp(brix_ssi_responder_t *r, const unsigned char *b, size_t n, int last)
{ rec_t *x = r->state; memcpy(x->data + x->data_len, b, n); x->data_len += n;
  x->last = last; x->resp_set = 1; }
static void rec_alert(brix_ssi_responder_t *r, const unsigned char *b, size_t n)
{ (void) r; (void) b; (void) n; }
static void rec_err(brix_ssi_responder_t *r, int code, const char *t)
{ rec_t *x = r->state; x->err_code = code; x->err_text = t; x->err_set = 1; }

static brix_ssi_responder_t
make_responder(rec_t *rec)
{
    brix_ssi_responder_t r;
    memset(rec, 0, sizeof(*rec));
    r.set_metadata = rec_md;
    r.set_response = rec_resp;
    r.alert        = rec_alert;
    r.error        = rec_err;
    r.state        = rec;
    return r;
}

static void
test_echo_service(void)
{
    brix_ssi_process_fn fn = brix_ssi_service_lookup("echo");
    CHECK(fn != NULL);
    if (!fn) return;

    rec_t rec;
    brix_ssi_responder_t r = make_responder(&rec);
    int rc = fn((const unsigned char *) "hello", 5, &r);
    CHECK(rc == 0);
    CHECK(rec.resp_set);
    CHECK(rec.last == 1);                       /* unary: final chunk */
    CHECK(rec.data_len == 5 && memcmp(rec.data, "hello", 5) == 0);
}

static void
test_unknown_service(void)
{
    CHECK(brix_ssi_service_lookup("nope") == NULL);
}

int
main(void)
{
    test_echo_service();
    test_unknown_service();
    if (g_fail) { printf("%d check(s) FAILED\n", g_fail); return 1; }
    printf("all ssi_service checks passed\n");
    return 0;
}
