/* metalink_unit.c — unit tests for the phase-100 metalink parser: v4/v3
 * dialects, ranking, entity decoding, digest folding, and the hostile-input
 * hard caps (scheme policy, URL/document size, mirror-count eviction).
 *
 * Build+run (from client/): part of `make test` (CLIENT_UNIT_TESTS). */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "brix.h"
#include "xfer/metalink.h"

static const char V4_DOC[] =
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
    "<metalink xmlns=\"urn:ietf:params:xml:ns:metalink\">\n"
    "  <file name=\"data.bin\">\n"
    "    <size>1048576</size>\n"
    "    <hash type=\"sha-256\">deadbeef00deadbeef00deadbeef00dd</hash>\n"
    "    <hash type=\"md5\">0123456789ABCDEF0123456789abcdef</hash>\n"
    "    <url priority=\"2\">root://mirror-b.example:1094//data.bin</url>\n"
    "    <url priority=\"1\">root://mirror-a.example:1094//data.bin?tok=1&amp;x=2</url>\n"
    "    <url>https://mirror-c.example:8443/data.bin</url>\n"
    "  </file>\n"
    "</metalink>\n";

static const char V3_DOC[] =
    "<metalink version=\"3.0\" xmlns=\"http://www.metalinker.org/\">\n"
    " <files>\n"
    "  <file name=\"data.bin\">\n"
    "   <verification><hash type=\"md5\">ffffffffffffffffffffffffffffffff</hash>"
    "</verification>\n"
    "   <resources>\n"
    "    <url type=\"root\" preference=\"50\">root://slow.example:1094//d</url>\n"
    "    <url type=\"root\" preference=\"100\">root://fast.example:1094//d</url>\n"
    "   </resources>\n"
    "  </file>\n"
    " </files>\n"
    "</metalink>\n";


static void test_v4_parse_success(void)          /* success */
{
    brix_metalink ml;
    brix_status st;

    brix_status_clear(&st);
    assert(brix_metalink_parse(V4_DOC, sizeof(V4_DOC) - 1, &ml, &st) == 0);
    assert(ml.n_urls == 3);
    /* priority 1 sorts first; the &amp; entity decodes to '&'. */
    assert(strcmp(ml.urls[0].rank_url,
                  "root://mirror-a.example:1094//data.bin?tok=1&x=2") == 0);
    assert(strcmp(ml.urls[1].rank_url,
                  "root://mirror-b.example:1094//data.bin") == 0);
    /* no-priority mirror ranks after every explicit one */
    assert(strncmp(ml.urls[2].rank_url, "https://mirror-c", 16) == 0);
    assert(ml.size == 1048576);
    /* sha-256 is unsupported; md5 wins and is lowercased */
    assert(strcmp(ml.hash_algo, "md5") == 0);
    assert(strcmp(ml.hash_hex, "0123456789abcdef0123456789abcdef") == 0);
}


static void test_v3_parse_success(void)          /* success */
{
    brix_metalink ml;
    brix_status st;

    brix_status_clear(&st);
    assert(brix_metalink_parse(V3_DOC, sizeof(V3_DOC) - 1, &ml, &st) == 0);
    assert(ml.n_urls == 2);
    /* preference 100 beats 50 (descending scale mapped to ascending rank) */
    assert(strcmp(ml.urls[0].rank_url, "root://fast.example:1094//d") == 0);
    assert(strcmp(ml.urls[1].rank_url, "root://slow.example:1094//d") == 0);
    assert(strcmp(ml.hash_algo, "md5") == 0);
}


static void test_suffix_detection(void)          /* success */
{
    assert(brix_metalink_is_name("/a/b/file.meta4") == 1);
    assert(brix_metalink_is_name("root://h:1/f.METALINK") == 1);
    assert(brix_metalink_is_name("root://h:1//f.meta4?xrd.k=v") == 1);
    assert(brix_metalink_is_name("/a/b/file.metal") == 0);
    assert(brix_metalink_is_name("/a/b/meta4") == 0);      /* no dot */
    assert(brix_metalink_is_name("plain.bin") == 0);
    assert(brix_metalink_is_name(NULL) == 0);
}


static void test_malformed_documents(void)       /* error */
{
    brix_metalink ml;
    brix_status st;
    static const char no_file[] = "<metalink></metalink>";
    static const char not_ml[]  = "<html><body>404</body></html>";
    static const char no_urls[] =
        "<metalink><file name=\"x\"><size>5</size></file></metalink>";

    brix_status_clear(&st);
    assert(brix_metalink_parse("", 0, &ml, &st) == -1);
    assert(brix_metalink_parse(not_ml, sizeof(not_ml) - 1, &ml, &st) == -1);
    assert(brix_metalink_parse(no_file, sizeof(no_file) - 1, &ml, &st) == -1);
    assert(brix_metalink_parse(no_urls, sizeof(no_urls) - 1, &ml, &st) == -1);
    assert(st.kxr == XRDC_EPROTO);
}


static void test_oversized_document_refused(void) /* security-neg */
{
    brix_metalink ml;
    brix_status st;
    size_t big = XRDC_METALINK_MAX_BYTES + 1;
    char *doc = (char *) malloc(big);

    assert(doc != NULL);
    memset(doc, 'a', big);
    brix_status_clear(&st);
    assert(brix_metalink_parse(doc, big, &ml, &st) == -1);
    free(doc);
}


static void test_local_and_unknown_schemes_skipped(void) /* security-neg */
{
    brix_metalink ml;
    brix_status st;
    static const char doc[] =
        "<metalink><file name=\"x\">"
        "<url priority=\"1\">file:///etc/passwd</url>"
        "<url priority=\"2\">/etc/shadow</url>"
        "<url priority=\"3\">s3://bucket/key</url>"
        "<url priority=\"4\">gopher://old.example/x</url>"
        "</file></metalink>";
    static const char mixed[] =
        "<metalink><file name=\"x\">"
        "<url priority=\"1\">file:///etc/passwd</url>"
        "<url priority=\"2\">root://ok.example:1094//f</url>"
        "</file></metalink>";

    /* Only hostile schemes: the parse FAILS (no usable mirrors) and reports
     * every candidate as skipped — the copy never runs. */
    brix_status_clear(&st);
    assert(brix_metalink_parse(doc, sizeof(doc) - 1, &ml, &st) == -1);
    assert(ml.n_urls == 0);
    assert(ml.n_skipped == 4);

    /* Mixed: the hostile mirror is dropped, the legit one survives. */
    assert(brix_metalink_parse(mixed, sizeof(mixed) - 1, &ml, &st) == 0);
    assert(ml.n_urls == 1);
    assert(ml.n_skipped == 1);
    assert(strcmp(ml.urls[0].rank_url, "root://ok.example:1094//f") == 0);
}


static void test_mirror_cap_keeps_best(void)     /* security-neg */
{
    brix_metalink ml;
    brix_status st;
    char doc[8192];
    size_t off = 0;
    int i;

    off += (size_t) snprintf(doc + off, sizeof(doc) - off,
                             "<metalink><file name=\"x\">");
    /* 20 mirrors at priority 50, then the BEST one (priority 1) listed last —
     * the eviction rule must keep it despite the 16-slot cap. */
    for (i = 0; i < 20; i++) {
        off += (size_t) snprintf(doc + off, sizeof(doc) - off,
                                 "<url priority=\"50\">root://m%02d.x:1094//f</url>", i);
    }
    off += (size_t) snprintf(doc + off, sizeof(doc) - off,
                             "<url priority=\"1\">root://best.x:1094//f</url>"
                             "</file></metalink>");

    brix_status_clear(&st);
    assert(brix_metalink_parse(doc, off, &ml, &st) == 0);
    assert(ml.n_urls == XRDC_METALINK_MAX_URLS);
    assert(ml.n_skipped == 5);   /* 21 candidates, 16 kept */
    assert(strcmp(ml.urls[0].rank_url, "root://best.x:1094//f") == 0);
}


static void test_bogus_digests_ignored(void)     /* security-neg */
{
    brix_metalink ml;
    brix_status st;
    static const char doc[] =
        "<metalink><file name=\"x\">"
        "<hash type=\"md5\">not-hex-at-all-zzzz</hash>"
        "<hash type=\"md5\">abcd</hash>"                    /* too short */
        "<hash type=\"sha-256\">0123456789abcdef0123456789abcdef</hash>"
        "<url priority=\"1\">root://ok.example:1094//f</url>"
        "</file></metalink>";

    brix_status_clear(&st);
    assert(brix_metalink_parse(doc, sizeof(doc) - 1, &ml, &st) == 0);
    assert(ml.hash_algo[0] == '\0');   /* nothing usable survived */
}


static void test_oversized_url_skipped(void)     /* security-neg */
{
    brix_metalink ml;
    brix_status st;
    char doc[8192];
    char long_url[4000];
    size_t off = 0;

    memset(long_url, 'a', sizeof(long_url) - 1);
    long_url[sizeof(long_url) - 1] = '\0';
    off += (size_t) snprintf(doc + off, sizeof(doc) - off,
                             "<metalink><file name=\"x\">"
                             "<url priority=\"1\">root://%s:1094//f</url>"
                             "<url priority=\"2\">root://ok.example:1094//f</url>"
                             "</file></metalink>", long_url);

    brix_status_clear(&st);
    assert(brix_metalink_parse(doc, off, &ml, &st) == 0);
    assert(ml.n_urls == 1);
    assert(ml.n_skipped == 1);
    assert(strcmp(ml.urls[0].rank_url, "root://ok.example:1094//f") == 0);
}


int
main(void)
{
    test_v4_parse_success();
    test_v3_parse_success();
    test_suffix_detection();
    test_malformed_documents();
    test_oversized_document_refused();
    test_local_and_unknown_schemes_skipped();
    test_mirror_cap_keeps_best();
    test_bogus_digests_ignored();
    test_oversized_url_skipped();
    printf("metalink_unit: ALL PASS\n");
    return 0;
}
