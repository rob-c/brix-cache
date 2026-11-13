/* Native URL parsers reject oversized authority/path inputs before transport. */
#include "brix.h"
#include <assert.h>

/* WHAT: Render one native parse. WHY: Keep boundary behavior observable.
 * HOW: Call the parser and print its bounded fields only after success. */
static void root_url(const char *text, int endpoint)
{
    brix_url out; brix_status status; brix_status_clear(&status);
    int rc = endpoint ? brix_endpoint_parse(text, &out, &status)
                      : brix_url_parse(text, &out, &status);
    printf("%d\n", rc);
    if (!rc) { printf("%s\n%d\n%s\n%s\n%d\n", out.host, out.port, out.path,
                      out.user, out.single_slash_path); }
    else { puts(status.msg); }
}

/* WHAT: Render a web parse. WHY: Preserve IPv6, TLS and object-store flags.
 * HOW: Parse the supplied value and expose each independent result. */
static void web_url(const char *text, int null_output)
{
    brix_weburl out;
    int rc = brix_weburl_parse(text, null_output ? NULL : &out); printf("%d\n", rc);
    if (!rc) { printf("%s\n%d\n%s\n%d\n%d\n", out.host, out.port, out.path,
                      out.tls, out.is_s3); }
}

/* WHAT: Render an FTP parse. WHY: Preserve authentication selection and path.
 * HOW: Parse one isolated value without creating any connection. */
static void ftp_url(const char *text, int null_output)
{
    brix_ftpurl out;
    int rc = brix_ftpurl_parse(text, null_output ? NULL : &out); printf("%d\n", rc);
    if (!rc) { printf("%s\n%d\n%s\n%d\n", out.host, out.port, out.path, out.gsi); }
}

/* WHAT: Dispatch a finite parser probe. WHY: Test null and oversized boundaries.
 * HOW: Select the public parser, or expose documented field capacities. */
int main(int argc, char **argv)
{
    assert(argc == 3); const char *text = !strcmp(argv[2], "<null>") ? NULL : argv[2];
    if (!strcmp(argv[1], "sizes")) {
        brix_url u; brix_weburl w; brix_ftpurl f;
        printf("%zu %zu %zu %zu %zu %zu %zu\n", sizeof(u.host), sizeof(u.path),
            sizeof(u.user), sizeof(w.host), sizeof(w.path), sizeof(f.host), sizeof(f.path));
    } else if (!strcmp(argv[1], "url")) { root_url(text, 0); }
    else if (!strcmp(argv[1], "endpoint")) { root_url(text, 1); }
    else if (!strncmp(argv[1], "web", 3)) { web_url(text, !strcmp(argv[1], "web-null")); }
    else if (!strncmp(argv[1], "ftp", 3)) { ftp_url(text, !strcmp(argv[1], "ftp-null")); }
    else {
        printf("%d %d %d\n", brix_is_web_url(text), brix_is_ftp_url(text), brix_is_block_url(text));
    }
    return 0;
}
