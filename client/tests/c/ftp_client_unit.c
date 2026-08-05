/* ftp_client_unit.c — unit tests for the pure pieces of the gsiftp:// client.
 *
 * WHAT: exercises the three side-effect-free kernels the GridFTP engine is built
 *       on — URL recognition/parsing (client/lib/net/url.c), the data-channel
 *       address policy (client/lib/protocols/ftp/ftp_screen.c), and the RFC 2228
 *       ADAT/ENC base64 codec (client/lib/protocols/ftp/ftp_gsi_cred.c).
 * WHY:  the screen is a security control — it is what stops a hostile or
 *       compromised FTP server from turning xrdcp into an SSRF probe via the
 *       classic PASV bounce — and a security control that is only ever exercised
 *       through a live socket is a security control nobody tests. The URL parser
 *       decides which host a copy contacts at all, so its overflow and
 *       port-range rejections belong here too.
 * HOW:  no sockets, no servers: every function under test is pure, so each case
 *       is a direct call plus assert(). The live protocol behaviour (login,
 *       transfer, refusal of a bounced data channel) is covered end to end by
 *       tests/test_xrdcp_gsiftp.py.
 *
 * Build+run (from client/):
 *   cc -std=c11 -Wall -Ilib tests/c/ftp_client_unit.c \
 *       libbrix.a ../shared/xrdproto/libxrdproto.a -lssl -lcrypto -lz \
 *       -o bin/ftp_client_unit && ./bin/ftp_client_unit
 */
#include "protocols/ftp/ftp_client.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---- URL recognition + parsing: success ---------------------------------- */

/*
 * WHAT: gsiftp:// is recognised, defaults to the GridFTP control port 2811, and
 *       keeps its path verbatim.
 * WHY:  2811 is the registered GridFTP port; a wrong default silently dials the
 *       wrong service on every WLCG endpoint written without an explicit port.
 */
static void
test_parse_gsiftp_defaults(void)
{
    brix_ftpurl u;

    assert(brix_is_ftp_url("gsiftp://grid.example.org/data/file.root"));
    assert(brix_ftpurl_parse("gsiftp://grid.example.org/data/file.root", &u) == 0);
    assert(u.gsi == 1);
    assert(strcmp(u.host, "grid.example.org") == 0);
    assert(u.port == 2811);
    assert(strcmp(u.path, "/data/file.root") == 0);
    printf("  PASS  gsiftp:// defaults to port 2811\n");
}


/*
 * WHAT: plain ftp:// is a distinct scheme with port 21 and no GSI.
 * WHY:  the login router keys on u.gsi — mis-flagging ftp:// would make the
 *       client demand a proxy for an anonymous server (and vice versa, which
 *       would be a silent security downgrade).
 */
static void
test_parse_plain_ftp_defaults(void)
{
    brix_ftpurl u;

    assert(brix_is_ftp_url("ftp://mirror.example.org/pub/x.tar"));
    assert(brix_ftpurl_parse("ftp://mirror.example.org/pub/x.tar", &u) == 0);
    assert(u.gsi == 0);
    assert(u.port == 21);
    assert(strcmp(u.host, "mirror.example.org") == 0);
    printf("  PASS  ftp:// defaults to port 21, no GSI\n");
}


/*
 * WHAT: an explicit port wins, a missing path becomes "/", and the globus-style
 *       double slash ("//path" = absolute) collapses to one.
 * WHY:  globus-url-copy URLs in production are overwhelmingly written
 *       `gsiftp://host:2811//store/…`; the second slash is the "absolute path"
 *       marker, not part of the name.
 */
static void
test_parse_port_and_path_forms(void)
{
    brix_ftpurl u;

    assert(brix_ftpurl_parse("gsiftp://h.example:2812//store/atlas/x", &u) == 0);
    assert(u.port == 2812);
    assert(strcmp(u.path, "/store/atlas/x") == 0);

    assert(brix_ftpurl_parse("gsiftp://h.example:2812", &u) == 0);
    assert(strcmp(u.path, "/") == 0);
    printf("  PASS  explicit port, // collapse, empty path\n");
}


/* ---- URL parsing: error paths -------------------------------------------- */

/*
 * WHAT: a non-FTP scheme is neither recognised nor parsed.
 * WHY:  brix_copy() routes on brix_is_ftp_url(); a false positive would divert
 *       a root:// or local copy into the FTP engine.
 */
static void
test_reject_foreign_schemes(void)
{
    brix_ftpurl u;

    assert(!brix_is_ftp_url("root://srv//store/x"));
    assert(!brix_is_ftp_url("https://srv/x"));
    assert(!brix_is_ftp_url("/local/path"));
    assert(!brix_is_ftp_url(NULL));
    assert(brix_ftpurl_parse("root://srv//store/x", &u) != 0);
    printf("  PASS  foreign schemes rejected\n");
}


/*
 * WHAT: an out-of-range or non-numeric port is a parse failure, not a clamp.
 * WHY:  silently clamping "gsiftp://h:99999/x" to some other port would dial a
 *       service the user never named.
 */
static void
test_reject_bad_port(void)
{
    brix_ftpurl u;

    assert(brix_ftpurl_parse("gsiftp://h.example:0/x", &u) != 0);
    assert(brix_ftpurl_parse("gsiftp://h.example:99999/x", &u) != 0);
    assert(brix_ftpurl_parse("gsiftp://h.example:-1/x", &u) != 0);
    printf("  PASS  out-of-range ports rejected\n");
}


/*
 * WHAT: an over-long authority or path is rejected outright.
 * WHY:  the parse writes into fixed-size fields; rejecting (rather than
 *       truncating) keeps a long name from being silently rewritten into a
 *       different, valid one.
 */
static void
test_reject_overflow(void)
{
    char        big[8192];
    brix_ftpurl u;

    memset(big, 'a', sizeof(big) - 1);
    big[sizeof(big) - 1] = '\0';

    {
        char url[8300];
        snprintf(url, sizeof(url), "gsiftp://%s/x", big);
        assert(brix_ftpurl_parse(url, &u) != 0);
    }
    {
        char url[8300];
        snprintf(url, sizeof(url), "gsiftp://h.example/%s", big);
        assert(brix_ftpurl_parse(url, &u) != 0);
    }
    printf("  PASS  over-long authority/path rejected\n");
}


/* ---- data-channel screen: success ---------------------------------------- */

/*
 * WHAT: the ordinary case — a passive reply naming the control peer and an
 *       ephemeral port is dialled.
 * WHY:  the screen must not break the 99.9% case it exists to protect.
 */
static void
test_screen_accepts_peer_ephemeral(void)
{
    assert(brix_ftp_data_addr_ok("192.0.2.10", "192.0.2.10", 50000, 0) == 1);
    assert(brix_ftp_data_addr_ok("192.0.2.10", "192.0.2.10", 1024, 0) == 1);
    assert(brix_ftp_data_addr_ok("192.0.2.10", "192.0.2.10", 65535, 0) == 1);
    printf("  PASS  screen accepts control peer on an unprivileged port\n");
}


/* ---- data-channel screen: security negatives ----------------------------- */

/*
 * WHAT: an address that is not the control peer is refused (FTP bounce).
 * WHY:  this is the SSRF primitive: a hostile server answers PASV with someone
 *       else's address, and an unscreened client connects wherever it is told —
 *       cloud metadata endpoints, internal admin ports, a victim host it can
 *       reach and the attacker cannot.
 */
static void
test_screen_refuses_offpeer_address(void)
{
    assert(brix_ftp_data_addr_ok("192.0.2.10", "169.254.169.254", 50000, 0) == 0);
    assert(brix_ftp_data_addr_ok("192.0.2.10", "10.0.0.5", 50000, 0) == 0);
    assert(brix_ftp_data_addr_ok("192.0.2.10", "127.0.0.1", 50000, 0) == 0);
    printf("  PASS  screen refuses an off-peer data address\n");
}


/*
 * WHAT: a privileged port is refused even when the address IS the control peer,
 *       and the opt-out env override does not relax it.
 * WHY:  a passive data port never legitimately lands below 1024, while 22/25/
 *       6379 are exactly what a bounce targets — so the port rule is the hard
 *       gate the address rule can fall back on.
 */
static void
test_screen_refuses_privileged_port(void)
{
    assert(brix_ftp_data_addr_ok("192.0.2.10", "192.0.2.10", 22, 0) == 0);
    assert(brix_ftp_data_addr_ok("192.0.2.10", "192.0.2.10", 25, 0) == 0);
    assert(brix_ftp_data_addr_ok("192.0.2.10", "192.0.2.10", 1023, 0) == 0);
    assert(brix_ftp_data_addr_ok("192.0.2.10", "192.0.2.10", 0, 0) == 0);
    assert(brix_ftp_data_addr_ok("192.0.2.10", "192.0.2.10", 70000, 0) == 0);
    /* allow_offpeer relaxes the ADDRESS rule only — never the port rule. */
    assert(brix_ftp_data_addr_ok("192.0.2.10", "169.254.169.254", 22, 1) == 0);
    assert(brix_ftp_data_addr_ok("192.0.2.10", "169.254.169.254", 50000, 1) == 1);
    printf("  PASS  screen refuses privileged/invalid ports, override is "
           "address-only\n");
}


/*
 * WHAT: a missing control-peer or data address is refused.
 * WHY:  getpeername() can fail; "unknown peer" must fail closed, not compare
 *       an empty string against an attacker-supplied one.
 */
static void
test_screen_refuses_unknown_addresses(void)
{
    assert(brix_ftp_data_addr_ok("", "192.0.2.10", 50000, 0) == 0);
    assert(brix_ftp_data_addr_ok(NULL, "192.0.2.10", 50000, 0) == 0);
    assert(brix_ftp_data_addr_ok("192.0.2.10", "", 50000, 0) == 0);
    assert(brix_ftp_data_addr_ok("192.0.2.10", NULL, 50000, 0) == 0);
    printf("  PASS  screen fails closed on an unknown address\n");
}


/* ---- ADAT/ENC base64 codec ----------------------------------------------- */

/*
 * WHAT: every byte value survives an encode/decode round trip.
 * WHY:  ADAT carries raw TLS records — binary, NUL-bearing, and fatal to a
 *       handshake if one byte is altered or the length is wrong.
 */
static void
test_b64_roundtrip_all_bytes(void)
{
    uint8_t  in[256];
    size_t   out_len = 0;
    uint8_t *back;
    char    *b64;
    size_t   i;

    for (i = 0; i < sizeof(in); i++) {
        in[i] = (uint8_t) i;
    }
    b64 = brix_ftp_b64_encode(in, sizeof(in));
    assert(b64 != NULL);
    back = brix_ftp_b64_decode(b64, &out_len);
    assert(back != NULL);
    assert(out_len == sizeof(in));
    assert(memcmp(back, in, sizeof(in)) == 0);
    free(back);
    free(b64);
    printf("  PASS  base64 round-trips all 256 byte values\n");
}


/*
 * WHAT: lengths that exercise every padding case round-trip exactly.
 * WHY:  the decoder subtracts padding by hand; an off-by-one there hands the
 *       TLS engine a token one or two bytes too long and the handshake dies
 *       with an opaque error.
 */
static void
test_b64_padding_lengths(void)
{
    const uint8_t src[] = { 0xde, 0xad, 0xbe, 0xef, 0x00 };
    size_t        n;

    for (n = 1; n <= sizeof(src); n++) {
        size_t   out_len = 0;
        char    *b64 = brix_ftp_b64_encode(src, n);
        uint8_t *back;

        assert(b64 != NULL);
        back = brix_ftp_b64_decode(b64, &out_len);
        assert(back != NULL);
        assert(out_len == n);
        assert(memcmp(back, src, n) == 0);
        free(back);
        free(b64);
    }
    printf("  PASS  base64 padding lengths 1..5 exact\n");
}


/*
 * WHAT: a malformed ADAT argument is rejected rather than decoded into garbage.
 * WHY:  the token comes straight off the wire from an unauthenticated peer —
 *       it is the first attacker-controlled input the session ever parses.
 */
static void
test_b64_rejects_malformed(void)
{
    size_t out_len = 0;

    assert(brix_ftp_b64_decode("abc", &out_len) == NULL);      /* len % 4 */
    assert(brix_ftp_b64_decode("", &out_len) == NULL);         /* empty   */
    assert(brix_ftp_b64_decode("!!!!", &out_len) == NULL);     /* alphabet*/
    printf("  PASS  malformed base64 rejected\n");
}


int
main(void)
{
    printf("ftp_client_unit: gsiftp:// client pure kernels\n");

    test_parse_gsiftp_defaults();
    test_parse_plain_ftp_defaults();
    test_parse_port_and_path_forms();
    test_reject_foreign_schemes();
    test_reject_bad_port();
    test_reject_overflow();

    test_screen_accepts_peer_ephemeral();
    test_screen_refuses_offpeer_address();
    test_screen_refuses_privileged_port();
    test_screen_refuses_unknown_addresses();

    test_b64_roundtrip_all_bytes();
    test_b64_padding_lengths();
    test_b64_rejects_malformed();

    printf("ftp_client_unit: ALL PASS\n");
    return 0;
}
