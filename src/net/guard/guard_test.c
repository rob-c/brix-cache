/*
 * guard_test.c — standalone unit tests for the pure-C guard core.
 *
 * WHAT: exercises every guard.h entry point (ruleset construction, signature
 *   matching, grammar, pre/post classification, audit formatting) with no
 *   nginx, no network, no allocation.
 * WHY:  the guard core must stay embeddable in any adapter; a plain-gcc test
 *   binary is the proof and the regression net.
 * HOW:  CHECK() accumulates failures; main() returns non-zero if any check
 *   failed. Build + run via tests/guard/run_guard_core.sh.
 */
#include "guard.h"
#include <stdio.h>
#include <string.h>

static int fails;
#define CHECK(cond) do { if (!(cond)) { \
    printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond); fails++; } } while (0)

int main(void)
{
    /* --- ruleset init: header + enums compile and link --- */
    guard_ruleset_t rs;
    guard_ruleset_init(&rs);
    CHECK(rs.n_sigs == 0);
    CHECK(rs.n_prefixes == 0);

    /* --- signatures --- */
    guard_ruleset_t sg; guard_ruleset_init(&sg);
    guard_ruleset_add_default_signatures(&sg);
    CHECK(guard_signature_match(&sg, "/wp-login.php", 13));   /* suffix .php */
    CHECK(guard_signature_match(&sg, "/wp-admin/", 10));       /* prefix /wp- */
    CHECK(guard_signature_match(&sg, "/x/.env", 7));           /* substr .env */
    CHECK(guard_signature_match(&sg, "/a/../b", 7));           /* substr /../ */
    CHECK(!guard_signature_match(&sg, "/rest/1.0/jobs", 14));  /* clean */
    CHECK(!guard_signature_match(&sg, "/data/file.root", 15)); /* clean */
    /* custom substring */
    guard_ruleset_t cs; guard_ruleset_init(&cs);
    CHECK(guard_ruleset_add_signature(&cs, GUARD_SIG_SUBSTR, "phpMyAdmin", 10));
    CHECK(guard_signature_match(&cs, "/phpMyAdmin/index", 17));
    CHECK(!guard_signature_match(&cs, "/data/ok", 8));

    /* --- grammar + classify_pre --- */
    guard_ruleset_t ar; guard_ruleset_init(&ar);
    guard_ruleset_add_default_signatures(&ar);
    guard_ruleset_load_profile(&ar, "arc");   /* sets prefixes + op_allowed */

    guard_reason_t why = GUARD_R_NONE;
    guard_request_t ok = { "1.2.3.4", "arc", GUARD_OP_READ,
                           "/arex/rest/1.0/jobs", 19, 1, OUTCOME_PENDING, 0 };
    CHECK(guard_classify_pre(&ar, &ok, &why) == GUARD_ALLOW);
    CHECK(why == GUARD_R_NONE);

    guard_request_t junk = { "1.2.3.4", "arc", GUARD_OP_READ,
                             "/wp-login.php", 13, 0, OUTCOME_PENDING, 0 };
    CHECK(guard_classify_pre(&ar, &junk, &why) == GUARD_BOUNCE);
    CHECK(why == GUARD_R_SIGNATURE);

    guard_request_t offns = { "1.2.3.4", "arc", GUARD_OP_READ,
                              "/random/path", 12, 0, OUTCOME_PENDING, 0 };
    CHECK(guard_classify_pre(&ar, &offns, &why) == GUARD_BOUNCE);
    CHECK(why == GUARD_R_GRAMMAR);

    /* signatures take precedence over grammar (both would fire) */
    guard_request_t both = { "1.2.3.4", "arc", GUARD_OP_READ,
                             "/evil/.env", 10, 0, OUTCOME_PENDING, 0 };
    CHECK(guard_classify_pre(&ar, &both, &why) == GUARD_BOUNCE);
    CHECK(why == GUARD_R_SIGNATURE);

    /* advisory grammar: off-namespace ALLOWED when enforce_grammar==0 */
    guard_ruleset_t adv; guard_ruleset_init(&adv);
    guard_ruleset_add_prefix(&adv, "/arex", 5);
    adv.enforce_grammar = 0;
    CHECK(guard_classify_pre(&adv, &offns, &why) == GUARD_ALLOW);

    /* --- classify_post --- */
    guard_ruleset_t pr; guard_ruleset_init(&pr);
    pr.flag_notfound = 1; pr.flag_authfail = 1;
    guard_request_t nf = { "1.2.3.4","arc",GUARD_OP_READ,"/arex/x",7,1,
                           OUTCOME_NOTFOUND, 404 };
    CHECK(guard_classify_post(&pr, &nf) == GUARD_R_NOTFOUND);
    guard_request_t af = { "1.2.3.4","arc",GUARD_OP_READ,"/arex/x",7,0,
                           OUTCOME_AUTHFAIL, 401 };
    CHECK(guard_classify_post(&pr, &af) == GUARD_R_AUTHFAIL);
    guard_request_t okr = { "1.2.3.4","arc",GUARD_OP_READ,"/arex/x",7,1,
                            OUTCOME_OK, 200 };
    CHECK(guard_classify_post(&pr, &okr) == GUARD_R_NONE);
    /* toggled off => not flagged */
    guard_ruleset_t off; guard_ruleset_init(&off);
    off.flag_notfound = 0; off.flag_authfail = 0;
    CHECK(guard_classify_post(&off, &nf) == GUARD_R_NONE);
    CHECK(guard_classify_post(&off, &af) == GUARD_R_NONE);

    /* --- wire-level handshake classifier --- */
    {
        int nm;
        /* full 20-byte kXR ClientInitHandShake: 12 zeros, fourth=htonl(4),
         * fifth=htonl(2012) — forwarded, verdict final. */
        unsigned char root_hs[20] = {
            0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,4, 0,0,0x07,0xDC };
        CHECK(guard_classify_handshake(root_hs, 20, &nm) == GUARD_WIRE_ROOT);
        CHECK(nm == 0);
        /* zero-prefix shorter than the signature -> defer (need_more) */
        CHECK(guard_classify_handshake(root_hs, 8, &nm) == GUARD_WIRE_ROOT);
        CHECK(nm == 1);
        CHECK(guard_classify_handshake(root_hs, 16, &nm) == GUARD_WIRE_ROOT);
        CHECK(nm == 0);                 /* fourth complete: decided, forward */
        /* 16+ zero-led bytes but fourth != htonl(4) -> not root */
        unsigned char zero_bad[16] = { 0 };
        CHECK(guard_classify_handshake(zero_bad, 16, &nm) == GUARD_WIRE_JUNK);
        CHECK(nm == 0);
        /* non-root clients knocking on the root port */
        unsigned char tls[3] = { 0x16, 0x03, 0x01 };  /* TLS ClientHello */
        CHECK(guard_classify_handshake(tls, 3, &nm) == GUARD_WIRE_TLS);
        CHECK(guard_classify_handshake((const unsigned char *) "GET / HTTP/1.1",
                                       14, &nm) == GUARD_WIRE_HTTP);
        CHECK(guard_classify_handshake((const unsigned char *) "OPTIONS * ",
                                       10, &nm) == GUARD_WIRE_HTTP);
        CHECK(guard_classify_handshake((const unsigned char *) "SSH-2.0-x",
                                       9, &nm) == GUARD_WIRE_SSH);
        CHECK(guard_classify_handshake((const unsigned char *) "", 0, &nm)
              == GUARD_WIRE_EMPTY);
        CHECK(guard_classify_handshake((const unsigned char *) "\xde\xad\xbe",
                                       3, &nm) == GUARD_WIRE_JUNK);
        /* "GET" without the trailing space is NOT misread as HTTP */
        CHECK(guard_classify_handshake((const unsigned char *) "GETX", 4, &nm)
              == GUARD_WIRE_JUNK);
        /* wire tokens */
        CHECK(strcmp(guard_wire_str(GUARD_WIRE_ROOT), "root") == 0);
        CHECK(strcmp(guard_wire_str(GUARD_WIRE_TLS), "tls-clienthello") == 0);
        CHECK(strcmp(guard_wire_str(GUARD_WIRE_HTTP), "http-request") == 0);
        CHECK(strcmp(guard_wire_str(GUARD_WIRE_SSH), "ssh-banner") == 0);
        CHECK(strcmp(guard_wire_str(GUARD_WIRE_EMPTY), "empty") == 0);
        CHECK(strcmp(guard_wire_str(GUARD_WIRE_JUNK), "junk") == 0);
        CHECK(strcmp(guard_reason_str(GUARD_R_NOTROOT), "notroot") == 0);
        CHECK(strcmp(guard_reason_str(GUARD_R_PROXYABUSE), "proxyabuse") == 0);
        CHECK(strcmp(guard_reason_str(GUARD_R_TAMPER), "cvmfs_tamper") == 0);
    }

    /* --- audit format --- */
    char line[512];
    guard_request_t sigreq = { "203.0.113.9","arc",GUARD_OP_READ,
                               "/wp-login.php",13,0,OUTCOME_PENDING,403 };
    size_t n = guard_audit_format(&sigreq, GUARD_R_SIGNATURE,
                                  "2026-07-01T12:00:00Z", line, sizeof(line));
    CHECK(n > 0);
    CHECK(strcmp(line,
        "2026-07-01T12:00:00Z ip=203.0.113.9 proto=arc signal=signature "
        "op=read path=\"/wp-login.php\" status=403") == 0);
    /* notroot line: op=handshake, wire guess in the path, status=0 */
    guard_request_t nrreq = { "192.0.2.5","root",GUARD_OP_HANDSHAKE,
                              "tls-clienthello",15,0,OUTCOME_PENDING,0 };
    CHECK(guard_audit_format(&nrreq, GUARD_R_NOTROOT,
                             "2026-07-01T12:00:00Z", line, sizeof(line)) > 0);
    CHECK(strcmp(line,
        "2026-07-01T12:00:00Z ip=192.0.2.5 proto=root signal=notroot "
        "op=handshake path=\"tls-clienthello\" status=0") == 0);
    /* proxyabuse line: op=read, the attempted upstream authority in the path,
     * status=403 (the reject that fed it) */
    guard_request_t pareq = { "203.0.113.44","cvmfs",GUARD_OP_READ,
                              "evil.example.com:8000",21,0,OUTCOME_PENDING,403 };
    CHECK(guard_audit_format(&pareq, GUARD_R_PROXYABUSE,
                             "2026-07-01T12:00:00Z", line, sizeof(line)) > 0);
    CHECK(strcmp(line,
        "2026-07-01T12:00:00Z ip=203.0.113.44 proto=cvmfs signal=proxyabuse "
        "op=read path=\"evil.example.com:8000\" status=403") == 0);
    /* cvmfs_tamper line: the offending ORIGIN authority rides the ip field
     * (the tamper actor is upstream, not the client), the failed object key
     * rides the path, status=502 (the gateway error the client saw) */
    guard_request_t tpreq = { "s1.bad.example.org","cvmfs",GUARD_OP_READ,
                              "/cvmfs/repo.io/data/ab/cdef",27,0,
                              OUTCOME_PENDING,502 };
    CHECK(guard_audit_format(&tpreq, GUARD_R_TAMPER,
                             "2026-07-01T12:00:00Z", line, sizeof(line)) > 0);
    CHECK(strcmp(line,
        "2026-07-01T12:00:00Z ip=s1.bad.example.org proto=cvmfs "
        "signal=cvmfs_tamper op=read path=\"/cvmfs/repo.io/data/ab/cdef\" "
        "status=502") == 0);
    /* token maps */
    CHECK(strcmp(guard_reason_str(GUARD_R_AUTHFAIL), "authfail") == 0);
    CHECK(strcmp(guard_reason_str(GUARD_R_NOTFOUND), "notfound") == 0);
    CHECK(strcmp(guard_op_str(GUARD_OP_STAGE), "stage") == 0);
    /* too-small buffer => 0, no overflow */
    char tiny[8];
    CHECK(guard_audit_format(&sigreq, GUARD_R_SIGNATURE,
                             "2026-07-01T12:00:00Z", tiny, sizeof(tiny)) == 0);

    printf(fails ? "GUARD CORE: %d FAIL\n" : "GUARD CORE: all pass\n", fails);
    return fails ? 1 : 0;
}
