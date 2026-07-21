#include "ftp_ev.h"

#include <strings.h>   /* strcasecmp / strncasecmp */
#include <string.h>    /* strcasestr, strrchr */
#include <stdlib.h>    /* atoi, strtoll */
#include <unistd.h>    /* close() for ABOR's dangling listener */

/*
 * ftp_ev_dispatch.c — the command dispatcher and the small stateless verbs.
 *
 * WHAT: brix_ftp_ev_dispatch() frames a single command line into verb+arg,
 * enforces the pre-auth gate, and routes to the right handler; the transfer-
 * parameter and session verbs whose entire implementation is a single reply
 * (TYPE/MODE/STRU/ALLO/PWD/CDUP/NOOP/SYST/OPTS/REST/ABOR/SITE/PBSZ/PROT/DCAU/
 * USER/PASS/QUIT/FEAT) are handled inline here; the heavier namespace, security,
 * and transfer verbs delegate to their own files.
 *
 * WHY: this mirrors the sync engine's ftp_dispatch() one-to-one so the two engines
 * accept exactly the same grammar and emit the same reply codes — the invariant
 * the transition depends on.  Keeping the one-line verbs here (rather than one
 * trivial function each) keeps the dispatcher readable without inflating the file
 * count with near-empty handlers.
 *
 * HOW: the verbs are split into per-section group routers (ev_grp_*), each a thin
 * strcasecmp chain that returns the handler's result for a verb it owns or
 * NGX_DECLINED for one it does not; brix_ftp_ev_dispatch() tries them in grammar
 * order and falls through to "500 Unknown command".  Only the genuinely branchy
 * inline verbs (PROT/DCAU/OPTS/MODE/ALLO/REST) get their own static helper so no
 * single function carries the whole grammar's branch weight.  Each handler queues
 * its reply via brix_ftp_ev_reply() and returns NGX_OK to continue, NGX_DONE on
 * QUIT (flush then close), or NGX_ERROR on a fatal reply failure.  The dispatcher
 * never performs I/O itself — the engine flushes.
 */


/* Verbs accepted before the client has authenticated: the login verbs, the RFC
 * 2228 security handshake (which sets ->authed once ADAT completes), and
 * stateless capability probes.  Everything else is gated behind login. */
static int
ev_verb_preauth(const char *verb)
{
    static const char *const ok[] = {
        "USER", "PASS", "AUTH", "ADAT", "PBSZ", "PROT",
        "MIC",  "CONF", "ENC",  "QUIT", "FEAT", "SYST",
        "NOOP", "HELP", "OPTS", NULL
    };
    int i;

    for (i = 0; ok[i] != NULL; i++) {
        if (strcasecmp(verb, ok[i]) == 0) {
            return 1;
        }
    }
    return 0;
}


/* FEAT: advertise supported extensions; the GSI mechanisms only when a security
 * context is configured. */
static ngx_int_t
ev_cmd_feat(ftp_ev_t *fc)
{
    if (fc->conf->gsi && fc->conf->tls_ctx != NULL) {
        return brix_ftp_ev_reply(fc,
            "211-Features:\r\n SIZE\r\n MDTM\r\n REST STREAM\r\n PASV\r\n"
            " EPSV\r\n EPRT\r\n TYPE\r\n MLSD\r\n MLST type*;size*;modify*;perm*;\r\n"
            " CKSM\r\n AUTH GSSAPI\r\n PBSZ\r\n PROT\r\n DCAU\r\n211 End\r\n");
    }
    return brix_ftp_ev_reply(fc,
        "211-Features:\r\n SIZE\r\n MDTM\r\n REST STREAM\r\n PASV\r\n"
        " EPSV\r\n EPRT\r\n TYPE\r\n MLSD\r\n MLST type*;size*;modify*;perm*;\r\n"
        " CKSM\r\n211 End\r\n");
}


/* PROT: data-channel protection level.  Clear is always accepted; Private only
 * once a GSI security context is up (the data channel wraps under it). */
static ngx_int_t
ev_cmd_prot(ftp_ev_t *fc, const char *arg)
{
    if (arg[0] == 'C' || arg[0] == 'c' || arg[0] == '\0') {
        fc->prot = 'C';
        return brix_ftp_ev_reply(fc, "200 Protection level set to Clear\r\n");
    }
    if ((arg[0] == 'P' || arg[0] == 'p') && fc->sec_active) {
        fc->prot = 'P';
        return brix_ftp_ev_reply(fc, "200 Protection level set to Private\r\n");
    }
    return brix_ftp_ev_reply(fc,
        "536 Only PROT C supported; retry with -nodcau\r\n");
}


/* DCAU: data-channel authentication.  N (none) is always accepted; A (self)
 * only under an active GSI context. */
static ngx_int_t
ev_cmd_dcau(ftp_ev_t *fc, const char *arg)
{
    if (arg[0] == 'N' || arg[0] == 'n') {
        fc->dcau_a = 0;
        return brix_ftp_ev_reply(fc, "200 DCAU N\r\n");
    }
    if ((arg[0] == 'A' || arg[0] == 'a') && fc->sec_active) {
        fc->dcau_a = 1;
        return brix_ftp_ev_reply(fc, "200 DCAU A\r\n");
    }
    return brix_ftp_ev_reply(fc,
        "504 Data channel authentication unsupported; use -nodcau\r\n");
}


/* OPTS: only Parallelism=<n> is honoured (clamped 1..64); everything else is a
 * lenient 200 so a client's capability probe never fails the session. */
static ngx_int_t
ev_cmd_opts(ftp_ev_t *fc, const char *arg)
{
    const char *par = strcasestr(arg, "Parallelism=");

    if (par != NULL) {
        int n = atoi(par + 12);
        if (n < 1)  { n = 1; }
        if (n > 64) { n = 64; }
        fc->parallelism = n;
    }
    return brix_ftp_ev_reply(fc, "200 OK\r\n");
}


/* MODE: stream (S) or extended-block (E); nothing else. */
static ngx_int_t
ev_cmd_mode(ftp_ev_t *fc, const char *arg)
{
    if (arg[0] == 'S' || arg[0] == 's') {
        fc->mode_e = 0;
        return brix_ftp_ev_reply(fc, "200 Mode set to Stream\r\n");
    }
    if (arg[0] == 'E' || arg[0] == 'e') {
        fc->mode_e = 1;
        return brix_ftp_ev_reply(fc, "200 Mode set to Extended-block\r\n");
    }
    return brix_ftp_ev_reply(fc, "504 Only stream (S) and extended-block (E) "
                                 "modes supported\r\n");
}


/* ALLO <bytes> [R <recsize>] (RFC 959): the leading integer is the size of the
 * file about to be stored.  Record it (one-shot, consumed by the next STOR) so
 * brix_gridftp_require_allo_size can hold the transfer to exactly that many
 * bytes — the only completeness signal a stream-mode STOR has, since a bare
 * connection close is indistinguishable from a mid-flight truncation.  A
 * malformed/negative size leaves it unset (the ACK stays lenient, matching
 * historical behaviour). */
static ngx_int_t
ev_cmd_allo(ftp_ev_t *fc, const char *arg)
{
    char      *endp = NULL;
    long long  sz   = strtoll(arg, &endp, 10);

    fc->allo_size = (arg[0] != '\0' && endp != arg && sz >= 0)
                  ? (off_t) sz : -1;
    return brix_ftp_ev_reply(fc, "200 ALLO ok\r\n");
}


/* REST <offset>: restart position for the next transfer. */
static ngx_int_t
ev_cmd_rest(ftp_ev_t *fc, const char *arg)
{
    char      *endp = NULL;
    long long  off  = strtoll(arg, &endp, 10);

    if (arg[0] == '\0' || endp == arg || off < 0) {
        return brix_ftp_ev_reply(fc, "501 Bad restart offset\r\n");
    }
    fc->rest_off = (off_t) off;
    return brix_ftp_ev_reply(fc, "350 Restart position accepted (%lld)\r\n", off);
}


/* CDUP/XCUP: strip the last path component, floored at "/". */
static ngx_int_t
ev_cmd_cdup(ftp_ev_t *fc)
{
    char *slash = strrchr(fc->cwd, '/');

    if (slash != NULL && slash != fc->cwd) {
        *slash = '\0';
    } else {
        fc->cwd[0] = '/'; fc->cwd[1] = '\0';
    }
    return brix_ftp_ev_reply(fc, "250 Directory changed to %s\r\n", fc->cwd);
}


/* ---- group routers ---------------------------------------------------------
 * Each returns the handler's result for a verb it owns, or NGX_DECLINED for a
 * verb it does not.  brix_ftp_ev_dispatch() tries them in grammar order. */


/* RFC 2228 GSI security handshake (ftp_ev_sec.c). */
static ngx_int_t
ev_grp_security(ftp_ev_t *fc, const char *verb, const char *arg)
{
    if (strcasecmp(verb, "AUTH") == 0) {
        return brix_ftp_ev_cmd_auth(fc, arg);
    } else if (strcasecmp(verb, "ADAT") == 0) {
        return brix_ftp_ev_cmd_adat(fc, arg);
    } else if (strcasecmp(verb, "MIC") == 0) {
        return brix_ftp_ev_cmd_protected(fc, "631", arg);
    } else if (strcasecmp(verb, "CONF") == 0) {
        return brix_ftp_ev_cmd_protected(fc, "632", arg);
    } else if (strcasecmp(verb, "ENC") == 0) {
        return brix_ftp_ev_cmd_protected(fc, "633", arg);
    }
    return NGX_DECLINED;
}


/* Login: a GSI-authenticated session is already logged in when USER arrives. */
static ngx_int_t
ev_grp_login(ftp_ev_t *fc, const char *verb, const char *arg)
{
    if (strcasecmp(verb, "USER") == 0) {
        if (fc->sec_active) {                        /* GSI already logged in  */
            fc->authed = 1;
            return brix_ftp_ev_reply(fc, "230 GSI user %s logged in\r\n", arg);
        }
        return brix_ftp_ev_reply(fc, "331 Please specify the password\r\n");
    } else if (strcasecmp(verb, "PASS") == 0) {
        fc->authed = 1;
        return brix_ftp_ev_reply(fc, "230 Login successful\r\n");
    }
    return NGX_DECLINED;
}


/* Data-channel protection negotiation (PBSZ/PROT/DCAU). */
static ngx_int_t
ev_grp_dcprot(ftp_ev_t *fc, const char *verb, const char *arg)
{
    if (strcasecmp(verb, "PBSZ") == 0) {
        return brix_ftp_ev_reply(fc, "200 PBSZ=0\r\n");
    } else if (strcasecmp(verb, "PROT") == 0) {
        return ev_cmd_prot(fc, arg);
    } else if (strcasecmp(verb, "DCAU") == 0) {
        return ev_cmd_dcau(fc, arg);
    }
    return NGX_DECLINED;
}


/* Capability / session probes (SITE/SYST/FEAT/NOOP/OPTS). */
static ngx_int_t
ev_grp_session(ftp_ev_t *fc, const char *verb, const char *arg)
{
    if (strcasecmp(verb, "SITE") == 0) {
        return brix_ftp_ev_reply(fc, "200 OK\r\n");
    } else if (strcasecmp(verb, "SYST") == 0) {
        return brix_ftp_ev_reply(fc, "215 UNIX Type: L8\r\n");
    } else if (strcasecmp(verb, "FEAT") == 0) {
        return ev_cmd_feat(fc);
    } else if (strcasecmp(verb, "NOOP") == 0) {
        return brix_ftp_ev_reply(fc, "200 NOOP ok\r\n");
    } else if (strcasecmp(verb, "OPTS") == 0) {
        return ev_cmd_opts(fc, arg);
    }
    return NGX_DECLINED;
}


/* Transfer parameters (TYPE/MODE/STRU/ALLO/REST). */
static ngx_int_t
ev_grp_xferparam(ftp_ev_t *fc, const char *verb, const char *arg)
{
    if (strcasecmp(verb, "TYPE") == 0) {
        fc->type_binary = (arg[0] == 'I' || arg[0] == 'i');
        return brix_ftp_ev_reply(fc, "200 Type set to %s\r\n",
                                 fc->type_binary ? "I" : "A");
    } else if (strcasecmp(verb, "MODE") == 0) {
        return ev_cmd_mode(fc, arg);
    } else if (strcasecmp(verb, "STRU") == 0) {
        if (arg[0] == 'F' || arg[0] == 'f') {
            return brix_ftp_ev_reply(fc, "200 Structure set to File\r\n");
        }
        return brix_ftp_ev_reply(fc,
            "504 Only file structure (STRU F) supported\r\n");
    } else if (strcasecmp(verb, "ALLO") == 0) {
        return ev_cmd_allo(fc, arg);
    } else if (strcasecmp(verb, "REST") == 0) {
        return ev_cmd_rest(fc, arg);
    }
    return NGX_DECLINED;
}


/* Navigation (PWD/CWD/CDUP and their X-prefixed aliases). */
static ngx_int_t
ev_grp_navigation(ftp_ev_t *fc, const char *verb, const char *arg)
{
    if (strcasecmp(verb, "PWD") == 0 || strcasecmp(verb, "XPWD") == 0) {
        return brix_ftp_ev_reply(fc,
            "257 \"%s\" is the current directory\r\n", fc->cwd);
    } else if (strcasecmp(verb, "CWD") == 0 || strcasecmp(verb, "XCWD") == 0) {
        return brix_ftp_ev_cmd_cwd(fc, arg);
    } else if (strcasecmp(verb, "CDUP") == 0 || strcasecmp(verb, "XCUP") == 0) {
        return ev_cmd_cdup(fc);
    }
    return NGX_DECLINED;
}


/* Namespace metadata (ftp_ev_cmd.c). */
static ngx_int_t
ev_grp_namespace(ftp_ev_t *fc, const char *verb, const char *arg)
{
    if (strcasecmp(verb, "SIZE") == 0) {
        return brix_ftp_ev_cmd_size(fc, arg);
    } else if (strcasecmp(verb, "MKD") == 0 || strcasecmp(verb, "XMKD") == 0) {
        return brix_ftp_ev_cmd_mkd(fc, arg);
    } else if (strcasecmp(verb, "DELE") == 0) {
        return brix_ftp_ev_cmd_dele(fc, arg);
    } else if (strcasecmp(verb, "RMD") == 0 || strcasecmp(verb, "XRMD") == 0) {
        return brix_ftp_ev_cmd_rmd(fc, arg);
    } else if (strcasecmp(verb, "MDTM") == 0) {
        return brix_ftp_ev_cmd_mdtm(fc, arg);
    } else if (strcasecmp(verb, "MLST") == 0) {
        return brix_ftp_ev_cmd_mlst(fc, arg);
    } else if (strcasecmp(verb, "STAT") == 0) {
        return brix_ftp_ev_cmd_stat(fc, arg);
    } else if (strcasecmp(verb, "CKSM") == 0) {
        return brix_ftp_ev_cmd_cksm(fc, arg);
    } else if (strcasecmp(verb, "RNFR") == 0) {
        return brix_ftp_ev_cmd_rnfr(fc, arg);
    } else if (strcasecmp(verb, "RNTO") == 0) {
        return brix_ftp_ev_cmd_rnto(fc, arg);
    }
    return NGX_DECLINED;
}


/* Data transfers (ftp_ev_xfer.c — P82.2 event pump). */
static ngx_int_t
ev_grp_transfer(ftp_ev_t *fc, const char *verb, const char *arg)
{
    if (strcasecmp(verb, "PASV") == 0) {
        return brix_ftp_ev_do_transfer(fc, -1 /* PASV setup */, arg);
    } else if (strcasecmp(verb, "EPSV") == 0) {
        return brix_ftp_ev_do_transfer(fc, -2 /* EPSV setup */, arg);
    } else if (strcasecmp(verb, "PORT") == 0) {
        return brix_ftp_ev_do_transfer(fc, -3 /* PORT setup */, arg);
    } else if (strcasecmp(verb, "EPRT") == 0) {
        return brix_ftp_ev_do_transfer(fc, -4 /* EPRT setup */, arg);
    } else if (strcasecmp(verb, "RETR") == 0) {
        return brix_ftp_ev_do_transfer(fc, FTP_EV_OP_RETR, arg);
    } else if (strcasecmp(verb, "STOR") == 0) {
        return brix_ftp_ev_do_transfer(fc, FTP_EV_OP_STOR, arg);
    } else if (strcasecmp(verb, "APPE") == 0) {
        return brix_ftp_ev_do_transfer(fc, FTP_EV_OP_APPE, arg);
    } else if (strcasecmp(verb, "LIST") == 0) {
        return brix_ftp_ev_do_transfer(fc, FTP_EV_OP_LIST, arg);
    } else if (strcasecmp(verb, "NLST") == 0) {
        return brix_ftp_ev_do_transfer(fc, FTP_EV_OP_NLST, arg);
    } else if (strcasecmp(verb, "MLSD") == 0) {
        return brix_ftp_ev_do_transfer(fc, FTP_EV_OP_MLSD, arg);
    }
    return NGX_DECLINED;
}


/* Abort / quit. */
static ngx_int_t
ev_grp_ctl(ftp_ev_t *fc, const char *verb)
{
    if (strcasecmp(verb, "ABOR") == 0) {
        if (fc->pasv_fd >= 0) { (void) close(fc->pasv_fd); fc->pasv_fd = -1; }
        fc->active = 0;
        return brix_ftp_ev_reply(fc, "226 ABOR: no transfer in progress\r\n");
    } else if (strcasecmp(verb, "QUIT") == 0) {
        (void) brix_ftp_ev_reply(fc, "221 Goodbye\r\n");
        return NGX_DONE;
    }
    return NGX_DECLINED;
}


/* Handle one framed command line. */
ngx_int_t
brix_ftp_ev_dispatch(ftp_ev_t *fc, char *line)
{
    char      *verb;
    char      *arg = brix_ftp_ev_split(line, &verb);
    ngx_int_t  rc;

    /* Pre-auth gate: reject file/namespace/transfer verbs until login. */
    if (!fc->authed && !ev_verb_preauth(verb)) {
        return brix_ftp_ev_reply(fc, "530 Please login with USER and PASS\r\n");
    }

    if ((rc = ev_grp_security(fc, verb, arg))   != NGX_DECLINED) { return rc; }
    if ((rc = ev_grp_login(fc, verb, arg))      != NGX_DECLINED) { return rc; }
    if ((rc = ev_grp_dcprot(fc, verb, arg))     != NGX_DECLINED) { return rc; }
    if ((rc = ev_grp_session(fc, verb, arg))    != NGX_DECLINED) { return rc; }
    if ((rc = ev_grp_xferparam(fc, verb, arg))  != NGX_DECLINED) { return rc; }
    if ((rc = ev_grp_navigation(fc, verb, arg)) != NGX_DECLINED) { return rc; }
    if ((rc = ev_grp_namespace(fc, verb, arg))  != NGX_DECLINED) { return rc; }
    if ((rc = ev_grp_transfer(fc, verb, arg))   != NGX_DECLINED) { return rc; }
    if ((rc = ev_grp_ctl(fc, verb))             != NGX_DECLINED) { return rc; }

    return brix_ftp_ev_reply(fc, "500 Unknown command\r\n");
}
