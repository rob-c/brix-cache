/*
 * diag_check.c - extracted concern
 * Phase-38 split of xrddiag.c; behavior-identical.
 */
#include "diag_internal.h"
#include "cli/jsonout.h"


/* check — protocol-correctness probes                                 */

/*
 * emit_json_bool_or_null — write "key":bool or "key":null + optional comma.
 *
 * WHAT: helper for optional probe fields in do_check's JSON block.
 * WHY:  distinguishes untested probes (null) from tested-and-failed (false) —
 *       null tells the consumer "we never ran this probe", false says "ran + failed".
 * HOW:  writes directly to out; used only in the JSON emit block of do_check.
 */
static void
emit_json_bool_or_null(FILE *out, const char *k, int tested, int v, int comma)
{
    brix_json_fputs(out, k);
    if (tested) {
        fprintf(out, ":%s%s", v ? "true" : "false", comma ? "," : "");
    } else {
        fprintf(out, ":null%s", comma ? "," : "");
    }
}


/*
 * do_check — protocol-correctness and security probes against a live endpoint.
 *
 * WHAT: connects, runs a battery of functional and security probes, then
 *       outputs either a human-readable report or (--json) a single JSON object.
 * WHY:  JSON mode lets CI/CD pipelines and monitoring scripts consume results
 *       without parsing prose; the machine-readable path mirrors the human one 1:1.
 * HOW:  each probe runs regardless of output mode; outcomes accumulate in locals.
 *       Human path (probe/note/printf) is guarded by !a->json throughout.
 *       JSON is emitted once at the very end — never partial, never on early error.
 */
int
do_check(const diag_args *a)
{
    brix_url      u;
    brix_conn     c;
    brix_status   st;
    brix_statinfo sti;
    char          target[XRDC_PATH_MAX];
    int           have_file;
    /* JSON-mode accumulators — zero-init: bools default false, counts 0 */
    int       js_fails = 0;
    int       js_auth_ok = 0, js_tls_active = 0, js_tls_required = 0;
    int       js_confinement_ok = 0, js_dirlist_ok = 0;
    int       js_dstat_tested = 0, js_dstat_ok = 0;
    int       js_cksum_tested = 0, js_cksum_ok = 0;
    int       js_pgread_tested = 0, js_pgread_ok = 0;
    int       js_posc_tested = 0, js_posc_ok = 0;
    int       js_hlim_tested = 0, js_hlim_ok = 0;
    long long js_dirlist_count = 0;
    char      js_auth_proto[64] = "anon";
    char      js_tls_ver[32]    = "";

    brix_status_clear(&st);
    if (brix_endpoint_parse(a->url, &u, &st) != 0) {
        fprintf(stderr, "xrddiag: %s\n", st.msg);
        return 50;
    }
    if (brix_connect(&c, &u, &a->conn, &st) != 0) {
        fprintf(stderr, "xrddiag: connect %s:%d: %s\n", u.host, u.port, st.msg);
        return brix_shellcode(&st);
    }

    if (!a->json) {
        printf("Session facts:\n");
        brix_explain_conn(&c, &a->conn, stdout);
        printf("Probes:\n");
    }

    /* (1) auth-as-advertised: the driver's chosen protocol must be anon (no &P=)
     *     or appear in the server's advertised security list. */
    {
        int ok;
        if (c.sec_list[0] == '\0') {
            ok = (c.diag.chosen_auth == NULL);
        } else {
            ok = (c.diag.chosen_auth != NULL) &&
                 (strstr(c.sec_list, c.diag.chosen_auth) != NULL);
        }
        js_auth_ok = ok;
        if (!ok) { js_fails++; }
        if (c.diag.chosen_auth != NULL) {
            snprintf(js_auth_proto, sizeof(js_auth_proto), "%s", c.diag.chosen_auth);
        }
        if (!a->json) {
            if (c.sec_list[0] == '\0') {
                probe("auth-as-advertised", ok,
                      c.diag.chosen_auth == NULL ? "anonymous (no &P= offered)"
                                                 : "client used %s but server offered none",
                      c.diag.chosen_auth ? c.diag.chosen_auth : "");
            } else {
                probe("auth-as-advertised", ok, "chose %s from \"%s\"",
                      c.diag.chosen_auth ? c.diag.chosen_auth : "(none)", c.sec_list);
            }
        }
    }

    /* (2) no-silent-TLS-downgrade: gotoTLS advertised ⇒ session must be TLS. */
    {
        unsigned    f = (unsigned) c.server_flags;
        const char *v = NULL, *cf = NULL;
        int         tls_active = brix_tls_info(&c, &v, &cf);
        js_tls_active   = tls_active;
        js_tls_required = (f & kXR_gotoTLS) ? 1 : 0;
        if (v != NULL) {
            snprintf(js_tls_ver, sizeof(js_tls_ver), "%s", v);
        }
        /* count as a failure only when the server demanded TLS but we got cleartext */
        if (js_tls_required && !tls_active) { js_fails++; }
        if (!a->json) {
            if (f & kXR_gotoTLS) {
                probe("no-tls-downgrade", tls_active,
                      tls_active ? "gotoTLS honored (%s)" : "gotoTLS advertised but cleartext!",
                      v ? v : "");
            } else {
                note("no-tls-downgrade", tls_active ? "TLS active" : "cleartext (gotoTLS not required)");
            }
        }
    }

    /* (3) path-confinement: an escape attempt must be refused, never served. */
    {
        brix_statinfo esc;
        brix_status   est;
        int           rc;
        brix_status_clear(&est);
        rc = brix_stat(&c, "/../../../../../../etc/passwd", &esc, &est);
        js_confinement_ok = (rc != 0);
        if (!js_confinement_ok) { js_fails++; }
        if (!a->json) {
            probe("path-confinement", rc != 0,
                  rc != 0 ? "escape refused (%s)" : "ESCAPE SERVED — confinement broken!",
                  rc != 0 ? brix_kxr_name(est.kxr) : "");
        }
    }

    /* (4) dirlist works + (7) dirlist-dstat == stat for the first entry. */
    {
        brix_dirent *ents = NULL;
        size_t       n = 0;
        brix_status  dst;
        brix_status_clear(&dst);
        if (brix_dirlist(&c, "/", 1, &ents, &n, &dst) != 0) {
            js_dirlist_ok = 0;
            js_fails++;
            if (!a->json) { probe("dirlist", 0, "%s", dst.msg); }
        } else {
            js_dirlist_ok     = 1;
            js_dirlist_count  = (long long) n;
            if (!a->json) { probe("dirlist", 1, "%zu entries under /", n); }
            /* find a regular file entry with a stat and cross-check it */
            for (size_t i = 0; i < n; i++) {
                if (ents[i].have_stat && !(ents[i].st.flags & kXR_isDir)) {
                    char         p[XRDC_PATH_MAX];
                    brix_statinfo s2;
                    brix_status   s2st;
                    snprintf(p, sizeof(p), "/%s", ents[i].name);
                    brix_status_clear(&s2st);
                    if (brix_stat(&c, p, &s2, &s2st) == 0) {
                        int ok = (s2.size == ents[i].st.size);
                        js_dstat_tested = 1;
                        js_dstat_ok     = ok;
                        if (!ok) { js_fails++; }
                        if (!a->json) {
                            probe("dstat==stat", ok,
                                  "%s size dstat=%lld stat=%lld", ents[i].name,
                                  (long long) ents[i].st.size, (long long) s2.size);
                        }
                    }
                    break;
                }
            }
            free(ents);
        }
    }

    /* Resolve a file for the integrity probes (skip cleanly if none). */
    have_file = (resolve_target(&c, &u, target, sizeof(target), &sti, &st) == 0);
    if (!have_file && !a->json) {
        note("checksum/pgread", "skipped — %s", st.msg);
    }

    /* (5) checksum-works: server digest == local digest of the downloaded bytes. */
    if (have_file) {
        char        srv[160], loc[160];
        brix_status qst, lst;
        int         tmpfd;
        char        tmpl[] = "/tmp/xrddiag.XXXXXX";

        brix_status_clear(&qst);
        if (brix_query_cksum(&c, target, "adler32", srv, sizeof(srv), &qst) != 0) {
            if (!a->json) {
                note("checksum-works", "server has no adler32 (%s)", qst.msg);
            }
        } else {
            tmpfd = mkstemp(tmpl);
            if (tmpfd < 0) {
                if (!a->json) { note("checksum-works", "mkstemp failed"); }
            } else {
                int64_t got = 0;
                brix_status_clear(&lst);
                if (download_to_fd(&c, target, tmpfd, &got, &lst) == 0 &&
                    brix_cksum_fd(tmpfd, XRDC_CK_ADLER32, loc, sizeof(loc), &lst) == 0) {
                    int ok = (strcmp(srv, loc) == 0);
                    js_cksum_tested = 1;
                    js_cksum_ok     = ok;
                    if (!ok) { js_fails++; }
                    if (!a->json) {
                        probe("checksum-works", ok,
                              "%s server=%s local=%s", target, srv, loc);
                    }
                } else {
                    js_cksum_tested = 1;
                    js_cksum_ok     = 0;
                    js_fails++;
                    if (!a->json) { probe("checksum-works", 0, "%s", lst.msg); }
                }
                close(tmpfd);
                unlink(tmpl);
            }
        }
    }

    /* (6) pgread-integrity: pgread self-validates per-page CRC32c. */
    if (have_file) {
        char        buf[8192];
        brix_file   f;
        brix_status pst;
        brix_status_clear(&pst);
        if (brix_file_open_read(&c, target, &f, &pst) != 0) {
            js_pgread_tested = 1;
            js_pgread_ok     = 0;
            js_fails++;
            if (!a->json) { probe("pgread-integrity", 0, "open: %s", pst.msg); }
        } else {
            ssize_t r = brix_file_pgread(&c, &f, 0, buf, sizeof(buf), &pst);
            js_pgread_tested = 1;
            js_pgread_ok     = (r >= 0);
            if (!js_pgread_ok) { js_fails++; }
            if (!a->json) {
                probe("pgread-integrity", r >= 0,
                      r >= 0 ? "%zd bytes, all page CRC32c verified" : "%s",
                      r >= 0 ? (size_t) r : 0, r >= 0 ? "" : pst.msg);
            }
            brix_file_close(&c, &f, &pst);
        }
    }

    /* (8) POSC-atomicity: a non-finalized POSC upload must leave NO file. Open a
     *     SECOND connection, posc-open + partial write, then ABANDON it (close the
     *     socket without kXR_close) and confirm the path is absent on the main conn. */
    if (have_file) {
        brix_conn   pc;
        brix_status pst;
        brix_file   pf;
        char        ppath[64];
        snprintf(ppath, sizeof(ppath), "/_xrddiag_posc_%d.tmp", (int) getpid());
        brix_status_clear(&pst);
        if (brix_connect(&pc, &u, &a->conn, &pst) != 0) {
            if (!a->json) {
                note("posc-atomicity", "skipped — 2nd connect: %s", pst.msg);
            }
        } else if (brix_file_open_write(&pc, ppath, 1, 1, &pf, &pst) != 0) {
            if (!a->json) {
                note("posc-atomicity", "skipped — posc open: %s (read-only export?)",
                     pst.msg);
            }
            brix_close(&pc);
        } else {
            brix_statinfo si;
            brix_status   s2;
            int           visible;
            (void) brix_file_write(&pc, &pf, 0, "partial", 7, &pst);
            /* ABANDON: drop the socket with no kXR_close → server discards POSC. */
            if (pc.io.fd >= 0) { close(pc.io.fd); pc.io.fd = -1; }
            brix_close(&pc);
            brix_status_clear(&s2);
            visible          = (brix_stat(&c, ppath, &si, &s2) == 0);
            js_posc_tested   = 1;
            js_posc_ok       = !visible;
            if (visible) { js_fails++; }
            if (!a->json) {
                probe("posc-atomicity", !visible,
                      visible ? "PARTIAL FILE VISIBLE after abandoned upload!"
                              : "abandoned upload left no file (%s)",
                      visible ? "" : brix_kxr_name(s2.kxr));
            }
            if (visible) { brix_rm(&c, ppath, &s2); }   /* clean up the leak */
        }
    }

    /* (9) handle-limits: opening files past the server cap must fail GRACEFULLY
     *     (a clean kXR_* error, not a crash/hang) and the connection survive. */
    if (have_file) {
        brix_file   fhs[64];
        brix_status hst;
        int         opened = 0, i, graceful;
        for (i = 0; i < 64; i++) {
            brix_status_clear(&hst);
            if (brix_file_open_read(&c, target, &fhs[opened], &hst) != 0) {
                break;
            }
            opened++;
        }
        graceful = (opened < 64);   /* hit a cap with a clean error */
        {
            brix_statinfo si;
            brix_status   s2;
            int           alive;
            brix_status_clear(&s2);
            alive = (brix_stat(&c, "/", &si, &s2) == 0) || (s2.kxr > 0);
            if (graceful) {
                js_hlim_tested = 1;
                js_hlim_ok     = alive;
                if (!alive) { js_fails++; }
                if (!a->json) {
                    probe("handle-limits", alive, "capped at %d open (%s), conn alive",
                          opened, brix_kxr_name(hst.kxr));
                }
            } else {
                if (!a->json) {
                    note("handle-limits", "no cap hit (opened %d), conn %s", opened,
                         alive ? "alive" : "DEAD");
                }
            }
        }
        for (i = 0; i < opened; i++) {
            brix_status cs;
            brix_status_clear(&cs);
            brix_file_close(&c, &fhs[i], &cs);
        }
    }

    /* (10) credential validity / clock-skew: surface env-credential expiry (the
     *      actionable client-side signal — see also `xrdfs explain`). */
    if (!a->json) {
        char       *tok = brix_token_discover();
        const char *proxy = getenv("X509_USER_PROXY");
        if (tok != NULL || (proxy != NULL && proxy[0] != '\0')) {
            printf("Credential validity:\n");
            if (tok != NULL) { brix_token_explain(tok, stdout); free(tok); }
            if (proxy != NULL && proxy[0] != '\0') {
                brix_gsi_cert_explain(proxy, stdout);
            }
        } else {
            note("cred-validity", "anonymous — no credential expiry to check");
        }
    }

    brix_close(&c);

    if (a->json) {
        printf("{");
        brix_json_kv_str(stdout,  "url",                  a->url,             1);
        brix_json_kv_bool(stdout, "connect_ok",           1,                  1);
        brix_json_kv_str(stdout,  "auth_proto",           js_auth_proto,      1);
        brix_json_kv_bool(stdout, "auth_ok",              js_auth_ok,         1);
        brix_json_kv_bool(stdout, "tls_required",         js_tls_required,    1);
        brix_json_kv_bool(stdout, "tls_active",           js_tls_active,      1);
        brix_json_kv_str(stdout,  "tls_ver",              js_tls_ver,         1);
        brix_json_kv_bool(stdout, "path_confinement_ok",  js_confinement_ok,  1);
        brix_json_kv_bool(stdout, "dirlist_ok",           js_dirlist_ok,      1);
        brix_json_kv_ll(stdout,   "dirlist_count",        js_dirlist_count,   1);
        emit_json_bool_or_null(stdout, "dstat_ok",        js_dstat_tested,  js_dstat_ok,  1);
        emit_json_bool_or_null(stdout, "checksum_ok",     js_cksum_tested,  js_cksum_ok,  1);
        emit_json_bool_or_null(stdout, "pgread_ok",       js_pgread_tested, js_pgread_ok, 1);
        emit_json_bool_or_null(stdout, "posc_ok",         js_posc_tested,   js_posc_ok,   1);
        emit_json_bool_or_null(stdout, "handle_ok",       js_hlim_tested,   js_hlim_ok,   1);
        brix_json_kv_ll(stdout,   "failures",             (long long) js_fails, 0);
        printf("}\n");
        return js_fails ? 1 : 0;
    }

    printf("Result: %d failure(s)\n", g_fails);
    return g_fails ? 1 : 0;
}


/* auth posture: did we connect anonymously to a server that advertises auth? */
void
dx_probe_auth(const brix_conn *c, doctor_ep *e)
{
    int anon = (c->diag.chosen_auth == NULL);
    if (anon && c->sec_list[0] != '\0') {
        dx_record(e, "auth", DX_WARN, 0,
                  "server advertises auth but the client connected anonymously",
                  "provide matching credentials (--auth + token/proxy) if operations are denied");
    } else {
        dx_record(e, "auth", DX_OK, 0,
                  anon ? "anonymous (server offered no auth)" : "authenticated", "");
    }
}


/* namespace: the export root must stat as a directory and be listable. */
void
dx_probe_namespace(brix_conn *c, doctor_ep *e)
{
    brix_statinfo si;
    brix_status   st;
    brix_dirent  *ents = NULL;
    size_t        n = 0;

    brix_status_clear(&st);
    if (brix_stat(c, "/", &si, &st) != 0) {
        dx_record_status(e, "namespace", &st);
        return;
    }
    brix_status_clear(&st);
    if (brix_dirlist(c, "/", 0, &ents, &n, &st) != 0) {
        dx_record_status(e, "namespace", &st);
        return;
    }
    {
        /* Count visible (non-dot) entries — the server keeps its own dotfiles
         * (e.g. a checkpoint-recovery lock) in the root, so a naive count is
         * never zero; only an absence of real data is a meaningful signal. */
        size_t i, visible = 0;
        for (i = 0; i < n; i++) {
            if (ents[i].name[0] != '.') { visible++; }
        }
        free(ents);
        if (visible == 0) {
            dx_record(e, "namespace", DX_WARN, 0,
                      "export root has no visible files (empty or wrong brix_root)",
                      "confirm data is present under the configured export root");
        } else {
            dx_record(e, "namespace", DX_OK, 0, "export root listable", "");
        }
    }
}


/*
 * read path: stat the target (note kXR_offline = on tape), then open it and read one
 * block. A failure is classified by the (read, kxr) rule; offline is a tape signal.
 */
void
dx_probe_read(brix_conn *c, const char *target, doctor_ep *e)
{
    brix_statinfo si;
    brix_status   st;
    brix_file     f;

    brix_status_clear(&st);
    if (brix_stat(c, target, &si, &st) != 0) {
        dx_record_status(e, "read", &st);
        return;
    }
    if (si.flags & kXR_offline) {
        e->offline_seen = 1;
        dx_record(e, "read", DX_WARN, 0, "file is offline (on tape/cache, not staged)",
                  "issue a stage/prepare and retry after recall (use --allow-write for an active stage probe)");
        return;
    }
    brix_status_clear(&st);
    if (brix_file_open_read(c, target, &f, &st) != 0) {
        dx_record_status(e, "read", &st);
        return;
    }
    {
        uint8_t     buf[4096];   /* stack-backed: a read probe proves the path, no malloc */
        brix_status rst;
        ssize_t     r;
        brix_status_clear(&rst);
        r = brix_file_read(c, &f, 0, buf, sizeof(buf), &rst);
        if (r < 0) {
            brix_file_close(c, &f, &st);
            dx_record_status(e, "read", &rst);
            return;
        }
    }
    brix_file_close(c, &f, &st);
    dx_record(e, "read", DX_OK, 0, "read path healthy", "");
}


/*
 * checksum integrity: compare the server's advertised checksum against one recomputed
 * locally from the bytes we downloaded. A disagreement means a stale checksum DB or
 * on-disk corruption — a class of bug only a cross-check can surface.
 */
void
dx_probe_checksum(brix_conn *c, const char *target, doctor_ep *e)
{
    char        srv[160], loc[160];
    brix_status st;
    int         fd;
    char        tmpl[] = "/tmp/xrddiag-dx.XXXXXX";
    int64_t     got = 0;

    /* Request adler32 (the client can recompute it) and compare the bare hex,
     * mirroring the proven `check` checksum-works probe. */
    brix_status_clear(&st);
    if (brix_query_cksum(c, target, "adler32", srv, sizeof(srv), &st) != 0) {
        if (st.kxr == kXR_Unsupported) {
            dx_record_status(e, "checksum", &st);
        }
        return;   /* server simply doesn't expose a checksum — not a problem */
    }
    fd = mkstemp(tmpl);
    if (fd < 0) {
        return;
    }
    brix_status_clear(&st);
    if (download_to_fd(c, target, fd, &got, &st) == 0
        && brix_cksum_fd(fd, XRDC_CK_ADLER32, loc, sizeof(loc), &st) == 0) {
        if (strcmp(srv, loc) == 0) {
            dx_record(e, "checksum", DX_OK, 0, "server checksum matches read data", "");
        } else {
            dx_record(e, "checksum", DX_FAIL, 0,
                      "server checksum disagrees with the bytes read (stale checksum DB or data corruption)",
                      "recompute/repair the server checksum; verify storage integrity");
        }
    }
    close(fd);
    unlink(tmpl);
}


/*
 * write path (GATED): create a unique temp dir, write+read-back a small object, verify
 * byte-exactness, then clean up. The failure code pins the cause precisely
 * (kXR_fsReadOnly = read-only export, kXR_NotAuthorized = no write scope, quota/space).
 * Always reverses its own mutations; bounded; never touches user data paths.
 */
void
dx_probe_write(brix_conn *c, doctor_ep *e)
{
    char        dir[96], path[160];
    brix_status st;
    brix_file   f;
    const char  payload[] = "xrddiag-remote-doctor-write-probe\n";
    int         wrote = 0;

    /* pid + monotonic clock makes the temp namespace collision-proof across runs
     * and pid reuse, so the probe never reuses or fights a pre-existing directory. */
    snprintf(dir, sizeof(dir), "/.xrddiag-dx-%ld-%llx", (long) getpid(),
             (unsigned long long) brix_mono_ns());
    snprintf(path, sizeof(path), "%s/probe.tmp", dir);

    brix_status_clear(&st);
    if (brix_mkdir(c, dir, 0700, 0, &st) != 0) {
        dx_record_status(e, "write", &st);
        return;
    }
    brix_status_clear(&st);
    if (brix_file_open_write(c, path, 1 /*force*/, 0 /*posc*/, &f, &st) != 0) {
        dx_record_status(e, "write", &st);
        brix_rmdir(c, dir, &st);
        return;
    }
    brix_status_clear(&st);
    if (brix_file_write(c, &f, 0, payload, sizeof(payload) - 1, &st) == 0) {
        wrote = 1;
    }
    {
        /* a close failure means the server never durably committed the write. */
        brix_status cst;
        brix_status_clear(&cst);
        if (brix_file_close(c, &f, &cst) != 0 && wrote) {
            wrote = 0;
            st = cst;
        }
    }

    if (!wrote) {
        dx_record_status(e, "write", &st);
    } else {
        /* read back + verify byte-exactness */
        brix_file   rf;
        uint8_t     rb[64];
        ssize_t     rn = -1;
        brix_status rst;
        brix_status_clear(&rst);
        if (brix_file_open_read(c, path, &rf, &rst) == 0) {
            rn = brix_file_read(c, &rf, 0, rb, sizeof(rb), &rst);
            brix_file_close(c, &rf, &rst);
        }
        if (rn == (ssize_t) (sizeof(payload) - 1)
            && memcmp(rb, payload, sizeof(payload) - 1) == 0) {
            dx_record(e, "write", DX_OK, 0, "write path healthy (write/read-back verified)", "");
        } else {
            dx_record(e, "write", DX_FAIL, 0,
                      "write succeeded but read-back did not match (durability/consistency fault)",
                      "check the server write-through/cache flush path and storage backend");
        }
    }
    /* always clean up our mutations; warn (no silent residue) if the dir survives. */
    brix_status_clear(&st);
    brix_rm(c, path, &st);
    brix_status_clear(&st);
    if (brix_rmdir(c, dir, &st) != 0) {
        dx_record(e, "write", DX_WARN, st.kxr,
                  "write-probe test directory could not be removed",
                  "remove the leftover write-probe directory under the export root");
    }
}


/*
 * stage path (GATED, conditional): only if the read probe saw an offline file — request
 * a recall via kXR_prepare and report whether the server accepted the stage request.
 */
void
dx_probe_stage(brix_conn *c, const char *target, doctor_ep *e)
{
    const char *paths[1];
    char        out[256];
    brix_status st;

    paths[0] = target;
    brix_status_clear(&st);
    if (brix_prepare(c, paths, 1, 0, 0, 0, out, sizeof(out), &st) == 0) {
        dx_record(e, "stage", DX_OK, 0, "stage/prepare request accepted by the server",
                  "wait for the recall to complete, then re-read");
    } else {
        dx_record_status(e, "stage", &st);
    }
}


/*
 * authz-anon: open a force_anon session (login, NO credential), learn the server's
 * advertised auth from its &P= list, and on an auth-REQUIRED server assert that
 * unauthenticated stat/read is DENIED. A served op on an auth-advertising server is
 * the auth-bypass smoking gun. Writes the discovered sec list to *sec_out so the
 * caller can run the token tests. Returns 1 if the session was established.
 */
int
dx_authz_anon(const diag_args *a, const brix_url *u, const char *target,
              int have_target, char *sec_out, size_t sec_sz, doctor_ep *e)
{
    brix_conn     c;
    brix_status   st;
    brix_statinfo si;
    int           served = 0;

    if (sec_out != NULL && sec_sz > 0) { sec_out[0] = '\0'; }
    if (dx_connect_as(a, u, 1, NULL, NULL, &c, &st) != 0) {
        dx_record(e, "authz-anon", DX_WARN, st.kxr,
                  "could not establish even an unauthenticated session (cannot assess auth posture)",
                  "check reachability and retry when the server is up");
        return 0;
    }
    if (sec_out != NULL && sec_sz > 0) {
        snprintf(sec_out, sec_sz, "%s", c.sec_list);
    }
    if (c.sec_list[0] == '\0') {
        brix_close(&c);
        dx_record(e, "authz-anon", DX_OK, 0,
                  "server requires no authentication (anonymous by design)", "");
        return 1;
    }
    brix_status_clear(&st);
    if (brix_stat(&c, "/", &si, &st) == 0) {
        served = 1;
    }
    if (!served && have_target) {
        brix_file   f;
        brix_status ost;
        brix_status_clear(&ost);
        if (brix_file_open_read(&c, target, &f, &ost) == 0) {
            served = 1;
            brix_file_close(&c, &f, &ost);
        }
    }
    brix_close(&c);
    if (served) {
        dx_record(e, "authz-anon", DX_FAIL, 0,
                  "an unauthenticated client was served data/metadata on an auth-required server (auth bypass)",
                  "the server is not enforcing authentication — audit the auth config and the server build");
    } else {
        dx_record(e, "authz-anon", DX_OK, st.kxr,
                  "unauthenticated access correctly denied", "");
    }
    return 1;
}


/*
 * authz-forged: present a structurally-valid but cryptographically-invalid bearer
 * token (garbage signature, or alg:none). A correct server rejects it at kXR_auth
 * (connect fails). A connect SUCCESS means the server accepted an unverifiable
 * token — exactly the broken-signature-verification class of regression.
 */
void
dx_authz_forged(const diag_args *a, const brix_url *u, const char *probe,
                const char *bad_token, doctor_ep *e)
{
    brix_conn   c;
    brix_status st;

    if (dx_connect_as(a, u, 0, bad_token, "ztn", &c, &st) == 0) {
        brix_close(&c);
        dx_record(e, probe, DX_FAIL, 0,
                  "server ACCEPTED an invalid bearer token (broken token verification)",
                  "CRITICAL: invalid tokens must be rejected — patch/upgrade the server token auth");
    } else if (st.kxr == kXR_NotAuthorized || st.kxr == kXR_AuthFailed
               || st.kxr == XRDC_EAUTH) {
        dx_record(e, probe, DX_OK, st.kxr,
                  "invalid bearer token correctly rejected", "");
    } else {
        /* connect failed for a non-auth reason (e.g. transport) — we did NOT get
         * to test token verification; do not report a false pass. */
        dx_record(e, probe, DX_WARN, st.kxr,
                  "could not complete the forged-token test (server unreachable mid-test)",
                  "retry when the server is reachable");
    }
}


/*
 * authz-expired: present the operator's REAL (validly-signed) token when it has
 * already expired. A correct server rejects on the exp claim. Acceptance means
 * expiry is not enforced.
 */
void
dx_authz_expired(const diag_args *a, const brix_url *u, const char *tok, doctor_ep *e)
{
    brix_conn   c;
    brix_status st;

    if (dx_connect_as(a, u, 0, tok, "ztn", &c, &st) == 0) {
        brix_close(&c);
        dx_record(e, "authz-expired", DX_FAIL, 0,
                  "server ACCEPTED an expired bearer token",
                  "CRITICAL: the server is not enforcing token expiry (exp claim)");
    } else if (st.kxr == kXR_NotAuthorized || st.kxr == kXR_AuthFailed
               || st.kxr == XRDC_EAUTH) {
        dx_record(e, "authz-expired", DX_OK, st.kxr,
                  "expired bearer token correctly rejected", "");
    } else {
        dx_record(e, "authz-expired", DX_WARN, st.kxr,
                  "could not complete the expired-token test (server unreachable mid-test)",
                  "retry when the server is reachable");
    }
}


/*
 * authz-scope (GATED --allow-write): present a read-only token and attempt a write
 * in a unique temp namespace. A correct server denies (kXR_NotAuthorized). A write
 * that SUCCEEDS means token write-scope is not enforced — privilege escalation.
 * Always reverses any mutation.
 */
void
dx_authz_scope(const diag_args *a, const brix_url *u, const char *tok, doctor_ep *e)
{
    brix_conn   c;
    brix_status st;
    char        dir[96];

    if (dx_connect_as(a, u, 0, tok, "ztn", &c, &st) != 0) {
        dx_record(e, "authz-scope", DX_WARN, st.kxr,
                  "read-only token did not authenticate; cannot test write-scope enforcement", "");
        return;
    }
    snprintf(dir, sizeof(dir), "/.xrddiag-az-%ld-%llx", (long) getpid(),
             (unsigned long long) brix_mono_ns());

    /*
     * mkdir IS a write operation: a read-only token must be denied it. Testing it
     * directly avoids the mkdir-then-open ambiguity (if mkdir is denied, a later
     * open-write fails with NotFound, not a scope verdict). The DENIAL CODE is
     * decisive: kXR_NotAuthorized = scope/ACL enforced (correct); kXR_fsReadOnly =
     * read-only export, so we CANNOT isolate scope enforcement (inconclusive);
     * SUCCESS = a read-only token mutated the namespace (scope NOT enforced).
     */
    brix_status_clear(&st);
    if (brix_mkdir(&c, dir, 0700, 0, &st) == 0) {
        dx_record(e, "authz-scope", DX_FAIL, 0,
                  "a read-only token was allowed to create a directory (token scope not enforced)",
                  "CRITICAL: the server is not enforcing token write-scope");
        brix_status_clear(&st);
        brix_rmdir(&c, dir, &st);                 /* reverse our mutation */
    } else if (st.kxr == kXR_NotAuthorized || st.kxr == kXR_AuthFailed
               || st.kxr == XRDC_EAUTH) {
        dx_record(e, "authz-scope", DX_OK, st.kxr,
                  "write (mkdir) correctly denied for a read-only token (scope/ACL enforced)", "");
    } else if (st.kxr == kXR_fsReadOnly) {
        dx_record(e, "authz-scope", DX_WARN, st.kxr,
                  "export is read-only (allow_write off) — cannot isolate token write-scope enforcement",
                  "re-run against a read-write export to test token write-scope");
    } else {
        dx_record(e, "authz-scope", DX_WARN, st.kxr,
                  "write probe failed for an unexpected reason; scope enforcement unclear",
                  "inspect the server logs for this operation");
    }
    brix_close(&c);
}
