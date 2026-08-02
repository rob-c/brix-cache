/*
 * diag_check_probe.c - doctor per-endpoint probes + differential authZ suite.
 * Phase-38 split of diag_check.c; behavior-identical.
 */
#include "diag_internal.h"
#include "cli/jsonout.h"

/* auth posture: did we connect anonymously to a server that advertises auth? */
void
dx_probe_auth(const brix_conn *c, doctor_ep *e)
{
    int anon = (c->diag.chosen_auth == NULL);
    if (anon && c->sec_list[0] != '\0') {
        dx_record(e, &(dx_note){ "auth", DX_WARN, 0,
                  "server advertises auth but the client connected anonymously",
                  "provide matching credentials (--auth + token/proxy) if operations are denied" });
    } else {
        dx_record(e, &(dx_note){ "auth", DX_OK, 0,
                  anon ? "anonymous (server offered no auth)" : "authenticated", "" });
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
            dx_record(e, &(dx_note){ "namespace", DX_WARN, 0,
                      "export root has no visible files (empty or wrong brix_root)",
                      "confirm data is present under the configured export root" });
        } else {
            dx_record(e, &(dx_note){ "namespace", DX_OK, 0, "export root listable", "" });
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
        dx_record(e, &(dx_note){ "read", DX_WARN, 0, "file is offline (on tape/cache, not staged)",
                  "issue a stage/prepare and retry after recall (use --allow-write for an active stage probe)" });
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
    dx_record(e, &(dx_note){ "read", DX_OK, 0, "read path healthy", "" });
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
            dx_record(e, &(dx_note){ "checksum", DX_OK, 0, "server checksum matches read data", "" });
        } else {
            dx_record(e, &(dx_note){ "checksum", DX_FAIL, 0,
                      "server checksum disagrees with the bytes read (stale checksum DB or data corruption)",
                      "recompute/repair the server checksum; verify storage integrity" });
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
            dx_record(e, &(dx_note){ "write", DX_OK, 0, "write path healthy (write/read-back verified)", "" });
        } else {
            dx_record(e, &(dx_note){ "write", DX_FAIL, 0,
                      "write succeeded but read-back did not match (durability/consistency fault)",
                      "check the server write-through/cache flush path and storage backend" });
        }
    }
    /* always clean up our mutations; warn (no silent residue) if the dir survives. */
    brix_status_clear(&st);
    brix_rm(c, path, &st);
    brix_status_clear(&st);
    if (brix_rmdir(c, dir, &st) != 0) {
        dx_record(e, &(dx_note){ "write", DX_WARN, st.kxr,
                  "write-probe test directory could not be removed",
                  "remove the leftover write-probe directory under the export root" });
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
        dx_record(e, &(dx_note){ "stage", DX_OK, 0, "stage/prepare request accepted by the server",
                  "wait for the recall to complete, then re-read" });
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
    if (dx_connect_as(a, u, &(dx_cred_sel){ .force_anon = 1 }, &c, &st) != 0) {
        dx_record(e, &(dx_note){ "authz-anon", DX_WARN, st.kxr,
                  "could not establish even an unauthenticated session (cannot assess auth posture)",
                  "check reachability and retry when the server is up" });
        return 0;
    }
    if (sec_out != NULL && sec_sz > 0) {
        snprintf(sec_out, sec_sz, "%s", c.sec_list);
    }
    if (c.sec_list[0] == '\0') {
        brix_close(&c);
        dx_record(e, &(dx_note){ "authz-anon", DX_OK, 0,
                  "server requires no authentication (anonymous by design)", "" });
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
        dx_record(e, &(dx_note){ "authz-anon", DX_FAIL, 0,
                  "an unauthenticated client was served data/metadata on an auth-required server (auth bypass)",
                  "the server is not enforcing authentication — audit the auth config and the server build" });
    } else {
        dx_record(e, &(dx_note){ "authz-anon", DX_OK, st.kxr,
                  "unauthenticated access correctly denied", "" });
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

    if (dx_connect_as(a, u, &(dx_cred_sel){ .token_override = bad_token,
                                            .auth_force = "ztn" }, &c, &st) == 0) {
        brix_close(&c);
        dx_record(e, &(dx_note){ probe, DX_FAIL, 0,
                  "server ACCEPTED an invalid bearer token (broken token verification)",
                  "CRITICAL: invalid tokens must be rejected — patch/upgrade the server token auth" });
    } else if (st.kxr == kXR_NotAuthorized || st.kxr == kXR_AuthFailed
               || st.kxr == XRDC_EAUTH) {
        dx_record(e, &(dx_note){ probe, DX_OK, st.kxr,
                  "invalid bearer token correctly rejected", "" });
    } else {
        /* connect failed for a non-auth reason (e.g. transport) — we did NOT get
         * to test token verification; do not report a false pass. */
        dx_record(e, &(dx_note){ probe, DX_WARN, st.kxr,
                  "could not complete the forged-token test (server unreachable mid-test)",
                  "retry when the server is reachable" });
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

    if (dx_connect_as(a, u, &(dx_cred_sel){ .token_override = tok,
                                            .auth_force = "ztn" }, &c, &st) == 0) {
        brix_close(&c);
        dx_record(e, &(dx_note){ "authz-expired", DX_FAIL, 0,
                  "server ACCEPTED an expired bearer token",
                  "CRITICAL: the server is not enforcing token expiry (exp claim)" });
    } else if (st.kxr == kXR_NotAuthorized || st.kxr == kXR_AuthFailed
               || st.kxr == XRDC_EAUTH) {
        dx_record(e, &(dx_note){ "authz-expired", DX_OK, st.kxr,
                  "expired bearer token correctly rejected", "" });
    } else {
        dx_record(e, &(dx_note){ "authz-expired", DX_WARN, st.kxr,
                  "could not complete the expired-token test (server unreachable mid-test)",
                  "retry when the server is reachable" });
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

    if (dx_connect_as(a, u, &(dx_cred_sel){ .token_override = tok,
                                            .auth_force = "ztn" }, &c, &st) != 0) {
        dx_record(e, &(dx_note){ "authz-scope", DX_WARN, st.kxr,
                  "read-only token did not authenticate; cannot test write-scope enforcement", "" });
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
        dx_record(e, &(dx_note){ "authz-scope", DX_FAIL, 0,
                  "a read-only token was allowed to create a directory (token scope not enforced)",
                  "CRITICAL: the server is not enforcing token write-scope" });
        brix_status_clear(&st);
        brix_rmdir(&c, dir, &st);                 /* reverse our mutation */
    } else if (st.kxr == kXR_NotAuthorized || st.kxr == kXR_AuthFailed
               || st.kxr == XRDC_EAUTH) {
        dx_record(e, &(dx_note){ "authz-scope", DX_OK, st.kxr,
                  "write (mkdir) correctly denied for a read-only token (scope/ACL enforced)", "" });
    } else if (st.kxr == kXR_fsReadOnly) {
        dx_record(e, &(dx_note){ "authz-scope", DX_WARN, st.kxr,
                  "export is read-only (allow_write off) — cannot isolate token write-scope enforcement",
                  "re-run against a read-write export to test token write-scope" });
    } else {
        dx_record(e, &(dx_note){ "authz-scope", DX_WARN, st.kxr,
                  "write probe failed for an unexpected reason; scope enforcement unclear",
                  "inspect the server logs for this operation" });
    }
    brix_close(&c);
}
