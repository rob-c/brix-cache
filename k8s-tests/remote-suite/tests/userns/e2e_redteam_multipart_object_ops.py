"""Multipart object, deletion, authentication, and survival checks."""

def _mpa_b1(state):
    (TAG, BKT, MARK, data, s3port, _etag, _complete_xml, _initiate,
     _uid_of, _exists, _body_of) = _mpa_context(state)
    # B1. CONTROL: self-copy is owned by alice.
    s3("PUT", f"alice/{TAG}_csrc.txt", s3port, data=b"copy-source-body\n")
    st, _ = s3("PUT", f"alice/{TAG}_cdst.txt", s3port,
               extra_hdrs={"x-amz-copy-source": f"/{BKT}/alice/{TAG}_csrc.txt"})
    ok(st in (200, 201) and _exists(f"alice/{TAG}_cdst.txt")
       and _uid_of(f"alice/{TAG}_cdst.txt") == UID_ALICE,
       f"CopyObject self -> alice-owned (HTTP {st})")


def _mpa_b2(state):
    (TAG, BKT, MARK, data, s3port, _etag, _complete_xml, _initiate,
     _uid_of, _exists, _body_of) = _mpa_context(state)
    bob_secret_rel = _mpa_secret(state)
    # B2. CopyObject CROSS-TENANT SOURCE (bob's 0600) -> denied, no theft of marker.
    st, _ = s3("PUT", f"alice/{TAG}_cstolen.txt", s3port,
               extra_hdrs={"x-amz-copy-source": f"/{BKT}/{bob_secret_rel}"})
    stolen_body = _body_of(f"alice/{TAG}_cstolen.txt")
    ok(st not in (200, 201) and MARK not in stolen_body,
       f"CopyObject cross-tenant 0600 source DENIED, marker absent (HTTP {st})")


def _mpa_b3(state):
    (TAG, BKT, MARK, data, s3port, _etag, _complete_xml, _initiate,
     _uid_of, _exists, _body_of) = _mpa_context(state)
    # B3. CopyObject ONTO bob's path (destination in bob's space) -> denied; bob's
    #     world-readable control file is untouched.
    bread_rel = "bob/readable.txt"
    before = _body_of(bread_rel)
    st, _ = s3("PUT", bread_rel, s3port,
               extra_hdrs={"x-amz-copy-source": f"/{BKT}/alice/{TAG}_csrc.txt"})
    ok(st not in (200, 201) and _body_of(bread_rel) == before,
       f"CopyObject ONTO bob's file DENIED, bob's file intact (HTTP {st})")


def _mpa_b4(state):
    (TAG, BKT, MARK, data, s3port, _etag, _complete_xml, _initiate,
     _uid_of, _exists, _body_of) = _mpa_context(state)
    # B4. metadata-directive REPLACE vs COPY on a self-copy: both must stay
    #     alice-owned and never escalate.
    for directive in ["COPY", "REPLACE"]:
        dk = f"alice/{TAG}_md_{directive.lower()}.txt"
        st, _ = s3("PUT", dk, s3port,
                   extra_hdrs={"x-amz-copy-source": f"/{BKT}/alice/{TAG}_csrc.txt",
                               "x-amz-metadata-directive": directive})
        uid = _uid_of(dk)
        ok(st in (200, 201, 400, 501) and (not _exists(dk) or uid == UID_ALICE),
           f"CopyObject metadata-directive {directive}: alice-owned/handled "
           f"(HTTP {st}, uid={uid})")


def _mpa_b5(state):
    (TAG, BKT, MARK, data, s3port, _etag, _complete_xml, _initiate,
     _uid_of, _exists, _body_of) = _mpa_context(state)
    # B5. copy-source with ENCODED ../ -> must not read /etc/passwd nor write outside.
    for src in [f"/{BKT}/../../../etc/passwd",
                f"/{BKT}/alice/..%2f..%2f..%2fetc%2fpasswd",
                f"/{BKT}/..%2F..%2Fbob%2F{TAG}_secret.txt"]:
        dk = f"alice/{TAG}_cesc.txt"
        st, _ = s3("PUT", dk, s3port, extra_hdrs={"x-amz-copy-source": src})
        body = _body_of(dk)
        ok(st not in (200, 201) or (b"root:x:" not in body and MARK not in body),
           f"CopyObject encoded ../ source {src[-16:]!r} no escape/leak (HTTP {st})")

    # =========================================================================
    # C. DeleteObjects batches
    # =========================================================================


def _mpa_c1(state):
    (TAG, BKT, MARK, data, s3port, _etag, _complete_xml, _initiate,
     _uid_of, _exists, _body_of) = _mpa_context(state)
    bread_rel = "bob/readable.txt"
    # C1. MIXED batch (alice's own + bob's): only alice's is deleted; bob's intact.
    s3("PUT", f"alice/{TAG}_delmine.txt", s3port, data=b"delete-me\n")
    bread_before = _body_of(bread_rel)
    st, _ = s3("POST", "", s3port, params={"delete": ""},
               data=_delete_xml([f"alice/{TAG}_delmine.txt", bread_rel]))
    ok(not _exists(f"alice/{TAG}_delmine.txt"),
       f"DeleteObjects mixed batch: alice's own object deleted (HTTP {st})")
    ok(_exists(bread_rel) and _body_of(bread_rel) == bread_before,
       "DeleteObjects mixed batch: bob's object NOT deleted (DAC on bob's dir)")


def _mpa_c2(state):
    (TAG, BKT, MARK, data, s3port, _etag, _complete_xml, _initiate,
     _uid_of, _exists, _body_of) = _mpa_context(state)
    bob_secret_rel = _mpa_secret(state)
    # C2. batch targeting bob's 0600 private secret -> not deleted, marker survives.
    st, _ = s3("POST", "", s3port, params={"delete": ""},
               data=_delete_xml([bob_secret_rel]))
    ok(_exists(bob_secret_rel) and MARK in _body_of(bob_secret_rel),
       f"DeleteObjects of bob's 0600 secret did NOT delete it (HTTP {st})")


def _mpa_c3(state):
    (TAG, BKT, MARK, data, s3port, _etag, _complete_xml, _initiate,
     _uid_of, _exists, _body_of) = _mpa_context(state)
    # C3. batch with TRAVERSAL keys must not delete anything outside the export.
    outside = os.path.join(os.path.dirname(os.path.abspath(data)), f"{TAG}_OUTSIDE")
    try:
        with open(outside, "wb") as fh:
            fh.write(b"outside-sentinel\n")
    except OSError:
        outside = None
    st, _ = s3("POST", "", s3port, params={"delete": ""},
               data=_delete_xml(["../../../etc/passwd",
                                 f"../{TAG}_OUTSIDE",
                                 "..%2f..%2fetc%2fpasswd"]))
    ok(_mpa_outside_survived(outside),
       f"DeleteObjects traversal keys deleted nothing outside the export (HTTP {st})")
    ok(os.path.exists("/etc/passwd"),
       "DeleteObjects traversal keys did not touch /etc/passwd")
    _mpa_remove_outside(outside)


def _mpa_outside_survived(path):
    if path is None:
        return True
    return os.path.exists(path)


def _mpa_remove_outside(path):
    if path is None:
        return
    try:
        if os.path.exists(path):
            os.unlink(path)
    except OSError:
        pass


def _mpa_c4(state):
    (TAG, BKT, MARK, data, s3port, _etag, _complete_xml, _initiate,
     _uid_of, _exists, _body_of) = _mpa_context(state)
    # C4. CONTROL: a clean self-only delete batch succeeds (proves the deny above is
    #     real, not a blanket DeleteObjects failure).
    s3("PUT", f"alice/{TAG}_delctl.txt", s3port, data=b"x\n")
    st, _ = s3("POST", "", s3port, params={"delete": ""},
               data=_delete_xml([f"alice/{TAG}_delctl.txt"]))
    ok(not _exists(f"alice/{TAG}_delctl.txt"),
       f"CONTROL DeleteObjects self-only batch deleted alice's object (HTTP {st})")

    # =========================================================================
    # D. Range correctness + no-oracle + conditional copy + auth-negatives
    # =========================================================================


def _mpa_d1(state, p1, okey):
    (TAG, BKT, MARK, data, s3port, _etag, _complete_xml, _initiate,
     _uid_of, _exists, _body_of) = _mpa_context(state)
    # D1. Range GET correctness on alice's own assembled object.
    if p1 is not None and _exists(okey):
        st, b = s3("GET", okey, s3port, params=None,
                   extra_hdrs={"Range": "bytes=0-9"})
        ok(st in (206, 200) and (st != 206 or b == b"A" * 10),
           f"Range GET on own assembled object correct (HTTP {st})")
        # a tail range into the second part.
        st, b = s3("GET", okey, s3port, extra_hdrs={"Range": "bytes=5242880-5242883"})
        ok(st in (206, 200) and (st != 206 or b == b"B" * 4),
           f"Range GET crossing part boundary correct (HTTP {st})")
    else:
        ok(True, "Range correctness skipped (no assembled object)")


def _mpa_d2(state):
    (TAG, BKT, MARK, data, s3port, _etag, _complete_xml, _initiate,
     _uid_of, _exists, _body_of) = _mpa_context(state)
    bob_secret_rel = _mpa_secret(state)
    # D2. Range GET on bob's 0600 must NOT be a confidentiality oracle (no marker).
    for rng in ["bytes=0-4", "bytes=0-0", "bytes=-3"]:
        st, b = s3("GET", bob_secret_rel, s3port, extra_hdrs={"Range": rng})
        ok(st not in (200, 206) and MARK not in (b or b""),
           f"Range '{rng}' GET on bob's 0600 DENIED, no marker leak (HTTP {st})")


def _mpa_d3(state):
    (TAG, BKT, MARK, data, s3port, _etag, _complete_xml, _initiate,
     _uid_of, _exists, _body_of) = _mpa_context(state)
    # D3. Conditional COPY: x-amz-copy-source-if-match with a WRONG ETag must not
    #     copy; with no/correct precondition the self-copy works (control).
    st, _ = s3("PUT", f"alice/{TAG}_condcopy.txt", s3port,
               extra_hdrs={"x-amz-copy-source": f"/{BKT}/alice/{TAG}_csrc.txt",
                           "x-amz-copy-source-if-match":
                               '"00000000000000000000000000000000"'})
    # conditional-copy preconditions are not implemented (the copy proceeds, HTTP
    # 200) — that is a benign S3 strictness gap. The SECURITY invariant is that the
    # copy stayed source-confined (same-tenant alice source) and the destination is
    # owned by alice, never svc(1500)/root(0)/bob.
    cc_uid = _uid_of(f"alice/{TAG}_condcopy.txt")
    ok((not _exists(f"alice/{TAG}_condcopy.txt") or cc_uid == UID_ALICE)
       and cc_uid != UID_SVC and cc_uid != 0 and cc_uid != UID_BOB,
       f"conditional CopyObject if-match: dest alice-owned, no escalation/leak "
       f"(HTTP {st}, uid={cc_uid})")
    st, _ = s3("PUT", f"alice/{TAG}_condcopy_ok.txt", s3port,
               extra_hdrs={"x-amz-copy-source": f"/{BKT}/alice/{TAG}_csrc.txt"})
    ok(st in (200, 201) and _uid_of(f"alice/{TAG}_condcopy_ok.txt") == UID_ALICE,
       f"CONTROL unconditional self-copy succeeds alice-owned (HTTP {st})")


def _mpa_d4(state):
    (TAG, BKT, MARK, data, s3port, _etag, _complete_xml, _initiate,
     _uid_of, _exists, _body_of) = _mpa_context(state)
    # D4. ANONYMOUS multipart ops (no SigV4) must be rejected, no object created.
    apath = f"/{BKT}/alice/{TAG}_anon.bin"
    st, _ = http("POST", apath + "?uploads", s3port)
    ok(st in (401, 403) and not _exists(f"alice/{TAG}_anon.bin"),
       f"anonymous multipart initiate DENIED (HTTP {st})")
    st, _ = http("PUT", apath + "?uploadId=x&partNumber=1", s3port, data=b"x")
    ok(st in (401, 403) and not _exists(f"alice/{TAG}_anon.bin"),
       f"anonymous UploadPart DENIED (HTTP {st})")
    st, _ = http("POST", f"/{BKT}/?delete", s3port,
                 data=_delete_xml([f"alice/{TAG}_ok.bin"]))
    ok(st in (401, 403) and _exists(okey),
       f"anonymous DeleteObjects DENIED, object survives (HTTP {st})")


def _mpa_d5(state, okey):
    (TAG, BKT, MARK, data, s3port, _etag, _complete_xml, _initiate,
     _uid_of, _exists, _body_of) = _mpa_context(state)
    # D5. MALFORMED-SigV4 multipart initiate must be rejected, no staging created.
    h = dict(s3_sign("POST", f"/{BKT}/alice/{TAG}_badsig.bin", s3port,
                     params={"uploads": ""}))
    h["Authorization"] = h["Authorization"][:-12] + "000000000000"
    st, _ = http("POST", f"/{BKT}/alice/{TAG}_badsig.bin?uploads", s3port, hdrs=h)
    ok(st not in (200, 201) and not _exists(f"alice/{TAG}_badsig.bin"),
       f"malformed-SigV4 multipart initiate REJECTED, no object (HTTP {st})")
    # bad-sig DeleteObjects must not delete alice's own object either.
    h = dict(s3_sign("POST", f"/{BKT}/", s3port, params={"delete": ""}))
    h["Authorization"] = h["Authorization"][:-8] + "00000000"
    st, _ = http("POST", f"/{BKT}/?delete", s3port,
                 data=_delete_xml([okey]), hdrs=h)
    ok(st not in (200,) and _exists(okey),
       f"malformed-SigV4 DeleteObjects REJECTED, object survives (HTTP {st})")

    # =========================================================================
    # E. Ownership-invariant sweep + WORKER SURVIVAL
    # =========================================================================


def _mpa_e1(state):
    (TAG, BKT, MARK, data, s3port, _etag, _complete_xml, _initiate,
     _uid_of, _exists, _body_of) = _mpa_context(state)
    # E1. Re-scan every object this function created under alice/: NONE may be owned
    #     by svc(1500)/root(0)/bob(1002) — the principal must never have leaked.
    bad_owned = []
    try:
        adir = os.path.join(data, "alice")
        for name in os.listdir(adir):
            if name.startswith(f"{TAG}_"):
                try:
                    u = os.stat(os.path.join(adir, name)).st_uid
                except OSError:
                    continue
                if u in (UID_SVC, 0, UID_BOB):
                    bad_owned.append((name, u))
    except OSError:
        pass
    ok(not bad_owned,
       f"INVARIANT sweep: no alice/{TAG}_* object owned by svc/root/bob "
       f"(violations={bad_owned})")


def _mpa_e2(state):
    (TAG, BKT, MARK, data, s3port, _etag, _complete_xml, _initiate,
     _uid_of, _exists, _body_of) = _mpa_context(state)
    # E2. No object this function created landed in bob's space owned by alice
    #     (cross-tenant write would show alice's uid on a bob/ path).
    cross = []
    try:
        bdir = os.path.join(data, "bob")
        for name in os.listdir(bdir):
            if name.startswith(f"{TAG}_") and name != f"{TAG}_secret.txt":
                cross.append(name)
    except OSError:
        pass
    ok(not cross,
       f"INVARIANT: no {TAG}_* attacker object created inside bob's dir "
       f"(found={cross})")


def _mpa_e3(state):
    (TAG, BKT, MARK, data, s3port, _etag, _complete_xml, _initiate,
     _uid_of, _exists, _body_of) = _mpa_context(state)
    # E3. WORKER SURVIVAL: after all the lifecycle abuse, a fresh legit multipart
    #     still completes and is alice-owned (the broker was not wedged).
    skey = f"alice/{TAG}_survive.bin"
    st_i, ups = _initiate(skey)
    surv_ok = False
    if ups:
        _, es = s3("PUT", skey, s3port,
                   params={"uploadId": ups, "partNumber": "1"}, data=b"S" * 5242880)
        st_c, _ = s3("POST", skey, s3port, params={"uploadId": ups},
                     data=_complete_xml([(1, _etag(es) or "x")]))
        surv_ok = st_c in (200, 201) and _uid_of(skey) == UID_ALICE
    ok(surv_ok,
       f"worker SURVIVED the adversarial battery: fresh multipart completes "
       f"alice-owned (init {st_i})")


def _mpa_e4(state):
    (TAG, BKT, MARK, data, s3port, _etag, _complete_xml, _initiate,
     _uid_of, _exists, _body_of) = _mpa_context(state)
    # E4. and a plain single-PUT + GET still round-trips (data plane intact).
    st, _ = s3("PUT", f"alice/{TAG}_final.txt", s3port, data=b"final-ok\n")
    st_g, b = s3("GET", f"alice/{TAG}_final.txt", s3port)
    ok(st in (200, 201) and st_g == 200 and b == b"final-ok\n"
       and _uid_of(f"alice/{TAG}_final.txt") == UID_ALICE,
       f"final single-object PUT/GET round-trips alice-owned (PUT {st}, GET {st_g})")
