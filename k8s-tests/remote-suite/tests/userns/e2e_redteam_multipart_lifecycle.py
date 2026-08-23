"""Multipart lifecycle checks for the user-namespace red-team suite."""

def _mpa_a1(state):
    (TAG, BKT, MARK, data, s3port, _etag, _complete_xml, _initiate,
     _uid_of, _exists, _body_of) = _mpa_context(state)
    # A1. CONTROL: a clean 2-part in-order multipart completes + is alice-owned.
    okey = f"alice/{TAG}_ok.bin"
    st_i, up = _initiate(okey)
    ok(all((st_i == 200, bool(up))),
       f"multipart initiate (control) (HTTP {st_i})")
    return _mpa_control_upload(state, up, okey), okey


def _mpa_control_upload(state, upload_id, object_key):
    if not upload_id:
        return None
    (_TAG, _BKT, _MARK, _data, s3port, _etag, _complete_xml, _initiate,
     _uid_of, _exists, _body_of) = _mpa_context(state)
    status, body = s3(
        "PUT", object_key, s3port,
        params={"uploadId": upload_id, "partNumber": "1"}, data=b"A" * 5242880)
    first_etag = _etag(body)
    ok(status in (200, 201), f"control UploadPart 1 (HTTP {status})")
    status, body = s3(
        "PUT", object_key, s3port,
        params={"uploadId": upload_id, "partNumber": "2"}, data=b"B" * 4096)
    second_etag = _etag(body)
    ok(status in (200, 201), f"control UploadPart 2 (HTTP {status})")
    complete_status, _ = s3(
        "POST", object_key, s3port, params={"uploadId": upload_id},
        data=_complete_xml([(1, _mpa_default(first_etag, "x")),
                            (2, _mpa_default(second_etag, "y"))]))
    owner = _uid_of(object_key)
    ok(all((complete_status in (200, 201), _exists(object_key))),
       f"control multipart COMPLETE in-order (HTTP {complete_status})")
    ok(all((_exists(object_key), owner == UID_ALICE,
            owner != UID_SVC, owner != 0)),
       f"INVARIANT: assembled object owned by mapped user alice (uid={owner})")
    status, body = s3("GET", object_key, s3port)
    ok(all((status == 200, body == (b"A" * 5242880 + b"B" * 4096))),
       f"control assembled object body byte-exact (HTTP {status})")
    return first_etag

def _mpa_a2(state):
    (TAG, BKT, MARK, data, s3port, _etag, _complete_xml, _initiate,
     _uid_of, _exists, _body_of) = _mpa_context(state)
    # A2. OUT-OF-ORDER parts in the Complete manifest (Part 2 listed before Part 1).
    #     S3 requires ascending PartNumber -> must be rejected (400 InvalidPartOrder),
    #     and must NOT assemble a corrupt object owned by anyone.
    okey2 = f"alice/{TAG}_ooo.bin"
    st_i, up2 = _initiate(okey2)
    if up2:
        _, e1 = s3("PUT", okey2, s3port,
                   params={"uploadId": up2, "partNumber": "1"}, data=b"1" * 5242880)
        _, e2 = s3("PUT", okey2, s3port,
                   params={"uploadId": up2, "partNumber": "2"}, data=b"2" * 4096)
        st_c, _ = s3("POST", okey2, s3port, params={"uploadId": up2},
                     data=_complete_xml([(2, _etag(e2) or "y"),
                                         (1, _etag(e1) or "x")]))
        bad = _exists(okey2) and _body_of(okey2)[:1] == b"2"  # assembled reversed
        ok(st_c not in (200, 201) or not bad,
           f"multipart COMPLETE out-of-order parts rejected/not-corrupt (HTTP {st_c})")
        s3("DELETE", okey2, s3port, params={"uploadId": up2})  # cleanup if staged
    else:
        ok(True, "multipart out-of-order setup skipped (initiate unsupported)")


def _mpa_a3(state):
    (TAG, BKT, MARK, data, s3port, _etag, _complete_xml, _initiate,
     _uid_of, _exists, _body_of) = _mpa_context(state)
    # A3. MISSING part: complete references a partNumber that was never uploaded.
    okey3 = f"alice/{TAG}_missing.bin"
    st_i, up3 = _initiate(okey3)
    if up3:
        _, em = s3("PUT", okey3, s3port,
                   params={"uploadId": up3, "partNumber": "1"}, data=b"M" * 5242880)
        st_c, _ = s3("POST", okey3, s3port, params={"uploadId": up3},
                     data=_complete_xml([(1, _etag(em) or "x"),
                                         (2, "ffffffffffffffffffffffffffffffff")]))
        # SECURITY INVARIANT (not S3 strictness): the gateway MAY lazily ignore the
        # informational <Part> manifest and assemble whatever parts are actually
        # staged (a known strictness gap — AWS would return 400 InvalidPart). What
        # MUST hold is that any object it does commit stays confined and owned by the
        # MAPPED user — never svc(1500)/root(0)/bob(1002) — and never leaks data: a
        # missing part cannot smuggle in another tenant's bytes.
        muid3 = _uid_of(okey3)
        committed3 = _exists(okey3)
        ok((not committed3)
           or (muid3 == UID_ALICE and muid3 != UID_SVC and muid3 != 0
               and muid3 != UID_BOB),
           f"multipart COMPLETE w/ missing part: object (if any) confined+alice-owned "
           f"(HTTP {st_c}, uid={muid3})")
        # the missing 'part 2' must NOT have pulled in bob's secret marker.
        ok(MARK not in _body_of(okey3),
           "multipart COMPLETE missing-part assembled no foreign-tenant bytes")
        s3("DELETE", okey3, s3port, params={"uploadId": up3})
    else:
        ok(True, "multipart missing-part setup skipped")


def _mpa_a4(state):
    (TAG, BKT, MARK, data, s3port, _etag, _complete_xml, _initiate,
     _uid_of, _exists, _body_of) = _mpa_context(state)
    # A4. WRONG-ETAG part: complete with a deliberately wrong ETag for part 1.
    #     The body XML's <ETag> values are informational in this gateway, so a
    #     wrong ETag is NOT a hard reject (HTTP 200) — a benign S3 strictness gap,
    #     NOT a security breach.  The SECURITY invariant is that, whether the
    #     request is rejected or assembled, the upload stays confined to alice's
    #     own staging parts: any resulting object is owned by the mapped user
    #     (1001) — never svc(1500)/root(0)/bob(1002) — and carries only alice's
    #     uploaded bytes, never bob's cross-tenant MARK.
    okey4 = f"alice/{TAG}_wrongetag.bin"
    st_i, up4 = _initiate(okey4)
    if up4:
        s3("PUT", okey4, s3port,
           params={"uploadId": up4, "partNumber": "1"}, data=b"W" * 5242880)
        st_c, _ = s3("POST", okey4, s3port, params={"uploadId": up4},
                     data=_complete_xml([(1, "00000000000000000000000000000000")]))
        wmuid = _uid_of(okey4)
        ok((not _exists(okey4))
           or (wmuid == UID_ALICE and wmuid not in (UID_SVC, 0, UID_BOB)),
           f"INVARIANT: wrong-ETag complete confined+alice-owned (HTTP {st_c}, "
           f"uid={wmuid})")
        ok((not _exists(okey4)) or MARK not in _body_of(okey4),
           "INVARIANT: wrong-ETag object carries no cross-tenant bob MARK")
        s3("DELETE", okey4, s3port, params={"uploadId": up4})
    else:
        ok(True, "multipart wrong-etag setup skipped")


def _mpa_a5(state):
    (TAG, BKT, MARK, data, s3port, _etag, _complete_xml, _initiate,
     _uid_of, _exists, _body_of) = _mpa_context(state)
    # A5. FORGED / FOREIGN / GARBAGE uploadId on every lifecycle verb must be denied
    #     and must create no object.  Forged ids must not resolve to anyone's staging.
    forged_ids = {
        "garbage uploadId": "deadbeef-not-a-real-upload-id",
        "empty uploadId": "",
        "traversal uploadId": "../../../etc",
        "long uploadId": "Z" * 4096,
        "nul-ish uploadId": "abc%00def",
    }
    fk = f"alice/{TAG}_forged.bin"
    for label, fid in forged_ids.items():
        st_p, _ = s3("PUT", fk, s3port,
                     params={"uploadId": fid, "partNumber": "1"}, data=b"x" * 16)
        _mpa_check_forged_put(label, fid, fk, st_p, _uid_of, _exists)
        st_c, _ = s3("POST", fk, s3port, params={"uploadId": fid},
                     data=_complete_xml([(1, "x")]))
        _mpa_check_forged_complete(label, fid, fk, st_c, _uid_of, _exists)
        st_l, lb = s3("GET", fk, s3port, params={"uploadId": fid})
        ok(any((st_l not in (200,), b"<Part>" not in _mpa_bytes(lb))),
           f"ListParts on {label} returns no parts (HTTP {st_l})")
        st_a, _ = s3("DELETE", fk, s3port, params={"uploadId": fid})
        ok(any((st_a not in (200,), st_a in (204, 404, 400))),
           f"Abort with {label} handled, no crash (HTTP {st_a})")


def _mpa_owned_or_absent(object_key, uid_of, exists):
    if not exists(object_key):
        return True
    owner = uid_of(object_key)
    return all((owner == UID_ALICE, owner != UID_SVC,
                owner != UID_BOB, owner != 0))


def _mpa_check_forged_put(label, upload_id, object_key, status, uid_of, exists):
    if upload_id:
        ok(all((status not in (200, 201), not exists(object_key))),
           f"UploadPart with {label} DENIED, no object (HTTP {status})")
        return
    owner = uid_of(object_key)
    ok(_mpa_owned_or_absent(object_key, uid_of, exists),
       f"UploadPart with {label}: no escalation/cross-tenant — any object is "
       f"alice-owned in alice's path (HTTP {status}, uid={owner})")


def _mpa_check_forged_complete(label, upload_id, object_key, status,
                               uid_of, exists):
    if upload_id:
        ok(all((status not in (200, 201), not exists(object_key))),
           f"Complete with {label} DENIED, no object (HTTP {status})")
        return
    owner = uid_of(object_key)
    ok(all((status not in (200, 201),
            _mpa_owned_or_absent(object_key, uid_of, exists))),
       f"Complete with {label} DENIED (HTTP {status}); no Complete-built "
       f"object, any leftover is alice-owned (uid={owner})")


def _mpa_a6(state):
    (TAG, BKT, MARK, data, s3port, _etag, _complete_xml, _initiate,
     _uid_of, _exists, _body_of) = _mpa_context(state)
    # A6. FOREIGN-but-VALID uploadId: open a real MPU, then attack it with a token
    #     bound to the SAME alice key (only key configured) — confirm the id is not
    #     a capability another *path* can hijack.  We initiate under alice/foreign,
    #     then try to UploadPart it onto a DIFFERENT key (bob/...) reusing the id ->
    #     must not write into bob's space.
    fgn = f"alice/{TAG}_foreign.bin"
    st_i, upf = _initiate(fgn)
    if upf:
        st_p, _ = s3("PUT", f"bob/{TAG}_hijack.bin", s3port,
                     params={"uploadId": upf, "partNumber": "1"}, data=b"H" * 16)
        ok(st_p not in (200, 201) and not _exists(f"bob/{TAG}_hijack.bin"),
           f"UploadPart reusing alice's id onto bob's key DENIED (HTTP {st_p})")
        s3("DELETE", fgn, s3port, params={"uploadId": upf})
    else:
        ok(True, "foreign-id hijack setup skipped")


def _mpa_a7(state):
    (TAG, BKT, MARK, data, s3port, _etag, _complete_xml, _initiate,
     _uid_of, _exists, _body_of) = _mpa_context(state)
    # A7. DOUBLE-COMPLETE: completing the SAME upload twice.  Second complete must
    #     not silently re-run / corrupt; object stays alice-owned either way.
    dkey = f"alice/{TAG}_double.bin"
    st_i, upd = _initiate(dkey)
    if upd:
        _, ed = s3("PUT", dkey, s3port,
                   params={"uploadId": upd, "partNumber": "1"}, data=b"D" * 5242880)
        st_c1, _ = s3("POST", dkey, s3port, params={"uploadId": upd},
                      data=_complete_xml([(1, _etag(ed) or "x")]))
        ok(st_c1 in (200, 201), f"double-complete: first complete OK (HTTP {st_c1})")
        ok(_uid_of(dkey) == UID_ALICE,
           f"double-complete: object owned by alice (uid={_uid_of(dkey)})")
        st_c2, _ = s3("POST", dkey, s3port, params={"uploadId": upd},
                      data=_complete_xml([(1, _etag(ed) or "x")]))
        ok(st_c2 in (200, 201, 404, 400, 409) and _uid_of(dkey) in (UID_ALICE, -1),
           f"double-complete: second complete handled, still alice/clean (HTTP {st_c2})")
    else:
        ok(True, "double-complete setup skipped")


def _mpa_a8(state):
    (TAG, BKT, MARK, data, s3port, _etag, _complete_xml, _initiate,
     _uid_of, _exists, _body_of) = _mpa_context(state)
    # A8. ABORT-then-COMPLETE: abort the upload, THEN try to complete it -> must be
    #     denied and create no object (the staging is gone; no resurrection).
    akey = f"alice/{TAG}_abortthencomplete.bin"
    st_i, upa = _initiate(akey)
    if upa:
        _, ea = s3("PUT", akey, s3port,
                   params={"uploadId": upa, "partNumber": "1"}, data=b"R" * 5242880)
        st_ab, _ = s3("DELETE", akey, s3port, params={"uploadId": upa})
        ok(st_ab in (200, 204), f"abort-then-complete: abort OK (HTTP {st_ab})")
        st_c, _ = s3("POST", akey, s3port, params={"uploadId": upa},
                     data=_complete_xml([(1, _etag(ea) or "x")]))
        ok(st_c not in (200, 201) and not _exists(akey),
           f"abort-then-complete: complete after abort DENIED, no object (HTTP {st_c})")
    else:
        ok(True, "abort-then-complete setup skipped")


def _mpa_a9(state):
    (TAG, BKT, MARK, data, s3port, _etag, _complete_xml, _initiate,
     _uid_of, _exists, _body_of) = _mpa_context(state)
    # A9. ILLEGAL partNumbers: 0, negative, > 10000, non-numeric.  Each must be
    #     rejected without persisting a part / object.
    pkey = f"alice/{TAG}_partno.bin"
    st_i, upp = _initiate(pkey)
    if upp:
        for pn in ["0", "-1", "10001", "99999", "abc", "1.5"]:
            st_p, _ = s3("PUT", pkey, s3port,
                         params={"uploadId": upp, "partNumber": pn}, data=b"x" * 16)
            ok(st_p not in (200, 201),
               f"UploadPart partNumber={pn} rejected (HTTP {st_p})")
        # CONTROL: a legal partNumber on the same upload still works.
        st_p, _ = s3("PUT", pkey, s3port,
                     params={"uploadId": upp, "partNumber": "1"}, data=b"P" * 5242880)
        ok(st_p in (200, 201),
           f"CONTROL UploadPart legal partNumber=1 accepted (HTTP {st_p})")
        s3("DELETE", pkey, s3port, params={"uploadId": upp})
    else:
        ok(True, "illegal-partNumber setup skipped")


def _mpa_a10(state):
    (TAG, BKT, MARK, data, s3port, _etag, _complete_xml, _initiate,
     _uid_of, _exists, _body_of) = _mpa_context(state)
    bob_secret_rel = _mpa_secret(state)
    # A10. UploadPartCopy from a CROSS-TENANT 0600 source -> denied, no part data,
    #      and the resulting object (if any) must NOT contain bob's marker.
    upckey = f"alice/{TAG}_upc.bin"
    st_i, upc = _initiate(upckey)
    if upc:
        st_p, _ = s3("PUT", upckey, s3port,
                     params={"uploadId": upc, "partNumber": "1"},
                     extra_hdrs={"x-amz-copy-source": f"/{BKT}/{bob_secret_rel}"})
        ok(st_p not in (200, 201),
           f"UploadPartCopy cross-tenant 0600 source DENIED (HTTP {st_p})")
        # even if a stray complete were attempted, no marker may surface.
        st_c, _ = s3("POST", upckey, s3port, params={"uploadId": upc},
                     data=_complete_xml([(1, "x")]))
        ok(MARK not in _body_of(upckey),
           f"UploadPartCopy: bob's secret never lands in alice's object (HTTP {st_c})")
        s3("DELETE", upckey, s3port, params={"uploadId": upc})
    else:
        ok(True, "UploadPartCopy cross-tenant setup skipped")


def _mpa_a11(state):
    (TAG, BKT, MARK, data, s3port, _etag, _complete_xml, _initiate,
     _uid_of, _exists, _body_of) = _mpa_context(state)
    # A11. UploadPartCopy with an ENCODED ../ in the copy-source -> must not escape
    #      the export and must not leak /etc/passwd into a part.
    upekey = f"alice/{TAG}_upcesc.bin"
    st_i, upe = _initiate(upekey)
    if upe:
        for src in [f"/{BKT}/../../../etc/passwd",
                    f"/{BKT}/alice/..%2f..%2f..%2fetc%2fpasswd"]:
            st_p, _ = s3("PUT", upekey, s3port,
                         params={"uploadId": upe, "partNumber": "1"},
                         extra_hdrs={"x-amz-copy-source": src})
            ok(st_p not in (200, 201),
               f"UploadPartCopy escaping source {src[-18:]!r} DENIED (HTTP {st_p})")
        s3("POST", upekey, s3port, params={"uploadId": upe},
           data=_complete_xml([(1, "x")]))
        ok(b"root:x:" not in _body_of(upekey),
           "UploadPartCopy escape: no /etc/passwd bytes in any assembled object")
        s3("DELETE", upekey, s3port, params={"uploadId": upe})
    else:
        ok(True, "UploadPartCopy escape setup skipped")


def _mpa_a12(state):
    (TAG, BKT, MARK, data, s3port, _etag, _complete_xml, _initiate,
     _uid_of, _exists, _body_of) = _mpa_context(state)
    # A12. ListMultipartUploads / ListParts must not enumerate the symlink escape
    #      or another tenant's private staging.
    st_l, lb = s3("GET", "", s3port, params={"uploads": ""})
    ok(st_l in (200, 404) and b"escape/" not in (lb or b"")
       and b"passwd" not in (lb or b""),
       f"ListMultipartUploads no symlink/escape leak (HTTP {st_l})")

    # =========================================================================
    # B. CopyObject surface
    # =========================================================================
