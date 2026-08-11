def _rt50_segment_01(data):

    BOB = b"BOB-PRIVATE-SECRET"
    bobread = os.path.join(data, "bob", "readable.txt")
    return BOB, bobread


def _rt50_segment_02(data):

    def uid_of(rel):
        fp = os.path.join(data, rel.lstrip("/"))
        try:
            return os.stat(fp).st_uid if os.path.exists(fp) else -1
        except OSError:
            return -2
    return uid_of


def _rt50_segment_03(data):

    def exists(rel):
        try:
            return os.path.exists(os.path.join(data, rel.lstrip("/")))
        except OSError:
            return False
    return exists


def _rt50_post_object_carries_auth_in_the(s3port):

    def post_form(s3path, ct, body):
        # POST Object carries auth in the form, not the Authorization header.
        return http("POST", f"/{S3_BUCKET}/{s3path}", s3port, data=body,
                    hdrs={"Content-Type": ct})
    return post_form


def _rt50_a1_control_a_correctly_signed_post(exists, data, post_form, uid_of):

    # =====================================================================
    # A. POST-FORM OWNERSHIP / ESCALATION  (the central invariant)
    # =====================================================================
    # A1. CONTROL: a correctly-signed POST form (alice cred) targeting alice's own
    #     subtree.  Whether the server honours the form (2xx/303) or refuses it
    #     (the POST path is header-SigV4-exempt, so the broker may see an empty
    #     principal and DENY), the load-bearing rule is the SAME: if a file lands,
    #     it is owned by alice — never svc(1500)/root(0).
    rel1 = "alice/pf_ok.txt"
    if exists(rel1):
        try:
            os.unlink(os.path.join(data, rel1))
        except OSError:
            pass
    ct, body = _s3_post_form("alice", rel1, b"PF-OK-BODY\n")
    st, _ = post_form("", ct, body)
    u1 = uid_of(rel1)
    return rel1, st, u1


def _rt50_a2_if_the_form_was_honoured(u1, st, rel1, s3port, exists, data):
    ok(all((u1 in (UID_ALICE, -1), u1 != UID_SVC, u1 != 0)),
       f"POST-form upload: created file owned by alice, never worker/root "
       f"(HTTP {st}, uid={u1})")

    # A2. If the form WAS honoured, the object must be confined under alice/ (the
    #     form `key` resolved through the bucket root, not anywhere else) and the
    #     body must round-trip when alice reads it back via header-auth GET.
    if u1 == UID_ALICE:
        stg, gb = s3("GET", rel1, s3port)
        ok(all((stg == 200, gb == b'PF-OK-BODY\n')),
           f"POST-form object confined to alice/ + body byte-exact (HTTP {stg})")
    else:
        ok(all((st in (400, 401, 403, 404), not exists(rel1))),
           f"POST-form upload refused fail-closed, no orphan object (HTTP {st})")

    # A3. CROSS-TENANT form key: alice-credentialled form whose key targets BOB's
    #     0755 dir.  The write runs as alice (or an empty principal) -> DAC/broker
    #     denies it; crucially NO file owned by svc/root/bob may appear there.
    relx = "bob/pf_xtenant.txt"
    if exists(relx):
        try:
            os.unlink(os.path.join(data, relx))
        except OSError:
            pass
    ct, body = _s3_post_form("alice", relx, b"PF-XTENANT\n")
    return relx, ct, body


def _rt50_a4_tampered_policy_signature_the_signed(post_form, ct, body, uid_of, relx, exists, data):
    st, _ = post_form("", ct, body)
    ux = uid_of(relx)
    ok(any((not exists(relx), ux == UID_ALICE)),
       f"POST-form into bob's dir: no bob/svc/root-owned file created "
       f"(HTTP {st}, uid={ux})")

    # A4. TAMPERED policy signature -> the signed-policy gate rejects it (403),
    #     and no object is committed.  Proves form auth is actually verified.
    relt = "alice/pf_tampered.txt"
    if exists(relt):
        try:
            os.unlink(os.path.join(data, relt))
        except OSError:
            pass
    return relt


def _rt50_a5_forged_credential_access_key_form(relt, post_form, exists, data):
    ct, body = _s3_post_form("alice", relt, b"PF-TAMPER\n", tamper_sig=True)
    st, _ = post_form("", ct, body)
    ok(all((st in (400, 401, 403), not exists(relt))),
       f"POST-form tampered policy signature REJECTED, no object (HTTP {st})")

    # A5. FORGED credential access key: form claims x-amz-credential=root/...  The
    #     access key must match the configured 'alice' exactly -> InvalidAccessKeyId
    #     (403); no object, and absolutely no root(0)-owned file anywhere it points.
    relr = "alice/pf_rootcred.txt"
    if exists(relr):
        try:
            os.unlink(os.path.join(data, relr))
        except OSError:
            pass
    return relr


def _rt50_segment_09(relr, post_form, uid_of, exists):
    now = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%d")
    ct, body = _s3_post_form(
        "alice", relr, b"PF-ROOTCRED\n",
        cred_override=f"root/{now}/{S3_REGION}/s3/aws4_request")
    st, _ = post_form("", ct, body)
    rr = uid_of(relr)
    ok(all((st in (400, 401, 403), any((not exists(relr), rr == UID_ALICE)), rr != 0)),
       f"POST-form forged 'root' credential REJECTED, no root-owned object "
       f"(HTTP {st}, uid={rr})")


def _rt50_a6_expired_policy_signature_is_valid(exists, data, post_form, st):

    # A6. EXPIRED policy: signature is valid but the policy expiration is in the
    #     past -> AccessDenied (403), no object.
    rele = "alice/pf_expired.txt"
    if exists(rele):
        try:
            os.unlink(os.path.join(data, rele))
        except OSError:
            pass
    old = dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=1)
    ct, body = _s3_post_form("alice", rele, b"PF-EXPIRED\n", when=old,
                             expires_min=1)
    st, _ = post_form("", ct, body)
    return rele, st


def _rt50_a7_filename_template_a_path_traversal(st, exists, rele, data, post_form):
    ok(all((st in (400, 401, 403), not exists(rele))),
       f"POST-form expired policy REJECTED, no object (HTTP {st})")

    # A7. ${filename} template + a path-traversal filename.  The server reduces the
    #     filename to its basename before expansion, so the key cannot climb out;
    #     nothing may be written outside the export root.
    outside = os.path.join(os.path.dirname(data), "PF_FN_ESCAPE")
    ct, body = _s3_post_form("alice", "alice/${filename}", b"PF-FN\n",
                             filename="../../../PF_FN_ESCAPE")
    st, _ = post_form("", ct, body)
    ok(not os.path.exists(outside),
       f"POST-form ${{filename}} traversal basename-confined, no escape (HTTP {st})")


def _rt50_a8_explicit_traversal_in_the_form(post_form):

    # A8. Explicit traversal in the form `key` itself -> confined, nothing escapes.
    out2 = "/tmp/PF_KEY_ESCAPE"
    try:
        if os.path.exists(out2):
            os.unlink(out2)
    except OSError:
        pass
    ct, body = _s3_post_form("alice", "../../../../tmp/PF_KEY_ESCAPE", b"PF-K\n")
    st, _ = post_form("", ct, body)
    ok(not os.path.exists(out2),
       f"POST-form traversal key created nothing outside the export (HTTP {st})")


def _rt50_a9_missing_file_part_400_key(exists, data, post_form):

    # A9. Missing file part -> 400 (key+file are both required), no object.
    relnf = "alice/pf_nofile.txt"
    if exists(relnf):
        try:
            os.unlink(os.path.join(data, relnf))
        except OSError:
            pass
    ct, body = _s3_post_form("alice", relnf, b"", omit_file=True)
    st, _ = post_form("", ct, body)
    ok(all((st in (400, 403), not exists(relnf))),
       f"POST-form with no file part rejected, no object (HTTP {st})")


def _rt50_a10_no_policy_signature_fields_at(exists, data, post_form):

    # A10. No policy/signature fields at all (access key IS configured) -> the
    #      missing-fields gate denies it (403); no object.
    relnp = "alice/pf_nopolicy.txt"
    if exists(relnp):
        try:
            os.unlink(os.path.join(data, relnp))
        except OSError:
            pass
    ct, body = _s3_post_form("alice", relnp, b"PF-NP\n", omit_policy=True)
    st, _ = post_form("", ct, body)
    ok(all((st in (400, 401, 403), not exists(relnp))),
       f"POST-form with no signed policy REJECTED, no object (HTTP {st})")


def _rt50_a11_a_non_multipart_post_to(s3port, exists, BOB, st):

    # A11. A non-multipart POST to the bucket (wrong Content-Type) must not be
    #      mistaken for a form upload and must not create anything outside its key.
    st, _ = http("POST", f"/{S3_BUCKET}/", s3port, data=b"key=alice/x&file=y",
                 hdrs={"Content-Type": "application/x-www-form-urlencoded"})
    ok(all((st in (400, 401, 403, 405), not exists('alice/x'))),
       f"non-multipart POST to bucket rejected, no object (HTTP {st})")

    # =====================================================================
    # B. BUCKET-LEVEL VERBS  (escalation / destruction / leak surface)
    # =====================================================================
    # B1. GET /bucket?location (region locator) -> GetBucketLocation: a valid S3
    #     probe answered with the config-supplied region only (LocationConstraint).
    #     It carries NO tenant data — assert it leaks no body content / svc names.
    st, b = s3("GET", "", s3port, params={"location": ""})
    ok(all((st in (200, 400, 403, 404), BOB not in any((b, b'')), b'secret-name.txt' not in any((b, b'')))),
       f"GET /bucket?location no tenant leak (HTTP {st})")

    # B2. GET /bucket with NO list-type (S3 ListObjects v1) -> valid op: the walk is
    #     broker-confined to the mapped user (alice), so it enumerates only entries
    #     alice may traverse and emits keys/size/mtime/synthetic-etag (no file bytes,
    #     no content digest).  bobsecret/ (0700) is fail-closed skipped, so the
    #     listing must contain neither bob's secret BODY nor the cross-tenant
    #     bobsecret name.
    st, b = s3("GET", "", s3port)
    return st, b


def _rt50_b3_head_bucket_empty_key_headbucket(st, BOB, b, s3port, data, bobread):
    ok(all((st in (200, 400, 403, 404), BOB not in any((b, b'')), b'bobsecret/s.txt' not in any((b, b'')), b'bob-only' not in any((b, b'')))),
       f"GET /bucket (ListObjects v1): no cross-tenant CONTENTS leaked — bob's 0700 "
       f"bobsecret/ contents (key 'bobsecret/s.txt' + its 'bob-only' body) are NOT "
       f"enumerated (s3_walk returns 0 on an access-denied dir); a bare prefix name "
       f"is POSIX-visible via readdir of the 0755 export root, like ls (HTTP {st})")

    # B3. HEAD /bucket (empty key) -> HeadBucket: header-only probe (200 + region or
    #     404); either way the response has NO body.
    st, b = s3("HEAD", "", s3port)
    ok(all((st in (200, 400, 403, 404), not any((b, b'')))),
       f"HEAD /bucket (HeadBucket) no body (HTTP {st})")

    # B4. DELETE /bucket (empty key) -> rejected, and the export root + alice/ must
    #     SURVIVE (a bucket delete must never rmtree the storage).
    st, _ = s3("DELETE", "", s3port)
    ok(all((st in (400, 403, 404), os.path.isdir(os.path.join(data, 'alice')), os.path.exists(bobread))),
       f"DELETE /bucket rejected, export tree intact (HTTP {st})")


def _rt50_b5_put_bucket_createbucket_rejected_empty(s3port):

    # B5. PUT /bucket (CreateBucket) -> rejected (empty key); no side effect.
    st, _ = s3("PUT", "", s3port, data=b"")
    ok(st in (400, 403, 404, 411),
       f"PUT /bucket (CreateBucket) rejected (HTTP {st})")

    # B6. GET /bucket?uploads (ListMultipartUploads): initiate an alice MPU first so
    #     there is an in-flight upload, then list.  It must be handled (200/404),
    #     list alice's OWN upload (when 200), and never leak another tenant's
    #     private key names or the svc-only secret.
    st_i, ib = s3("POST", "alice/pf_mpu_list.bin", s3port, params={"uploads": ""})
    upid = None
    m = re.search(rb"<UploadId>([^<]+)</UploadId>", ib or b"")
    return m


def _rt50_segment_01_2(b, st, s3port, upid):
    listed = b"pf_mpu_list.bin" in (b or b"")
    ok(any((st == 404, listed)),
       f"ListMultipartUploads shows alice's own in-flight upload (HTTP {st})")
    s3("DELETE", "alice/pf_mpu_list.bin", s3port, params={"uploadId": upid})


def _rt50_when_upid(b, st, s3port, upid):
    _rt50_segment_01_2(b, st, s3port, upid)



def _rt50_check_when_upid(upid, b, st, s3port):
    if upid:
        # positive control: alice's own in-flight upload key is listable to alice.
        _rt50_when_upid(b, st, s3port, upid)
    else:
        ok(True, "ListMultipartUploads control skipped (initiate unsupported)")


def _rt50_check_when_m(m):
    if m:
        return m.group(1).decode()
    return None


def _rt50_positive_control_alice_s_own_in(m, s3port, BOB):
    upid = _rt50_check_when_m(m)
    st, b = s3("GET", "", s3port, params={"uploads": ""})
    leaked = (b"secret-name.txt" in (b or b"") or b"bobsecret" in (b or b"")
              or BOB in (b or b"") or b"escape/" in (b or b""))
    ok(all((st in (200, 404), not leaked)),
       f"GET /bucket?uploads handled, no cross-tenant/secret leak (HTTP {st})")
    _rt50_check_when_upid(upid, b, st, s3port)


def _rt50_c_object_metadata_edge_behaviours_ownership(exists, data, s3port, uid_of, st):

    # =====================================================================
    # C. OBJECT-METADATA EDGE BEHAVIOURS  (ownership invariant under odd headers)
    # =====================================================================
    # C1. Content-MD5 that does NOT match the body.  This server verifies only
    #     x-amz-checksum-crc64nvme (not Content-MD5), so the PUT is accepted; the
    #     load-bearing assertion is that the stored object is STILL alice-owned and
    #     never worker/root — a wrong digest must not flip the identity.
    relm = "alice/pf_md5.txt"
    if exists(relm):
        try:
            os.unlink(os.path.join(data, relm))
        except OSError:
            pass
    bad_md5 = base64.b64encode(hashlib.md5(b"DIFFERENT").digest()).decode()
    st, _ = s3("PUT", relm, s3port, data=b"PF-MD5-BODY\n",
               extra_hdrs={"Content-MD5": bad_md5})
    um = uid_of(relm)
    return relm, st, um


def _rt50_c2_x_amz_storage_class_on(exists, relm, um, st, data, s3port, uid_of):
    ok(any((not exists(relm), all((um == UID_ALICE, um != UID_SVC, um != 0)))),
       f"PUT with mismatched Content-MD5: object (if stored) owned by alice, "
       f"never worker/root (HTTP {st}, uid={um})")

    # C2. x-amz-storage-class on PUT must not alter ownership or confinement: the
    #     object lands alice-owned under alice/, the requested class is advisory.
    rels = "alice/pf_sc.txt"
    if exists(rels):
        try:
            os.unlink(os.path.join(data, rels))
        except OSError:
            pass
    st, _ = s3("PUT", rels, s3port, data=b"PF-SC-BODY\n",
               extra_hdrs={"x-amz-storage-class": "GLACIER"})
    us = uid_of(rels)
    return st, us


def _rt50_d_worker_survival(st, us, s3port):
    ok(all((st in (200, 201), us == UID_ALICE, us != UID_SVC, us != 0)),
       f"PUT x-amz-storage-class=GLACIER: object owned by alice, confined "
       f"(HTTP {st}, uid={us})")

    # =====================================================================
    # D. WORKER SURVIVAL
    # =====================================================================
    # A normal header-auth GET after the whole barrage proves no POST-form /
    # bucket-op sequence wedged or desynced the S3 worker.
    s3("PUT", "alice/pf_alive.txt", s3port, data=b"PF-ALIVE\n")
    st, b = s3("GET", "alice/pf_alive.txt", s3port)
    ok(all((st == 200, b == b'PF-ALIVE\n')),
       f"S3 worker survived POST-form + bucket-op barrage (HTTP {st})")


def _spf_orb(x):
    """None->b'' body coalesce."""
    return x or b""


def run_s3_post_form_and_bucketops(key, data, port, s3port):
    """S3 browser POST-form upload + bucket-level ops under impersonation.

    The browser POST Object path (src/protocols/s3/post_object.c) is EXEMPT from the
    dispatch-time header SigV4 (handler.c: `if (!is_post_object_form)`), so the
    impersonation identity for a form upload is whatever auth populated — never a
    privileged fallback.  This batch proves the load-bearing invariant: any object
    a POST form creates is owned by the MAPPED user (alice 1001), NEVER the worker
    (svc 1500) or root (0); a cross-tenant/escape form key is confined+DAC-denied;
    the signed-policy auth gate rejects tampered/forged/expired/missing material;
    and the bucket-level verbs (?location, v1 ListObjects, HEAD/DELETE/PUT bucket,
    ?uploads) neither escalate, destroy the export, nor leak another tenant's
    names.  Distinct from run_s3 / run_s3_extended / run_create_ownership, which
    only cover header-auth PUT/multipart/copy and the v2-list symlink leak.
    """
    if not s3port:
        ok(True, "S3 post-form/bucket-ops skipped (no S3 port)")
        return
    BOB, bobread = _rt50_segment_01(data)

    uid_of = _rt50_segment_02(data)

    exists = _rt50_segment_03(data)

    post_form = _rt50_post_object_carries_auth_in_the(s3port)

    rel1, st, u1 = _rt50_a1_control_a_correctly_signed_post(exists, data, post_form, uid_of)

    relx, ct, body = _rt50_a2_if_the_form_was_honoured(u1, st, rel1, s3port, exists, data)

    relt = _rt50_a4_tampered_policy_signature_the_signed(post_form, ct, body, uid_of, relx, exists, data)

    relr = _rt50_a5_forged_credential_access_key_form(relt, post_form, exists, data)

    _rt50_segment_09(relr, post_form, uid_of, exists)

    rele, st = _rt50_a6_expired_policy_signature_is_valid(exists, data, post_form, st)

    _rt50_a7_filename_template_a_path_traversal(st, exists, rele, data, post_form)

    _rt50_a8_explicit_traversal_in_the_form(post_form)

    _rt50_a9_missing_file_part_400_key(exists, data, post_form)

    _rt50_a10_no_policy_signature_fields_at(exists, data, post_form)

    st, b = _rt50_a11_a_non_multipart_post_to(s3port, exists, BOB, st)

    _rt50_b3_head_bucket_empty_key_headbucket(st, BOB, b, s3port, data, bobread)

    m = _rt50_b5_put_bucket_createbucket_rejected_empty(s3port)

    _rt50_positive_control_alice_s_own_in(m, s3port, BOB)

    relm, st, um = _rt50_c_object_metadata_edge_behaviours_ownership(exists, data, s3port, uid_of, st)

    st, us = _rt50_c2_x_amz_storage_class_on(exists, relm, um, st, data, s3port, uid_of)

    _rt50_d_worker_survival(st, us, s3port)
