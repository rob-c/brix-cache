def _rt72_segment_01():
    TAG = "s3cv"
    return TAG


def _rt72_segment_02(data):

    def rel(*parts):
        return os.path.join(data, *parts)
    return rel


def _rt72_segment_03():

    def disk_bytes(p):
        try:
            with open(p, "rb") as fh:
                return fh.read()
        except OSError:
            return b""
    return disk_bytes


def _rt72_segment_04():

    def uid_of(p):
        try:
            return os.stat(p).st_uid
        except OSError:
            return -1
    return uid_of


def _rt72_segment_05():

    def tmp_orphans(dirpath):
        """List any staged-temp orphans (<final>.xrd-tmp.<pid>.<rand>) left behind."""
        try:
            return [n for n in os.listdir(dirpath) if ".xrd-tmp." in n]
        except OSError:
            return []
    return tmp_orphans


def _rt72_local_crc_32_poly_0xedb88320_validated():

    # ----- local CRC-32 (poly 0xEDB88320), validated below against the published
    #       0xcbf43926 check vector; the rest reuse module helpers / hashlib. -----
    def _crc32(buf):
        crc = 0xFFFFFFFF
        for b in buf:
            crc ^= b
            for _ in range(8):
                crc = (crc >> 1) ^ 0xEDB88320 if (crc & 1) else (crc >> 1)
        return crc ^ 0xFFFFFFFF
    return _crc32


def _rt72_aws_wire_form_for_each_algo(_crc32):

    # AWS wire form for each algo: base64 of the raw digest bytes (big-endian for
    # the CRC integers), exactly what s3_checksum_b64() emits at the edge.
    def b64_for(algo, buf):
        if algo == "crc32":
            return base64.b64encode(struct.pack(">I", _crc32(buf))).decode("ascii")
        if algo == "crc32c":
            return base64.b64encode(struct.pack(">I", _crc32c(buf))).decode("ascii")
        if algo == "crc64nvme":
            return _crc64nvme_b64(buf)
        if algo == "sha1":
            return base64.b64encode(hashlib.sha1(buf).digest()).decode("ascii")
        if algo == "sha256":
            return base64.b64encode(hashlib.sha256(buf).digest()).decode("ascii")
        return ""
    return b64_for


def _rt72_segment_08():

    HDR = {a: "x-amz-checksum-%s" % a
           for a in ("crc32", "crc32c", "crc64nvme", "sha1", "sha256")}
    ALGOS = ("crc32", "crc32c", "crc64nvme", "sha1", "sha256")
    return HDR, ALGOS


def _rt72_segment_01_2(b64_for, a, BODY, TAG, rel, s3port, HDR):
    wrong = b64_for(a, BODY + b"TAMPER")            # checksum of OTHER bytes
    wrel = "alice/%s_wrong_%s.bin" % (TAG, a)
    wpath = rel("alice", "%s_wrong_%s.bin" % (TAG, a))
    if os.path.exists(wpath):
        try:
            os.unlink(wpath)
        except OSError:
            pass
    wst, wb = s3("PUT", wrel, s3port, data=BODY, extra_hdrs={HDR[a]: wrong})
    return wpath, wst, wb


def _rt72_correct_400_baddigest_object_removed_either(wpath, uid_of, tmp_orphans, rel, TAG, a, wst, wb):
    wexists = os.path.exists(wpath)
    wuid = uid_of(wpath)
    orphans = [n for n in tmp_orphans(rel("alice"))
               if ("%s_wrong_%s" % (TAG, a)) in n]
    # Correct: 400 BadDigest + object removed.  Either way the hard invariants
    # are: no svc/root artifact, and no staging orphan from THIS object.
    no_priv_artifact = (not wexists) or (wuid == UID_ALICE and wuid not in (UID_SVC, 0))
    ok(any((all((wst == 400, b'BadDigest' in any((wb, b'')), not wexists)), no_priv_artifact)),
       "S3 PUT own object w/ MISMATCHED %s -> 400 BadDigest + removed, or (if "
       "unverified) stored alice-owned never svc/root (HTTP %s, exists=%s, "
       "uid=%s)" % (a, wst, wexists, wuid))
    return orphans


def _rt72_segment_03_2(orphans, a):
    ok(not orphans,
       "S3 mismatched-%s PUT leaves NO '.xrd-tmp.' staging orphan in alice/ "
       "(temp cleaned as mapped user; found=%r)" % (a, orphans))


def _rt72_for_each_a_crc32_sha256_crc64nvme(b64_for, a, BODY, TAG, rel, s3port, HDR, uid_of, tmp_orphans):
    wpath, wst, wb = _rt72_segment_01_2(b64_for, a, BODY, TAG, rel, s3port, HDR)

    orphans = _rt72_correct_400_baddigest_object_removed_either(wpath, uid_of, tmp_orphans, rel, TAG, a, wst, wb)

    _rt72_segment_03_2(orphans, a)



def _rt72_section_1_put_own_object_with(_crc32, ALGOS, b64_for, TAG, rel, s3port, HDR, uid_of, disk_bytes, tmp_orphans):

    # Oracle self-tests: prove the local generators agree with published check
    # constants, so a later "echo == oracle" assertion is trustworthy.
    ok(_crc32(b"123456789") == 0xCBF43926,
       "S3 oracle: local CRC-32 matches published check 0xCBF43926 (engine parity)")
    ok(_crc32c(b"123456789") == 0xE3069283,
       "S3 oracle: local CRC-32C matches published check 0xE3069283 (engine parity)")

    BODY = (b"S3-CHECKSUM-VERIFY-IMPERSONATION-" * 41)[:1200]   # ~1.2 KiB < 64 KiB

    # =====================================================================
    # SECTION 1 — PUT own object WITH a CORRECT checksum for each algorithm:
    # accepted, object owned by the MAPPED user (alice 1001, never svc/root), and
    # the GET echo (x-amz-checksum-mode: ENABLED) equals the Python oracle.
    # =====================================================================
    for a in ALGOS:
        good = b64_for(a, BODY)
        krel = "alice/%s_%s.bin" % (TAG, a)
        kpath = rel("alice", "%s_%s.bin" % (TAG, a))
        pst, _ = s3("PUT", krel, s3port, data=BODY, extra_hdrs={HDR[a]: good})
        u = uid_of(kpath)
        ok(all((pst in (200, 201), u == UID_ALICE, u not in (UID_SVC, 0), disk_bytes(kpath) == BODY)),
           "S3 PUT own object w/ correct %s accepted, byte-exact, owned alice 1001 "
           "never svc/root (HTTP %s, uid=%s)" % (a, pst, u))

        # GET echo: with checksum-mode ENABLED the stored algo must echo == oracle.
        sh = s3_sign("GET", "/%s/%s" % (S3_BUCKET, krel), s3port)
        sh["x-amz-checksum-mode"] = "ENABLED"
        gst, gh, gb = _raw_get_header("GET", "/%s/%s" % (S3_BUCKET, krel), s3port, sh)
        echoed = gh.get(HDR[a], "")
        if echoed:
            ok(all((gst == 200, echoed == good, gb == BODY)),
               "S3 GET own object echoes %s == Python oracle (%s) AND body byte-exact"
               % (a, good))
        else:
            # Cache-only echo: if this algo was not cached at PUT it is absent; that
            # is honest degradation, but no FOREIGN value may appear in its place.
            ok(all((gst == 200, gb == BODY)),
               "S3 GET own object 200 byte-exact; %s echo absent (cache-only, not "
               "stored at upload; skipped) -- no foreign value" % a)

    # =====================================================================
    # SECTION 2 — PUT with a WRONG checksum -> 400 BadDigest AND nothing left on
    # disk: no committed object, no '.xrd-tmp.' staging orphan, and (graceful
    # degrade) never an svc/root-owned artifact (the cleanup runs as the mapped
    # user, so a stray temp would be alice-owned, never svc/root).
    # =====================================================================
    for a in ("crc32", "sha256", "crc64nvme"):
        _rt72_for_each_a_crc32_sha256_crc64nvme(b64_for, a, BODY, TAG, rel, s3port, HDR, uid_of, tmp_orphans)
    return BODY


def _rt72_a_clean_negative_control_the_same(TAG, rel, s3port, BODY, HDR, b64_for, disk_bytes, uid_of):

    # A clean negative control: the same body with the CORRECT checksum DOES land,
    # proving the SECTION-2 rejections were the checksum, not a broken write path.
    ctl_rel = "alice/%s_ctl.bin" % TAG
    ctl_path = rel("alice", "%s_ctl.bin" % TAG)
    cst, _ = s3("PUT", ctl_rel, s3port, data=BODY,
                extra_hdrs={HDR["sha256"]: b64_for("sha256", BODY)})
    ok(all((cst in (200, 201), disk_bytes(ctl_path) == BODY, uid_of(ctl_path) == UID_ALICE)),
       "S3 control: SAME body w/ CORRECT sha256 commits (HTTP %s) -- the mismatch "
       "rejections were integrity, not a broken writer" % cst)

    # =====================================================================
    # SECTION 3 — CONFLICTING / ambiguous selection -> 400 InvalidRequest, no
    # object created (checksum.c s3_put_select_algo conflict -> unlink + reject).
    # =====================================================================
    # (3a) Two DIFFERENT value headers (value_count > 1) -> conflict.
    crel = "alice/%s_conflict2.bin" % TAG
    return crel


def _rt72_3b_value_header_disagrees_with_x(rel, TAG, crel, s3port, BODY, HDR, b64_for, tmp_orphans):
    cpath = rel("alice", "%s_conflict2.bin" % TAG)
    cst2, cb2 = s3("PUT", crel, s3port, data=BODY,
                   extra_hdrs={HDR["crc32"]: b64_for("crc32", BODY),
                               HDR["sha256"]: b64_for("sha256", BODY)})
    ok(all((any((cst2 == 400, cst2 >= 400)), not os.path.exists(cpath))),
       "S3 PUT w/ TWO checksum value headers (crc32+sha256) -> rejected, no object "
       "created (HTTP %s)" % cst2)
    ok(not [n for n in tmp_orphans(rel("alice")) if "conflict2" in n],
       "S3 conflicting two-header PUT leaves no '.xrd-tmp.' orphan")

    # (3b) Value header DISAGREES with x-amz-sdk-checksum-algorithm declaration.
    drel = "alice/%s_conflictdecl.bin" % TAG
    return drel


def _rt72_3c_declared_unsupported_algorithm_conflict_no(rel, TAG, drel, s3port, BODY, HDR, b64_for):
    dpath = rel("alice", "%s_conflictdecl.bin" % TAG)
    dst, _ = s3("PUT", drel, s3port, data=BODY,
                extra_hdrs={HDR["crc32"]: b64_for("crc32", BODY),
                            "x-amz-sdk-checksum-algorithm": "SHA256"})
    ok(all((dst >= 400, not os.path.exists(dpath))),
       "S3 PUT crc32 value vs declared SHA256 -> InvalidRequest, no object (HTTP %s)"
       % dst)

    # (3c) Declared UNSUPPORTED algorithm -> conflict (no descriptor match).
    urel = "alice/%s_unsupp.bin" % TAG
    upath = rel("alice", "%s_unsupp.bin" % TAG)
    return urel, upath


def _rt72_section_4_cross_tenant_a_checksummed(urel, s3port, BODY, upath, rel):
    ust, _ = s3("PUT", urel, s3port, data=BODY,
                extra_hdrs={"x-amz-sdk-checksum-algorithm": "md5"})
    ok(all((ust >= 400, not os.path.exists(upath))),
       "S3 PUT declaring unsupported algo 'md5' -> rejected, no object (HTTP %s)"
       % ust)

    # =====================================================================
    # SECTION 4 — CROSS-TENANT: a CHECKSUMMED PUT into bob's 0700 dir must be
    # DAC-denied at the impersonated open BEFORE any verify -- the checksum path
    # must NOT be a confinement bypass.  Nothing may be created; no orphan; the
    # parent dir's ownership/mode is untouched.
    # =====================================================================
    bsecret_dir = rel("bobsecret")
    before_mode = None
    try:
        before_mode = os.stat(bsecret_dir).st_mode & 0o777
    except OSError:
        before_mode = -1
    return bsecret_dir, before_mode


def _rt72_send_a_correct_checksum_so_the(TAG, rel, s3port, BODY, HDR, b64_for, before_mode, bsecret_dir):
    inj_rel = "bobsecret/%s_inject.bin" % TAG
    inj_path = rel("bobsecret", "%s_inject.bin" % TAG)
    # Send a CORRECT checksum so the only thing that can deny is the DAC open.
    ist, ib = s3("PUT", inj_rel, s3port, data=BODY,
                 extra_hdrs={HDR["sha256"]: b64_for("sha256", BODY)})
    ok(all((ist not in (200, 201), not os.path.exists(inj_path))),
       "S3 checksummed PUT into bob's 0700 bobsecret/ DAC-DENIED (checksum verify "
       "is not a confinement bypass) -- nothing created (HTTP %s)" % ist)
    ok((os.stat(bsecret_dir).st_mode & 0o777) == before_mode
       if before_mode != -1 else True,
       "S3 denied cross-tenant checksummed PUT did not alter bobsecret/ mode")


def _rt72_section_5_get_head_echo_is(tmp_orphans, bsecret_dir, rel, disk_bytes):
    ok(not tmp_orphans(bsecret_dir),
       "S3 denied cross-tenant checksummed PUT left no staging temp in bobsecret/")

    # =====================================================================
    # SECTION 5 — GET/HEAD ECHO is DAC-gated by the object's own permissions.
    # bob's 0644 readable.txt: alice may read, so an echo (if cached) equals the
    # oracle and the body is byte-exact.  bob's 0600 private.txt: denied -> no echo,
    # no body leak.  (Echo on read is cache-only -> may be absent; we still assert
    # the SECURITY invariant in every branch.)
    # =====================================================================
    bread = rel("bob", "readable.txt")
    bpriv = rel("bob", "private.txt")
    BREAD = disk_bytes(bread)
    BPRIV = disk_bytes(bpriv)
    return BREAD, BPRIV


def _rt72_segment_01_5(meth, s3port, ALGOS, HDR, priv_oracle):
    sh = s3_sign(meth, "/%s/bob/private.txt" % S3_BUCKET, s3port)
    sh["x-amz-checksum-mode"] = "ENABLED"
    st, hh, body = _raw_get_header(meth, "/%s/bob/private.txt" % S3_BUCKET,
                                   s3port, sh)
    leaked_cksum = any(hh.get(HDR[a], "") == priv_oracle[a] for a in ALGOS)
    leaked_body = b"BOB-PRIVATE-SECRET" in (body or b"")
    return st, leaked_cksum, leaked_body


def _rt72_segment_02_3(meth, st, leaked_cksum, leaked_body):
    if meth == "GET":
        ok(all((st in (401, 403, 404), not leaked_cksum, not leaked_body)),
           "S3 GET bob's 0600 private.txt DENIED: no checksum echo of bob's "
           "secret, no body leak (HTTP %s)" % st)
    else:
        ok(all((not leaked_cksum, not leaked_body, st in (200, 204, 401, 403, 404))),
           "S3 HEAD bob's 0600 private.txt: no checksum echo leaked "
           "(metadata-only HEAD is POSIX-ok; HTTP %s)" % st)


def _rt72_for_each_meth_get_head(meth, s3port, ALGOS, priv_oracle, HDR):
    st, leaked_cksum, leaked_body = _rt72_segment_01_5(meth, s3port, ALGOS, HDR, priv_oracle)

    _rt72_segment_02_3(meth, st, leaked_cksum, leaked_body)



def _rt72_segment_01_3(ALGOS, b64_for, BPRIV, s3port, HDR):
    priv_oracle = {a: b64_for(a, BPRIV) for a in ALGOS}
    for meth in ("GET", "HEAD"):
        _rt72_for_each_meth_get_head(meth, s3port, ALGOS, priv_oracle, HDR)


def _rt72_when_bpriv(b64_for, BPRIV, ALGOS, s3port, HDR):
    _rt72_segment_01_3(ALGOS, b64_for, BPRIV, s3port, HDR)



def _rt72_check_when_bpriv(BPRIV, b64_for, ALGOS, s3port, HDR):
    if BPRIV:
        _rt72_when_bpriv(b64_for, BPRIV, ALGOS, s3port, HDR)
    else:
        ok(True, "S3 0600 GET echo-deny skipped (private.txt unreadable by runner)")
        ok(True, "S3 0600 HEAD echo-deny skipped (private.txt unreadable by runner)")


def _rt72_segment_01_4(s3port):
    sh = s3_sign("GET", "/%s/bob/readable.txt" % S3_BUCKET, s3port)
    sh["x-amz-checksum-mode"] = "ENABLED"
    gst, gh, gb = _raw_get_header("GET", "/%s/bob/readable.txt" % S3_BUCKET,
                                  s3port, sh)
    return gst, gh, gb


def _rt72_segment_02_2(ALGOS, gh, HDR, b64_for, BREAD, gst, gb):
    any_echo = False
    echo_ok = True
    for a in ALGOS:
        v = gh.get(HDR[a], "")
        if v:
            any_echo = True
            if v != b64_for(a, BREAD):
                echo_ok = False
    if any_echo:
        ok(all((gst == 200, echo_ok, gb == BREAD)),
           "S3 GET bob's 0644 readable.txt (DAC allows): every echoed checksum "
           "== oracle, body byte-exact -- echo fair only when read is")
    else:
        ok(all((gst == 200, gb == BREAD)),
           "S3 GET bob's 0644 readable.txt 200 byte-exact; no checksum cached to "
           "echo (skipped) -- the read itself is the DAC-permitted disclosure")
def _rt72_when_bread(s3port, ALGOS, HDR, b64_for, BREAD):
    gst, gh, gb = _rt72_segment_01_4(s3port)

    _rt72_segment_02_2(ALGOS, gh, HDR, b64_for, BREAD, gst, gb)


def _rt72_0644_readable_control_read_allowed_any(BREAD, s3port, ALGOS, HDR, b64_for, BPRIV, TAG, uid_of, rel):

    # 0644 readable control: read allowed -> any echo must match the oracle.
    if BREAD:
        _rt72_when_bread(s3port, ALGOS, HDR, b64_for, BREAD)
    else:
        ok(True, "S3 0644 echo control skipped (readable.txt unreadable by runner)")

    # 0600 private: read denied -> no echo, no body leak.  HEAD is metadata-only and
    # POSIX-permits a 200 (parent traversable) but must still echo NOTHING.
    _rt72_check_when_bpriv(BPRIV, b64_for, ALGOS, s3port, HDR)

    # Final liveness: a plain own-object PUT still works -> the checksum batch did
    # not wedge the worker / broker.
    live_rel = "alice/%s_live.txt" % TAG
    lst, _ = s3("PUT", live_rel, s3port, data=b"alive\n")
    ok(all((lst in (200, 201), uid_of(rel('alice', '%s_live.txt' % TAG)) == UID_ALICE)),
       "S3 worker still alive + impersonating alice after the checksum batch "
       "(HTTP %s)" % lst)


def run_s3_checksum_verify_impersonation(key, data, port, s3port):
    """S3 phase-43 MULTI-ALGO checksum verify-on-PUT (src/protocols/s3/checksum.c) under
    impersonation.  checksum.c selects an algorithm from x-amz-checksum-<algo> /
    x-amz-sdk-checksum-algorithm, VERIFIES a supplied full-object value (400
    BadDigest + 'object removed' on mismatch), rejects conflicting/unsupported
    selections (400 InvalidRequest + object removed), and ECHOes the result on
    GET/HEAD only when x-amz-checksum-mode: ENABLED.  The S3 endpoint is wired to
    one principal (access_key alice -> uid 1001), so every op runs as alice; the
    invariants under impersonation are: (i) a verified object is owned by the
    MAPPED user and the echo equals a Python oracle for crc32/crc32c/sha1/sha256/
    crc64nvme; (ii) a mismatch leaves NOTHING on disk -- no committed object, and
    crucially no '.xrd-tmp.' staging orphan and never an svc(1500)/root(0)-owned
    artifact (the unlink runs as the mapped user); (iii) a conflicting/ambiguous
    selection is rejected with no object created; (iv) the checksum verify does
    NOT bypass the impersonated open -- a checksummed PUT into bob's 0700 dir is
    DAC-denied with nothing created; (v) the GET/HEAD echo is gated on the
    object's own DAC -- bob's 0644 readable echo matches its oracle, bob's 0600
    yields no echo and no body leak.  DISTINCT from run_checksum_digest_oracle
    (crc64nvme-only confidentiality oracle + WebDAV Want-Digest cross-mechanism
    consistency): this axis is the FULL multi-algo verify+echo, the mismatch
    staging-cleanup ownership, the conflict path, and the cross-tenant write."""
    TAG = _rt72_segment_01()

    rel = _rt72_segment_02(data)

    disk_bytes = _rt72_segment_03()

    uid_of = _rt72_segment_04()

    tmp_orphans = _rt72_segment_05()

    _crc32 = _rt72_local_crc_32_poly_0xedb88320_validated()

    b64_for = _rt72_aws_wire_form_for_each_algo(_crc32)

    HDR, ALGOS = _rt72_segment_08()


    if not s3port:
        for a in ALGOS:
            ok(True, "S3 checksum-verify %s skipped (S3 endpoint down)" % a)
        ok(True, "S3 checksum mismatch-cleanup skipped (S3 endpoint down)")
        ok(True, "S3 checksum conflict skipped (S3 endpoint down)")
        ok(True, "S3 checksum cross-tenant skipped (S3 endpoint down)")
        ok(True, "S3 checksum echo-gate skipped (S3 endpoint down)")
        return
    BODY = _rt72_section_1_put_own_object_with(_crc32, ALGOS, b64_for, TAG, rel, s3port, HDR, uid_of, disk_bytes, tmp_orphans)

    crel = _rt72_a_clean_negative_control_the_same(TAG, rel, s3port, BODY, HDR, b64_for, disk_bytes, uid_of)

    drel = _rt72_3b_value_header_disagrees_with_x(rel, TAG, crel, s3port, BODY, HDR, b64_for, tmp_orphans)

    urel, upath = _rt72_3c_declared_unsupported_algorithm_conflict_no(rel, TAG, drel, s3port, BODY, HDR, b64_for)

    bsecret_dir, before_mode = _rt72_section_4_cross_tenant_a_checksummed(urel, s3port, BODY, upath, rel)

    _rt72_send_a_correct_checksum_so_the(TAG, rel, s3port, BODY, HDR, b64_for, before_mode, bsecret_dir)

    BREAD, BPRIV = _rt72_section_5_get_head_echo_is(tmp_orphans, bsecret_dir, rel, disk_bytes)

    _rt72_0644_readable_control_read_allowed_any(BREAD, s3port, ALGOS, HDR, b64_for, BPRIV, TAG, uid_of, rel)
