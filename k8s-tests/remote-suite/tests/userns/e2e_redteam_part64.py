def _rt64_segment_01(key):
    import zlib
    TAG = "cdo"
    ta = mint(key, "alice")
    return zlib, TAG, ta


def _rt64_segment_02(data):

    def rel(*parts):
        return os.path.join(data, *parts)
    return rel


def _rt64_segment_03():

    def disk_bytes(p):
        try:
            with open(p, "rb") as fh:
                return fh.read()
        except OSError:
            return b""
    return disk_bytes


def _rt64_segment_04():

    def uid_of(p):
        try:
            return os.stat(p).st_uid
        except OSError:
            return -1
    return uid_of


def _rt64_python_content_oracles_for_every_algorithm(zlib):

    # ---- Python content oracles for every algorithm the module emits ----
    def hex_digests(content):
        return {
            "adler32": "%08x" % (zlib.adler32(content) & 0xffffffff),
            "crc32":   "%08x" % (zlib.crc32(content) & 0xffffffff),
            "md5":     hashlib.md5(content).hexdigest(),
            "sha256":  hashlib.sha256(content).hexdigest(),
        }
    return hex_digests


def _rt64_alice_s_known_content_file_write(TAG, port, ta, rel, uid_of, disk_bytes):

    # alice's known-content file (write it via WebDAV PUT as alice).
    A_CONTENT = b"CHECKSUM-DIGEST-ORACLE-alice-" * 37          # ~1 KiB, < 64 KiB cap
    a_rel = "alice/%s_own.bin" % TAG
    st, _ = http("PUT", "/" + a_rel, port, ta, A_CONTENT)
    ap = rel("alice", "%s_own.bin" % TAG)
    ok(all((st in (200, 201, 204), uid_of(ap) == UID_ALICE, disk_bytes(ap) == A_CONTENT)),
       "setup: alice's known-content file written, owned alice 1001, byte-exact "
       "(HTTP %s, uid=%s)" % (st, uid_of(ap)))
    return A_CONTENT, a_rel


def _rt64_bob_s_fixtures_with_their_real(hex_digests, A_CONTENT, rel, disk_bytes):
    A = hex_digests(A_CONTENT)

    # bob's fixtures, with their REAL on-disk digests (the runner can read them; this
    # makes the leak assertion EXACT regardless of fixture trailing bytes).
    bpriv = rel("bob", "private.txt")                          # 0600 — alice DENIED
    bread = rel("bob", "readable.txt")                         # 0644 — alice allowed
    BPRIV_BYTES = disk_bytes(bpriv)
    BREAD_BYTES = disk_bytes(bread)
    return A, BPRIV_BYTES, BREAD_BYTES


def _rt64_segment_08(BPRIV_BYTES, hex_digests, BREAD_BYTES):
    BPRIV = hex_digests(BPRIV_BYTES) if BPRIV_BYTES else {}
    BREAD = hex_digests(BREAD_BYTES) if BREAD_BYTES else {}
    ALGOS = ["adler32", "md5", "sha-256", "crc32"]             # RFC3230 request tokens
    NORM = {"adler32": "adler32", "md5": "md5", "sha-256": "sha256", "crc32": "crc32"}
    return BPRIV, BREAD, ALGOS, NORM


def _rt64_xrdhttp_flavoured_headers_maximise_the_chance():

    # XrdHttp-flavoured headers maximise the chance the digest path activates.
    def want_hdrs(alg, token):
        return {"Authorization": "Bearer " + token,
                "Want-Digest": alg, "X-Xrootd-Proto": "1.0"}
    return want_hdrs


def _rt64_segment_10():

    def parse_digest(hmap):
        """Return {algo_lower: hexvalue} from a 'Digest: algo=hex[, ...]' header."""
        out = {}
        dv = hmap.get("digest", "")
        for tok in dv.replace(";", ",").split(","):
            tok = tok.strip()
            if "=" in tok:
                a, _, v = tok.partition("=")
                out[a.strip().lower()] = v.strip()
        return out
    return parse_digest


def _rt64_section_a_webdav_want_digest_of(ALGOS, NORM, a_rel, port, want_hdrs, ta, parse_digest, A):

    # =====================================================================
    # SECTION A — WebDAV Want-Digest of OWN file: digest emitted + MATCHES oracle.
    # =====================================================================
    self_digest = {}                                           # algo -> value seen
    for alg in ALGOS:
        norm = NORM[alg]
        gst, gh, gb = _raw_get_header("GET", "/" + a_rel, port, want_hdrs(alg, ta))
        dmap = parse_digest(gh)
        if norm in dmap:
            self_digest[norm] = dmap[norm]
            ok(dmap[norm].lower() == A[norm],
               "WebDAV GET Want-Digest:%s of OWN file -> Digest %s MATCHES Python "
               "content oracle (%s)" % (alg, norm, A[norm]))
        else:
            # Feature may be gated to XrdHttp clients / unsupported algo — degrade
            # honestly, but still assert NO foreign digest snuck in and GET succeeded.
            ok(gst == 200,
               "WebDAV GET Want-Digest:%s of OWN file served 200 (Digest header not "
               "emitted for this algo; skipped)" % alg)

    # HEAD path emits the Digest from a separate fd-open; prove parity with GET.
    hst, hh, _hb = _raw_get_header("HEAD", "/" + a_rel, port,
                                   want_hdrs("sha-256", ta))
    hmap = parse_digest(hh)
    if "sha256" in hmap:
        ok(hmap["sha256"].lower() == A["sha256"],
           "WebDAV HEAD Want-Digest:sha-256 of OWN file MATCHES oracle (head/get "
           "parity, no body needed to leak)")
    else:
        ok(hst in (200, 204),
           "WebDAV HEAD Want-Digest:sha-256 of OWN file 200/204 (Digest not emitted "
           "on HEAD; skipped)")


def _rt64_self_test_the_helper_against_the(A_CONTENT, TAG, s3port, rel):
    s3_self = _crc64nvme_b64(A_CONTENT)
    # self-test the helper against the published NVME check constant first.
    ok(_crc64nvme(b"123456789") == 0xAE8B14860A799888,
       "S3 oracle: local CRC-64/NVME matches published check constant "
       "0xAE8B14860A799888 (engine parity vs src/core/compat/crc64.c)")
    # D1: PUT own object WITH a correct crc64nvme -> accepted (server verifies).
    s3_rel = "alice/%s_s3.bin" % TAG
    pst, _ = s3("PUT", s3_rel, s3port, data=A_CONTENT,
                extra_hdrs={"x-amz-checksum-crc64nvme": s3_self})
    sp = rel("alice", "%s_s3.bin" % TAG)
    return s3_self, s3_rel, pst, sp


def _rt64_d2_put_with_a_wrong_crc64nvme(pst, uid_of, sp, disk_bytes, A_CONTENT, TAG, rel):
    ok(all((pst in (200, 201), uid_of(sp) == UID_ALICE, disk_bytes(sp) == A_CONTENT)),
       "S3 PUT own object with CORRECT x-amz-checksum-crc64nvme accepted + owned "
       "alice (HTTP %s)" % pst)
    # D2: PUT with a WRONG crc64nvme -> rejected (BadDigest) and NOT stored.
    wrong_rel = "alice/%s_s3wrong.bin" % TAG
    wp = rel("alice", "%s_s3wrong.bin" % TAG)
    if os.path.exists(wp):
        try:
            os.unlink(wp)
        except OSError:
            pass
    bad = _crc64nvme_b64(A_CONTENT + b"X")                 # checksum of OTHER bytes
    return wrong_rel, wp, bad


def _rt64_correct_behaviour_400_baddigest_object_removed(wrong_rel, s3port, A_CONTENT, bad, uid_of, wp, s3_rel):
    wst, _ = s3("PUT", wrong_rel, s3port, data=A_CONTENT,
                extra_hdrs={"x-amz-checksum-crc64nvme": bad})
    # Correct behaviour: 400 BadDigest + object removed.  If a config doesn't
    # verify header-form checksums it may store it — that is degraded, but the
    # security invariant that MUST hold either way is no identity escalation: a
    # forged checksum must never flip the object off alice (svc/root).
    wuid = uid_of(wp)
    ok(any((all((wst not in (200, 201), not os.path.exists(wp))), all((os.path.exists(wp), wuid == UID_ALICE, wuid not in (UID_SVC, 0))))),
       "S3 PUT own object with MISMATCHED crc64nvme rejected+removed, or (if "
       "verification not wired) stored STILL alice-owned never svc/root "
       "(HTTP %s, uid=%s)" % (wst, wuid))
    # D3: GET own object echoes x-amz-checksum-crc64nvme == oracle.
    sh = s3_sign("GET", "/%s/%s" % (S3_BUCKET, s3_rel), s3port)
    gst, gh, _b = _raw_get_header("GET", "/%s/%s" % (S3_BUCKET, s3_rel),
                                  s3port, sh)
    return gst, gh


def _rt64_d4_head_own_object_same_cache(gh, gst, s3_self, s3_rel, s3port):
    echoed = gh.get("x-amz-checksum-crc64nvme", "")
    if echoed:
        ok(all((gst == 200, echoed == s3_self)),
           "S3 GET own object echoes x-amz-checksum-crc64nvme MATCHING the "
           "base64-of-8-BE-bytes oracle (%s)" % s3_self)
    else:
        ok(gst == 200,
           "S3 GET own object 200 (crc64nvme echo absent — cache-only, not "
           "stored at upload; skipped)")
    # D4: HEAD own object — same cache-only echo path, metadata only.
    sh = s3_sign("HEAD", "/%s/%s" % (S3_BUCKET, s3_rel), s3port)
    hst, hh2, _b = _raw_get_header("HEAD", "/%s/%s" % (S3_BUCKET, s3_rel),
                                   s3port, sh)
    he = hh2.get("x-amz-checksum-crc64nvme", "")
    return hst, he


def _rt64_d5_get_head_bob_s_0600(hst, he, s3_self, BPRIV_BYTES, s3port, s3_rel):
    ok(all((hst == 200, any((not he, he == s3_self)))),
       "S3 HEAD own object: any crc64nvme echo equals oracle, never a foreign "
       "value (HTTP %s)" % hst)
    # D5: GET/HEAD bob's 0600 -> DENIED, no crc64nvme of bob's secret leaked.
    if BPRIV_BYTES:
        bob_b64 = _crc64nvme_b64(BPRIV_BYTES)
        for meth in ("GET", "HEAD"):
            sh = s3_sign(meth, "/%s/bob/private.txt" % S3_BUCKET, s3port)
            st, hmh, body = _raw_get_header(meth,
                                            "/%s/bob/private.txt" % S3_BUCKET,
                                            s3port, sh)
            leaked = (hmh.get("x-amz-checksum-crc64nvme", "") == bob_b64) or \
                     (b"BOB-PRIVATE-SECRET" in (body or b""))
            if meth == "GET":
                ok(all((st in (401, 403, 404), not leaked)),
                   "S3 GET bob's 0600 DENIED, no body/crc64nvme leak (HTTP %s)"
                   % st)
            else:
                ok(all((not leaked, st in (200, 204, 401, 403, 404))),
                   "S3 HEAD bob's 0600: no crc64nvme echoed (metadata-only HEAD "
                   "is POSIX-ok; HTTP %s)" % st)
    else:
        ok(True, "S3 cross-tenant crc64nvme deny skipped (bob fixture)")
        ok(True, "S3 HEAD cross-tenant crc64nvme deny skipped")
    # D6: anonymous (no SigV4) GET must not yield a digest oracle either.
    ast, ah, _b = _raw_get_header("GET", "/%s/%s" % (S3_BUCKET, s3_rel),
                                  s3port, {})
    ok(all((ast in (401, 403), 'x-amz-checksum-crc64nvme' not in ah)),
       "S3 anonymous GET of alice's object denied + no crc64nvme oracle leaked "
       "(HTTP %s)" % ast)


def _rt64_when_s3port(A_CONTENT, TAG, s3port, rel, uid_of, disk_bytes, BPRIV_BYTES):
    s3_self, s3_rel, pst, sp = _rt64_self_test_the_helper_against_the(A_CONTENT, TAG, s3port, rel)

    wrong_rel, wp, bad = _rt64_d2_put_with_a_wrong_crc64nvme(pst, uid_of, sp, disk_bytes, A_CONTENT, TAG, rel)

    gst, gh = _rt64_correct_behaviour_400_baddigest_object_removed(wrong_rel, s3port, A_CONTENT, bad, uid_of, wp, s3_rel)

    hst, he = _rt64_d4_head_own_object_same_cache(gh, gst, s3_self, s3_rel, s3port)

    _rt64_d5_get_head_bob_s_0600(hst, he, s3_self, BPRIV_BYTES, s3port, s3_rel)



def _rt64_the_security_boundary_is_the_digest(ALGOS, NORM, port, want_hdrs, ta, parse_digest, BPRIV):
    for alg in ALGOS:
        norm = NORM[alg]
        for meth in ("GET", "HEAD"):
            st, hh, bb = _raw_get_header(meth, "/bob/private.txt", port,
                                         want_hdrs(alg, ta))
            dmap = parse_digest(hh)
            bobval = BPRIV.get(norm, "\x00never")
            leaked = (dmap.get(norm, "").lower() == bobval) or \
                     (bobval and bobval.encode() in (bb or b"")) or \
                     (b"BOB-PRIVATE-SECRET" in (bb or b""))
            # The security boundary is the DIGEST/CONTENT, not stat metadata.
            # A GET of bob's 0600 must be DENIED (a 200 would leak the body).
            # A HEAD returns only stat metadata (size/etag) of a 0600 file whose
            # PARENT (bob/, 0755) alice may traverse -> a 200 HEAD is standard
            # POSIX, and the digest is correctly gated behind the impersonated
            # open (EACCES -> no Digest header).  So for HEAD accept 200 PROVIDED
            # no digest value / secret leaked; for GET require an outright denial.
            if meth == "GET":
                ok(all((st in (401, 403, 404), not leaked)),
                   "WebDAV GET Want-Digest:%s of bob's 0600 DENIED, no body/"
                   "%s digest leaked (HTTP %s)" % (alg, norm, st))
            else:
                ok(all((not leaked, st in (200, 204, 401, 403, 404))),
                   "WebDAV HEAD Want-Digest:%s of bob's 0600: no %s digest "
                   "leaked (metadata-only HEAD ok; HTTP %s)" % (alg, norm, st))


def _rt64_and_the_control_read_must_equal(port, want_hdrs, ta, parse_digest, BREAD, BREAD_BYTES):
    gst, gh, _gb = _raw_get_header("GET", "/bob/readable.txt", port,
                                   want_hdrs("sha-256", ta))
    dmap = parse_digest(gh)
    if "sha256" in dmap:
        ok(all((gst == 200, dmap['sha256'].lower() == BREAD['sha256'])),
           "WebDAV control: alice GETs bob's 0644 readable.txt sha-256 (DAC "
           "allows) and it MATCHES oracle — digest fair only when read is")
    else:
        ok(gst == 200,
           "WebDAV control: alice GETs bob's 0644 readable.txt 200 (Digest not "
           "emitted; the read itself is the disclosure, which DAC permits)")
    # And the control read must equal the on-disk bytes (no other file served).
    ok(all((gst == 200, any((_gb, b'')) == BREAD_BYTES)),
       "WebDAV control: bob's 0644 GET body is exactly readable.txt (the digest "
       "describes the SAME bytes alice is allowed to read)")


def _rt64_when_bread_bytes(port, want_hdrs, ta, parse_digest, BREAD, BREAD_BYTES):
    _rt64_and_the_control_read_must_equal(port, want_hdrs, ta, parse_digest, BREAD, BREAD_BYTES)



def _rt64_segment_01_3(ALGOS):
    for alg in ALGOS:
        ok(True, "WebDAV cross-tenant Want-Digest:%s deny skipped "
                 "(bob fixture unreadable by runner)" % alg)
        ok(True, "WebDAV HEAD cross-tenant Want-Digest:%s deny skipped" % alg)


def _rt64_otherwise_bpriv_bytes(ALGOS):
    _rt64_segment_01_3(ALGOS)



def _rt64_section_b_cross_tenant_denial_alice(BPRIV_BYTES, ALGOS, NORM, port, want_hdrs, ta, parse_digest, BPRIV, BREAD_BYTES, BREAD, s3port, A_CONTENT, TAG, rel, uid_of, disk_bytes):

    # =====================================================================
    # SECTION B — CROSS-TENANT DENIAL: alice asks for bob's 0600 digest.  Must be
    # refused AND must NOT echo any of bob's real on-disk digest strings (the leak).
    # =====================================================================
    if BPRIV_BYTES:
        _rt64_the_security_boundary_is_the_digest(
            ALGOS, NORM, port, want_hdrs, ta, parse_digest, BPRIV
        )
    else:
        _rt64_otherwise_bpriv_bytes(ALGOS)

    # The whole Digest response header for the denied request must carry NO digest at
    # all (no partial computation before the DAC check).
    st, hh, _b = _raw_get_header("GET", "/bob/private.txt", port,
                                 want_hdrs("md5", ta))
    ok(all((st in (401, 403, 404), 'digest' not in hh)),
       "WebDAV denied cross-tenant request emits NO Digest header (digest gated "
       "behind the open, computed only after DAC) (HTTP %s)" % st)

    # =====================================================================
    # SECTION C — CONTROL: bob's 0644 readable.txt digest IS obtainable by alice and
    # MATCHES its oracle (DAC permits the read, so the digest is a FAIR disclosure).
    # =====================================================================
    if BREAD_BYTES:
        _rt64_when_bread_bytes(port, want_hdrs, ta, parse_digest, BREAD, BREAD_BYTES)
    else:
        ok(True, "WebDAV 0644-control digest skipped (readable.txt unreadable)")
        ok(True, "WebDAV 0644-control body skipped")

    # =====================================================================
    # SECTION D — S3 x-amz-checksum-crc64nvme as the same oracle, base64-of-bytes form.
    # =====================================================================
    if s3port:
        _rt64_when_s3port(A_CONTENT, TAG, s3port, rel, uid_of, disk_bytes, BPRIV_BYTES)
    else:
        for _i in range(8):
            ok(True, "S3 checksum-oracle leg skipped (S3 endpoint down)")


def _rt64_segment_01_2(a_rel, A):
    rc, out, _e = xrd_fs(["query", "checksum", "/" + a_rel], "alice")
    out_l = (out or "").lower()
    ok(rc == 0, "root:// query checksum of alice's OWN file succeeds (rc=%s)" % rc)
    matched = False
    for norm, val in (("adler32", A["adler32"]), ("crc32", A["crc32"]),
                      ("md5", A["md5"]), ("sha256", A["sha256"])):
        if norm in out_l and val in out_l:
            matched = True
            ok(val in out_l,
               "root:// query checksum %s of alice's file EQUALS the Python "
               "oracle AND the WebDAV Digest (one engine, cross-protocol "
               "agreement)" % norm)
            break
    return rc, matched


def _rt64_cross_tenant_the_digest_output_must(matched, rc, BPRIV):
    if not matched:
        ok(rc == 0,
           "root:// query checksum returned a (crc32c/crc64/other) algo not in "
           "the WebDAV/Python oracle set — handled, no false fail")
    # cross-tenant: the digest output must not contain bob's secret bytes (the
    # deny itself is covered by run_root_deep; here we assert ZERO secret leak in
    # any returned text even if some algo were mistakenly emitted).
    rc2, out2, _e = xrd_fs(["query", "checksum", "/bob/private.txt"], "alice")
    ok(all((rc2 != 0, 'BOB-PRIVATE-SECRET' not in any((out2, '')), any((not BPRIV, BPRIV.get('md5', 'zz') not in any((out2, '')).lower())))),
       "root:// query checksum of bob's 0600 DENIED with NO bob digest/secret "
       "text in output (rc=%s)" % rc2)


def _rt64_when_xrd_avail(a_rel, A, BPRIV):
    rc, matched = _rt64_segment_01_2(a_rel, A)

    _rt64_cross_tenant_the_digest_output_must(matched, rc, BPRIV)



def _rt64_section_e_root_query_checksum_cross(a_rel, A, BPRIV, TAG, port, want_hdrs, ta, s3port):

    # =====================================================================
    # SECTION E — root:// query checksum: cross-MECHANISM consistency (one engine).
    # The digest of alice's SAME inode via root:// must equal the WebDAV Digest value
    # for whichever algo both emit — proving a single content-fingerprint engine, and
    # that no protocol is a softer oracle than another.
    # =====================================================================
    if xrd_avail():
        _rt64_when_xrd_avail(a_rel, A, BPRIV)
    else:
        ok(True, "root:// query-checksum consistency skipped (native client absent)")
        ok(True, "root:// query-checksum oracle-match skipped (native client absent)")
        ok(True, "root:// query-checksum cross-tenant deny skipped (client absent)")

    # =====================================================================
    # SECTION F — nonexistent file digest -> clean error, never a fabricated value.
    # =====================================================================
    miss = "/alice/%s_nope.bin" % TAG
    st, hh, _b = _raw_get_header("GET", miss, port, want_hdrs("sha-256", ta))
    ok(all((st == 404, 'digest' not in hh)),
       "WebDAV Want-Digest of NONEXISTENT file -> 404, no fabricated Digest header "
       "(HTTP %s)" % st)
    if s3port:
        sh = s3_sign("GET", "/%s/alice/%s_nope.bin" % (S3_BUCKET, TAG), s3port)
        st, hh, _b = _raw_get_header("GET",
                                     "/%s/alice/%s_nope.bin" % (S3_BUCKET, TAG),
                                     s3port, sh)
        ok(all((st in (403, 404), 'x-amz-checksum-crc64nvme' not in hh)),
           "S3 GET checksum of NONEXISTENT object -> error, no fabricated checksum "
           "header (HTTP %s)" % st)
    else:
        ok(True, "S3 nonexistent-checksum skipped (S3 endpoint down)")


def _rt64_section_g_liveness_the_digest_storm(TAG, port, ta, uid_of, rel):
    if xrd_avail():
        rc, out, _e = xrd_fs(["query", "checksum", "/alice/%s_nope.bin" % TAG],
                             "alice")
        ok(rc != 0, "root:// query checksum of NONEXISTENT file -> error (rc=%s)" % rc)
    else:
        ok(True, "root:// nonexistent-checksum skipped (native client absent)")

    # =====================================================================
    # SECTION G — LIVENESS: the digest storm did not wedge / strand a principal.
    # =====================================================================
    lst, _ = http("PUT", "/alice/%s_live.txt" % TAG, port, ta, b"CDO-LIVE\n")
    gst, gb = http("GET", "/alice/%s_live.txt" % TAG, port, ta)
    ok(all((lst in (200, 201, 204), gst == 200, gb == b'CDO-LIVE\n', uid_of(rel('alice', '%s_live.txt' % TAG)) == UID_ALICE)),
       "liveness: worker still serves a fresh alice PUT+GET byte-exact after the "
       "digest-oracle storm (PUT %s, GET %s)" % (lst, gst))


def run_checksum_digest_oracle(key, data, port, s3port):
    """CHECKSUM / DIGEST endpoints as a CROSS-TENANT CONFIDENTIALITY ORACLE under
    impersonation.  A content digest is a partial read: revealing the adler32 / md5 /
    sha256 / crc64nvme of a file the caller cannot READ leaks a fingerprint enabling
    offline content-guessing.  Under map mode the digest MUST be computed AS THE
    MAPPED USER and DAC-gated exactly like a read.  Distinct from run_dataplane_
    integrity (which oracle-matches a root:// query-checksum of OWN files only): here
    the novel angle is the cross-tenant digest DENIAL across THREE mechanisms — WebDAV
    "Want-Digest:"->"Digest:", S3 x-amz-checksum-crc64nvme echo, and root:// query
    checksum — each proven by (a) own-file digest succeeds AND equals a Python content
    oracle, (b) bob's 0600 private.txt digest is DENIED with NONE of bob's real on-disk
    digest strings present in the response, (c) bob's 0644 readable.txt digest IS
    obtainable (control: DAC permits the read so the digest is fair) and matches its
    oracle, (d) nonexistent-file digest is a clean error, plus cross-mechanism digest
    equality (same inode, same engine).  Worker proven alive afterwards."""
    zlib, TAG, ta = _rt64_segment_01(key)

    rel = _rt64_segment_02(data)

    disk_bytes = _rt64_segment_03()

    uid_of = _rt64_segment_04()

    hex_digests = _rt64_python_content_oracles_for_every_algorithm(zlib)

    A_CONTENT, a_rel = _rt64_alice_s_known_content_file_write(TAG, port, ta, rel, uid_of, disk_bytes)

    A, BPRIV_BYTES, BREAD_BYTES = _rt64_bob_s_fixtures_with_their_real(hex_digests, A_CONTENT, rel, disk_bytes)

    BPRIV, BREAD, ALGOS, NORM = _rt64_segment_08(BPRIV_BYTES, hex_digests, BREAD_BYTES)

    want_hdrs = _rt64_xrdhttp_flavoured_headers_maximise_the_chance()

    parse_digest = _rt64_segment_10()

    _rt64_section_a_webdav_want_digest_of(ALGOS, NORM, a_rel, port, want_hdrs, ta, parse_digest, A)

    _rt64_section_b_cross_tenant_denial_alice(BPRIV_BYTES, ALGOS, NORM, port, want_hdrs, ta, parse_digest, BPRIV, BREAD_BYTES, BREAD, s3port, A_CONTENT, TAG, rel, uid_of, disk_bytes)

    _rt64_section_e_root_query_checksum_cross(a_rel, A, BPRIV, TAG, port, want_hdrs, ta, s3port)

    _rt64_section_g_liveness_the_digest_storm(TAG, port, ta, uid_of, rel)
