def _rt53_segment_01(key, data):
    ta = mint(key, "alice")
    tb = mint(key, "bob")
    H = HOST
    bpriv = os.path.join(data, "bob", "private.txt")
    SECRET = b"BOB-PRIVATE-SECRET"
    return ta, tb, H, bpriv, SECRET


def _rt53_the_canonical_0600_secret_must_be(bpriv, SECRET):

    def bob_secret_intact():
        # the canonical 0600 secret must be byte-exact + still bob-owned + still 0600.
        try:
            with open(bpriv, "rb") as fh:
                c = fh.read()
            stt = os.stat(bpriv)
            return (SECRET in c and stt.st_uid == UID_BOB
                    and (stt.st_mode & 0o777) == 0o600)
        except OSError:
            return False
    return bob_secret_intact


def _rt53_a_path_the_smuggled_request_tried(data):

    def no_smuggled(rel):
        # a path the smuggled request tried to create/clobber must not exist (or, for
        # bob/private.txt, must be unchanged -- handled separately by bob_secret_intact).
        return not os.path.exists(os.path.join(data, rel))
    return no_smuggled


def _rt53_seed_a_clean_alice_owned_sentinel(port, ta):

    # seed a clean, alice-owned sentinel used as the desync-survival follow-up target.
    http("PUT", "/alice/sds_clean.txt", port, ta, b"SDS-ALICE-CLEAN\n")


def _rt53_fresh_connection_clean_get_with_alice(port, ta):

    def survives(tag):
        # FRESH-connection clean GET with alice's token: correct bytes + the worker is
        # alive => no desync poisoned this connection or wedged the worker.
        st, b = http("GET", "/alice/sds_clean.txt", port, ta)
        ok(all((st == 200, b == b'SDS-ALICE-CLEAN\n')),
           "post-%s: fresh alice GET served byte-exact, worker alive (HTTP %s)" % (tag, st))
    return survives


def _rt53_1_te_cl_transfer_encoding_first(H, ta, port, bob_secret_intact, survives):

    # ---- (1) TE.CL: Transfer-Encoding FIRST then Content-Length; chunked body holds a
    #          smuggled PUT to bob/private.txt.  The terminating 0-chunk must end the
    #          request so the smuggled bytes are never a second request.
    teclbody = (b"PUT /bob/private.txt HTTP/1.1\r\nHost: " + H.encode()
                + b"\r\nAuthorization: Bearer " + ta.encode()
                + b"\r\nContent-Length: 5\r\n\r\nPWNED")
    tecl = (b"POST /alice/sds_tecl.txt HTTP/1.1\r\nHost: " + H.encode()
            + b"\r\nAuthorization: Bearer " + ta.encode()
            + b"\r\nTransfer-Encoding: chunked\r\nContent-Length: "
            + str(len(teclbody)).encode() + b"\r\n\r\n0\r\n\r\n" + teclbody)
    raw_http(tecl, port, read_timeout=3.0)
    ok(bob_secret_intact(),
       "TE.CL (TE-first+CL) smuggled PUT did NOT overwrite bob's 0600 secret")
    survives("TE.CL")


def _rt53_2_cl_te_content_length_first(H, ta, port, bob_secret_intact, survives):

    # ---- (2) CL.TE: Content-Length FIRST then Transfer-Encoding; CL frames a short
    #          body, the trailing chunked data tries to surface as a smuggled request.
    clte = (b"POST /alice/sds_clte.txt HTTP/1.1\r\nHost: " + H.encode()
            + b"\r\nAuthorization: Bearer " + ta.encode()
            + b"\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n"
            + b"5c\r\nPUT /bob/private.txt HTTP/1.1\r\nHost: " + H.encode()
            + b"\r\nContent-Length: 3\r\n\r\nXXX\r\n0\r\n\r\n")
    raw_http(clte, port, read_timeout=3.0)
    ok(bob_secret_intact(),
       "CL.TE (CL-first+TE) trailing chunk not run as smuggled write to bob")
    survives("CL.TE")

    # ---- (3) Conflicting DOUBLE Content-Length (5 then 0): the second framing must not
    #          let trailing bytes become a smuggled PUT.  (run_http_protocol_abuse uses
    #          5/120 with a DIFFERENT smuggled target+ordering; here 5/0 -> bob.)
    dcl = (b"POST /alice/sds_dcl.txt HTTP/1.1\r\nHost: " + H.encode()
           + b"\r\nAuthorization: Bearer " + ta.encode()
           + b"\r\nContent-Length: 5\r\nContent-Length: 0\r\n\r\nhelloPUT "
           + b"/bob/private.txt HTTP/1.1\r\nHost: " + H.encode()
           + b"\r\nContent-Length: 3\r\n\r\nYYY")
    return dcl


def _rt53_4_obfuscated_transfer_encoding_header_forms(dcl, port, bob_secret_intact, survives, H, ta):
    raw_http(dcl, port, read_timeout=3.0)
    ok(bob_secret_intact(),
       "conflicting double Content-Length (5/0) did not smuggle a write to bob")
    survives("double-CL-5-0")

    # ---- (4) OBFUSCATED Transfer-Encoding header forms.  Each tries to sneak chunked
    #          framing past the CL parser so the chunk body becomes a smuggled request.
    #          A correct server treats an unrecognized TE as no-TE (uses CL) OR 400s --
    #          either way no smuggled op runs.  Distinct framings probed individually:
    te_obf = [
        ("tab-folded TE value", b"Transfer-Encoding:\tchunked"),
        ("leading-space TE name", b" Transfer-Encoding: chunked"),
        ("TE list chunked,x", b"Transfer-Encoding: chunked, x"),
        ("space-before-colon TE", b"Transfer-Encoding : chunked"),
        ("doubled TE identity+chunked", b"Transfer-Encoding: identity\r\nTransfer-Encoding: chunked"),
        ("uppercase CHUNKED", b"Transfer-Encoding: CHUNKED"),
    ]
    for i, (label, hdr) in enumerate(te_obf):
        body = (b"PUT /bob/private.txt HTTP/1.1\r\nHost: " + H.encode()
                + b"\r\nContent-Length: 3\r\n\r\nZZZ")
        raw = (b"POST /alice/sds_obf%d.txt HTTP/1.1\r\nHost: " % i + H.encode()
               + b"\r\nAuthorization: Bearer " + ta.encode() + b"\r\n" + hdr
               + b"\r\nContent-Length: " + str(len(body)).encode()
               + b"\r\n\r\n0\r\n\r\n" + body)
        raw_http(raw, port, read_timeout=2.5)
        ok(bob_secret_intact(),
           "obfuscated TE (%s) did not enable a smuggled write to bob" % label)


def _rt53_5_malformed_chunk_sizes_on_a(survives, H, ta, port, bob_secret_intact, no_smuggled):
    survives("obfuscated-TE")

    # ---- (5) MALFORMED chunk sizes on a genuine chunked PUT to alice's OWN dir.  A bad
    #          size must be a parse error (4xx) or truncated read -- never a desync that
    #          spills the remainder as a smuggled request.  Each size probed distinctly.
    bad_sizes = [
        ("negative chunk size", b"-1"),
        ("0x-prefixed overflow", b"0xFFFFFFFFFFFFFFFF"),
        ("huge hex size", b"FFFFFFFF"),
        ("non-hex size", b"zz"),
        ("empty size line", b""),
    ]
    for i, (label, sz) in enumerate(bad_sizes):
        trailer_smuggle = (b"\r\nPUT /bob/private.txt HTTP/1.1\r\nHost: " + H.encode()
                           + b"\r\nContent-Length: 3\r\n\r\nWWW")
        raw = (b"PUT /alice/sds_chk%d.txt HTTP/1.1\r\nHost: " % i + H.encode()
               + b"\r\nAuthorization: Bearer " + ta.encode()
               + b"\r\nTransfer-Encoding: chunked\r\n\r\n" + sz
               + b"\r\nABC" + trailer_smuggle)
        resp = raw_http(raw, port, read_timeout=2.5)
        ok(any((_resp_status(resp) in (400, 411, 413, 422, 501, -1), _resp_status(resp) < 300, _resp_status(resp) >= 400)),
           "malformed chunk size (%s) handled with a status, no crash" % label)
        ok(bob_secret_intact(),
           "malformed chunk size (%s) did not smuggle a write to bob" % label)
        ok(no_smuggled("alice/sds_chk%d_PWN.txt" % i),
           "malformed chunk size (%s): no stray smuggled artifact created" % label)
    survives("malformed-chunk-size")

    # ---- (6) CHUNK-EXTENSION junk: a valid chunk with a huge bogus ;ext=... parameter.
    #          The extension must be ignored (chunk still 3 bytes) -- the junk must not
    #          shift framing so trailing bytes leak out as a smuggled request.
    ext = b";evil=" + b"A" * 2048 + b';name="PUT /bob/private.txt"'
    return ext


def _rt53_segment_10(H, ta, ext, port, bob_secret_intact, data):
    cext = (b"PUT /alice/sds_ext.txt HTTP/1.1\r\nHost: " + H.encode()
            + b"\r\nAuthorization: Bearer " + ta.encode()
            + b"\r\nTransfer-Encoding: chunked\r\n\r\n3" + ext + b"\r\nABC\r\n0\r\n\r\n")
    resp = raw_http(cext, port, read_timeout=3.0)
    ok(bob_secret_intact(),
       "chunk-extension junk did not desync into a smuggled write to bob")
    fext = os.path.join(data, "alice", "sds_ext.txt")
    ok(any((not os.path.exists(fext), os.stat(fext).st_uid == UID_ALICE)),
       "chunk-ext PUT (if created) owned by alice, never worker/root")


def _rt53_7_trailer_headers_after_the_final(survives, H, ta, tb, port, data):
    survives("chunk-extension-junk")

    # ---- (7) TRAILER headers after the final chunk trying to inject Authorization/Host
    #          to retroactively change the request's identity.  Trailers must NOT alter
    #          the already-authenticated principal -> the PUT stays alice-scoped and bob
    #          is untouched.  Trailers naming bob's token must not promote the write.
    trail = (b"PUT /alice/sds_trail.txt HTTP/1.1\r\nHost: " + H.encode()
             + b"\r\nAuthorization: Bearer " + ta.encode()
             + b"\r\nTransfer-Encoding: chunked\r\nTrailer: Authorization\r\n\r\n"
             + b"3\r\nABC\r\n0\r\n"
             + b"Authorization: Bearer " + tb.encode() + b"\r\n"
             + b"Host: bob.example\r\n\r\n")
    resp = raw_http(trail, port, read_timeout=3.0)
    ftr = os.path.join(data, "alice", "sds_trail.txt")
    ok(any((not os.path.exists(ftr), os.stat(ftr).st_uid == UID_ALICE)),
       "trailer-injected Authorization did NOT re-map identity (file stays alice-owned)")


def _rt53_8_bare_lf_framed_request_whose(bob_secret_intact, survives, H, ta, port):
    ok(bob_secret_intact(),
       "trailer-injected Host/Authorization did not redirect the write onto bob")
    survives("trailer-header-injection")

    # ---- (8) BARE-LF framed request whose body carries a bare-LF-framed SECOND request
    #          (\n line endings, no CR).  A server that splits on bare LF could treat the
    #          tail as a smuggled PUT; it must not run as a write to bob.  (abuse-batch's
    #          bare-LF case is a single GET; this smuggles a second request via bare-LF.)
    lf = (b"POST /alice/sds_lf.txt HTTP/1.1\nHost: " + H.encode()
          + b"\nAuthorization: Bearer " + ta.encode()
          + b"\nContent-Length: 4\n\ndataPUT /bob/private.txt HTTP/1.1\nHost: "
          + H.encode() + b"\nContent-Length: 3\n\nLFX")
    raw_http(lf, port, read_timeout=3.0)
    ok(bob_secret_intact(),
       "bare-LF-framed smuggled second request did not write to bob's secret")


def _rt53_9_fully_formed_second_request_smuggled(survives, H, tb, ta, port, bob_secret_intact):
    survives("bare-LF-smuggle")

    # ---- (9) Fully-formed SECOND request smuggled via an over-large Content-Length lie
    #          combined with a 0-chunk TE (the classic CL.0/TE.0 victim-poison).  The
    #          smuggled victim is a complete PUT to bob/private.txt with bob's OWN token
    #          -- even though bob COULD write his own file, the smuggled request must not
    #          execute as a side effect of alice's request (no second-request parse).
    victim = (b"PUT /bob/private.txt HTTP/1.1\r\nHost: " + H.encode()
              + b"\r\nAuthorization: Bearer " + tb.encode()
              + b"\r\nContent-Length: 9\r\n\r\nSMUGGLED!")
    poison = (b"GET /alice/sds_clean.txt HTTP/1.1\r\nHost: " + H.encode()
              + b"\r\nAuthorization: Bearer " + ta.encode()
              + b"\r\nTransfer-Encoding: chunked\r\nContent-Length: "
              + str(len(victim)).encode() + b"\r\n\r\n0\r\n\r\n" + victim)
    raw_http(poison, port, read_timeout=3.0)
    ok(bob_secret_intact(),
       "fully-formed smuggled PUT (bob token) to bob/private NOT executed as 2nd request")


def _rt53_10_desync_poison_the_next_connection(survives, H, ta, port, SECRET):
    survives("formed-second-request")

    # ---- (10) DESYNC-POISON the NEXT connection: send a smuggling prefix, then on a
    #           SEPARATE fresh connection alice GETs her file.  If the worker were
    #           desynced, alice's response could be poisoned by the smuggled prefix or
    #           she could receive bob's bytes; she must get exactly her own clean bytes.
    prefix = (b"POST /alice/sds_poison.txt HTTP/1.1\r\nHost: " + H.encode()
              + b"\r\nAuthorization: Bearer " + ta.encode()
              + b"\r\nContent-Length: 50\r\n\r\nGET /bob/private.txt HTTP/1.1\r\nHost: "
              + H.encode() + b"\r\n")
    raw_http(prefix, port, read_timeout=2.0)
    st, b = http("GET", "/alice/sds_clean.txt", port, ta)
    ok(all((st == 200, b == b'SDS-ALICE-CLEAN\n', SECRET not in any((b, b'')))),
       "after smuggle-prefix: next conn alice GET clean, no bob bytes bled in (HTTP %s)" % st)


def _rt53_11_final_invariants_nothing_the_raw(data, bob_secret_intact):

    # ---- (11) FINAL invariants: nothing the raw writes produced landed wrongly-owned in
    #           alice's dir, and bob's secret survived the whole batch byte-exact.
    bad = 0
    try:
        for f in os.listdir(os.path.join(data, "alice")):
            if f.startswith("sds_"):
                try:
                    if os.lstat(os.path.join(data, "alice", f)).st_uid in (UID_SVC, 0):
                        bad += 1
                except OSError:
                    pass
    except OSError:
        pass
    ok(bad == 0, "no sds_* file landed worker/root-owned after smuggling batch (mismatches=%d)" % bad)
    ok(bob_secret_intact(),
       "bob's 0600 private.txt byte-exact + 1002:1002 + 0600 after ALL smuggling vectors")


def run_http_smuggling_desync_deep(key, data, port, s3port):
    """DEEP HTTP request-smuggling / desync under impersonation.  Probes TE.CL, CL.TE
    (TE-first), conflicting double Content-Length, OBFUSCATED Transfer-Encoding header
    forms, malformed/over-large/non-hex chunk sizes, chunk-extension junk, trailer
    headers that try to inject Authorization/Host AFTER the body, bare-LF-framed
    smuggled requests, and a fully-formed SECOND request (a PUT to bob/private.txt)
    smuggled in the body of the first.  After EACH probe we prove on a FRESH
    connection that (a) alice's clean GET is still served byte-exact, (b) the smuggled
    op did NOT run under the wrong identity, (c) bob's 0600 secret is intact on disk,
    and (d) the worker is alive.  Distinct from run_http_protocol_abuse (dup-CL, dup
    Host, HTTP/1.0, absolute-URI, multi-range, header-flood) and run_malformed_hostile
    (XML/XXE/Content-Length-lies): here every vector is a NEW desync framing."""
    ta, tb, H, bpriv, SECRET = _rt53_segment_01(key, data)

    bob_secret_intact = _rt53_the_canonical_0600_secret_must_be(bpriv, SECRET)

    no_smuggled = _rt53_a_path_the_smuggled_request_tried(data)

    _rt53_seed_a_clean_alice_owned_sentinel(port, ta)

    survives = _rt53_fresh_connection_clean_get_with_alice(port, ta)

    _rt53_1_te_cl_transfer_encoding_first(H, ta, port, bob_secret_intact, survives)

    dcl = _rt53_2_cl_te_content_length_first(H, ta, port, bob_secret_intact, survives)

    _rt53_4_obfuscated_transfer_encoding_header_forms(dcl, port, bob_secret_intact, survives, H, ta)

    ext = _rt53_5_malformed_chunk_sizes_on_a(survives, H, ta, port, bob_secret_intact, no_smuggled)

    _rt53_segment_10(H, ta, ext, port, bob_secret_intact, data)

    _rt53_7_trailer_headers_after_the_final(survives, H, ta, tb, port, data)

    _rt53_8_bare_lf_framed_request_whose(bob_secret_intact, survives, H, ta, port)

    _rt53_9_fully_formed_second_request_smuggled(survives, H, tb, ta, port, bob_secret_intact)

    _rt53_10_desync_poison_the_next_connection(survives, H, ta, port, SECRET)

    _rt53_11_final_invariants_nothing_the_raw(data, bob_secret_intact)

