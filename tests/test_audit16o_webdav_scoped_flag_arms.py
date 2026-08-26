"""Test cases for audit16o_webdav_scoped_flag_arms — preamble (fixtures/helpers/mocks) lives in
_test_audit16o_webdav_scoped_flag_arms_helpers.py; reexported below so pytest resolves fixtures in
this module's namespace (split for the 600 logical-line file cap)."""
from split_continuation import reexport as _reexport
_reexport(globals(), "_test_audit16o_webdav_scoped_flag_arms_helpers")


class TestTheZipAccessArm:
    """``get_zip_member_serve`` (get.c:152-172) returns NGX_DECLINED before it
    looks at the query string when the flag is clear, so the GET falls through to
    the whole-file path.  Both arms therefore answer 200 for the same URI and the
    reading is the BODY — a status-only table would say the flag does nothing."""

    @pytest.mark.parametrize("host,prefix", ZIP_ON)
    def test_the_enabled_arm_serves_the_member(self, sc, host, prefix):
        """The control every row below is measured against: with the flag set,
        `xrdcl.unzip` selects one member of the archive."""
        r = _unzip(sc, host, prefix, MEMBER_NAME)
        assert r.status_code == 200, (r.status_code, sc.errlog()[-2000:])
        assert r.content == MEMBER, r.content[:80]

    @pytest.mark.parametrize("host,prefix", ZIP_OFF)
    def test_the_disabled_arm_serves_the_whole_archive(self, sc, host, prefix):
        """The same request on every clear arm — written `off` in a location,
        absent, written `off` in a location under a server that wrote `on`, and
        written `off` in a server{} — yields the archive itself.  The argument is
        not refused, it is not read."""
        r = _unzip(sc, host, prefix, MEMBER_NAME)
        assert r.status_code == 200, (r.status_code, sc.errlog()[-2000:])
        assert r.content.startswith(b"PK\x03\x04"), r.content[:80]
        assert r.content != MEMBER
        assert MEMBER in r.content, "the member is IN the archive it served"

    def test_the_opt_out_is_the_reading_absence_cannot_express(self, sc):
        """The whole point of three legal scopes, in one comparison.

        ``/inherit/`` and ``/opt-out/`` are the same body under the same server;
        the only difference is that one writes ``off``.  The server wrote ``on``,
        so absence in ``/inherit/`` inherits it — which is exactly why ``off`` in
        ``/opt-out/`` is not a redundant spelling of saying nothing.
        """
        inherited = _unzip(sc, SRV_ON, "/inherit/", MEMBER_NAME)
        opted_out = _unzip(sc, SRV_ON, "/opt-out/", MEMBER_NAME)
        assert inherited.status_code == opted_out.status_code == 200
        assert inherited.content == MEMBER, inherited.content[:80]
        assert opted_out.content.startswith(b"PK\x03\x04"), opted_out.content[:80]

    def test_a_bare_location_matches_a_location_that_wrote_off(self, sc):
        """And the other half: where there is nothing above it to inherit, the
        merge default makes ``off`` and absent the same configuration.  Both
        halves are true at once, which is why the ladder needs both rows."""
        wrote_off = _unzip(sc, DEFAULT_VHOST, "/zp-off/", MEMBER_NAME)
        wrote_nothing = _unzip(sc, DEFAULT_VHOST, "/zp-bare/", MEMBER_NAME)
        assert wrote_off.status_code == wrote_nothing.status_code == 200
        assert wrote_off.content == wrote_nothing.content

    @pytest.mark.parametrize("host,prefix", ZIP_ON + ZIP_OFF)
    def test_no_argument_is_the_whole_archive_on_every_arm(self, sc, host,
                                                           prefix):
        """The attribution control.  ``zr == 0`` is NGX_DECLINED on the enabled
        arm too (get.c:170-171), so a request that carries no `xrdcl.unzip` is
        answered identically everywhere — the flag changes the handling of
        requests that ask for a member, and of nothing else."""
        r = sc.request("GET", f"{prefix}a.zip", host=host)
        assert r.status_code == 200, (r.status_code, sc.errlog()[-2000:])
        assert r.content.startswith(b"PK\x03\x04"), r.content[:80]

    @pytest.mark.parametrize("member", ("../secret.txt",
                                        "%2E%2E%2Fsecret.txt",
                                        "/etc/passwd",
                                        "a/../../secret.txt",
                                        ""))
    @pytest.mark.parametrize("host,prefix", ZIP_ON)
    def test_the_enabled_arm_refuses_a_member_name_that_escapes(self, sc, host,
                                                                prefix, member):
        """The security negative for the ``on`` arm.  ``zip_http_name_ok``
        (zip_http.c:24-40) rejects a leading '/', a leading or embedded '../' and
        an empty name, and ``brix_zip_http_member_arg`` URL-DECODES before that
        check (zip_http.c:61-65) — so the percent-encoded form is refused too,
        with 400 and not with the escaped file."""
        r = _unzip(sc, host, prefix, member)
        assert r.status_code == 400, (r.status_code, sc.errlog()[-2000:])
        assert SECRET not in r.content, "an escape served the file next door"
        assert b"root:" not in r.content

    @pytest.mark.parametrize("member", ("../secret.txt",
                                        "%2E%2E%2Fsecret.txt",
                                        "/etc/passwd"))
    @pytest.mark.parametrize("host,prefix", ZIP_OFF)
    def test_the_disabled_arm_never_reads_the_escape_at_all(self, sc, host,
                                                            prefix, member):
        """The mirror of it, and the reason the flag's ``off`` arm is not a
        weaker security posture: the argument is never parsed, so there is no
        name to escape with.  The archive is served and the file next door is
        not."""
        r = _unzip(sc, host, prefix, member)
        assert r.status_code == 200, (r.status_code, sc.errlog()[-2000:])
        assert r.content.startswith(b"PK\x03\x04"), r.content[:80]
        assert SECRET not in r.content

    @pytest.mark.parametrize("host,prefix", ZIP_ON)
    def test_the_enabled_arm_404s_a_member_that_is_not_there(self, sc, host,
                                                             prefix):
        """A well-formed name for a member the archive does not contain is
        BRIX_ZIP_NOMEMBER -> 404 (zip_http.c:153), which is the third status this
        flag can produce and separates "malformed" from "absent"."""
        r = _unzip(sc, host, prefix, "nope.txt")
        assert r.status_code == 404, (r.status_code, sc.errlog()[-2000:])

    @pytest.mark.parametrize("host,prefix", ZIP_OFF)
    def test_the_disabled_arm_serves_the_archive_for_a_missing_member(
            self, sc, host, prefix):
        """The same name on a clear arm is a 200, because the 404 comes from the
        central-directory walk the flag gates."""
        r = _unzip(sc, host, prefix, "nope.txt")
        assert r.status_code == 200, (r.status_code, sc.errlog()[-2000:])
        assert r.content.startswith(b"PK\x03\x04"), r.content[:80]


# --------------------------------------------------------------------------- #
# §B — brix_webdav_require_digest                                              #
# --------------------------------------------------------------------------- #

def _put(sc, host, prefix, headers, body=BODY):
    """PUT `body` to a name nothing else has used, returning (response, stored)."""
    uri = sc.unique(prefix)
    r = sc.request("PUT", uri, host=host, data=body, headers=headers)
    return r, sc.stored(uri)


# The header forms that carry a digest the server can read and check.  Each is
# correct for BODY, so `on` and `off` must both accept them.
GOOD_DIGESTS = (
    ("adler32", {"Digest": f"adler32={ADLER32}"}),
    ("md5", {"Digest": f"md5={MD5_B64}"}),
    ("sha-256", {"Digest": f"sha-256={SHA256_B64}"}),
    ("content-md5", {"Content-MD5": MD5_B64}),
)
# Forms that carry a digest the server can read and that does NOT match.
BAD_DIGESTS = (
    ("adler32 mismatch", {"Digest": "adler32=deadbeef"}),
    ("content-md5 mismatch", {"Content-MD5": WRONG_MD5_B64}),
    ("md5 not base64", {"Digest": "md5=not-base64!!"}),
)
# Forms that carry NOTHING the server can use — WEBDAV_DIGEST_NONE, the one
# outcome this flag decides.
UNUSABLE_DIGESTS = (
    ("no header at all", {}),
    ("unknown algorithm", {"Digest": "sha3-512=AAAA"}),
    ("empty Digest value", {"Digest": ""}),
    ("Digest with no '='", {"Digest": "adler32"}),
)


class TestTheRequireDigestArm:
    """``webdav_put_verify_ingest_digest`` (put_body_digest.c:241-266) consults
    the flag at exactly one place — the ``WEBDAV_DIGEST_NONE`` arm — so the
    table has to separate "nothing usable was asserted" from "something was
    asserted and it was wrong"."""

    @pytest.mark.parametrize("label,headers", UNUSABLE_DIGESTS,
                             ids=[x[0] for x in UNUSABLE_DIGESTS])
    @pytest.mark.parametrize("host,prefix", DIGEST_ON)
    def test_the_enabled_arm_refuses_a_write_it_cannot_verify(
            self, sc, host, prefix, label, headers):
        """Four header forms, one outcome: the server has no digest it can check,
        and the flag turns that into a refusal that stores nothing.  The three
        malformed forms land here and not with the mismatches because
        ``webdav_digest_select`` reports them as NONE, not BAD."""
        r, stored = _put(sc, host, prefix, headers)
        assert r.status_code == 400, (label, r.status_code,
                                      sc.errlog()[-2000:])
        assert stored is None, f"{label}: a refused PUT left bytes on disk"

    @pytest.mark.parametrize("label,headers", UNUSABLE_DIGESTS,
                             ids=[x[0] for x in UNUSABLE_DIGESTS])
    @pytest.mark.parametrize("host,prefix", DIGEST_OFF)
    def test_the_disabled_arm_accepts_a_write_it_cannot_verify(
            self, sc, host, prefix, label, headers):
        """The same four forms on every clear arm commit — best-effort interop is
        the default, and that is what the flag exists to switch off."""
        r, stored = _put(sc, host, prefix, headers)
        assert r.status_code == 201, (label, r.status_code,
                                      sc.errlog()[-2000:])
        assert stored == BODY, label

    @pytest.mark.parametrize("label,headers", GOOD_DIGESTS,
                             ids=[x[0] for x in GOOD_DIGESTS])
    @pytest.mark.parametrize("host,prefix", DIGEST_ON + DIGEST_OFF)
    def test_a_correct_digest_commits_on_every_arm(self, sc, host, prefix,
                                                   label, headers):
        """The first attribution control: the flag is a requirement, not a
        verifier.  Four readable header forms that match the body are accepted
        identically on all six arms."""
        r, stored = _put(sc, host, prefix, headers)
        assert r.status_code == 201, (label, r.status_code,
                                      sc.errlog()[-2000:])
        assert stored == BODY, label

    @pytest.mark.parametrize("label,headers", BAD_DIGESTS,
                             ids=[x[0] for x in BAD_DIGESTS])
    @pytest.mark.parametrize("host,prefix", DIGEST_ON + DIGEST_OFF)
    def test_a_wrong_digest_is_refused_on_every_arm(self, sc, host, prefix,
                                                     label, headers):
        """The second, and the one that matters: VERIFICATION is not gated by
        this flag.  A digest the server can read and that does not match the body
        is 400 with nothing stored whether the flag is set or clear — so a
        deployment that leaves it off has not turned off integrity checking, only
        the requirement to assert one."""
        r, stored = _put(sc, host, prefix, headers)
        assert r.status_code == 400, (label, r.status_code,
                                      sc.errlog()[-2000:])
        assert stored is None, f"{label}: a refused PUT left bytes on disk"

    def test_the_opt_out_is_the_reading_absence_cannot_express(self, sc):
        """Same comparison as §A, on the other flag: ``/inherit/`` writes nothing
        and inherits the server's ``on``; ``/opt-out/`` writes ``off`` and is the
        only spelling that could have done so."""
        inherited, in_stored = _put(sc, SRV_ON, "/inherit/", {})
        opted_out, out_stored = _put(sc, SRV_ON, "/opt-out/", {})
        assert inherited.status_code == 400, sc.errlog()[-2000:]
        assert in_stored is None
        assert opted_out.status_code == 201, sc.errlog()[-2000:]
        assert out_stored == BODY

    def test_the_server_scope_off_arm_reaches_the_setter(self, sc):
        """``srv-off.test`` writes ``brix_webdav_require_digest off`` in a
        ``server{}``, which nothing in the tree had ever done in either arm.  Its
        one location writes neither flag, so the 201 is the server-scope value
        merging down and not a location default."""
        r, stored = _put(sc, SRV_OFF, "/", {})
        assert r.status_code == 201, (r.status_code, sc.errlog()[-2000:])
        assert stored == BODY


# --------------------------------------------------------------------------- #
# §B2 — DEFECT CANDIDATE #90: Content-Encoding skips the requirement            #
# --------------------------------------------------------------------------- #

class TestTheContentEncodingSkip:
    """The security negative for ``require_digest``, and a defect.

    put_body_digest.c:253-258 returns NGX_OK on any non-empty
    ``Content-Encoding`` before the flag is consulted.  For a codec that really
    decodes, skipping is correct — the asserted digest describes the decoded
    bytes.  ``identity`` is a registered available codec that decodes nothing
    (core/compat/codec_core.c:65-67), so the header is a bare verification-skip switch.
    """

    IDENTITY = {"Content-Encoding": "identity"}

    @pytest.mark.parametrize("host,prefix", DIGEST_ON)
    def test_identity_defeats_the_requirement_entirely(self, sc, host, prefix):
        """Half one: a digest-less PUT is accepted on an export configured to
        refuse writes it cannot verify.  The stored bytes are the request body
        unchanged, so nothing was decoded — there was no transformation for the
        skip to be about."""
        r, stored = _put(sc, host, prefix, dict(self.IDENTITY))
        assert r.status_code == 201, (r.status_code, sc.errlog()[-2000:])
        assert stored == BODY, "the body was stored verbatim, undecoded"

    @pytest.mark.parametrize("label,headers", BAD_DIGESTS,
                             ids=[x[0] for x in BAD_DIGESTS])
    @pytest.mark.parametrize("host,prefix", DIGEST_ON + DIGEST_OFF)
    def test_identity_also_defeats_verification_of_a_wrong_digest(
            self, sc, host, prefix, label, headers):
        """Half two, and the worse half: a digest the client ASSERTED and that
        does not match the body is never checked.  The same three headers are
        400 on every arm without the Content-Encoding (see
        ``test_a_wrong_digest_is_refused_on_every_arm``), so this is the header
        and not the flag."""
        r, stored = _put(sc, host, prefix, {**headers, **self.IDENTITY})
        assert r.status_code == 201, (label, r.status_code,
                                      sc.errlog()[-2000:])
        assert stored == BODY, label

    @pytest.mark.parametrize("host,prefix", DIGEST_ON)
    def test_an_empty_content_encoding_does_not_skip(self, sc, host, prefix):
        """The first fence around the defect: the guard is
        ``ce != NULL && ce->value.len > 0``, so a present-but-empty header falls
        through to the digest check and the requirement still bites.  Pinning
        this says the bypass needs a VALUE and is not merely the header's
        presence."""
        r, stored = _put(sc, host, prefix, {"Content-Encoding": ""})
        assert r.status_code == 400, (r.status_code, sc.errlog()[-2000:])
        assert stored is None

    @pytest.mark.parametrize("host,prefix", DIGEST_ON + DIGEST_OFF)
    def test_a_codec_that_really_decodes_fails_honestly(self, sc, host, prefix):
        """The second fence, and the shape of the cure.  ``deflate`` over a body
        that is not deflate-coded is 400 on BOTH arms — the decode is attempted
        and it fails.  Only a no-op codec turns the skip into a bypass, which is
        why gating it on ``put_codec != BRIX_CODEC_IDENTITY`` would close the
        defect without changing any legitimate transfer."""
        r, stored = _put(sc, host, prefix, {"Content-Encoding": "deflate"})
        assert r.status_code == 400, (r.status_code, sc.errlog()[-2000:])
        assert stored is None

    @pytest.mark.parametrize("host,prefix", DIGEST_ON + DIGEST_OFF)
    def test_an_unregistered_codec_is_refused_before_any_of_this(self, sc, host,
                                                                  prefix):
        """The boundary of the bypass: an unknown token is 415 on both arms
        (put_body.c:316-329), so the skip is reachable only through a codec the
        server actually registered.  ``identity`` is one of them, which is
        exactly the defect."""
        r, stored = _put(sc, host, prefix, {"Content-Encoding": "no-such-codec"})
        assert r.status_code == 415, (r.status_code, sc.errlog()[-2000:])
        assert stored is None


# --------------------------------------------------------------------------- #
# §C — brix_webdav_dig                                                         #
# --------------------------------------------------------------------------- #

class TestTheDigArm:
    """``dig_precheck`` (dig.c:158-174) is consulted from the WebDAV content
    dispatcher (dispatch.c:158-163) and returns NGX_DECLINED when the flag is
    clear, so the reserved prefix is not refused — it stops being a diagnostics
    endpoint and becomes part of the export again."""

    def test_the_enabled_arm_serves_the_dig_export(self, sc):
        """The control.  An authorized principal reads the file from the DIG
        export, which lives outside the WebDAV export entirely."""
        r = sc.request("GET", DIG_TARGET, host=DIG_VHOSTS["dig-on"],
                       headers=sc.token("diguser"))
        assert r.status_code == 200, (r.status_code, sc.errlog()[-2000:])
        assert r.content == DIG_BODY, r.content[:80]

    @pytest.mark.parametrize("arm", DIG_OFF_ARMS)
    def test_every_clear_arm_serves_the_export_instead(self, sc, arm):
        """The same URI, the same token, on the three ways the flag can be clear
        — a per-location opt-out under a server that wrote ``on``, a server that
        wrote ``off``, and a server that wrote nothing while still declaring the
        export and the allow-file.  All three serve the OTHER file, so the flag
        decides which of two trees owns the URI."""
        r = sc.request("GET", DIG_TARGET, host=DIG_VHOSTS[arm],
                       headers=sc.token("diguser"))
        assert r.status_code == 200, (arm, r.status_code, sc.errlog()[-2000:])
        assert r.content == SHADOW_BODY, (arm, r.content[:80])

    def test_the_opt_out_is_the_reading_absence_cannot_express(self, sc):
        """``dig-locoff.test`` writes ``brix_webdav_dig on`` in its ``server{}``
        and ``off`` in the one location that can hold the reserved prefix.  Its
        sibling ``dig-on.test`` is the same server without that location, so the
        difference in which file answers is the location's ``off`` and nothing
        else — and absence there would have inherited the ``on``."""
        enabled = sc.request("GET", DIG_TARGET, host=DIG_VHOSTS["dig-on"],
                             headers=sc.token("diguser"))
        opted_out = sc.request("GET", DIG_TARGET,
                               host=DIG_VHOSTS["dig-locoff"],
                               headers=sc.token("diguser"))
        assert enabled.status_code == opted_out.status_code == 200
        assert enabled.content == DIG_BODY
        assert opted_out.content == SHADOW_BODY

    @pytest.mark.parametrize("sub", ("otheruser", None))
    def test_the_enabled_arm_is_fail_closed_for_anyone_unlisted(self, sc, sub):
        """dig_authz (dig.c:58-113) allows only an explicitly listed principal;
        an authenticated principal the allow-file does not name and an anonymous
        request are both 403."""
        headers = sc.token(sub) if sub else {}
        r = sc.request("GET", DIG_TARGET, host=DIG_VHOSTS["dig-on"],
                       headers=headers)
        assert r.status_code == 403, (sub, r.status_code, sc.errlog()[-2000:])
        assert DIG_BODY not in r.content

    @pytest.mark.parametrize("arm", DIG_OFF_ARMS)
    @pytest.mark.parametrize("sub", ("otheruser", None))
    def test_a_clear_arm_answers_the_principals_dig_refuses(self, sc, arm, sub):
        """The observation in the header docstring, measured.  The flag does not
        layer on top of the export's authorization — it REPLACES it for this
        subtree.  Clear the flag and the same anonymous or unlisted principal
        that dig refused is answered by the export's own policy, which here is
        ``brix_webdav_auth optional``."""
        headers = sc.token(sub) if sub else {}
        r = sc.request("GET", DIG_TARGET, host=DIG_VHOSTS[arm], headers=headers)
        assert r.status_code == 200, (arm, sub, r.status_code,
                                      sc.errlog()[-2000:])
        assert r.content == SHADOW_BODY, (arm, sub, r.content[:80])

    @pytest.mark.parametrize("method", ("PUT", "DELETE", "PROPFIND"))
    def test_the_enabled_arm_refuses_every_write_method(self, sc, method):
        """dig is read-only at its own gate (dig.c:170-172), and the export
        beneath it permits writes — so this 405 is the flag's and not
        ``brix_allow_write``'s.  A write-disabled export would have answered 403
        in the access phase before the content handler ran at all."""
        uri = sc.unique(f"{DIG_PREFIX}conf/", stem="w")
        r = sc.request(method, uri, host=DIG_VHOSTS["dig-on"], data=BODY,
                       headers=sc.token("diguser"))
        assert r.status_code == 405, (method, r.status_code,
                                      sc.errlog()[-2000:])
        assert sc.stored(uri) is None, f"{method} wrote through a 405"

    @pytest.mark.parametrize("arm", DIG_OFF_ARMS)
    def test_a_clear_arm_makes_the_reserved_prefix_writable(self, sc, arm):
        """The security negative, and the sharpest row in §C: with the flag set,
        a PUT under the reserved prefix is refused and nothing lands; with it
        clear the identical request is a plain WebDAV write INTO the export, at
        the URI the diagnostics endpoint would otherwise own."""
        uri = sc.unique(f"{DIG_PREFIX}conf/", stem="w")
        r = sc.request("PUT", uri, host=DIG_VHOSTS[arm], data=BODY,
                       headers=sc.token("diguser"))
        assert r.status_code == 201, (arm, r.status_code, sc.errlog()[-2000:])
        assert sc.stored(uri) == BODY, arm

    def test_the_prefix_itself_is_not_captured_on_either_arm(self, sc):
        """``r->uri.len <= BRIX_DIG_PREFIX_LEN`` (dig.c:164-169) declines a URI
        that is exactly the prefix, so ``/.well-known/dig/`` is a collection in
        the export on BOTH arms.  The flag captures strictly longer URIs only,
        and the boundary is worth a row because an off-by-one there would move a
        whole subtree."""
        for arm in ("dig-on",) + DIG_OFF_ARMS:
            r = sc.request("GET", DIG_PREFIX, host=DIG_VHOSTS[arm],
                           headers=sc.token("diguser"))
            assert r.status_code == 403, (arm, r.status_code,
                                          sc.errlog()[-2000:])

    def test_nothing_outside_the_prefix_moves_on_either_arm(self, sc):
        """The attribution control for the vhosts: a URI that is not under the
        reserved prefix is served by the export identically on all four arms, so
        no §C row can be explained by the vhost rather than the flag."""
        for arm in ("dig-on",) + DIG_OFF_ARMS:
            r = sc.request("GET", f"/{SECRET_NAME}", host=DIG_VHOSTS[arm],
                           headers=sc.token("diguser"))
            assert r.status_code == 200, (arm, r.status_code,
                                          sc.errlog()[-2000:])
            assert r.content == SECRET, arm

    def test_a_target_with_no_file_part_reads_differently_on_each_arm(self, sc):
        """``/.well-known/dig/conf`` has an export name and no file, which
        dig_parse_target (dig.c:190-196) reports as 404.  On a clear arm the same
        URI names a collection in the export, which WebDAV GET refuses with 403.
        Two different components, same URI, and the flag chooses which one
        answers."""
        enabled = sc.request("GET", DIG_NO_FILE_PART,
                             host=DIG_VHOSTS["dig-on"],
                             headers=sc.token("diguser"))
        assert enabled.status_code == 404, (enabled.status_code,
                                            sc.errlog()[-2000:])
        for arm in DIG_OFF_ARMS:
            r = sc.request("GET", DIG_NO_FILE_PART, host=DIG_VHOSTS[arm],
                           headers=sc.token("diguser"))
            assert r.status_code == 403, (arm, r.status_code,
                                          sc.errlog()[-2000:])

    def test_an_unknown_export_name_carries_no_information(self, sc):
        """Recorded because it is a row a reader would expect to discriminate and
        it does not.  ``dig_match_export`` misses (dig.c:242) on the enabled arm
        and the export has no such file on the clear arms, so all four answer 404
        for two unrelated reasons.  A table that counted this as agreement
        between the arms would be measuring a coincidence."""
        for arm in ("dig-on",) + DIG_OFF_ARMS:
            r = sc.request("GET", DIG_UNKNOWN_EXPORT, host=DIG_VHOSTS[arm],
                           headers=sc.token("diguser"))
            assert r.status_code == 404, (arm, r.status_code,
                                          sc.errlog()[-2000:])


# --------------------------------------------------------------------------- #
# §D — the parse tier                                                          #
# --------------------------------------------------------------------------- #

def _parse(tmp_path, **slots):
    """`nginx -t` on file 14's scaffold with the named slots filled.

    Every slot defaults to empty so a case names only what it is about; the
    scaffold's probe location writes none of the three, so a negative about one
    of them is never answered by a duplicate diagnostic first.
    """
    data = tmp_path / "parse-data"
    data.mkdir(exist_ok=True)
    values = {"PORT": PARSE_PLACEHOLDER_PORT,
              "STREAM_PORT": PARSE_PLACEHOLDER_PORT + 1,
              "LOG_DIR": str(tmp_path),
              "DATA": str(data),
              "LOC_KNOBS": "", "SRV_KNOBS": "", "HTTP_KNOBS": "",
              "OUTER": "", "STREAM_KNOBS": "", "STREAM_MAIN": "",
              "EXTRA_LOC": ""}
    values.update(slots)
    result = nginx_t("nginx_audit16nparse.conf", str(tmp_path), **values)
    return result.returncode, (result.stdout or "") + (result.stderr or "")


# The three scopes the declaration names, and the slot each one is.
RIGHT_SCOPES = ("LOC_KNOBS", "SRV_KNOBS", "HTTP_KNOBS")
# Every placement the declaration does NOT name.
WRONG_SCOPES = ("OUTER", "STREAM_KNOBS", "STREAM_MAIN")


@_needs_nginx
class TestTheParseTier:
    """Values, arity, duplicates, and the placement matrix — asked once per scope
    the declaration names, because the runtime tier can only carry two of the
    three at a time."""

    @pytest.mark.parametrize("scope", RIGHT_SCOPES)
    @pytest.mark.parametrize("arm", ("on", "off"))
    @pytest.mark.parametrize("flag", FLAG_NAMES)
    def test_both_arms_are_accepted_in_every_declared_scope(self, tmp_path,
                                                             flag, arm, scope):
        """The audit's step-1 question, asked at all three scopes.  Nine of these
        eighteen cases are the ``off`` arm the corpus never wrote, and three of
        them are a scope no arm of these directives had ever been written in."""
        rc, out = _parse(tmp_path, **{scope: f"        {flag} {arm};\n"})
        assert rc == 0, out

    @pytest.mark.parametrize("scope", RIGHT_SCOPES)
    @pytest.mark.parametrize("flag", FLAG_NAMES)
    def test_the_off_arm_advises_nothing(self, tmp_path, flag, scope):
        """Writing the value that disables a feature must not produce a
        diagnostic of any severity, in any scope — an operator who turns
        something off is not misconfiguring anything."""
        rc, out = _parse(tmp_path, **{scope: f"        {flag} off;\n"})
        assert rc == 0, out
        assert _diagnostics(out) == [], out

    def test_a_server_on_with_a_location_off_parses_clean(self, tmp_path):
        """The file's whole subject, at the parse tier: the opt-out is not a
        conflict to be diagnosed.  All three flags written ``on`` in the server
        and ``off`` in a location beneath it is an ordinary configuration."""
        srv = "".join(f"        {f} on;\n" for f in FLAG_NAMES)
        loc = "".join(f"            {f} off;\n" for f in FLAG_NAMES)
        rc, out = _parse(tmp_path, SRV_KNOBS=srv, LOC_KNOBS=loc)
        assert rc == 0, out
        assert _diagnostics(out) == [], out

    @pytest.mark.parametrize("value", ("1", "0", "yes", "enabled", "true"))
    @pytest.mark.parametrize("flag", FLAG_NAMES)
    def test_only_on_and_off_are_accepted(self, tmp_path, flag, value):
        """``ngx_conf_set_flag_slot`` compares against exactly two tokens, so
        every other spelling of a boolean is refused rather than guessed at."""
        rc, out = _parse(tmp_path, LOC_KNOBS=f"            {flag} {value};\n")
        assert rc != 0, out
        assert 'invalid value "%s"' % value in out, out

    @pytest.mark.parametrize("flag", FLAG_NAMES)
    def test_two_arguments_are_refused(self, tmp_path, flag):
        """NGX_CONF_FLAG is NGX_CONF_TAKE1 plus a value check; a second argument
        is an arity error and not a silently ignored token."""
        rc, out = _parse(tmp_path, LOC_KNOBS=f"            {flag} on off;\n")
        assert rc != 0, out
        assert "invalid number of arguments" in out, out

    @pytest.mark.parametrize("flag", FLAG_NAMES)
    def test_a_second_write_in_the_same_scope_is_a_duplicate(self, tmp_path,
                                                              flag):
        """Two values in one scope is a duplicate, which is what makes the
        server/location pair above the ONLY way to write both arms of one flag in
        one configuration."""
        rc, out = _parse(tmp_path,
                         LOC_KNOBS=f"            {flag} on;\n"
                                   f"            {flag} off;\n")
        assert rc != 0, out
        assert "duplicate" in out, out

    @pytest.mark.parametrize("scope", WRONG_SCOPES)
    @pytest.mark.parametrize("arm", ("on", "off"))
    @pytest.mark.parametrize("flag", FLAG_NAMES)
    def test_no_other_placement_is_allowed(self, tmp_path, flag, arm, scope):
        """The main context and the stream plane must refuse, and the refusal
        must be about the CONTEXT: nginx searches every module's command table
        before it checks scope, so "unknown directive" here would mean the
        directive had been dropped from the table rather than misplaced."""
        rc, out = _parse(tmp_path, **{scope: f"    {flag} {arm};\n"})
        assert rc != 0, out
        assert "is not allowed here" in out, out
        assert "unknown directive" not in out, out


# --------------------------------------------------------------------------- #
# §E — the declarations this file's readings depend on                          #
# --------------------------------------------------------------------------- #

class TestTheDeclarationsAreWhatTheFileSays:
    """Every reading above is an inference from four lines of C.  If any of them
    changes, the tests would keep passing while measuring something else, so the
    lines themselves are pinned."""

    @pytest.mark.parametrize("flag,field", FLAGS,
                             ids=[f for f, _ in FLAGS])
    def test_the_scope_is_all_three_and_the_setter_is_the_flag_slot(self, flag,
                                                                     field):
        """The declaration is what makes the opt-out reachable: three legal
        scopes, and ``NGX_HTTP_LOC_CONF_OFFSET`` so a server-scope value becomes
        the parent of every location below it."""
        text = MODULE_COMMANDS_C.read_text()
        marker = f'{{ ngx_string("{flag}"),'
        assert marker in text, flag
        block = text.split(marker, 1)[1]
        # splitlines()[0] is the tail of the marker's own line, which is empty.
        lines = [ln.strip() for ln in block.splitlines()[1:5]]
        assert lines[0] == ("NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | "
                            "NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,"), lines
        assert lines[1] == "ngx_conf_set_flag_slot,", lines
        assert lines[2] == "NGX_HTTP_LOC_CONF_OFFSET,", lines
        assert f"offsetof(ngx_http_brix_webdav_loc_conf_t, {field})" in lines[3], \
            lines

    @pytest.mark.parametrize("field", [f for _, f in FLAGS])
    def test_all_three_merge_to_zero(self, field):
        """The bare arms read this 0.  A merge default of 1 would make the
        ``on`` arm the redundant one instead — which is the case for
        ``brix_webdav_upload_resume`` one file over, so the direction is not a
        given."""
        squashed = " ".join(CONFIG_MERGE_C.read_text().split())
        assert (f"ngx_conf_merge_value(conf->{field}, prev->{field}, 0);"
                in squashed), field

    def test_the_digest_skip_still_precedes_the_requirement(self):
        """The pin for #90: the Content-Encoding early return is still ABOVE the
        ``require_digest`` consultation, and still keyed on the header's length
        rather than on the codec doing any work.  When that changes, the four
        rows in §B2 change with it and should be revisited rather than
        adjusted."""
        text = PUT_BODY_DIGEST_C.read_text()
        skip = text.index('brix_http_find_header(r, "Content-Encoding"')
        guard = text.index("ce->value.len > 0", skip)
        gate = text.index("conf->require_digest", guard)
        assert skip < guard < gate, (skip, guard, gate)

    def test_identity_is_a_registered_codec_token(self):
        """And the other half of #90: ``identity`` reaching the skip at all is
        what makes the header a bypass rather than a description of a transfer
        encoding the server is about to undo."""
        assert '"identity"' in CODEC_CORE_C.read_text()

    def test_the_dig_prefix_boundary_is_strict(self):
        """The prefix-itself row in §C depends on the comparison being ``<=``
        against the prefix length, so a URI equal to the prefix declines."""
        text = DIG_C.read_text()
        assert "r->uri.len <= BRIX_DIG_PREFIX_LEN" in text

    def test_zip_member_selection_is_gated_before_the_argument_is_read(self):
        """The §A readings all rest on the flag being checked BEFORE
        ``brix_zip_http_member_arg``, which is why the ``off`` arm cannot 400 an
        escape: it never parses one."""
        text = GET_C.read_text()
        body = text.split("get_zip_member_serve(ngx_http_request_t *r,", 1)[1]
        body = body.split("\n}\n", 1)[0]
        assert body.index("!conf->zip_access") < \
            body.index("brix_zip_http_member_arg"), body
