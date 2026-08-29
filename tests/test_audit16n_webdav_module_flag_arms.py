"""Test cases for audit16n_webdav_module_flag_arms — preamble (fixtures/helpers/mocks) lives in
_test_audit16n_webdav_module_flag_arms_helpers.py; reexported below so pytest resolves fixtures in
this module's namespace (split for the 600 logical-line file cap)."""
from split_continuation import reexport as _reexport
_reexport(globals(), "_test_audit16n_webdav_module_flag_arms_helpers")


class TestTheWebdavSwitch:
    """``!conf->common.enable`` returns NGX_DECLINED from both the access-phase
    handler (access.c:416-419) and the content handler (dispatch.c:484-487), so
    the location does not answer 403 or 503 — it stops being a WebDAV location
    and whatever nginx has left answers instead.  The reading is therefore a
    method table, not one verb."""

    def test_the_enabled_control_answers_every_method(self, wd):
        """The row every refusal below is measured against.  Without it a table
        of 404s proves only that something declined, not that the flag did."""
        assert wd.request("GET", "/ref/f.bin").status_code == 200
        assert wd.request("PUT", "/ref/new.bin",
                          data=PAYLOAD).status_code == 201
        listing = wd.request("PROPFIND", "/ref/", headers={"Depth": "1"})
        assert listing.status_code == 207, listing.text[:300]

    def test_the_off_arm_stops_answering_as_webdav(self, wd):
        """The arm the corpus had never written.  Both handlers decline, so the
        request leaves the module: GET falls through to nginx's own static
        handler (which has no root here) and PUT/PROPFIND are refused by it as
        methods it does not implement."""
        assert wd.request("GET", "/wd-off/f.bin").status_code == 404
        assert wd.request("PUT", "/wd-off/new.bin",
                          data=PAYLOAD).status_code == 405
        assert wd.request("PROPFIND", "/wd-off/",
                          headers={"Depth": "1"}).status_code == 405

    def test_the_off_arm_is_the_absent_value(self, wd):
        """At the top level the merge default is 0 (shared_conf.h:339), so `off`
        must land exactly where saying nothing lands."""
        for uri, method, expect in (("/wd-bare/f.bin", "GET", 404),
                                    ("/wd-bare/new.bin", "PUT", 405),
                                    ("/wd-bare/", "PROPFIND", 405)):
            got = wd.request(method, uri, data=PAYLOAD if method == "PUT"
                             else None).status_code
            assert got == expect, f"{method} {uri} -> {got}"

    def test_the_off_arm_does_not_leak_the_object(self, wd):
        """The security negative.  A declined location must not hand the file to
        whatever answers next: the object exists on disk under the export root,
        and the 404 above has to be a 404 about a path nginx cannot find, not a
        200 served out of a root that happens to overlap the export."""
        response = wd.request("GET", "/wd-off/f.bin")
        assert response.status_code == 404
        assert PAYLOAD not in response.content, response.content[:200]

    def test_the_off_arm_creates_nothing(self, wd):
        """The other half: the refused PUT must not have written anything into
        the export, by any route."""
        wd.request("PUT", "/wd-off/never.bin", data=PAYLOAD)
        assert wd.stored("wd-off/never.bin") is None, \
            "a declined location accepted a write"

    def test_a_child_inherits_the_parent_locations_on(self, wd):
        """The inheritance control, and the reason the nested trio exists.
        ``brix_webdav`` is legal in NO scope above a location, so the only parent
        value its merge can ever read is another location's — and a child that
        writes nothing inherits it."""
        assert wd.request("GET", "/wd-parent/f.bin").status_code == 200
        assert wd.request("GET",
                          "/wd-parent/child-bare/f.bin").status_code == 200
        assert wd.request("PUT", "/wd-parent/child-bare/new.bin",
                          data=PAYLOAD).status_code == 201

    def test_only_the_off_arm_takes_the_inherited_value_back(self, wd):
        """The finding of §A: inside an enabled parent, ``off`` is the ONLY way
        to disable a child, because absence inherits.  This case cannot be
        written at all without the arm the corpus never wrote."""
        assert wd.request("GET", "/wd-parent/child-off/f.bin").status_code == 404
        assert wd.request("PUT", "/wd-parent/child-off/new.bin",
                          data=PAYLOAD).status_code == 405
        assert wd.stored("wd-parent/child-off/new.bin") is None


# --------------------------------------------------------------------------- #
# §B — brix_upload_resume                                               #
# --------------------------------------------------------------------------- #

def _resume_put(wd, arm, name, crange, body=CHUNK):
    """One Content-Range PUT against one upload_resume arm."""
    return wd.request("PUT", f"/{arm}/{name}", data=body,
                      headers={"Content-Range": crange})


class TestTheResumableUploadArm:
    """``put_setup.c:250-263`` consults the flag BEFORE the whole-body staged
    write, so the value decides which of two entirely different write paths a
    Content-Range PUT takes.  The merge default is 1 (config_merge.c:91), which
    makes ``off`` the only spelling that changes anything — and the one the
    corpus never wrote."""

    def test_the_on_arm_places_the_chunk_and_reports_the_offset(self, wd):
        """The control for the whole section: a non-final chunk is staged, the
        destination is not published, and the client is told where to continue
        (put_setup.c:190-193)."""
        response = _resume_put(wd, "ur-on", "part.bin", "bytes 0-4/10",
                               body=b"01234")
        assert response.status_code == 200, response.text[:300]
        assert response.headers.get("X-Upload-Offset") == "5", \
            dict(response.headers)
        assert wd.stored("ur-on/part.bin") is None, \
            "a partial upload published its destination"

    def test_the_off_arm_ignores_the_range_and_writes_the_body(self, wd):
        """The arm.  With the flag off the Content-Range header is not consulted
        at all: the request is an ordinary whole-object PUT, so it is created,
        published, and no resume marker comes back."""
        response = _resume_put(wd, "ur-off", "part.bin", "bytes 0-4/10",
                               body=b"01234")
        assert response.status_code == 201, response.text[:300]
        assert "X-Upload-Offset" not in response.headers, dict(response.headers)
        assert wd.stored("ur-off/part.bin") == b"01234"

    def test_the_absent_value_is_the_on_arm(self, wd):
        """The point of the merge default: ``on`` is what saying nothing already
        gives, so every existing resumable-upload config in the tree writes a
        value it did not need to.  Pinned here so a future change to the default
        has to be deliberate."""
        response = _resume_put(wd, "ur-bare", "part.bin", "bytes 0-4/10",
                               body=b"01234")
        assert response.status_code == 200, response.text[:300]
        assert response.headers.get("X-Upload-Offset") == "5"
        assert wd.stored("ur-bare/part.bin") is None

    def test_the_on_arm_refuses_a_malformed_range(self, wd):
        """A header the parser cannot read is a client error while the feature is
        on (put_setup.c:258-261)."""
        response = _resume_put(wd, "ur-on", "bad.bin", "bytes junk")
        assert response.status_code == 400, response.text[:300]
        assert wd.stored("ur-on/bad.bin") is None

    def test_the_off_arm_accepts_the_same_malformed_range(self, wd):
        """And the same header is not even looked at while it is off — which is
        the sharpest statement of what the flag gates: not a policy, a parser."""
        response = _resume_put(wd, "ur-off", "bad.bin", "bytes junk")
        assert response.status_code == 201, response.text[:300]
        assert wd.stored("ur-off/bad.bin") == CHUNK

    def test_the_on_arm_commits_a_complete_upload(self, wd):
        """The on arm is not merely a refusal path: a chunk that covers the whole
        declared total is committed and published (put_setup.c:158-188)."""
        response = _resume_put(wd, "ur-on", "whole.bin", "bytes 0-9/10",
                               body=WHOLE)
        assert response.status_code == 201, response.text[:300]
        assert wd.stored("ur-on/whole.bin") == WHOLE

    def test_the_on_arm_is_append_only_and_says_where_to_resume(self, wd):
        """A chunk that does not start at the partial's current size is refused
        with the real offset rather than written at the offset it asked for
        (put_setup.c:132-139) — the invariant that makes a resumed upload safe."""
        response = _resume_put(wd, "ur-on", "gap.bin", "bytes 5-9/10")
        assert response.status_code == 409, response.text[:300]
        assert response.headers.get("X-Upload-Offset") == "0", \
            dict(response.headers)
        assert wd.stored("ur-on/gap.bin") is None

    def test_the_off_arm_overwrites_where_the_on_arm_refuses(self, wd):
        """The security negative, and the hazard the unwritten arm carries.

        The byte-identical request the on arm answers 409 above — "place these
        five bytes at offset 5 of a ten-byte object" — is answered 201 by the off
        arm, and the ten-byte object it was aimed at is now five bytes long.  The
        range was not rejected and it was not honoured: it was ignored, and the
        PUT it was attached to replaced the whole object.  A client that resumes
        an interrupted upload against a location whose operator wrote
        ``brix_upload_resume off`` destroys what it was resuming.
        """
        wd.seed("ur-off/victim.bin", WHOLE)
        response = _resume_put(wd, "ur-off", "victim.bin", "bytes 5-9/10")
        assert response.status_code in (201, 204), response.text[:300]
        assert wd.stored("ur-off/victim.bin") == CHUNK, \
            "the off arm's whole-object write is the subject of this reading"
        assert wd.request("GET",
                          "/ur-off/victim.bin").content == CHUNK


# --------------------------------------------------------------------------- #
# §C — brix_webdav_tape_rest                                                   #
# --------------------------------------------------------------------------- #

def _archiveinfo(wd, arm, paths):
    """POST the WLCG Tape REST locality query at one tape_rest arm."""
    return wd.request("POST", TAPE_ARCHIVEINFO, host=ABS_VHOSTS[arm],
                      data=json.dumps({"paths": paths}).encode(),
                      headers={"Content-Type": "application/json"})


class TestTheTapeRestArm:
    """``dispatch.c:231-245`` routes ``/api/v1/`` to the Tape REST router when the
    flag is on and declines when it is off, so the arm decides whether an
    absolute URI prefix belongs to a protocol or to the export."""

    def test_the_on_arm_answers_the_locality_query(self, wd):
        """The control.  archiveinfo is synchronous and needs no stage registry
        (tape_rest_ops.c:405-470), so it reads the arm and nothing else."""
        response = _archiveinfo(wd, "abs-on", ["/f.bin"])
        assert response.status_code == 200, response.text[:300]
        body = response.json()
        assert "files" in body, body
        assert [entry["path"] for entry in body["files"]] == ["/f.bin"], body

    def test_the_off_arm_never_reaches_the_router(self, wd):
        """The arm.  With the flag off the request is not the router's, and the
        location it lands in instead is an ordinary WebDAV export — where POST is
        not a method WebDAV implements, so the answer is 405 and not the router's
        own 404 for an unrecognised endpoint.

        MEASURED, and the better reading for it: a 404 would have been ambiguous
        between "the router declined this path" and "the router never ran", while
        405 can only come from the method table of a location that handled the
        request itself.  The two 4xx verdicts are also told apart by shape — the
        router answers in JSON with a ``detail`` member and this does not.
        """
        response = _archiveinfo(wd, "abs-off", ["/f.bin"])
        assert response.status_code == 405, response.text[:300]
        assert "detail" not in response.text, response.text[:300]

    def test_the_off_arm_is_the_absent_value(self, wd):
        """The merge default is 0 (config_merge.c:88), so the vhost that writes
        nothing must answer exactly as the one that writes `off`."""
        assert _archiveinfo(wd, "abs-bare", ["/f.bin"]).status_code == 405

    def test_the_mixed_vhost_attributes_the_verdict_to_this_flag(self, wd):
        """abs-mixed carries ``brix_webdav_tape_rest on`` beside
        ``brix_delegation_endpoint off``.  Its 200 here — with §D's 200 on the
        delegation prefix in the same server — is what says each flag gates its
        own prefix and neither gates the vhost."""
        assert _archiveinfo(wd, "abs-mixed", ["/f.bin"]).status_code == 200

    def test_the_on_arm_validates_the_body_the_off_arm_never_sees(self, wd):
        """A request the router owns and rejects, against one it never receives.
        The 400 is the router's own (tape_rest_ops.c:415-419) and carries its
        message, so the two 4xx verdicts are told apart by more than a number."""
        bad = _archiveinfo(wd, "abs-on", [])
        assert bad.status_code == 400, bad.text[:300]
        assert "paths" in bad.json().get("detail", ""), bad.text[:300]

        unseen = _archiveinfo(wd, "abs-off", [])
        assert unseen.status_code == 405, unseen.text[:300]
        assert "paths" not in unseen.text, \
            "the off arm must not have parsed a body it never received"

    def test_the_on_arm_shadows_the_exports_own_api_subtree(self, wd):
        """The observation in this file's header.  One file, on disk, under the
        export root, reachable through the vhost whose flag is off and NOT
        through the one whose flag is on — where the router answers instead and
        says so."""
        served = wd.request("GET", TAPE_SHADOW, host=ABS_VHOSTS["abs-off"])
        assert served.status_code == 200, served.text[:300]
        assert served.content == PAYLOAD

        shadowed = wd.request("GET", TAPE_SHADOW, host=ABS_VHOSTS["abs-on"])
        assert shadowed.status_code == 404, shadowed.text[:300]
        assert shadowed.json().get("detail") == "unknown endpoint", \
            shadowed.text[:300]
        assert PAYLOAD not in shadowed.content


# --------------------------------------------------------------------------- #
# §D — brix_delegation_endpoint                                                #
# --------------------------------------------------------------------------- #

GSI_REQUIRED = "GSI client-certificate authentication required"


class TestTheDelegationEndpointArm:
    """Two dispatchers read this one flag: the upload form, matched by URI SUFFIX
    (dispatch.c:178-196), and the gridsite form, matched by URI PREFIX
    (dispatch.c:199-228).  Both are measured, because the arm is what decides
    whether either of them sees the request — and because the two do not agree on
    where the endpoint lives."""

    def test_the_on_arm_takes_the_put_as_a_credential_upload(self, wd):
        """The control.  A PUT whose URI ends in the reserved suffix is handed to
        the delegation handler, which fails closed over cleartext
        (delegation.c:462-467) — 401, and nothing written."""
        response = wd.request("PUT", f"/de-on{DELEG_SUFFIX}", data=PAYLOAD)
        assert response.status_code == 401, response.text[:300]
        assert GSI_REQUIRED in response.text, response.text[:300]
        assert wd.stored(f"de-on{DELEG_SUFFIX}") is None

    def test_the_off_arm_takes_the_same_put_as_a_file(self, wd):
        """The arm.  With the flag off the reserved suffix is an ordinary path,
        so the same request creates an object."""
        response = wd.request("PUT", f"/de-off{DELEG_SUFFIX}", data=PAYLOAD)
        assert response.status_code == 201, response.text[:300]
        assert wd.stored(f"de-off{DELEG_SUFFIX}") == PAYLOAD

    def test_the_off_arm_is_the_absent_value(self, wd):
        """The merge default is 0 (config_merge.c:124-125)."""
        response = wd.request("PUT", f"/de-bare{DELEG_SUFFIX}", data=PAYLOAD)
        assert response.status_code == 201, response.text[:300]
        assert wd.stored(f"de-bare{DELEG_SUFFIX}") == PAYLOAD

    def test_the_suffix_match_captures_a_put_anywhere_in_the_namespace(self, wd):
        """DEFECT CANDIDATE #89.

        The upload dispatcher compares the TAIL of the URI, so the endpoint is
        not at a place — it is at every place.  A PUT deep inside the export
        whose path merely ends in the reserved suffix is diverted into the
        credential handler, and the byte-identical PUT on the `off` arm is stored
        as an object.  The gridsite form two dozen lines further down anchors the
        same string at the start of the URI; that asymmetry is the defect.
        """
        deep = f"deep/nested{DELEG_SUFFIX}"
        captured = wd.request("PUT", f"/de-on/{deep}", data=PAYLOAD)
        assert captured.status_code == 401, captured.text[:300]
        assert GSI_REQUIRED in captured.text, captured.text[:300]
        assert wd.stored(f"de-on/{deep}") is None, \
            "the finding is that this PUT never becomes a file"

        stored = wd.request("PUT", f"/de-off/{deep}", data=PAYLOAD)
        assert stored.status_code == 201, stored.text[:300]
        assert wd.stored(f"de-off/{deep}") == PAYLOAD, \
            "the control: the same URI IS a file when the flag is off"

    def test_the_on_arm_owns_the_gridsite_request_endpoint(self, wd):
        """The prefix form, on the vhost whose `location /` carries the flag: a
        GET on the anchored path is the getProxyReq endpoint and fails closed
        (delegation_gridsite_req.c:333-337)."""
        response = wd.request("GET", DELEG_REQUEST, host=ABS_VHOSTS["abs-on"])
        assert response.status_code == 401, response.text[:300]
        assert GSI_REQUIRED in response.text, response.text[:300]
        assert PAYLOAD not in response.content

    @pytest.mark.parametrize("arm", ("abs-off", "abs-bare", "abs-mixed"))
    def test_every_disabled_arm_serves_the_shadowed_object_instead(self, wd, arm):
        """The arm, the merge default and the attribution control in one table.

        The same seeded file under the reserved prefix is served by all three —
        including abs-mixed, whose OTHER flag (tape_rest) is on, which is what
        says the verdict belongs to this flag and not to the vhost.
        """
        response = wd.request("GET", DELEG_REQUEST, host=ABS_VHOSTS[arm])
        assert response.status_code == 200, response.text[:300]
        assert response.content == PAYLOAD

    def test_the_on_arm_refuses_a_put_under_the_anchored_prefix(self, wd):
        """The gridsite PUT path (dispatch.c:222-227) is the credential store's,
        not the export's — so a PUT there is answered by the endpoint and creates
        no object, while the `off` arm stores it."""
        target = "/.well-known/brix-delegation/slot-16n"
        refused = wd.request("PUT", target, host=ABS_VHOSTS["abs-on"],
                             data=PAYLOAD)
        assert refused.status_code != 201, refused.text[:300]
        assert wd.stored(target) is None, refused.text[:300]

        stored = wd.request("PUT", target, host=ABS_VHOSTS["abs-off"],
                            data=PAYLOAD)
        assert stored.status_code == 201, stored.text[:300]
        assert wd.stored(target) == PAYLOAD


# --------------------------------------------------------------------------- #
# §E — brix_webdav_cors_credentials                                            #
# --------------------------------------------------------------------------- #

ACAO = "Access-Control-Allow-Origin"
ACAC = "Access-Control-Allow-Credentials"


def _cors(wd, arm, origin=None):
    """A GET at one CORS arm, with or without an Origin, returning its headers."""
    headers = {"Origin": origin} if origin is not None else {}
    response = wd.request("GET", f"/{arm}/f.bin", headers=headers)
    assert response.status_code == 200, response.text[:300]
    return response.headers


class TestTheCorsCredentialsArm:
    """``webdav_add_cors_headers`` copies the flag into the shared CORS config
    (cors.c:284) and it is read twice: once to emit Allow-Credentials
    (cors.c:126-131) and once to decide whether a ``*`` allowlist entry may be
    answered with the literal ``*`` (cors.c:68-71).  So on a wildcard allowlist
    the arm changes a VALUE, not just the presence of a header — and the value it
    changes is the one CORS forbids to combine with credentials."""

    def test_the_on_arm_asserts_credentials_and_echoes_the_origin(self, wd):
        """The control.  A credentialed response may not carry the literal ``*``,
        so the concrete request origin is echoed even though the allowlist is a
        wildcard."""
        headers = _cors(wd, "cc-on", CORS_OTHER)
        assert headers.get(ACAC) == "true", dict(headers)
        assert headers.get(ACAO) == CORS_OTHER, dict(headers)
        assert headers.get("Vary") == "Origin", dict(headers)

    def test_the_off_arm_drops_the_header_and_restores_the_wildcard(self, wd):
        """The arm, and both of its effects at once: no Allow-Credentials, and
        the wildcard is answered literally again."""
        headers = _cors(wd, "cc-off", CORS_OTHER)
        assert ACAC not in headers, dict(headers)
        assert headers.get(ACAO) == "*", dict(headers)

    def test_the_off_arm_is_the_absent_value(self, wd):
        """The merge default is 0 (config_merge.c:95)."""
        headers = _cors(wd, "cc-bare", CORS_OTHER)
        assert ACAC not in headers, dict(headers)
        assert headers.get(ACAO) == "*", dict(headers)

    def test_a_concrete_allowlist_isolates_the_header_from_the_wildcard_rule(
            self, wd):
        """The pair with no ``*`` in it: here the arm can only change the
        Allow-Credentials header, because the Allow-Origin value is the echoed
        origin either way.  Without this pair the wildcard reading above could be
        explained by the flag changing the allowlist rather than the answer."""
        on_headers = _cors(wd, "cx-on", CORS_ORIGIN)
        off_headers = _cors(wd, "cx-off", CORS_ORIGIN)
        assert on_headers.get(ACAC) == "true", dict(on_headers)
        assert ACAC not in off_headers, dict(off_headers)
        assert on_headers.get(ACAO) == CORS_ORIGIN, dict(on_headers)
        assert off_headers.get(ACAO) == CORS_ORIGIN, dict(off_headers)

    @pytest.mark.parametrize("arm", ("cc-on", "cc-off", "cc-bare",
                                     "cx-on", "cx-off"))
    def test_no_arm_ever_pairs_the_literal_wildcard_with_credentials(
            self, wd, arm):
        """The security negative, over every arm in the section.  ``Allow-Origin:
        *`` together with ``Allow-Credentials: true`` is the combination the CORS
        specification forbids and every browser rejects; the wildcard arms reach
        it only if the flag stops being consulted at cors.c:68."""
        headers = _cors(wd, arm, CORS_OTHER)
        assert not (headers.get(ACAO) == "*" and headers.get(ACAC) == "true"), \
            dict(headers)

    @pytest.mark.parametrize("arm", ("cc-on", "cc-off", "cx-on", "cx-off"))
    def test_no_arm_emits_cors_headers_without_an_origin(self, wd, arm):
        """A request that is not cross-origin gets no CORS headers on either arm
        — the flag is not a switch for the whole CORS surface."""
        headers = _cors(wd, arm)
        assert ACAO not in headers, dict(headers)
        assert ACAC not in headers, dict(headers)

    @pytest.mark.parametrize("arm", ("cx-on", "cx-off"))
    def test_neither_arm_allows_an_origin_off_the_allowlist(self, wd, arm):
        """The other security negative: ``on`` is not a grant.  An origin the
        location never allowlisted is refused CORS on both arms, so the flag
        decides how an allowed origin is answered and never which origins are
        allowed."""
        headers = _cors(wd, arm, CORS_OTHER)
        assert ACAO not in headers, dict(headers)
        assert ACAC not in headers, dict(headers)


# --------------------------------------------------------------------------- #
# §J — the parse tier                                                          #
# --------------------------------------------------------------------------- #

def _parse(tmp_path, **slots):
    """`nginx -t` on the 16n scaffold with the named slots filled.

    Every slot defaults to empty so a case names only what it is about; the
    scaffold writes none of the five itself — not even ``brix_webdav`` on its
    probe location — so a negative about one of them is never answered by a
    duplicate diagnostic first.
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


# Every placement that is NOT a location, and the scope each one is.
WRONG_SCOPES = ("SRV_KNOBS", "HTTP_KNOBS", "OUTER", "STREAM_KNOBS",
                "STREAM_MAIN")


@_needs_nginx
class TestTheParseTier:

    @pytest.mark.parametrize("flag", FLAG_NAMES)
    @pytest.mark.parametrize("arm", ("on", "off"))
    def test_both_arms_are_accepted_in_a_location(self, tmp_path, flag, arm):
        rc, out = _parse(tmp_path, LOC_KNOBS=f"            {flag} {arm};\n")
        assert rc == 0, out

    @pytest.mark.parametrize("flag", FLAG_NAMES)
    def test_the_off_arm_advises_nothing(self, tmp_path, flag):
        """Writing the value that disables a feature must not produce a
        diagnostic of any severity — an operator who turns something off is not
        misconfiguring anything."""
        rc, out = _parse(tmp_path, LOC_KNOBS=f"            {flag} off;\n")
        assert rc == 0, out
        assert _diagnostics(out) == [], out

    @pytest.mark.parametrize("flag", FLAG_NAMES)
    @pytest.mark.parametrize("value", ("1", "enabled"))
    def test_a_value_outside_the_two_arms_is_refused(self, tmp_path, flag,
                                                     value):
        rc, out = _parse(tmp_path, LOC_KNOBS=f"            {flag} {value};\n")
        assert rc != 0, f"{flag} {value} was accepted: {out}"

    @pytest.mark.parametrize("flag", FLAG_NAMES)
    def test_the_directive_takes_exactly_one_argument(self, tmp_path, flag):
        rc, out = _parse(tmp_path, LOC_KNOBS=f"            {flag} on off;\n")
        assert rc != 0, out
        assert "invalid number of arguments" in out, out

    @pytest.mark.parametrize("flag", FLAG_NAMES)
    def test_a_duplicate_is_refused(self, tmp_path, flag):
        rc, out = _parse(
            tmp_path,
            LOC_KNOBS=f"            {flag} off;\n            {flag} on;\n")
        assert rc != 0, out
        assert "duplicate" in out, out

    #: (flag, slot) placements the unification made LEGAL: brix_upload_resume
    #: and brix_delegation_endpoint moved to the common module at
    #: BRIX_HTTP_ALL_CONF (site/server-wide policy is the point), and
    #: brix_upload_resume gained a stream twin (directives_caps.h).
    WIDENED = {
        ("brix_upload_resume", "SRV_KNOBS"),
        ("brix_upload_resume", "HTTP_KNOBS"),
        ("brix_upload_resume", "STREAM_KNOBS"),
        ("brix_delegation_endpoint", "SRV_KNOBS"),
        ("brix_delegation_endpoint", "HTTP_KNOBS"),
    }

    @pytest.mark.parametrize("flag", FLAG_NAMES)
    @pytest.mark.parametrize("slot", WRONG_SCOPES)
    def test_every_other_placement_is_refused(self, tmp_path, flag, slot):
        """The webdav-prefixed three stay NGX_HTTP_LOC_CONF-only, so a location
        is their only legal context — on either plane; the two bare unified
        names accept the widened placements instead.  A refusal must name the
        scope and not the name: ``unknown directive`` would mean the module's
        table was never searched."""
        rc, out = _parse(tmp_path, **{slot: f"    {flag} on;\n"})
        if (flag, slot) in self.WIDENED:
            assert rc == 0, f"{flag} was refused in {slot}: {out}"
            return
        assert rc != 0, f"{flag} was accepted in {slot}: {out}"
        assert "is not allowed here" in out, out
        assert "unknown directive" not in out, out


@_needs_nginx
class TestWhatTheOffArmSilences:
    """``webdav_validate_webdav_enabled`` (config_merge.c:517-522) returns
    NGX_CONF_OK without validating ANYTHING when ``common.enable`` is zero — the
    export root, the authz rules, the storage backend, the root fd, the tier
    stores, the stage and cache dirs, the auth paths, the CA store, the JWKS path,
    the password file and the TPC paths are all left unchecked.  So the arm does
    not only change what the location does at run time: it changes whether the
    configuration is inspected at all."""

    # One location body whose only fault is an export that does not exist.
    BOGUS = ("        location /gate/ {\n"
             "{ARM}"
             "            brix_export      {LOG_DIR}/no-such-export;\n"
             "            brix_webdav_auth none;\n"
             "        }\n")

    def _gate(self, tmp_path, arm_line):
        body = self.BOGUS.replace("{ARM}", arm_line).replace(
            "{LOG_DIR}", str(tmp_path))
        return _parse(tmp_path, EXTRA_LOC=body)

    def test_the_on_arm_refuses_the_unusable_export(self, tmp_path):
        """The control: with the feature enabled the chain runs and the export is
        the first thing it checks."""
        rc, out = self._gate(tmp_path, "            brix_webdav on;\n")
        assert rc != 0, out
        assert "brix_export" in out and "not accessible" in out, out

    def test_the_off_arm_accepts_it_in_silence(self, tmp_path):
        """The arm.  The same body, one token different, is accepted — and not
        merely accepted: nothing is said about it at any severity, so an operator
        who disables a location learns nothing about the state it is in."""
        rc, out = self._gate(tmp_path, "            brix_webdav off;\n")
        assert rc == 0, out
        assert _diagnostics(out) == [], out

    def test_the_absent_value_silences_it_too(self, tmp_path):
        """Which is what makes the previous case a property of the VALUE 0 rather
        than of the word ``off``: the merge default reaches the same gate."""
        rc, out = self._gate(tmp_path, "")
        assert rc == 0, out
        assert _diagnostics(out) == [], out


# --------------------------------------------------------------------------- #
# §K — the declarations these readings are about                               #
# --------------------------------------------------------------------------- #

class TestTheDeclarationsAreWhatTheFileSays:
    """Cheap source pins.  Every section above is written against a specific
    scope and a specific merge default; if either changes, the section is
    measuring something else and should fail here first rather than mislead."""

    #: The two bare names live on the COMMON module at all three http scopes.
    COMMON_OWNED = {"brix_upload_resume", "brix_delegation_endpoint"}

    @pytest.mark.parametrize("flag", FLAG_NAMES)
    def test_each_flag_is_declared_location_only(self, flag):
        if flag in self.COMMON_OWNED:
            blob = "".join(
                path.read_text()
                for path in MODULE_COMMANDS_C.parent.parent.parent.joinpath(
                    "core/config").glob("http_directives_*.h"))
            needle = f'{{ ngx_string("{flag}"),'
            assert needle in blob, f"{flag} is not on the common module"
            entry = blob.split(needle, 1)[1].split("},")[0]
            assert "BRIX_HTTP_ALL_CONF" in entry, entry
            return
        text = MODULE_COMMANDS_C.read_text()
        needle = f'{{ ngx_string("{flag}"),'
        assert needle in text, f"{flag} is no longer in the webdav table"
        scope = text.split(needle, 1)[1].split("\n")[1].strip()
        assert scope == "NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,", \
            f"{flag} scope is now {scope!r} — §J's refusal matrix is stale"

    def test_upload_resume_is_the_one_that_defaults_on(self):
        """§B's whole shape depends on this being 1 while the other four are 0.

        Whitespace is collapsed first: two of these merge calls are wrapped across
        two lines and one is not, and the pin is about the third argument rather
        than about where the line happens to break.
        """
        shared = " ".join((CONFIG_MERGE_C.parent.parent.parent
                           / "core/config/shared_conf_merge.h")
                          .read_text().split())
        squashed = " ".join(CONFIG_MERGE_C.read_text().split())
        assert "ngx_conf_merge_value(conf->upload_resume, prev->upload_resume, 1)" \
            in shared, "upload_resume no longer defaults on — §B is stale"
        assert "ngx_conf_merge_value(conf->delegation_endpoint, prev->delegation_endpoint, 0)" \
            in shared, "delegation_endpoint no longer defaults off"
        for field in ("tape_rest", "cors_credentials"):
            assert f"ngx_conf_merge_value(conf->{field}, prev->{field}, 0)" \
                in squashed, f"{field} no longer defaults off"

    def test_the_two_delegation_dispatchers_still_disagree_on_anchoring(self):
        """The mechanism behind DEFECT CANDIDATE #89, pinned as source so the
        finding survives a refactor of the strings around it."""
        text = DISPATCH_C.read_text()
        assert "r->uri.data + r->uri.len - (sizeof(delegation_path) - 1)" in text, \
            "the upload dispatcher no longer compares the URI tail — #89 may be fixed"
        assert "ngx_memcmp(r->uri.data, deleg_prefix, prefix_len)" in text, \
            "the gridsite dispatcher no longer anchors at the URI start"
