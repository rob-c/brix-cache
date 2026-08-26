"""Test cases for audit16aj_cache_store_endpoint_arms — preamble (fixtures/helpers/mocks) lives in
_test_audit16aj_cache_store_endpoint_arms_helpers.py; reexported below so pytest resolves fixtures in
this module's namespace (split for the 600 logical-line file cap)."""
from split_continuation import reexport as _reexport
_reexport(globals(), "_test_audit16aj_cache_store_endpoint_arms_helpers")


class TestTheDisarmingTokenMatchesTheOmission:
    """Section A, and the reason the file starts here: `off` had never been
    written, so the first thing to establish is that writing it changes nothing
    against the merge default of 0 (shared_conf.h:380-381).

    It changes nothing, on every pattern and every verb.  What writing the arm
    turned out to be worth is everything after this class.
    """

    @pytest.mark.parametrize("vhost", DISARMED_DAV)
    @pytest.mark.parametrize("name", RESERVED, ids=RESERVED_IDS)
    def test_a_reserved_name_is_absent_on_both_disarmed_arms(self, srv, vhost, name):
        assert (srv / name).is_file(), "fixture missing from the shared export"
        assert _dav(vhost, "GET", "/" + name).status_code == 404

    @pytest.mark.parametrize("vhost", DISARMED_DAV)
    def test_the_genuine_sibling_is_served_on_both_disarmed_arms(self, srv, vhost):
        """The control without which every cell above is a claim about the
        export rather than about the name."""
        response = _dav(vhost, "GET", "/" + KEEP)
        assert response.status_code == 200
        assert response.content == KEEP_BYTES

    @pytest.mark.parametrize("name", RESERVED, ids=RESERVED_IDS)
    def test_the_two_disarmed_arms_answer_byte_for_byte_alike(self, srv, name):
        written = _fingerprint(_dav(DAV_OFF, "GET", "/" + name))
        omitted = _fingerprint(_dav(DAV_ABS, "GET", "/" + name))
        assert written == omitted

    @pytest.mark.parametrize("vhost", DISARMED_DAV)
    def test_the_refusal_is_indistinguishable_from_a_genuinely_absent_path(
            self, srv, vhost):
        """path.c:50-58's claim, measured: "404 (not 403) so the response does
        not distinguish an internal name from a genuinely absent one".

        On WebDAV it holds to the byte.  §D is what happens to the same claim on
        the plane the same comment says it covers.
        """
        assert not (srv / "ghost.dat").exists()
        reserved = _fingerprint(_dav(vhost, "GET", "/keep.dat.cinfo"))
        missing = _fingerprint(_dav(vhost, "GET", "/ghost.dat"))
        assert reserved == missing == (404, 153, reserved[2])

    @pytest.mark.parametrize("vhost", DISARMED_DAV)
    def test_no_header_distinguishes_the_two_refusals_either(self, srv, vhost):
        """A body digest says nothing about what a header leaked."""
        reserved = _dav(vhost, "HEAD", "/keep.dat.cinfo")
        missing = _dav(vhost, "HEAD", "/ghost.dat")
        volatile = {"date", "connection"}
        assert ({k.lower(): v for k, v in reserved.headers.items()
                 if k.lower() not in volatile}
                == {k.lower(): v for k, v in missing.headers.items()
                    if k.lower() not in volatile})

    @pytest.mark.parametrize("vhost", DISARMED_DAV)
    @pytest.mark.parametrize("method,expected", [("GET", 404), ("HEAD", 404),
                                                 ("DELETE", 404), ("PROPFIND", 404),
                                                 ("OPTIONS", 200)])
    def test_the_arms_agree_verb_by_verb(self, srv, vhost, method, expected):
        """OPTIONS is in the list because it is the one verb that answers before
        the resolver runs — an equality that held only over the guarded verbs
        would be a weaker statement than this one."""
        headers = {"Depth": "0"} if method == "PROPFIND" else None
        assert _dav(vhost, method, "/keep.dat.meta",
                    headers=headers).status_code == expected

    def test_the_reaper_and_not_the_guard_removes_a_dead_pid_temp(self, srv):
        """The `.xrd-tmp.` fixture names a LIVE pid, and this is why.

        core/config/process.c:43-72 unlinks `<final>.xrd-tmp.<dead-pid>.*` at
        startup, so a temp seeded with a dead pid is 404 on the ARMED arm too —
        for a reason that has nothing to do with this directive.  Both halves
        are stated so a future reader does not read the reaper's work as the
        guard's.
        """
        assert (srv / LIVE_TMP).is_file()
        assert not (srv / DEAD_TMP).exists(), "the reaper did not run"
        assert _dav(DAV_ON, "GET", "/" + LIVE_TMP).status_code == 200
        assert _dav(DAV_ON, "GET", "/" + DEAD_TMP).status_code == 404


# --------------------------------------------------------------------------- #
# B. The armed control — what writing `on` buys                                #
# --------------------------------------------------------------------------- #

class TestTheArmedArmServesWhatTheOthersHide:
    """Section B.  Every cell in section A is an absence, and an absence proves
    nothing on its own: the same 404 would be returned by an export that had
    never been seeded.  These are the same names, over the same bytes, through
    the first configuration in this tree that runs the custom setter.
    """

    @pytest.mark.parametrize("name", RESERVED, ids=RESERVED_IDS)
    def test_every_reserved_pattern_is_an_ordinary_object(self, srv, name):
        response = _dav(DAV_ON, "GET", "/" + name)
        assert response.status_code == 200
        assert response.content == SECRET

    def test_head_reports_the_real_size(self, srv):
        response = _dav(DAV_ON, "HEAD", "/keep.dat.cinfo")
        assert response.status_code == 200
        assert response.headers["Content-Length"] == str(len(SECRET))

    def test_a_sidecar_can_be_written_and_read_back(self, srv):
        """The feature's whole purpose: a cache node PERSISTS a sidecar to its
        origin and reads it back.  Writes are enabled on every face precisely so
        this half can be measured."""
        name = "written-by-b.cinfo"
        assert _dav(DAV_ON, "PUT", "/" + name, data=SECRET).status_code == 201
        assert (srv / name).read_bytes() == SECRET
        assert _dav(DAV_ON, "GET", "/" + name).content == SECRET

    def test_a_sidecar_can_be_deleted(self, srv):
        name = "deleted-by-b.xrdt"
        (srv / name).write_bytes(SECRET)
        assert _dav(DAV_ON, "DELETE", "/" + name).status_code == 204
        assert not (srv / name).exists()

    def test_propfind_names_the_sidecar_when_it_is_the_request_target(self, srv):
        """Depth:0 on the reserved name ITSELF — the precise boundary between
        this section and section H, where the same name is asked for as a
        MEMBER of a collection and is refused on every arm."""
        assert _dav(DAV_ON, "PROPFIND", "/keep.dat.meta",
                    headers={"Depth": "0"}).status_code == 207

    def test_a_sidecar_can_be_a_copy_source_and_a_copy_destination(self, srv):
        source = _dav(DAV_ON, "COPY", "/keep.dat.cinfo",
                      headers={"Destination": _dav_url() + "/copied-from-b.dat"})
        assert source.status_code == 201
        assert (srv / "copied-from-b.dat").read_bytes() == SECRET

        destination = _dav(DAV_ON, "COPY", "/" + KEEP,
                           headers={"Destination": _dav_url() + "/copied-to-b.cinfo"})
        assert destination.status_code == 201
        assert (srv / "copied-to-b.cinfo").read_bytes() == KEEP_BYTES

    def test_a_sidecar_can_be_moved(self, srv):
        (srv / "moved-by-b.xrdcinfo").write_bytes(SECRET)
        response = _dav(DAV_ON, "MOVE", "/moved-by-b.xrdcinfo",
                        headers={"Destination": _dav_url() + "/moved-by-b.dat"})
        assert response.status_code == 201
        assert (srv / "moved-by-b.dat").read_bytes() == SECRET

    def test_a_reserved_collection_can_be_created(self, srv):
        assert _dav(DAV_ON, "MKCOL", "/made-by-b.meta/").status_code == 201
        assert (srv / "made-by-b.meta").is_dir()

    def test_the_armed_arm_still_refuses_a_genuinely_absent_path(self, srv):
        """The flag lifts a NAME rule, not the filesystem."""
        assert _dav(DAV_ON, "GET", "/ghost.dat").status_code == 404
        assert _dav(DAV_ON, "GET", "/ghost.cinfo").status_code == 404


# --------------------------------------------------------------------------- #
# C. Scope, and the merge's UNSET/0 distinction                                #
# --------------------------------------------------------------------------- #

class TestScopeAndTheMergesUnsetDistinction:
    """Section C.  The directive is legal in http{}, server{} and location{},
    merged with ngx_conf_merge_value out of NGX_CONF_UNSET — so a written `off`
    is a VALUE that blocks inheritance where a deleted line is a hole that lets
    it through.

    That distinction is the only reason the merge is a merge rather than a
    default, and until this file no configuration had ever exercised it: the
    http declaration had never been written in any scope.
    """

    def test_a_child_that_writes_nothing_inherits_the_server(self, srv):
        assert _dav(DAV_SRVON, "GET", "/keep.dat.cinfo").status_code == 200

    def test_a_child_that_writes_off_overrides_the_server(self, srv):
        """The reading an absence cannot express."""
        assert _dav(DAV_SRVON, "GET", "/optout/keep.dat.cinfo").status_code == 404
        assert _dav(DAV_SRVON, "GET", "/optout/" + KEEP).status_code == 200

    def test_a_child_that_restates_on_is_no_different(self, srv):
        response = _dav(DAV_SRVON, "GET", "/reassert/keep.dat.cinfo")
        assert response.status_code == 200
        assert response.content == SECRET

    def test_a_server_scope_off_reaches_a_bare_child(self, srv):
        """The custom setter had never run with a 0 at server scope anywhere in
        this tree."""
        assert _dav(DAV_SRVOFF, "GET", "/keep.dat.cinfo").status_code == 404
        assert _dav(DAV_SRVOFF, "GET", "/" + KEEP).status_code == 200

    @pytest.mark.parametrize("name", RESERVED, ids=RESERVED_IDS)
    def test_server_scope_off_and_the_omission_are_indistinguishable(self, srv, name):
        assert (_fingerprint(_dav(DAV_SRVOFF, "GET", "/" + name))
                == _fingerprint(_dav(DAV_ABS, "GET", "/" + name)))

    def test_the_optout_subtree_is_seeded_identically(self, srv):
        """Without this the cell above it is a claim about two directories."""
        assert (srv / "optout" / "keep.dat.cinfo").read_bytes() == SECRET
        assert (srv / "keep.dat.cinfo").read_bytes() == SECRET


# --------------------------------------------------------------------------- #
# D. The S3 plane, the dual write, and DEFECT CANDIDATE #138                   #
# --------------------------------------------------------------------------- #

class TestTheS3PlaneExpressesTheRefusalItOnceCouldNot:
    """Section D.  One directive, two loc-confs: the custom setter writes
    `common.cache_store_endpoint` on the WebDAV loc-conf AND on the S3 one
    (module_acc_directives.c), and nothing in this tree had ever run it.

    The dual write works.  What the S3 plane then does with the flag was #138:
    `s3_resolve_key` collapsed the resolver's 403/404/414 into one bit and the
    dispatcher answered every one of them 403 AccessDenied, so a key named
    `ghost.cinfo` — absent from the export — was told apart from `ghost.dat` by
    an unauthenticated prober.  `s3_resolve_key_ex` now carries the status and
    `s3_resolve_key_error` maps it in one place; the reserved name leaves by the
    same door the absent one does, on every verb.  These cells are the
    regression guard.
    """

    @pytest.mark.parametrize("vhost", ARMED_S3)
    @pytest.mark.parametrize("name", ("keep.dat.cinfo", "keep.dat.meta"))
    def test_the_dual_write_reaches_the_s3_loc_conf(self, srv, vhost, name):
        """s3-srvon.test writes the directive at SERVER scope and nothing in the
        location, so the dual write has to survive the merge chain and not just
        the setter for that arm to see anything."""
        response = _s3(vhost, "GET", name)
        assert response.status_code == 200
        assert response.content == SECRET

    @pytest.mark.parametrize("vhost", DISARMED_S3)
    @pytest.mark.parametrize("name", ("keep.dat.cinfo", "keep.dat.meta"))
    def test_the_disarmed_s3_arms_refuse(self, srv, vhost, name):
        assert _s3(vhost, "GET", name).status_code != 200

    @pytest.mark.parametrize("vhost", ARMED_S3 + DISARMED_S3)
    def test_the_genuine_sibling_is_served_on_every_s3_arm(self, srv, vhost):
        response = _s3(vhost, "GET", KEEP)
        assert response.status_code == 200
        assert response.content == KEEP_BYTES

    @pytest.mark.parametrize("vhost", ARMED_S3 + DISARMED_S3)
    def test_a_genuinely_absent_plain_key_is_404_no_such_key_everywhere(
            self, srv, vhost):
        """The baseline the next two cells are measured against."""
        response = _s3(vhost, "GET", "ghost.dat")
        assert response.status_code == 404
        assert _s3_code(response) == "NoSuchKey"

    @pytest.mark.parametrize("vhost", DISARMED_S3)
    def test_the_refusal_is_the_404_the_resolver_specified(self, srv, vhost):
        """DEFECT CANDIDATE #138, first half, fixed.

        core/compat/path.c says the reserved-name answer is 404 "so the response
        does not distinguish an internal name from a genuinely absent one", and
        says the rule "Covers WebDAV + S3".  The S3 plane now says it too: the
        present-but-reserved key answers exactly what an absent one does.
        """
        response = _s3(vhost, "GET", "keep.dat.cinfo")
        assert (response.status_code, _s3_code(response)) == (404, "NoSuchKey")

    @pytest.mark.parametrize("vhost", DISARMED_S3)
    def test_a_reserved_name_that_does_not_exist_reads_as_an_ordinary_absence(
            self, srv, vhost):
        """DEFECT CANDIDATE #138, and the cell that made it a disclosure rather
        than a status-code preference.

        `ghost.cinfo` exists nowhere.  A client that cannot read any file on
        this bucket used to learn, from the status alone, that the NAME is
        reserved.  All three refusals are now one answer.
        """
        assert not (srv / "ghost.cinfo").exists()
        present_reserved = _s3(vhost, "GET", "keep.dat.cinfo")
        absent_reserved = _s3(vhost, "GET", "ghost.cinfo")
        absent_plain = _s3(vhost, "GET", "ghost.dat")
        answers = {(r.status_code, _s3_code(r))
                   for r in (present_reserved, absent_reserved, absent_plain)}
        assert answers == {(404, "NoSuchKey")}, answers

    @pytest.mark.parametrize("vhost", ARMED_S3)
    def test_the_armed_arm_answers_that_same_key_404(self, srv, vhost):
        """The control that pins the disclosure to the flag: the same absent
        reserved key is an ordinary NoSuchKey once the guard is lifted, so the
        403 above is the guard's answer and not the storage layer's."""
        response = _s3(vhost, "GET", "ghost.cinfo")
        assert response.status_code == 404
        assert _s3_code(response) == "NoSuchKey"

    def test_webdav_is_the_control_that_showed_this_was_a_defect(self, srv):
        """The same guard, the same export, the same two keys, over the plane
        that always kept the promise: three refusals, one fingerprint."""
        present = _fingerprint(_dav(DAV_OFF, "GET", "/keep.dat.cinfo"))
        absent_reserved = _fingerprint(_dav(DAV_OFF, "GET", "/ghost.cinfo"))
        absent_plain = _fingerprint(_dav(DAV_OFF, "GET", "/ghost.dat"))
        assert present == absent_reserved == absent_plain

    @pytest.mark.parametrize("method,key,body,expected", [
        ("HEAD", "keep.dat.cinfo", None, 404),
        ("PUT", "written-by-d-off.cinfo", SECRET, 404),
        ("DELETE", "keep.dat.xrdcinfo", None, 204),
    ])
    def test_every_guarded_verb_answers_as_if_the_key_were_absent(
            self, srv, method, key, body, expected):
        """The DELETE row is 204 and not 404 because S3 DELETE is idempotent —
        `s3_delete_respond(ENOENT)` answers 204 for a key that is not there, so
        that is what the reserved key has to answer too.  A status code is not
        the whole answer, and the verb the status alone does not cover is the
        one a fix that stops at the resolver would leave disclosing."""
        assert _s3(S3_OFF, method, key, data=body).status_code == expected

    @pytest.mark.parametrize("method,body", [
        ("GET", None), ("HEAD", None), ("PUT", SECRET), ("DELETE", None),
    ])
    def test_verb_by_verb_the_reserved_key_and_an_absent_one_agree(
            self, srv, method, body):
        """Stated as an equality rather than as literals, so a future change to
        what an absent key answers cannot re-open the gap by moving only one
        side of it."""
        reserved = _s3(S3_OFF, f"{method}", "ghost-per-verb.cinfo", data=body)
        plain = _s3(S3_OFF, f"{method}", "ghost-per-verb.dat", data=body)
        if method == "PUT":
            # A plain PUT is a create and succeeds; the comparison it belongs in
            # is against a name the guard refuses for a DIFFERENT reason, which
            # is what the WebDAV control below establishes.  Here the cell only
            # has to show the reserved PUT is the resolver's 404 and not a 403.
            assert (reserved.status_code, _s3_code(reserved)) == (404, "NoSuchKey")
            assert plain.status_code == 200
            return
        assert (reserved.status_code, _s3_code(reserved)) == \
               (plain.status_code, _s3_code(plain))

    def test_a_plain_key_is_still_writable_on_the_disarmed_arm(self, srv):
        """The gate is the NAME, not the method: `brix_allow_write on` is in
        force on every face, so a refusal that applied to writes generally would
        show up here."""
        assert _s3(S3_OFF, "PUT", "written-by-d-off.dat", data=SECRET).status_code == 200
        assert (srv / "written-by-d-off.dat").read_bytes() == SECRET

    def test_the_reserved_write_that_was_refused_left_nothing_behind(self, srv):
        assert not (srv / "written-by-d-off.cinfo").exists()
        assert (srv / "keep.dat.xrdcinfo").read_bytes() == SECRET

    def test_the_armed_arm_writes_and_deletes_sidecars(self, srv):
        assert _s3(S3_ON, "PUT", "written-by-d-on.cinfo", data=SECRET).status_code == 200
        assert (srv / "written-by-d-on.cinfo").read_bytes() == SECRET

        (srv / "deleted-by-d-on.meta").write_bytes(SECRET)
        assert _s3(S3_ON, "DELETE", "deleted-by-d-on.meta").status_code == 204
        assert not (srv / "deleted-by-d-on.meta").exists()

    def test_the_armed_arm_answers_head(self, srv):
        response = _s3(S3_ON, "HEAD", "keep.dat.cinfo")
        assert response.status_code == 200
        assert response.headers["Content-Length"] == str(len(SECRET))


# --------------------------------------------------------------------------- #
# E. The metric the S3 refusal books — DEFECT CANDIDATE #139                    #
# --------------------------------------------------------------------------- #

