"""Test cases for audit16aj_cache_store_endpoint_arms — preamble (fixtures/helpers/mocks) lives in
_test_audit16aj_cache_store_endpoint_arms_helpers.py; reexported below so pytest resolves fixtures in
this module's namespace (split for the 600 logical-line file cap)."""
from split_continuation import reexport as _reexport
_reexport(globals(), "_test_audit16aj_cache_store_endpoint_arms_helpers")


class TestTheDuplicateIsRefusedOnBothPlanes:
    """Section G.  ngx_conf_set_flag_slot opens with

        if (*fp != NGX_CONF_UNSET) { return "is duplicate"; }

    and the stream declaration inherits that for free.  The http declaration's
    custom setter writes the two slots itself and so never ran it, which made
    the same pair of lines a hard emerg in a stream server and silence in a
    location — and the line that survived was the second one, which in
    `off; on;` is the permissive one.  That is #142.

    The setter now performs the check against both slots it writes, so the pair
    is refused in nginx's own words on either plane.  The consequence is that a
    RUNNING vhost can no longer carry the duplicate at all: the measurement
    lives at the parse tier, where §J takes it scope by scope and in both
    orders.  What is left here is the runtime half — that the location which
    once carried the pair is an ordinary armed arm once the operator writes the
    single line they meant.
    """

    def test_the_duplicate_no_longer_parses_in_a_location(self, tmp_path):
        """The defect cell, at the only tier that can still hold it.  §J is the
        exhaustive version; this is the one that sits beside the vhost so a
        reader of section G is not sent elsewhere to learn why it changed."""
        rc, out = _parse(tmp_path, LOC_KNOBS=(f"            {FLAG} off;\n"
                                              f"            {FLAG} on;\n"))
        assert rc != 0, out
        assert f'"{FLAG}" directive is duplicate' in out, out

    def test_which_is_what_the_stream_plane_always_said(self, tmp_path):
        """The control that made #142 a disagreement rather than a preference:
        one directive name, one config text, and now one diagnostic."""
        rc, out = _parse(tmp_path, STREAM_KNOBS=(f"            {FLAG} off;\n"
                                                 f"            {FLAG} on;\n"))
        assert rc != 0, out
        assert f'"{FLAG}" directive is duplicate' in out, out

    def test_the_face_that_carried_it_is_an_ordinary_armed_arm(self, srv):
        """dav-dup.test now writes the single `on;` the `off; on;` pair used to
        resolve to, so the vhost still serves and the runtime shape §G once
        measured is unchanged — only its cause is."""
        response = _dav(DAV_DUP, "GET", "/keep.dat.cinfo")
        assert response.status_code == 200
        assert response.content == SECRET
        assert _dav(DAV_DUP, "GET", "/" + KEEP).content == KEEP_BYTES
        assert _dav(DAV_DUP, "GET", "/ghost.dat").status_code == 404


# --------------------------------------------------------------------------- #
# H. Enumeration is never lifted                                               #
# --------------------------------------------------------------------------- #

class TestEnumerationIgnoresTheFlagOnEveryPlane:
    """Section H.  Four enumeration filters — propfind_walk.c:82, search.c:105,
    s3/list_walk.c:293 and root/dirlist/handler_stream.c:88 — drop reserved
    names WITHOUT consulting the flag.

    So the armed arm is asymmetric by design: a sidecar can be fetched by name
    and can never be discovered by listing.  Worth stating on all three planes,
    because "the flag lifts the guard" would predict otherwise on every one of
    them.
    """

    @pytest.mark.parametrize("vhost", (DAV_ON, DAV_OFF, DAV_ABS, DAV_DUP))
    def test_propfind_hides_reserved_names_on_every_arm(self, srv, vhost):
        response = _dav(vhost, "PROPFIND", "/", headers={"Depth": "1"})
        assert response.status_code == 207
        names = _hrefs(response.text)
        assert KEEP in names
        assert not (set(RESERVED) & names), names

    @pytest.mark.parametrize("vhost", (DAV_ON, DAV_OFF))
    def test_propfind_keeps_the_near_misses_on_every_arm(self, srv, vhost):
        """Without this the cell above would also pass on a listing that
        returned nothing."""
        names = _hrefs(_dav(vhost, "PROPFIND", "/",
                            headers={"Depth": "1"}).text)
        assert {"keep.dat.CINFO", "keep.dat.cinfoX", "cinfo"} <= names, names

    def test_the_armed_arm_lists_exactly_what_the_disarmed_one_lists(self, srv):
        armed = _hrefs(_dav(DAV_ON, "PROPFIND", "/", headers={"Depth": "1"}).text)
        disarmed = _hrefs(_dav(DAV_OFF, "PROPFIND", "/", headers={"Depth": "1"}).text)
        assert armed == disarmed

    @pytest.mark.parametrize("vhost", (S3_ON, S3_OFF))
    def test_list_objects_hides_reserved_keys_on_every_arm(self, srv, vhost):
        response = _s3(vhost, "GET", "", query="list-type=2")
        assert response.status_code == 200
        assert b"<Key>keep.dat</Key>" in response.content
        for name in RESERVED:
            assert f"<Key>{name}</Key>".encode() not in response.content

    @pytest.mark.parametrize("port", (ROOT_ON, ROOT_OFF, ROOT_ABS))
    def test_dirlist_hides_reserved_names_on_every_arm(self, srv, port):
        names = _wire_plain_names(port, "/")
        assert KEEP in names
        assert not (set(RESERVED) & names), names
        assert "keep.dat.CINFO" in names

    def test_the_three_root_arms_list_identically(self, srv):
        assert (_wire_plain_names(ROOT_ON, "/")
                == _wire_plain_names(ROOT_OFF, "/")
                == _wire_plain_names(ROOT_ABS, "/"))

    def test_naming_the_sidecar_directly_is_the_boundary(self, srv):
        """The precise line between section B and this one: the same name, as a
        request TARGET, is served on the armed arm and refused on the disarmed
        one — while as a collection MEMBER it is hidden from both."""
        assert _dav(DAV_ON, "PROPFIND", "/keep.dat.meta",
                    headers={"Depth": "0"}).status_code == 207
        assert _dav(DAV_OFF, "PROPFIND", "/keep.dat.meta",
                    headers={"Depth": "0"}).status_code == 404
        assert "keep.dat.meta" not in _hrefs(
            _dav(DAV_ON, "PROPFIND", "/", headers={"Depth": "1"}).text)


# --------------------------------------------------------------------------- #
# I. Security negatives                                                        #
# --------------------------------------------------------------------------- #

class TestTheGuardCannotBeTalkedPast:
    """Section I.  The predicate is a lexical test on a decoded path, so every
    negative here asks the same question in a different alphabet: does the
    encoding, the normalization or the case of the request change which side of
    the guard the name lands on?

    It does not — with one exception, which is #144.
    """

    @pytest.mark.parametrize("path", [
        "/keep.dat%2Ecinfo",      # the dot, percent-encoded
        "/keep.dat.cinf%6F",      # the last letter of the suffix
        "/%6Beep.dat.cinfo",      # a letter of the stem, to prove decoding runs
        "/./keep.dat.cinfo",      # a no-op segment
        "//keep.dat.cinfo",       # a doubled separator
        "/../keep.dat.cinfo",     # traversal above the root
        "/plaindir/../keep.dat.cinfo",   # traversal back down to it
        "/keep.dat.cinfo/",       # a trailing separator on a file
        "/keep.dat.cinfo/.",      # and a no-op segment after it
    ])
    def test_no_spelling_of_a_reserved_name_gets_past_the_disarmed_arm(
            self, srv, path):
        assert _dav(DAV_OFF, "GET", path).status_code == 404

    @pytest.mark.parametrize("path", [
        "/keep.dat%2Ecinfo", "/keep.dat.cinf%6F", "/%6Beep.dat.cinfo",
        "/./keep.dat.cinfo", "//keep.dat.cinfo", "/../keep.dat.cinfo",
        "/plaindir/../keep.dat.cinfo", "/keep.dat.cinfo/", "/keep.dat.cinfo/.",
    ])
    def test_every_one_of_those_spellings_names_the_same_file(self, srv, path):
        """The control that turns the cell above from "nine paths 404" into
        "nine spellings of ONE name are guarded": each resolves to the same
        fifteen bytes once the guard is lifted."""
        response = _dav(DAV_ON, "GET", path)
        assert response.status_code == 200
        assert response.content == SECRET

    @pytest.mark.parametrize("vhost", (DAV_ON, DAV_OFF))
    def test_an_embedded_nul_is_refused_before_the_guard_is_reached(
            self, srv, vhost):
        """400, on both arms, from nginx's own request-line parser — the guard
        never sees it, which is the point: a name the resolver cannot decode
        cannot be smuggled past a resolver-level rule."""
        connection = socket.create_connection((HOST, HTTP_PORT), TIMEOUT)
        try:
            connection.sendall(
                b"GET /keep.dat.cinfo%00.txt HTTP/1.1\r\nHost: "
                + vhost.encode() + b"\r\nConnection: close\r\n\r\n")
            assert connection.recv(64).startswith(b"HTTP/1.1 400")
        finally:
            connection.close()

    @pytest.mark.parametrize("name", NEAR_MISS)
    def test_a_near_miss_name_stays_reachable_on_the_disarmed_arm(self, srv, name):
        """The guard is narrow on purpose: one character off a pattern and the
        file is an ordinary object.  `keep.dat.CINFO` is in this list because
        reserved_names.h compares with memcmp — a case-insensitive predicate
        would be a different bug from an over-broad one."""
        response = _dav(DAV_OFF, "GET", "/" + name)
        assert response.status_code == 200
        assert response.content == NEAR_BYTES

    def test_the_whole_basename_may_be_the_suffix(self, srv):
        """`.cinfo` has no stem at all and is still reserved — the predicate is
        a suffix test on the final component, not a stem-plus-extension test."""
        assert _dav(DAV_OFF, "GET", "/.cinfo").status_code == 404
        assert _dav(DAV_ON, "GET", "/.cinfo").status_code == 200

    def test_a_creating_verb_does_not_answer_as_if_absent(self, srv):
        """MKCOL of a reserved collection is 409 on the disarmed arm, where the
        resolver's rule would predict 404 — and 409 is what an ALREADY EXISTING
        collection answers, so the refusal is indistinguishable from "it is
        already there" rather than from "it is not".

        A milder relative of #138, on the plane that otherwise keeps the
        promise: the 404 rule holds for reads and not for creates.
        """
        assert _dav(DAV_OFF, "MKCOL", "/made-by-i.meta/").status_code == 409
        assert not (srv / "made-by-i.meta").exists()
        assert _dav(DAV_OFF, "MKCOL", "/made-by-i-plain/").status_code == 201
        assert _dav(DAV_ON, "MKCOL", "/made-by-i-armed.meta/").status_code == 201

    def test_a_reserved_copy_destination_answers_the_same_way(self, srv):
        assert _dav(DAV_OFF, "COPY", "/" + KEEP,
                    headers={"Destination": _dav_url() + "/copied-by-i.cinfo"}
                    ).status_code == 409
        assert not (srv / "copied-by-i.cinfo").exists()
        assert _dav(DAV_OFF, "COPY", "/" + KEEP,
                    headers={"Destination": _dav_url() + "/copied-by-i.dat"}
                    ).status_code == 201


class TestAReservedDirectoryHidesItsWholeSubtree:
    """DEFECT CANDIDATE #144, fixed.  brix_is_internal_name tested the FINAL
    path component only, so a directory whose name matched a pattern was hidden
    while every file beneath it stayed reachable by its own full path, on the
    disarmed arm, at 200.

    Nothing in this tree creates such a directory today, which is why the hole
    had never been reached.  It was one `mkdir` away: MKCOL creates one on the
    armed arm (section B), and after that the tree contains a subtree the
    disarmed arm believes it is hiding.

    The predicate now walks every component.  The infix search had to be
    rewritten for that: a component is a SLICE of the caller's path and is not
    NUL-terminated, so the strstr() the single-component version used would run
    past its end into the next one.
    """

    def test_the_directory_itself_is_hidden(self, srv):
        assert _dav(DAV_OFF, "GET", "/adir.meta/").status_code == 404
        assert _dav(DAV_OFF, "PROPFIND", "/adir.meta/",
                    headers={"Depth": "1"}).status_code == 404

    def test_and_so_are_its_contents(self, srv):
        response = _dav(DAV_OFF, "GET", "/adir.meta/inside.txt")
        assert response.status_code == 404

    def test_a_reserved_component_hides_the_subtree_at_any_depth(self, srv):
        """The general statement of the fix: the guarded component is neither
        the first nor the last, and the leaf name is entirely ordinary."""
        deep = srv / "plaindir" / "buried.xrd-tmp.d" / "sub"
        deep.mkdir(parents=True, exist_ok=True)
        (deep / "inside.txt").write_bytes(SECRET)
        assert _dav(DAV_OFF, "GET",
                    "/plaindir/buried.xrd-tmp.d/sub/inside.txt").status_code == 404
        assert _dav(DAV_ON, "GET",
                    "/plaindir/buried.xrd-tmp.d/sub/inside.txt").content == SECRET

    def test_the_same_hole_is_closed_on_the_root_plane(self, srv):
        session = _session(ROOT_OFF)
        try:
            _, hidden, body = _stat_path(session, "/adir.meta")
            assert hidden != kXR_ok and _err(body) == 3011

            _, inside, inside_body = _stat_path(session, "/adir.meta/inside.txt")
            assert inside != kXR_ok and _err(inside_body) == 3011
        finally:
            session.close()

    def test_the_hidden_directory_can_no_longer_be_listed(self, srv):
        """dirlist consulted the flag nowhere, so naming the collection the stat
        above refused enumerated it — the same two-planes-disagree shape as
        #141, since WebDAV PROPFIND 404s that very collection.  The refusal
        carries the genuine-miss text, so it says nothing the absence does not.

        This is about the collection being NAMED.  The per-entry filter that
        hides reserved MEMBERS of an ordinary directory is unconditional on
        every arm and is measured separately in section H."""
        with pytest.raises(_DirlistError) as refused:
            _wire_plain_names(ROOT_OFF, "/adir.meta")
        with pytest.raises(_DirlistError) as absent:
            _wire_plain_names(ROOT_OFF, "/ghostdir")
        assert refused.value.errnum == absent.value.errnum == 3011
        assert _reason(refused.value.body) == _reason(absent.value.body)
        assert _wire_plain_names(ROOT_ON, "/adir.meta") == {"inside.txt"}

    def test_the_armed_arm_is_the_control(self, srv):
        """On the armed arm the directory is an ordinary one, which is what
        makes the disarmed arm's partial hiding a hole rather than a design."""
        assert _dav(DAV_ON, "PROPFIND", "/adir.meta/",
                    headers={"Depth": "1"}).status_code == 207
        session = _session(ROOT_ON)
        try:
            assert _stat_path(session, "/adir.meta")[1] == kXR_ok
        finally:
            session.close()

    def test_a_plain_directory_is_the_other_control(self, srv):
        """`plaindir` is reachable on both arms, so the asymmetry above is about
        the NAME and not about directories."""
        assert _dav(DAV_OFF, "PROPFIND", "/plaindir/",
                    headers={"Depth": "1"}).status_code == 207
        assert _dav(DAV_OFF, "GET", "/plaindir/inside.txt").content == \
            b"INSIDE-A-PLAIN-DIRRR"


# --------------------------------------------------------------------------- #
# J. The parse tier — one line, one scope, on both declarations                 #
# --------------------------------------------------------------------------- #

PARSE_SLOTS = ("LOC_KNOBS", "SRV_KNOBS", "HTTP_KNOBS", "OUTER", "STREAM_KNOBS",
               "STREAM_MAIN", "EXTRA_LOC")


def _parse(tmp_path, **slots):
    """One `nginx -t` on the tranche's shared scaffold.

    nginx_audit16nparse.conf is reused rather than duplicated: it offers one slot
    per scope and takes no position on which should accept, and this subject —
    the first in the tree legal on BOTH planes — is the one that exercises all
    of them.
    """
    (tmp_path / "data").mkdir(exist_ok=True)
    (tmp_path / "logs").mkdir(exist_ok=True)
    values = {"PORT": PARSE_PLACEHOLDER_PORT,
              "STREAM_PORT": PARSE_PLACEHOLDER_PORT,
              "LOG_DIR": str(tmp_path),
              "DATA": str(tmp_path / "data")}
    values.update({slot: "" for slot in PARSE_SLOTS})
    values.update(slots)
    result = nginx_t("nginx_audit16nparse.conf", tmp_path, **values)
    return result.returncode, result.stderr


class TestTheTwoDeclarationsAcceptTheSameScopes:
    """Section J.  Two command-table entries, four accepting scopes between
    them, and nothing in this tree had ever asked `nginx -t` about any of them.
    """

    @pytest.mark.parametrize("value", ("on", "off"))
    @pytest.mark.parametrize("slot", ("LOC_KNOBS", "SRV_KNOBS", "HTTP_KNOBS",
                                      "STREAM_KNOBS"))
    def test_every_declared_scope_accepts_both_values(self, tmp_path, slot, value):
        rc, out = _parse(tmp_path, **{slot: f"            {FLAG} {value};\n"})
        assert rc == 0, out

    @pytest.mark.parametrize("value", ("on", "off"))
    @pytest.mark.parametrize("slot", ("OUTER", "STREAM_MAIN"))
    def test_the_two_undeclared_scopes_refuse_by_name(self, tmp_path, slot, value):
        """"not allowed here" and never "unknown directive": nginx searches every
        module's command table before it checks the context, so a misplaced
        occurrence is diagnosed by the table it belongs to.  stream{} main is
        the interesting one — the http declaration carries NGX_HTTP_MAIN_CONF
        and the stream one does not."""
        rc, out = _parse(tmp_path, **{slot: f"            {FLAG} {value};\n"})
        assert rc != 0, out
        assert f'"{FLAG}" directive is not allowed here' in out, out
        assert "unknown directive" not in out, out

    def test_the_three_http_scopes_compose(self, tmp_path):
        """http{}, server{} and location{} at once — the shape section C
        measures at runtime."""
        rc, out = _parse(tmp_path,
                         HTTP_KNOBS=f"    {FLAG} on;\n",
                         SRV_KNOBS=f"        {FLAG} off;\n",
                         LOC_KNOBS=f"            {FLAG} on;\n")
        assert rc == 0, out


class TestTheValuesAndTheArity:

    @pytest.mark.parametrize("slot", ("LOC_KNOBS", "STREAM_KNOBS"))
    @pytest.mark.parametrize("value", ("on", "off", "ON", "OFF", "On"))
    def test_both_declarations_take_the_token_case_insensitively(
            self, tmp_path, slot, value):
        """ngx_strcasecmp on both sides — the custom setter copied that much."""
        rc, out = _parse(tmp_path, **{slot: f"            {FLAG} {value};\n"})
        assert rc == 0, out

    @pytest.mark.parametrize("slot", ("LOC_KNOBS", "STREAM_KNOBS"))
    @pytest.mark.parametrize("value", ("1", "0", "yes", "true", "maybe", '""'))
    def test_both_declarations_refuse_everything_else(self, tmp_path, slot, value):
        rc, out = _parse(tmp_path, **{slot: f"            {FLAG} {value};\n"})
        assert rc != 0, out
        assert f'in "{FLAG}" directive' in out, out

    @pytest.mark.parametrize("slot", ("LOC_KNOBS", "STREAM_KNOBS"))
    @pytest.mark.parametrize("args", ("", "on on", "on off", "on extra"))
    def test_both_declarations_take_exactly_one_argument(self, tmp_path, slot, args):
        line = f"            {FLAG} {args};\n" if args else f"            {FLAG};\n"
        rc, out = _parse(tmp_path, **{slot: line})
        assert rc != 0, out
        assert f'invalid number of arguments in "{FLAG}" directive' in out, out


class TestTheDuplicateCheckAndTheDiagnosticText:
    """DEFECT CANDIDATES #142 and #143, at the tier that shows their cause.

    One directive name, two setters: everything they were both given for free by
    nginx (arity, case folding) matches, and everything the custom setter had to
    reimplement (the duplicate check, the diagnostic string) does not.
    """

    @pytest.mark.parametrize("slot", ("LOC_KNOBS", "SRV_KNOBS", "HTTP_KNOBS"))
    @pytest.mark.parametrize("pair", (("off", "on"), ("on", "off"), ("on", "on")))
    def test_the_http_declaration_refuses_a_duplicate(self, tmp_path, slot, pair):
        """#142, fixed.  In every http scope, in either order, including the
        pair that agrees with itself — nginx's own check does not exempt
        `on; on;` and neither does this one."""
        first, second = pair
        rc, out = _parse(tmp_path, **{slot: (f"            {FLAG} {first};\n"
                                             f"            {FLAG} {second};\n")})
        assert rc != 0, out
        assert f'"{FLAG}" directive is duplicate' in out, out

    def test_the_check_does_not_fire_across_scopes(self, tmp_path):
        """SECURITY-NEGATIVE for the fix itself.  The setter tests the two
        loc-confs it is about to write, and http{}, server{} and location{} each
        get their own — so a restatement one scope down is not a duplicate.
        Every scope carries the SAME value here, which is the shape a check
        written against a shared slot would have turned into an emerg, and the
        one an operator reaches by templating the flag into a base server and
        then repeating it in a child.  (`test_the_three_http_scopes_compose`
        above is the differing-value version of the same nesting.)"""
        rc, out = _parse(tmp_path,
                         HTTP_KNOBS=f"    {FLAG} on;\n",
                         SRV_KNOBS=f"        {FLAG} on;\n",
                         LOC_KNOBS=f"            {FLAG} on;\n")
        assert rc == 0, out

    @pytest.mark.parametrize("pair", (("off", "on"), ("on", "off"), ("on", "on")))
    def test_the_stream_declaration_refuses_the_identical_pair(self, tmp_path, pair):
        """The control: ngx_conf_set_flag_slot's own first line, which the http
        setter never reaches because it fills the slot itself."""
        first, second = pair
        rc, out = _parse(tmp_path, STREAM_KNOBS=(f"            {FLAG} {first};\n"
                                                 f"            {FLAG} {second};\n"))
        assert rc != 0, out
        assert f'"{FLAG}" directive is duplicate' in out, out

    def test_both_declarations_now_share_one_wording(self, tmp_path):
        """#143, fixed.  nginx's own text is `it must be "on" or "off"`; the
        custom setter's was the same sentence with the pronoun dropped.  One
        directive name, two diagnostics, and an operator grepping logs for
        either one missed half of its occurrences."""
        rc, out = _parse(tmp_path, LOC_KNOBS=f"            {FLAG} maybe;\n")
        assert rc != 0, out
        assert f'invalid value "maybe" in "{FLAG}" directive, it must be "on" or "off"' \
            in out, out

    def test_the_stream_declaration_uses_nginx_own_wording(self, tmp_path):
        rc, out = _parse(tmp_path, STREAM_KNOBS=f"            {FLAG} maybe;\n")
        assert rc != 0, out
        assert f'invalid value "maybe" in "{FLAG}" directive, it must be "on" or "off"' \
            in out, out


# --------------------------------------------------------------------------- #
# K. The source says what this file says                                       #
# --------------------------------------------------------------------------- #

SRC = Path(__file__).resolve().parents[1] / "src"


def _source(relative):
    return (SRC / relative).read_text(errors="replace")


def _code(text):
    """The C with its comments removed.

    Several cells below assert that a construct is ABSENT, and this file's own
    C carries comments that name the construct in order to explain why it is not
    used — so a raw substring search reads its own rationale as a violation.
    """
    return re.sub(r"/\*.*?\*/", " ", text, flags=re.S)


class TestTheSourceSaysWhatThisFileSays:
    """Section K.  Every claim above that names a file and a mechanism, read off
    the C rather than argued — so a refactor that moves the behaviour makes the
    narrative fail here instead of leaving it quietly wrong.
    """

    def test_the_directive_is_declared_twice_under_one_name(self):
        http = _source("protocols/webdav/module_commands.c")
        stream = _source("protocols/root/stream/module.c")
        assert FLAG in http and FLAG in stream

    def test_the_http_declaration_is_one_common_module_flag_slot(self):
        """phase-101 W2 retired the dual-conf custom setter: one registration
        on the common module's stock flag slot now covers every HTTP protocol
        (webdav, s3 AND cvmfs), adopted into each protocol's conf."""
        http = _source("core/config/http_directives_core.h")
        block = http[http.index(FLAG):http.index(FLAG) + 400]
        assert "ngx_conf_set_flag_slot" in block, block
        assert "common.cache_store_endpoint" in block, block

    def test_the_stream_declaration_uses_the_stock_one(self):
        stream = _source("protocols/root/stream/module.c")
        block = stream[stream.index(FLAG):stream.index(FLAG) + 300]
        assert "ngx_conf_set_flag_slot" in block, block
        assert "NGX_STREAM_SRV_CONF" in block, block

    def test_every_http_protocol_adopts_the_one_slot(self):
        """The W2 replacement for #138's dual write: the value is written once
        (common module flag slot), then adopted into every protocol conf, so
        no protocol's location can escape the endpoint gate."""
        adopt = _source("core/config/http_common.c")
        assert "BRIX_ADOPT_VAL(cache_store_endpoint, NGX_CONF_UNSET);" in adopt

    def test_the_merge_is_a_merge_and_not_a_default(self):
        init = _source("core/config/shared_conf.h")
        assert "conf->cache_store_endpoint = NGX_CONF_UNSET;" in init
        merge = _source("core/config/shared_conf_merge.h")
        assert re.search(r"ngx_conf_merge_value\(conf->cache_store_endpoint,"
                         r"\s*prev->cache_store_endpoint,\s*0\s*\)", merge), \
            "the merge no longer defaults to 0"

    def test_the_resolver_claims_the_404_is_deliberate_and_covers_s3(self):
        """The comment §D holds the S3 plane to."""
        body = _source("core/compat/path.c")
        # The sentence is wrapped across three comment lines, so it is matched a
        # fragment at a time rather than as one string.
        assert "404 (not 403) so the response does not distinguish an" in body
        assert "internal name from a genuinely absent one." in body
        assert "Covers WebDAV + S3" in body
        assert "if (!allow_internal && brix_is_internal_name(" in body

    def test_the_s3_resolver_carries_the_status_out(self):
        """The mechanism behind #138: three distinct refusals in, three out.
        `s3_resolve_key` is kept as the boolean wrapper for the callers that
        genuinely only need the bit, but it is now DERIVED from the status
        rather than the only thing the resolver computes."""
        body = _source("protocols/s3/util.c")
        assert "s3_resolve_key_ex(" in body, body
        assert re.search(r"s3_resolve_key\(.*?\)\s*\{[^}]*"
                         r"return\s+s3_resolve_key_ex\(", body, re.S), body

    def test_one_function_maps_the_status_to_the_answer(self):
        """#138 and #139 are one mapping, written once — a second copy is how
        the two of them got out of step with the resolver in the first place."""
        body = _code(_source("protocols/s3/util.c"))
        mapper = body[body.index("s3_resolve_key_error(int rc"):]
        mapper = mapper[:mapper.index("\n}\n") + 3]
        assert "NoSuchKey" in mapper and "BRIX_S3_EVENT_NO_SUCH_KEY" in mapper, mapper
        assert "404" in mapper and "414" in mapper, mapper

    def test_every_s3_call_site_goes_through_that_mapping(self):
        """The cell that keeps the fix from being partial: the object router,
        COPY's source leg, POST-form and the DeleteObjects batch each resolved a
        key on their own, and a fix at one of them would have left the other
        three answering 403 for a name the resolver called absent."""
        for path in ("protocols/s3/handler_dispatch.c",
                     "protocols/s3/copy.c",
                     "protocols/s3/post_object.c",
                     "protocols/s3/delete_objects_batch.c"):
            body = _source(path)
            assert "s3_resolve_key_ex(" in body, path

    def test_the_object_router_hands_a_reserved_key_to_the_absent_path(self):
        """A status alone is not the whole answer: DELETE of an absent key is
        204, not 404, so the reserved key has to be routed into the same
        per-method shaping and not merely given the same number."""
        body = _source("protocols/s3/handler_dispatch.c")
        window = body[body.index("s3_resolve_object_key"):]
        window = window[:window.index("\n}\n") + 3]
        assert "s3_dispatch_object_absent(" in window, window
        assert "NGX_HTTP_FORBIDDEN" not in window, window

        route = _source("protocols/s3/handler_object_route.c")
        absent = route[route.index("\ns3_dispatch_object_absent"):]
        absent = absent[:absent.index("\n}\n") + 3]
        assert "s3_delete_respond(r, ENOENT)" in absent, absent
        assert "s3_reject_write_disabled(" in absent, absent

    def test_the_event_label_set_is_low_cardinality_and_fixed(self):
        """Invariant 8, and the reason #139 cannot be fixed by adding a label."""
        body = _source("observability/metrics/s3.c")
        for label in ("access_denied", "no_such_key"):
            assert f'"{label}"' in body, label

    def test_the_predicate_is_lexical_and_walks_every_component(self):
        """#144's mechanism, and the reason the infix test had to be rewritten:
        a component is a slice of the caller's path and carries no NUL of its
        own, so strstr() on it would read into the next one."""
        body = _source("fs/path/reserved_names.h")
        for pattern in (".cinfo", ".xrdcinfo", ".meta", ".xrdt", ".commit",
                        ".xrd-tmp.", ".xrdresume."):
            assert f'"{pattern}"' in body, pattern
        assert "memcmp" in body, "the comparison is no longer case-sensitive"
        assert "brix_component_is_internal(" in body, body
        assert "strstr(" not in _code(body), \
            "an unbounded search over a non-terminated component slice"

    def test_the_root_plane_reads_the_flag_at_five_call_sites(self):
        """#141 closed: the reading verbs it always consulted, plus the shared
        resolve core every mutating path verb reaches and the dirlist target
        check.  Named individually rather than counted over a glob, so a sixth
        site is a deliberate addition and not a silently satisfied number."""
        expected = ("protocols/root/read/open_request.c",
                    "protocols/root/read/stat.c",
                    "protocols/root/read/statx.c",
                    "protocols/root/path/op_path.c",
                    "protocols/root/dirlist/handler.c")
        reading = [p for p in expected if "cache_store_endpoint" in _source(p)]
        assert list(reading) == list(expected), reading

    def test_the_mutating_verbs_inherit_the_guard_from_one_place(self):
        """#141's fix is a single insertion into `brix_path_resolve_beneath`,
        which rm, rmdir, mkdir, chmod, truncate, readlink, fattr and kXR_mv all
        reach — so the guard cannot be present on one verb and absent on its
        neighbour."""
        body = _source("protocols/root/path/op_path.c")
        window = body[body.index("brix_path_resolve_beneath"):]
        assert "brix_is_internal_name(" in window, window
        assert "return NGX_DECLINED;" in window, \
            "the refusal no longer leaves by the gate's own missing-path door"

    def test_the_enumeration_filters_never_consult_the_flag(self):
        """Section H's mechanism, stated as four absences."""
        for path in ("protocols/webdav/propfind_walk.c",
                     "protocols/webdav/search.c",
                     "protocols/s3/list_walk.c",
                     "protocols/root/dirlist/handler_stream.c"):
            body = _source(path)
            assert "brix_is_internal_name(" in body, path
            assert "cache_store_endpoint" not in body, path

    def test_no_file_includes_the_predicate_without_calling_it(self):
        """DEFECT CANDIDATE #145, fixed, and generalised from the three files
        that carried it to the whole tree.  A comment about hiding sidecars
        beside an include the file never uses is dead intent that reads, to the
        next person, as coverage — which is exactly how #141 survived: two of
        the three stale includes sat on the paths the guard was missing from.

        `dirlist/handler.c` is not on the stale list any more because its
        include became real, not because it was deleted."""
        stale = []
        for path in sorted(SRC.rglob("*.c")):
            body = path.read_text(errors="replace")
            if "reserved_names.h" in body and "brix_is_internal_name(" not in body:
                stale.append(str(path.relative_to(SRC)))
        assert stale == [], stale


# --------------------------------------------------------------------------- #
# L. The corpus's own claim about itself                                       #
# --------------------------------------------------------------------------- #

CONFIGS = Path(__file__).resolve().parent / "configs"
MINE = "nginx_audit16aj_store_endpoint.conf"


class TestTheCorpusHadWrittenAlmostNoneOfThis:
    """Section L.  The census that opened the file, as cells that will fail the
    moment someone writes the token — which is the point.
    """

    def _bodies(self):
        return {p.name: p.read_text(errors="replace")
                for p in CONFIGS.glob("*.conf") if p.name != MINE}

    def test_no_config_but_this_file_s_own_writes_the_disarming_token(self):
        writers = sorted(name for name, body in self._bodies().items()
                         if re.search(rf"^\s*{FLAG}\s+off\s*;", body, re.MULTILINE))
        assert writers == [], writers

    def test_exactly_one_config_writes_the_arming_token(self):
        """The other half, so the cell above is a statement about the DISARMING
        arm and not about the directive being unused."""
        writers = sorted(name for name, body in self._bodies().items()
                         if re.search(rf"^\s*{FLAG}\s+on\s*;", body, re.MULTILINE))
        assert writers == ["nginx_mu_sidecar_store.conf"], writers

    def test_that_one_config_writes_it_on_the_stream_plane(self):
        """Which is why the http declaration's custom setter had never run: the
        one writer in the tree reaches the stock setter."""
        body = (CONFIGS / "nginx_mu_sidecar_store.conf").read_text()
        stream = body[body.index("stream"):]
        assert re.search(rf"^\s*{FLAG}\s+on\s*;", stream, re.MULTILINE), stream
        assert not re.search(rf"^\s*{FLAG}", body[:body.index("stream")],
                             re.MULTILINE), "an http occurrence appeared"

    def test_this_file_s_own_template_writes_both_declarations(self):
        """The claim that makes every section above possible, checked rather
        than assumed."""
        body = (CONFIGS / MINE).read_text()
        assert re.search(rf"^\s*{FLAG}\s+off\s*;", body, re.MULTILINE), body
        assert body.count(FLAG) >= 10, body.count(FLAG)

    def test_the_two_planes_cannot_share_a_listener(self):
        """Why the template needs two http listeners rather than one: the load
        gate that forced the shape, recorded so a future simplification does not
        rediscover it at runtime."""
        assert "one brix protocol per port" in \
            _source("protocols/shared/proto_exclusive.c"), \
            "the gate the template's two listeners exist for is gone"
