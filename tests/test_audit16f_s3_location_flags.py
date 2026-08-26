"""Test cases for audit16f_s3_location_flags — preamble (fixtures/helpers/mocks) lives in
_test_audit16f_s3_location_flags_helpers.py; reexported below so pytest resolves fixtures in
this module's namespace (split for the 600 logical-line file cap)."""
from split_continuation import reexport as _reexport
_reexport(globals(), "_test_audit16f_s3_location_flags_helpers")


class TestThePerChunkSignatureChain:
    """The flag decides whether each aws-chunked chunk's own signature is
    checked (aws_chunked_parse.c:97-131), which is reachable only because
    s3_sigv4_finish() retained the signing material for it
    (auth_sigv4_verify.c:327)."""

    def test_on_refuses_a_forged_chunk_signature(self, s3flags):
        key = f"forged-{uuid.uuid4().hex}.txt"
        response = _streaming_put(s3flags.port, VERIFY[ON], key,
                                  [b"hello ", b"world"], tamper=1)
        assert response.status_code == 403, response.text[:300]
        assert _code(response) == "SignatureDoesNotMatch"
        assert not (s3flags.root(VERIFY[ON]) / key).exists(), \
            "the refused body was written anyway"

    def test_on_accepts_a_correctly_chained_body(self, s3flags):
        """The control: the ON arm is not simply refusing every chunked PUT."""
        key = f"good-{uuid.uuid4().hex}.txt"
        response = _streaming_put(s3flags.port, VERIFY[ON], key,
                                  [b"hello ", b"world"])
        assert response.status_code in (200, 201), response.text[:300]
        assert (s3flags.root(VERIFY[ON]) / key).read_bytes() == b"hello world"

    @pytest.mark.parametrize("arm", [OFF, DEFAULT], ids=["off", "absent"])
    def test_the_unchecked_arms_accept_a_forged_chunk_signature(self, s3flags,
                                                                arm):
        """The pair, and the reason the explicit ``off`` had to be written at
        all: it answers exactly as the absent directive does."""
        bucket = VERIFY[arm]
        key = f"forged-{uuid.uuid4().hex}.txt"
        response = _streaming_put(s3flags.port, bucket, key,
                                  [b"hello ", b"world"], tamper=1)
        assert response.status_code in (200, 201), response.text[:300]
        assert (s3flags.root(bucket) / key).read_bytes() == b"hello world", \
            "the unchecked arm accepted the request but stored other bytes"

    @pytest.mark.parametrize("arm", [ON, OFF, DEFAULT],
                             ids=["on", "off", "absent"])
    def test_a_forged_request_signature_is_refused_on_every_arm(self, s3flags,
                                                                arm):
        """Security-negative.  The flag narrows the per-CHUNK check; the
        request's own SigV4 signature is verified either way, so `off` is not a
        way to write to the export unsigned."""
        bucket = VERIFY[arm]
        key = f"seedforge-{uuid.uuid4().hex}.txt"
        response = _streaming_put(s3flags.port, bucket, key,
                                  [b"hello ", b"world"], forge_seed=True)
        assert response.status_code == 403, response.text[:300]
        assert _code(response) == "SignatureDoesNotMatch"
        assert not (s3flags.root(bucket) / key).exists()

    def test_the_two_arms_land_in_different_metric_buckets(self, s3flags):
        """One forged-chunk PUT per arm, read off the exposition: the refusal is
        a PUT 4xx, the acceptance a PUT 2xx.  Same request, same body, same
        credentials — the counter that moves is chosen by the flag."""
        before = _metrics(s3flags.port)
        _streaming_put(s3flags.port, VERIFY[ON], f"m-{uuid.uuid4().hex}.txt",
                       [b"hello ", b"world"], tamper=1)
        _streaming_put(s3flags.port, VERIFY[OFF], f"m-{uuid.uuid4().hex}.txt",
                       [b"hello ", b"world"], tamper=1)
        after = _metrics(s3flags.port)

        failures = 'brix_s3_responses_total{method="PUT",status_class="4xx"}'
        successes = 'brix_s3_responses_total{method="PUT",status_class="2xx"}'
        assert _metric(after, failures) - _metric(before, failures) == 1, \
            "the refused chunk was not counted as a PUT 4xx"
        assert _metric(after, successes) - _metric(before, successes) == 1, \
            "the accepted chunk was not counted as a PUT 2xx"


# --------------------------------------------------------------------------- #
# §B — DEFECT CANDIDATE #71: the nested override                               #
# --------------------------------------------------------------------------- #

class TestANestedOverrideNeedsTheHandlerBack:
    """``ngx_http_s3_set`` installs clcf->handler (module.c:201).  A nested
    location that writes only a flag inherits the whole S3 configuration and
    none of the routing."""

    def test_the_flag_only_nested_location_is_not_served_by_s3(self, s3flags):
        key = f"nested-{uuid.uuid4().hex}.txt"
        response = _streaming_put(s3flags.port, NESTED_BARE, key,
                                  [b"hello ", b"world"], tamper=1)
        assert response.status_code == 405, (
            "the nested location answered like an S3 export; if the handler is "
            f"now inherited, DEFECT CANDIDATE #71 is fixed:\n{response.text[:300]}")
        assert _code(response) is None, \
            "a 405 carrying an S3 error body means S3 did serve this"

    def test_the_flag_only_nested_location_does_not_even_read_as_s3(self,
                                                                    s3flags):
        """A GET is answered by nginx's static handler — a stock 404 page, not
        the ``NoSuchKey`` an S3 export would produce for the same URI."""
        response = _signed_get(s3flags.port, f"/{NESTED_BARE}/{SEED}")
        assert response.status_code == 404, response.text[:300]
        assert _code(response) is None

    def test_repeating_the_enable_directive_restores_the_route(self, s3flags):
        """The cure, and the proof the override itself was never the problem:
        the same nested override, one ``brix_s3 on;`` richer, accepts the
        forged chunk its parent refuses."""
        key = f"deep-{uuid.uuid4().hex}.txt"
        response = _streaming_put(s3flags.port, NESTED_WHOLE, key,
                                  [b"hello ", b"world"], tamper=1)
        assert response.status_code in (200, 201), response.text[:300]

    def test_the_nested_arm_addresses_its_parents_bucket(self, s3flags):
        """What the nested location inherited: bucket, root and credentials.
        The key written through /vcon/deep/ lands in the vcon export and reads
        back through the same prefix."""
        key = f"deep-{uuid.uuid4().hex}.txt"
        assert _streaming_put(s3flags.port, NESTED_WHOLE, key,
                              [b"hello ", b"world"]).status_code in (200, 201)
        on_disk = s3flags.root(VERIFY[ON]) / "deep" / key
        assert on_disk.read_bytes() == b"hello world"
        response = _signed_get(s3flags.port, f"/{NESTED_WHOLE}/{key}")
        assert response.status_code == 200, response.text[:300]
        assert response.content == b"hello world"


# --------------------------------------------------------------------------- #
# §C — brix_s3_allow_unsigned_session_token                                    #
# --------------------------------------------------------------------------- #

SESSION_TOKEN = "FwoGZXIvYXdzEAUDIT16FSESSIONTOKEN"


class TestTheStsSessionTokenGate:
    """s3_sigv4_check_session_token (auth_sigv4_verify.c:262-287) runs only when
    the request carries a session token at all, and then asks two questions in
    order: is the transport enabled, and was the header signed."""

    def test_on_accepts_a_signed_session_token(self, s3flags):
        response = _signed_get(s3flags.port, f"/{SESSION[ON]}/{SEED}",
                               session_token=SESSION_TOKEN)
        assert response.status_code == 200, response.text[:300]
        assert response.content == PAYLOAD

    def test_on_refuses_a_session_token_left_out_of_the_signature(self,
                                                                  s3flags):
        """Security-negative: the header is present but unsigned, so it is not
        covered by SigV4 and any proxy could have added it."""
        response = _signed_get(s3flags.port, f"/{SESSION[ON]}/{SEED}",
                               session_token=SESSION_TOKEN,
                               sign_session_token=False)
        assert response.status_code == 403, response.text[:300]
        assert _code(response) == "InvalidRequest"
        assert "must be signed" in _message(response)

    @pytest.mark.parametrize("arm", [OFF, DEFAULT], ids=["off", "absent"])
    @pytest.mark.parametrize("signed", [True, False],
                             ids=["signed", "unsigned"])
    def test_the_closed_arms_refuse_the_token_however_it_arrives(self, s3flags,
                                                                 arm, signed):
        """The pair and the default in one table.  The refusal is the FIRST
        question's, not the second's — the closed arms never look at whether the
        header was signed, and say so in a different message than §C's ON arm."""
        response = _signed_get(s3flags.port, f"/{SESSION[arm]}/{SEED}",
                               session_token=SESSION_TOKEN,
                               sign_session_token=signed)
        assert response.status_code == 403, response.text[:300]
        assert _code(response) == "AccessDenied"
        assert "not enabled" in _message(response)

    @pytest.mark.parametrize("arm", [ON, OFF, DEFAULT],
                             ids=["on", "off", "absent"])
    def test_every_arm_serves_a_request_that_carries_no_session_token(self,
                                                                      s3flags,
                                                                      arm):
        """The control.  The gate is a property of requests that present an STS
        token; a location with the transport closed is not a location that
        stopped serving."""
        response = _signed_get(s3flags.port, f"/{SESSION[arm]}/{SEED}")
        assert response.status_code == 200, response.text[:300]
        assert response.content == PAYLOAD

    def test_the_closed_arms_refusal_is_counted_as_malformed(self, s3flags):
        """auth_sigv4_verify.c:271 records BRIX_S3_AUTH_MALFORMED, and the
        accepted request one location away records sigv4_ok — the exposition
        distinguishes the two arms as sharply as the status code does."""
        before = _metrics(s3flags.port)
        _signed_get(s3flags.port, f"/{SESSION[OFF]}/{SEED}",
                    session_token=SESSION_TOKEN)
        _signed_get(s3flags.port, f"/{SESSION[ON]}/{SEED}",
                    session_token=SESSION_TOKEN)
        after = _metrics(s3flags.port)

        malformed = 'brix_s3_auth_total{result="malformed"}'
        ok = 'brix_s3_auth_total{result="sigv4_ok"}'
        assert _metric(after, malformed) - _metric(before, malformed) == 1
        assert _metric(after, ok) - _metric(before, ok) == 1


# --------------------------------------------------------------------------- #
# §D — brix_s3_token                                                           #
# --------------------------------------------------------------------------- #

class TestTheBearerGate:
    """s3_sigv4_bearer_intercept (auth_sigv4_verify.c:158-195) returns
    NGX_DECLINED immediately when the flag is off; when it is on the location
    becomes token-ONLY, which is more than "bearers are also accepted"."""

    def test_on_accepts_a_bearer(self, s3flags):
        response = _bearer_get(s3flags.port, f"/{BEARER[ON]}/{SEED}",
                               s3flags.token())
        assert response.status_code == 200, response.text[:300]
        assert response.content == PAYLOAD

    @pytest.mark.parametrize("arm", [OFF, DEFAULT], ids=["off", "absent"])
    def test_the_closed_arms_refuse_a_bearer(self, s3flags, arm):
        """Same token, same JWKS, same issuer and audience — the arms differ in
        the flag alone, and the closed ones never reach the verifier: the
        Authorization header falls through to SigV4, which cannot read it."""
        response = _bearer_get(s3flags.port, f"/{BEARER[arm]}/{SEED}",
                               s3flags.token())
        assert response.status_code == 403, response.text[:300]
        assert _code(response) == "InvalidRequest"

    @pytest.mark.parametrize("arm", [ON, OFF, DEFAULT],
                             ids=["on", "off", "absent"])
    def test_sigv4_keeps_working_on_every_arm(self, s3flags, arm):
        """The control: enabling the bearer gate does not retire the key pair,
        and disabling it does not disturb one."""
        response = _signed_get(s3flags.port, f"/{BEARER[arm]}/{SEED}")
        assert response.status_code == 200, response.text[:300]
        assert response.content == PAYLOAD

    def test_on_refuses_an_anonymous_request_differently_than_off(self,
                                                                  s3flags):
        """The token-only consequence.  With the gate on, a request carrying no
        credentials at all is refused by the intercept (AccessDenied,
        auth_sigv4_verify.c:186-191); with it off the same request is refused
        further down by the SigV4 verifier, which says something else.  Both
        refuse — the flag chooses WHO refuses."""
        enabled = _get(s3flags.port, f"/{BEARER[ON]}/{SEED}")
        disabled = _get(s3flags.port, f"/{BEARER[OFF]}/{SEED}")
        assert enabled.status_code == 403 and disabled.status_code == 403
        assert _code(enabled) == "AccessDenied"
        assert _code(disabled) == "InvalidRequest"

    def test_on_refuses_a_tampered_bearer(self, s3flags):
        """Security-negative: the gate verifies the signature rather than the
        shape of the header."""
        token = s3flags.token()
        forged = token[:-6] + ("A" * 6 if not token.endswith("A" * 6)
                               else "B" * 6)
        response = _bearer_get(s3flags.port, f"/{BEARER[ON]}/{SEED}", forged)
        assert response.status_code == 403, response.text[:300]
        assert _code(response) == "AccessDenied"

    def test_on_refuses_a_bearer_minted_for_another_audience(self, s3flags):
        """Security-negative: enabling the transport does not widen the trust
        anchor — the audience is still compared."""
        response = _bearer_get(s3flags.port, f"/{BEARER[ON]}/{SEED}",
                               s3flags.token(audience="somebody-else"))
        assert response.status_code == 403, response.text[:300]


# --------------------------------------------------------------------------- #
# §E — brix_s3_list_cache                                                      #
# --------------------------------------------------------------------------- #

def _write_key(s3flags, bucket, key, body=b"x"):
    response = _signed_put(s3flags.port, f"/{bucket}/{key}", body)
    assert response.status_code in (200, 201), response.text[:300]
    return key


def _wait_for_a_fresh_mtime_second(path):
    """Park until a write to ``path`` is guaranteed to move its mtime.

    s3_list_collect_sorted keys the cache on ``st_mtime`` (list_common.c:83),
    which is a whole number of seconds here.  A directory written twice inside
    one second keeps one mtime, so §E's invalidation case would be a coin flip
    if it did not wait for the second to turn over first.
    """
    deadline = time.time() + 5
    while time.time() < deadline:
        if int(os.stat(path).st_mtime) < int(time.time()):
            return
        time.sleep(0.05)
    raise AssertionError(f"{path} mtime never fell behind the wall clock")


class TestTheSortedListingCache:

    def test_on_serves_a_stale_listing_after_a_write_below_the_root(self,
                                                                    s3flags):
        bucket = LISTING[ON]
        _listing(s3flags.port, bucket)
        key = _write_key(s3flags, bucket, f"sub/new-{uuid.uuid4().hex}.txt")
        assert (s3flags.root(bucket) / key).exists(), \
            "the PUT was accepted but nothing landed under the export root"
        assert key not in _listing(s3flags.port, bucket), \
            "the cached arm answered from a fresh walk"

    @pytest.mark.parametrize("arm", [OFF, DEFAULT], ids=["off", "absent"])
    def test_the_uncached_arms_show_the_new_key_at_once(self, s3flags, arm):
        bucket = LISTING[arm]
        _listing(s3flags.port, bucket)
        key = _write_key(s3flags, bucket, f"sub/new-{uuid.uuid4().hex}.txt")
        assert key in _listing(s3flags.port, bucket)

    def test_the_cached_answer_is_the_previous_answer(self, s3flags):
        """Stale is not the same as broken: the ON arm's second listing is the
        first one, element for element, and not a truncated or empty one."""
        bucket = LISTING[ON]
        before = _listing(s3flags.port, bucket)
        _write_key(s3flags, bucket, f"sub/new-{uuid.uuid4().hex}.txt")
        assert _listing(s3flags.port, bucket) == before
        assert SEED in before and set(SUBKEYS) <= set(before)

    def test_on_invalidates_when_the_export_root_itself_changes(self, s3flags):
        """What the staleness is keyed on.  The cache entry carries the root's
        mtime, so a write into a subdirectory is invisible while a write into
        the root brings BOTH keys back — the hidden one included."""
        bucket = LISTING[ON]
        _listing(s3flags.port, bucket)
        hidden = _write_key(s3flags, bucket, f"sub/new-{uuid.uuid4().hex}.txt")
        assert hidden not in _listing(s3flags.port, bucket)

        _wait_for_a_fresh_mtime_second(s3flags.root(bucket))
        surfaced = _write_key(s3flags, bucket, f"root-{uuid.uuid4().hex}.txt")
        after = _listing(s3flags.port, bucket)
        assert surfaced in after
        assert hidden in after, \
            "the root write invalidated the entry but the walk missed the key"

    def test_the_cache_does_not_leak_between_exports(self, s3flags):
        """Security-negative on a shared cache: the entry is keyed on the export
        root, so one bucket's listing can never answer another's — the arms hold
        identical seed files and identical prefixes, which is exactly the shape
        a root-blind key would confuse."""
        key = _write_key(s3flags, LISTING[ON], f"sub/only-{uuid.uuid4().hex}.txt")
        for other in (LISTING[OFF], LISTING[DEFAULT]):
            assert key not in _listing(s3flags.port, other)


# --------------------------------------------------------------------------- #
# §F — brix_s3_zip_access                                                      #
# --------------------------------------------------------------------------- #

class TestZipMemberAccess:
    """s3_get_serve_zip_member (object.c:110-141) declines when the flag is off,
    so ``?xrdcl.unzip=`` stops being a member selector and becomes an ordinary
    (signed, and therefore harmless) query parameter."""

    def test_on_returns_the_member(self, s3flags):
        response = _signed_get(s3flags.port, f"/{ZIP[ON]}/{ARCHIVE}",
                               query={"xrdcl.unzip": MEMBER})
        assert response.status_code == 200, response.text[:300]
        assert response.content == MEMBER_BODY

    @pytest.mark.parametrize("arm", [OFF, DEFAULT], ids=["off", "absent"])
    def test_the_closed_arms_return_the_whole_archive(self, s3flags, arm):
        response = _signed_get(s3flags.port, f"/{ZIP[arm]}/{ARCHIVE}",
                               query={"xrdcl.unzip": MEMBER})
        assert response.status_code == 200, response.text[:300]
        assert response.content == s3flags.archive, \
            "a closed arm served something other than the object itself"

    def test_on_without_the_parameter_returns_the_whole_archive(self, s3flags):
        """The control: the flag arms the parameter, it does not rewrite every
        GET of a ZIP object."""
        response = _signed_get(s3flags.port, f"/{ZIP[ON]}/{ARCHIVE}")
        assert response.status_code == 200, response.text[:300]
        assert response.content == s3flags.archive

    def test_on_maps_a_missing_member_to_no_such_key(self, s3flags):
        response = _signed_get(s3flags.port, f"/{ZIP[ON]}/{ARCHIVE}",
                               query={"xrdcl.unzip": "absent.txt"})
        assert response.status_code == 404, response.text[:300]
        assert _code(response) == "NoSuchKey"

    def test_on_refuses_a_traversing_member_name(self, s3flags):
        """Security-negative.  A member name is a name inside the archive; the
        arm that reads member names is the arm that has to refuse one shaped
        like a path (INVARIANT #4 in miniature — the member never becomes a
        filesystem path)."""
        response = _signed_get(s3flags.port, f"/{ZIP[ON]}/{ARCHIVE}",
                               query={"xrdcl.unzip": "../../etc/passwd"})
        assert response.status_code == 400, response.text[:300]
        assert _code(response) == "InvalidArgument"

    def test_the_closed_arm_ignores_a_traversing_member_name_entirely(self,
                                                                      s3flags):
        """The same request one location away is not refused, because nothing
        parsed it — the closed arm serves the object and never looks at the
        parameter at all."""
        response = _signed_get(s3flags.port, f"/{ZIP[OFF]}/{ARCHIVE}",
                               query={"xrdcl.unzip": "../../etc/passwd"})
        assert response.status_code == 200, response.text[:300]
        assert response.content == s3flags.archive


# --------------------------------------------------------------------------- #
# §G — the parse tier                                                          #
# --------------------------------------------------------------------------- #

@pytest.fixture(scope="module")
def anchor(tmp_path_factory):
    """A real JWKS for the parse tier.

    The scaffold's probe location is a complete S3 export, JWKS included:
    ``brix_s3_token on`` is refused at merge time when the key set is missing
    (module_merge.c:134-138), and a scaffold that failed for THAT reason would
    look exactly like a flag the parser had rejected.
    """
    issuer = TokenIssuer(str(tmp_path_factory.mktemp("audit16f-anchor")),
                         issuer=ISSUER, audience=AUDIENCE)
    issuer.init_keys()
    return issuer


def _parse(tmp_path, anchor, *, knobs="", srv="", http="", outer="",
           stream=""):
    """`nginx -t` the scaffold with one slot filled.

    Every slot is rendered with a trailing newline and the scaffold's own
    indentation, so a filled slot reads like the line an operator would type.
    """
    def _block(text, indent):
        if not text:
            return ""
        return "".join(f"{indent}{line}\n" for line in text.splitlines())

    return nginx_t(
        "nginx_audit16fparse.conf", tmp_path,
        PORT=SHARED_PARSE_PLACEHOLDER_PORT,
        STREAM_PORT=PARSE_PLACEHOLDER_PORT,
        LOG_DIR=str(tmp_path),
        DATA=str(tmp_path),
        JWKS=anchor.jwks_path,
        ISSUER=ISSUER,
        AUDIENCE=AUDIENCE,
        KNOBS=_block(knobs, " " * 12),
        SRV_KNOBS=_block(srv, " " * 8),
        HTTP_KNOBS=_block(http, " " * 4),
        OUTER=_block(outer, ""),
        STREAM_EXTRA=_block(stream, " " * 8))


@_needs_nginx
@pytest.mark.parametrize("name", FLAG_NAMES)
@pytest.mark.parametrize("value", ["on", "off"])
def test_both_arms_parse_in_a_location(tmp_path, anchor, name, value):
    """The pair at parse level, for all five.  This is the claim the audit's
    step-2 measurement says nothing in the corpus had ever made: the word
    ``off``, written out, for a directive whose OFF behaviour had only ever been
    reached by leaving it out."""
    result = _parse(tmp_path, anchor, knobs=f"{name} {value};")
    assert result.returncode == 0, \
        f"{name} {value} was refused:\n{result.stderr}"


@_needs_nginx
@pytest.mark.parametrize("name", FLAG_NAMES)
def test_a_non_flag_value_is_refused(tmp_path, anchor, name):
    result = _parse(tmp_path, anchor, knobs=f"{name} banana;")
    assert result.returncode != 0 and "invalid value" in result.stderr, \
        f"{name} accepted a non-flag value:\n{result.stderr}"


@_needs_nginx
@pytest.mark.parametrize("name", FLAG_NAMES)
@pytest.mark.parametrize("line", ["{name};", "{name} on off;"],
                         ids=["no-argument", "two-arguments"])
def test_the_arity_is_exactly_one(tmp_path, anchor, name, line):
    result = _parse(tmp_path, anchor, knobs=line.format(name=name))
    assert result.returncode != 0, f"{name} accepted the wrong arity"
    assert "invalid number of arguments" in result.stderr, result.stderr


@_needs_nginx
@pytest.mark.parametrize("name", FLAG_NAMES)
def test_a_second_occurrence_is_a_duplicate(tmp_path, anchor, name):
    """ngx_conf_set_flag_slot refuses a repeat rather than letting the last one
    win — an operator who writes both arms is told, not silently resolved."""
    result = _parse(tmp_path, anchor, knobs=f"{name} on;\n{name} off;")
    assert result.returncode != 0 and "is duplicate" in result.stderr, \
        f"{name} allowed two values in one location:\n{result.stderr}"


@_needs_nginx
@pytest.mark.parametrize("name", FLAG_NAMES)
@pytest.mark.parametrize("slot", ["srv", "http", "outer", "stream"])
def test_the_flags_are_location_only(tmp_path, anchor, name, slot):
    """All five are NGX_HTTP_LOC_CONF and nothing else (module.c:266-292,
    382-387).  A server-wide or site-wide default is not a thing an operator can
    write for them, and the root:// plane has never heard of them."""
    result = _parse(tmp_path, anchor, **{slot: f"{name} on;"})
    assert result.returncode != 0, \
        f"{name} was accepted in the {slot} context:\n{result.stderr}"
    assert "is not allowed here" in result.stderr, result.stderr


# --------------------------------------------------------------------------- #
# §H — brix_backend_passthrough_persist, the last both-arms-unwritten name     #
# --------------------------------------------------------------------------- #

PASSTHROUGH = "brix_backend_passthrough_persist"


@_needs_nginx
@pytest.mark.parametrize("value", ["on", "off"])
@pytest.mark.parametrize("slot", ["knobs", "srv", "http"])
def test_the_passthrough_flag_parses_in_every_http_context(tmp_path, anchor,
                                                           value, slot):
    """The seventh and last of the both-arms-unwritten directives, and the only
    one that cannot be closed above parse level: it is BRIX_HTTP_ALL_CONF, it
    merges to 0 (shared_conf.h:428), and it has no reader anywhere in src/,
    client/ or shared/ — DEFECT CANDIDATE #35, pinned by
    test_audit15j_zero_coverage_stragglers.py.  Writing the value is therefore
    the whole of what can be asserted; what it does is nothing, in all six
    placements."""
    result = _parse(tmp_path, anchor, **{slot: f"{PASSTHROUGH} {value};"})
    assert result.returncode == 0, \
        f"{PASSTHROUGH} {value} was refused in the {slot} context:\n{result.stderr}"


# --------------------------------------------------------------------------- #
# §I — the mechanism is where this file says it is                             #
# --------------------------------------------------------------------------- #

def _source(path):
    return path.read_text(encoding="utf-8")


def _code_lines(path, token):
    """Lines naming ``token`` that are code rather than prose."""
    return [line for line in _source(path).splitlines()
            if token in line and not line.lstrip().startswith(("*", "/*", "//"))]


class TestTheMechanismIsWhereThisFileSaysItIs:

    def test_the_enable_directive_installs_the_handler_itself(self):
        """The mechanism behind §B.  If this assignment ever moves into
        postconfiguration or into the merge, the nested location stops being a
        trap and §B's expectations have to be re-measured."""
        lines = _code_lines(MODULE_C, "clcf->handler")
        assert lines == ["    clcf->handler = ngx_http_s3_handler;"], \
            f"the handler install moved or multiplied: {lines}"

    def test_the_enable_directive_has_its_own_setter(self):
        """...and it is that setter, not ngx_conf_set_flag_slot, that the
        command table points at for brix_s3 alone."""
        source = _source(MODULE_C)
        entry = source.split('ngx_string("brix_s3")')[1].split("},")[0]
        assert "ngx_http_s3_set" in entry, entry

    @pytest.mark.parametrize("name,field", FLAGS,
                             ids=[name for name, _ in FLAGS])
    def test_every_flag_merges_to_off(self, name, field):
        """The claim every ``absent`` arm in this file rests on."""
        # Whitespace-flattened: two of the five wrap their merge call across
        # lines and one pads it, which says nothing about the default.
        flat = " ".join(_source(MERGE_C).split())
        call = f"ngx_conf_merge_value(conf->{field}, prev->{field}, 0);"
        assert call in flat, f"{name} no longer merges to 0 — expected {call}"

    @pytest.mark.parametrize("name,field", FLAGS,
                             ids=[name for name, _ in FLAGS])
    def test_every_flag_is_a_plain_flag_slot(self, name, field):
        """The tranche's subject is the 128 ``ngx_conf_set_flag_slot``
        directives; a setter of its own would put the directive in a different
        measurement and give it config-time behaviour this file never probed."""
        source = _source(MODULE_C)
        entry = source.split(f'ngx_string("{name}")')[1].split("},")[0]
        assert "ngx_conf_set_flag_slot" in entry, entry
        assert "NGX_HTTP_LOC_CONF | NGX_CONF_FLAG" in entry, entry
        assert field in entry, entry
