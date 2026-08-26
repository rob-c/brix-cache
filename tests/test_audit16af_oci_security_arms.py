"""Test cases for audit16af_oci_security_arms — preamble (fixtures/helpers/mocks) lives in
_test_audit16af_oci_security_arms_helpers.py; reexported below so pytest resolves fixtures in
this module's namespace (split for the 600 logical-line file cap)."""
from split_continuation import reexport as _reexport
_reexport(globals(), "_test_audit16af_oci_security_arms_helpers")


class TestTheWrittenOffEqualsItsOmission:
    """The claim the corpus leans on: registry_lane's `anonymous=False` renders
    nothing, and the D4.5 suite treats that as having written `off`.

    Every cell here compares the two planes rather than asserting a constant,
    because the subject is the EQUALITY and not the value — a change that moved
    both planes together would leave a constant-asserting test green while
    breaking nothing the corpus depends on."""

    @pytest.mark.parametrize("method,path", PROBES,
                             ids=[f"{m}{p}" for m, p in PROBES])
    def test_both_planes_answer_a_credentialless_request_identically(
            self, arms, method, path):
        off = _plain(R_OFF)(method, path)
        absent = _plain(R_ABS)(method, path)

        assert off[0] == absent[0], f"off={off[0]} absent={absent[0]}"
        assert off[2] == absent[2], f"off={off[2][:120]} absent={absent[2][:120]}"

    @pytest.mark.parametrize("method,path", PROBES[:-1],
                             ids=[f"{m}{p}" for m, p in PROBES[:-1]])
    def test_both_planes_challenge_with_the_same_header(self, arms, method,
                                                        path):
        """The 401's shape is the part `podman login` reads, so an equality
        that held on the status code and not on the challenge would not be the
        equality anyone is relying on."""
        off = _plain(R_OFF)(method, path)
        absent = _plain(R_ABS)(method, path)

        assert off[0] == 401
        assert off[1].get("WWW-Authenticate") == absent[1].get(
            "WWW-Authenticate")

    @pytest.mark.parametrize("arm,port", AUTHENTICATING)
    def test_a_credentialless_write_is_refused_on_both(self, arms, arm, port):
        status, headers, body = _plain(port)(
            "POST", "/v2/lab/app/blobs/uploads/")

        assert status == 401
        assert _err(body) == "UNAUTHORIZED"
        assert "Bearer realm=" in headers.get("WWW-Authenticate", "")

    @pytest.mark.parametrize("arm,port", AUTHENTICATING)
    def test_a_scoped_token_publishes_a_pullable_image_on_both(self, arms, arm,
                                                               port):
        """The other half of the equality: what the token plane lets THROUGH is
        the same on both, byte for byte, all the way to the store."""
        call = _plain(port, {"Authorization": "Bearer " + arms.token()})
        repo = f"eq/{arm}"

        status, body = _push_image(call, repo, "v1")
        assert status == 201, f"{status} {body[:150]}"

        status, headers, blob = call("GET", f"/v2/{repo}/blobs/{_digest(LAYER)}")
        assert status == 200
        assert blob == LAYER

    def test_the_two_stores_hold_the_same_objects(self, arms):
        """Content addressing makes this the strongest form of "the same": the
        two planes wrote to two different roots and the file NAMES agree,
        because the names are the digests of what was written."""
        for arm, port in AUTHENTICATING:
            call = _plain(port, {"Authorization": "Bearer " + arms.token()})
            _check_test_the_two_stores_hold_the_same_objects_1(call, arm)

        off = _expression_1(arms)
        absent = _expression_2(arms)
        _check_test_the_two_stores_hold_the_same_objects_2(off, absent)

    @pytest.mark.parametrize("arm,port", AUTHENTICATING)
    def test_neither_plane_says_anything_about_the_flag(self, arms, arm, port):
        """A written `off` that drew a notice the omission did not would be a
        difference too, and a better world than this one — so it is measured
        rather than assumed away."""
        _plain(port)("POST", "/v2/lab/app/blobs/uploads/")

        noisy = [ln for ln in arms.errlog().splitlines()
                 if "allow_anonymous" in ln and "[emerg]" not in ln
                 and "detail" not in ln]
        assert noisy == [], noisy


# --------------------------------------------------------------------------- #
# §B  The open registry, which is the control for everything in §C             #
# --------------------------------------------------------------------------- #

class TestTheOpenRegistryIsOpenToEveryone:
    """`allow_anonymous on` with no issuer table — configs/oci_registry.conf's
    own lab leg.  Nothing here is a defect; it is the reference the composition
    in §C is measured against."""

    @pytest.mark.parametrize("tag,headers", [
        ("none", {}),
        ("garbage-bearer", {"Authorization": "Bearer not.a.jwt"}),
        ("basic", {"Authorization": "Basic YWxpY2U6cHc="}),
    ])
    def test_any_credential_or_none_may_start_an_upload(self, arms, tag,
                                                        headers):
        status, _, body = _plain(R_ANON, headers)(
            "POST", "/v2/lab/app/blobs/uploads/")

        assert status == 202, f"{status} {body[:120]}"

    def test_an_anonymous_client_publishes_a_pullable_image(self, arms):
        status, body = _push_image(_plain(R_ANON), "open/app", "v1")
        assert status == 201, f"{status} {body[:150]}"

        status, _, blob = _plain(R_ANON)(
            "GET", f"/v2/open/app/blobs/{_digest(LAYER)}")
        assert status == 200 and blob == LAYER

    def test_no_challenge_is_ever_issued(self, arms):
        """An open registry never sends a client into a login it cannot do."""
        for method, path in PROBES:
            _, headers, _ = _plain(R_ANON)(method, path)
            assert "WWW-Authenticate" not in headers, (method, path)


# --------------------------------------------------------------------------- #
# §C  An issuer table beside an open door  (DEFECT #115)                       #
# --------------------------------------------------------------------------- #

class TestAnIssuerTableBesideAnOpenDoor:
    """DEFECT #115 — a bearer the issuer table REJECTED is admitted anonymously.

    oci_authz_bearer() returns NGX_DECLINED both when no bearer was presented
    and when every configured issuer refused the one that was
    (oci_authz.c:135,175).  brix_oci_registry_authz() then reaches
    `lcf->registry_anon` and admits.  A rejected credential is therefore
    indistinguishable from an absent one, and on a plane carrying both
    directives the token plane is decorative.

    configs/oci_registry.conf has always permitted this composition — its
    ANON_LINES and ISSUER_LINES slots are independent — and no lane builds it,
    which is why nothing had noticed."""

    @pytest.mark.parametrize("tag", ["forged", "garbage", "none"])
    def test_a_rejected_bearer_starts_an_upload(self, arms, tag):
        creds = {"forged": {"Authorization": "Bearer " + arms.forged()},
                 "garbage": {"Authorization": "Bearer not.a.jwt"},
                 "none": {}}[tag]

        status, _, body = _plain(R_BOTH, creds)(
            "POST", "/v2/lab/app/blobs/uploads/")

        assert status == 202, f"{status} {body[:120]}"

    def test_the_same_bearer_is_refused_where_the_door_is_shut(self, arms):
        """The bound on #115: the forged token is not weak, and the issuer
        table is not broken.  Both other authenticating planes refuse it."""
        creds = {"Authorization": "Bearer " + arms.forged()}

        for arm, port in AUTHENTICATING:
            status, _, body = _plain(port, creds)(
                "POST", "/v2/lab/app/blobs/uploads/")
            assert status == 401, f"{arm}: {status} {body[:120]}"

    def test_a_forged_token_publishes_a_complete_pullable_image(self, arms):
        """The consequence, stated as what an attacker gets: not a status code
        but a published image every node that pulls the tag will run."""
        call = _plain(R_BOTH,
                      {"Authorization": "Bearer " + arms.forged()})

        status, body = _push_image(call, "forged/app", "v1")
        assert status == 201, f"{status} {body[:150]}"

        status, headers, manifest = call("GET", "/v2/forged/app/manifests/v1")
        assert status == 200
        assert headers["Docker-Content-Digest"].startswith("sha256:")
        assert json.loads(manifest)["layers"][0]["digest"] == _digest(LAYER)

    def test_the_log_records_the_rejection_the_registry_then_ignored(self,
                                                                     arms):
        """Both halves in one request: the token layer says the signature did
        not verify, and the object is on disk anyway.  The two lines are the
        defect written out in the server's own words."""
        call = _plain(R_BOTH,
                      {"Authorization": "Bearer " + arms.forged()})

        digest = _put_blob(call, "forged/logged", LAYER)

        assert "JWT signature verification failed" in arms.errlog()
        status, _, blob = call("GET", f"/v2/forged/logged/blobs/{digest}")
        assert status == 200 and blob == LAYER

    def test_the_guard_audit_never_hears_about_it(self, arms):
        """The sharpest form of #115.  Nothing was refused, so no `authfail`
        line is written — the [brix-oci-push] fail2ban jail sees a clean
        registry while forged credentials publish through it.

        Filtered by the plane's own port, because the other planes in this
        process are supposed to be emitting exactly this line."""
        call = _plain(R_BOTH,
                      {"Authorization": "Bearer " + arms.forged()})
        for n in range(3):
            _check_test_the_guard_audit_never_hears_about_it_3(call, n)

        audited = [ln for ln in arms.errlog().splitlines()
                   if "signal=authfail" in ln and f":{R_BOTH}\"" in ln]
        _check_test_the_guard_audit_never_hears_about_it_4(audited)

    def test_the_open_plane_and_the_composed_plane_are_indistinguishable(
            self, arms):
        """Which is the operator's real problem: the plane that names an issuer
        table answers a rejected credential exactly as the plane that names no
        token plane at all does."""
        creds = {"Authorization": "Bearer " + arms.forged()}

        opened = _plain(R_ANON, creds)("POST", "/v2/lab/app/blobs/uploads/")
        composed = _plain(R_BOTH, creds)("POST", "/v2/lab/app/blobs/uploads/")

        assert opened[0] == composed[0] == 202
        assert ("WWW-Authenticate" in opened[1]) == (
            "WWW-Authenticate" in composed[1])

    def test_a_valid_token_still_works_there(self, arms):
        """The composition is not broken in the other direction — which is why
        an operator who wrote it would see nothing wrong."""
        call = _plain(R_BOTH, {"Authorization": "Bearer " + arms.token()})

        assert _push_image(call, "composed/valid", "v1")[0] == 201


# --------------------------------------------------------------------------- #
# §D  What the load gate's third route is worth  (DEFECT #116)                 #
# --------------------------------------------------------------------------- #

class TestTheLoadGateAcceptsThreeVerifyModesAsOne:
    """oci_ssl_verifies_client() is `sslcf->verify != 0` (oci_merge.c:147), and
    nginx spells four modes into that field.  Three of them are non-zero."""

    @pytest.mark.parametrize("mode", ["on", "optional", "optional_no_ca"])
    def test_every_non_off_mode_satisfies_the_authenticated_context(
            self, tmp_path, pki, mode):
        rc, out = _parse(tmp_path, LOC_KNOBS=_REGISTRY,
                         HTTP_KNOBS=_tls_server(mode))

        assert rc == 0, out

    def test_only_off_is_refused(self, tmp_path, pki):
        rc, out = _parse(tmp_path, LOC_KNOBS=_REGISTRY,
                         HTTP_KNOBS=_tls_server("off"))

        assert rc != 0
        assert "without an authenticated context" in out


class TestWhatEachVerifyModeIsActuallyWorth:
    """DEFECT #116 — `optional_no_ca` asks a client for a certificate and
    validates nothing about it, so brix_oci_registry_authz()'s TLS branch
    (oci_authz.c:206-220, which asks only that ngx_ssl_get_subject_dn succeed)
    admits a certificate the client signed for itself.

    The other two modes are safe, and safe for a reason that is not brix's:
    nginx's own chain validation refuses the request before the OCI module is
    reached.  So the module's TLS identity branch is correct only where nginx
    was already going to be."""

    @pytest.mark.parametrize("mode,port", VERIFY_MODES)
    def test_a_client_with_no_certificate_never_gets_in(self, arms, mode,
                                                        port):
        """The common floor: none of the three is an open registry."""
        status, _, _ = _over_tls(port)("POST", "/v2/lab/app/blobs/uploads/")

        assert status in (400, 401), status

    @pytest.mark.parametrize("mode,port", [("on", R_VON),
                                           ("optional", R_VOPT)])
    def test_a_self_signed_certificate_is_refused_by_the_two_validating_modes(
            self, arms, stranger, mode, port):
        cert, key = stranger

        status, _, body = _over_tls(port, cert, key)(
            "POST", "/v2/lab/app/blobs/uploads/")

        assert status == 400, f"{status} {body[:120]}"
        assert b"SSL certificate error" in body

    def test_a_self_signed_certificate_is_admitted_by_optional_no_ca(
            self, arms, stranger):
        cert, key = stranger

        status, _, body = _over_tls(R_TLS, cert, key)(
            "POST", "/v2/lab/app/blobs/uploads/")

        assert status == 202, f"{status} {body[:120]}"

    def test_the_stranger_publishes_a_complete_pullable_image(self, arms,
                                                              stranger):
        """#116 stated as what it costs: a registry the operator was told had
        an authenticated context serves an image nobody authenticated."""
        cert, key = stranger
        call = _over_tls(R_TLS, cert, key)

        status, body = _push_image(call, "stranger/app", "v1")
        assert status == 201, f"{status} {body[:150]}"

        status, _, manifest = call("GET", "/v2/stranger/app/manifests/v1")
        assert status == 200
        assert json.loads(manifest)["layers"][0]["digest"] == _digest(LAYER)

    @pytest.mark.parametrize("mode,port", VERIFY_MODES)
    def test_a_ca_signed_certificate_is_admitted_everywhere(self, arms, mode,
                                                            port):
        """The bound: the three modes agree about the client the tree's own CA
        signed, so #116 is about what `optional_no_ca` ADDS and not about the
        route being broken."""
        if not os.path.exists(USER_CERT) or not os.path.exists(USER_KEY):
            pytest.skip("test PKI has no user certificate")

        status, _, body = _over_tls(port, USER_CERT, USER_KEY)(
            "POST", "/v2/lab/app/blobs/uploads/")

        assert status == 202, f"{mode}: {status} {body[:120]}"

    @pytest.mark.parametrize("evil", ["../abs/app", "lab/../../abs/app",
                                      "lab/%2e%2e%2f%2e%2e/app"])
    def test_a_traversal_that_climbs_out_never_reaches_the_registry(
            self, arms, stranger, evil):
        """The first half of the security-negative.  A `..` that leaves `/v2/`
        leaves the LOCATION, so nginx's own normalization answers it and the
        registry is never asked — the request is out of the module's reach
        rather than refused by it."""
        cert, key = stranger

        status, _, _ = _over_tls(R_TLS, cert, key)(
            "POST", f"/v2/{evil}/blobs/uploads/")

        assert status == 404, f"{evil}: {status}"

    @pytest.mark.parametrize("evil,seen", [("lab/%2e%2e/app", "app"),
                                           ("lab/..%2fapp", "app"),
                                           ("/etc/passwd", "etc/passwd")])
    def test_a_traversal_that_normalizes_arrives_as_an_ordinary_name(
            self, arms, stranger, evil, seen):
        """The second half, and the one worth writing down: a percent-encoded
        `..` IS decoded and collapsed, so the registry receives a name with no
        `..` left in it.  The Location it hands back is the proof of which name
        that was — an assertion on the status alone could not tell a refusal
        from a rewrite."""
        cert, key = stranger

        status, headers, _ = _over_tls(R_TLS, cert, key)(
            "POST", f"/v2/{evil}/blobs/uploads/")

        assert status == 202, f"{evil}: {status}"
        assert headers["Location"].startswith(f"/v2/{seen}/blobs/uploads/"), \
            headers["Location"]
        assert ".." not in headers["Location"]

    def test_nothing_the_stranger_wrote_left_its_own_store(self, arms,
                                                           stranger):
        """INVARIANT #4 under the hole #116 opens: the stranger is an
        authenticated pusher on ONE plane, and a name that normalized to
        something legal is still resolved under that plane's own root.  The six
        other stores are the measurement — a plane sharing a process is exactly
        what an escape would land in."""
        cert, key = stranger
        before = {p: arms.files(p) for p in ("anon", "off", "abs", "both",
                                             "von", "vopt")}

        assert _push_image(_over_tls(R_TLS, cert, key),
                           "lab/%2e%2e/escapee", "v1")[0] == 201

        assert {p: arms.files(p) for p in before} == before
        assert any(n for n in arms.files("tls"))


# --------------------------------------------------------------------------- #
# §E  Every refusal is a write  (DEFECT #117)                                  #
# --------------------------------------------------------------------------- #

class TestEveryRefusalIsAuditedAsAWrite:
    """DEFECT #117 — oci_challenge() and oci_deny() pass GUARD_OP_WRITE
    unconditionally (oci_authz.c:97,111), and so does the read-only refusal at
    :195.  GUARD_OP_READ exists (guard.h:21) and this module never emits it, so
    a refused pull and a refused push are one event to the audit trail and to
    every jail keyed on it."""

    def _audit(self, arms, port, needle):
        text = arms.await_log("error.log", needle)
        return [ln for ln in text.splitlines()
                if "signal=authfail" in ln and f":{port}\"" in ln
                and needle in ln]

    def test_a_refused_read_is_recorded_as_a_write(self, arms):
        path = "/v2/audit/read16af/manifests/latest"

        status, _, _ = _plain(R_OFF)("GET", path)
        assert status == 401

        lines = self._audit(arms, R_OFF, "read16af")
        assert lines, arms.errlog()[-1500:]
        assert all("op=write" in ln for ln in lines), lines

    def test_a_refused_head_is_recorded_as_a_write_too(self, arms):
        path = "/v2/audit/head16af/blobs/sha256:" + "0" * 64

        assert _plain(R_ABS)("HEAD", path)[0] == 401

        lines = self._audit(arms, R_ABS, "head16af")
        assert lines and all("op=write" in ln for ln in lines), lines

    def test_a_refused_write_is_recorded_the_same_way(self, arms):
        """Which is the point: the two are indistinguishable, so neither the
        operator nor the jail can tell an enumeration attempt from a push
        attempt."""
        assert _plain(R_OFF)(
            "POST", "/v2/audit/write16af/blobs/uploads/")[0] == 401

        reads = self._audit(arms, R_OFF, "read16af")
        writes = self._audit(arms, R_OFF, "write16af")
        assert reads and writes
        assert ({ln.split("op=")[1].split()[0] for ln in reads}
                == {ln.split("op=")[1].split()[0] for ln in writes})

    def test_the_audit_line_still_carries_what_it_promises(self, arms):
        """The bound: everything else in the line is right, which is why the
        one wrong field is worth naming rather than rewriting the emitter."""
        assert _plain(R_OFF)(
            "GET", "/v2/audit/shape16af/tags/list")[0] == 401

        lines = self._audit(arms, R_OFF, "shape16af")
        assert lines
        line = lines[-1]
        assert "proto=oci" in line
        assert "signal=authfail" in line
        assert "status=401" in line
        assert 'path="/v2/audit/shape16af/tags/list"' in line


# --------------------------------------------------------------------------- #
# §F  The challenge a client cannot follow  (DEFECT #118)                      #
# --------------------------------------------------------------------------- #

