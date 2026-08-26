"""Test cases for audit16i_cvmfs_resilience_flags — preamble (fixtures/helpers/mocks) lives in
_test_audit16i_cvmfs_resilience_flags_helpers.py; reexported below so pytest resolves fixtures in
this module's namespace (split for the 600 logical-line file cap)."""
from split_continuation import reexport as _reexport
_reexport(globals(), "_test_audit16i_cvmfs_resilience_flags_helpers")


class TestTheBundleEndpoint:
    """The batch-fetch endpoint under each arm, and the two refusals that never
    meet the client they were written for."""

    def test_on_answers_the_post_with_a_frame_of_what_was_asked_for(
            self, lifecycle, tmp_path, mock):
        """success: the control every `off` reading below is taken against.

        The wire format itself belongs to test_cvmfs_bundle.py — this asks only
        that the endpoint is open, so that a 405 in the next test is the flag
        and not the corpus.
        """
        endpoint = _start(lifecycle, tmp_path,
                          loc_arm=_flag("brix_cvmfs_bundle", "on"))
        rels = _base_rels(REPO_A)[:2]
        _warm(endpoint, REPO_A, rels)
        response = _fetch(endpoint, REPO_A, BUNDLE_PATH, method="POST",
                          data=_want(rels))
        assert response.status_code == 200, (
            f"{response.status_code}: {response.content[:200]!r}\n"
            f"{_errlog(endpoint)}")
        items = parse_bundle(response.content)
        assert [path for path, _ in items] == rels, items
        assert all(data for _, data in items), "a warm object came back a miss"

    @pytest.mark.parametrize("arm", CLOSED_ARMS)
    def test_a_closed_endpoint_refuses_the_post_without_ever_naming_the_flag(
            self, lifecycle, tmp_path, mock, arm):
        """error + the first half of the refusal inversion.

        ``cvmfs_gate_method`` (gate.c:295-307) refuses a non-GET method before
        class routing unless the bundle flag is on, so the POST a batch-fetch
        client sends is answered with the generic "method not allowed".  The
        sentence that names the directive is never reached by this request, and
        writing `off` is byte-identical to writing nothing.
        """
        endpoint = _start(lifecycle, tmp_path,
                          loc_arm=_flag("brix_cvmfs_bundle", arm))
        rels = _base_rels(REPO_A)[:2]
        _warm(endpoint, REPO_A, rels)
        response = _fetch(endpoint, REPO_A, BUNDLE_PATH, method="POST",
                          data=_want(rels))
        assert response.status_code == 405, (
            f"a closed bundle endpoint answered POST with "
            f"{response.status_code}\n{_errlog(endpoint)}")
        causes = _causes(endpoint)
        assert METHOD_NOT_ALLOWED in causes, (
            f"causes: {causes}\n{_errlog(endpoint)}")
        assert BUNDLE_DISABLED not in causes, (
            "the POST now reaches the refusal that names the directive — the "
            f"inversion this case pins may be fixed: {causes}")

    @pytest.mark.parametrize("arm", CLOSED_ARMS)
    def test_a_closed_endpoint_never_reaches_the_want_list_parser(
            self, lifecycle, tmp_path, mock, arm):
        """security-negative: `off` closes the parser, not just the feature.

        A want-list carrying a traversal is a 400 from
        ``cvmfs_bundle_parse_want`` when the endpoint is open.  Closed, the same
        body is refused at 405 by the method gate — which is the stronger
        property: the untrusted body is never parsed at all.
        """
        endpoint = _start(lifecycle, tmp_path,
                          loc_arm=_flag("brix_cvmfs_bundle", arm))
        response = _fetch(endpoint, REPO_A, BUNDLE_PATH, method="POST",
                          data=_want(["../../../../etc/passwd"]))
        assert response.status_code == 405, (
            "a closed bundle endpoint parsed a traversal want-list: "
            f"{response.status_code} {response.content[:200]!r}\n"
            f"{_errlog(endpoint)}")

    @pytest.mark.parametrize("arm", CLOSED_ARMS)
    def test_the_sentence_naming_the_flag_needs_a_method_the_endpoint_refuses(
            self, lifecycle, tmp_path, mock, arm):
        """The second half of the inversion, and the `off` arm's own wire.

        GET and HEAD DO reach class routing, so they see the 403 that names the
        directive — and those are precisely the two methods the endpoint refuses
        as POST-only when the flag is on.  Every method therefore gets a
        diagnostic written for the other one.
        """
        endpoint = _start(lifecycle, tmp_path,
                          loc_arm=_flag("brix_cvmfs_bundle", arm))
        for method in ("GET", "HEAD"):
            response = _fetch(endpoint, REPO_A, BUNDLE_PATH, method=method)
            assert response.status_code == 403, (
                f"{method} on a closed bundle endpoint answered "
                f"{response.status_code}\n{_errlog(endpoint)}")
        causes = _causes(endpoint)
        assert BUNDLE_DISABLED in causes, (
            f"causes: {causes}\n{_errlog(endpoint)}")

    def test_an_open_endpoint_refuses_the_only_methods_that_can_read_its_cause(
            self, lifecycle, tmp_path, mock):
        """The control that closes the inversion: with the flag ON, the GET
        that would have carried the "disabled" cause is itself refused."""
        endpoint = _start(lifecycle, tmp_path,
                          loc_arm=_flag("brix_cvmfs_bundle", "on"))
        response = _fetch(endpoint, REPO_A, BUNDLE_PATH, method="GET")
        assert response.status_code == 405, (
            f"an open bundle endpoint answered GET with "
            f"{response.status_code}\n{_errlog(endpoint)}")
        causes = _causes(endpoint)
        assert BUNDLE_POST_ONLY in causes, (
            f"causes: {causes}\n{_errlog(endpoint)}")


# --------------------------------------------------------------------------- #
# B. brix_cvmfs_dict                                                           #
# --------------------------------------------------------------------------- #

DICT_CURRENT = ".cvmfs-dict/current"
DICT_DISABLED = "dict endpoint disabled (brix_cvmfs_dict off)"


class TestTheSharedDictionaryEndpoint:
    """The dictionary endpoint is GET-only, so unlike §A both arms speak the
    same method and the whole difference is the status."""

    def test_on_trains_a_dictionary_and_serves_it_under_an_id(
            self, lifecycle, tmp_path, mock):
        """success: the control.  The trainer's own quality belongs to
        test_cvmfs_dict.py; what is needed here is that the endpoint answers
        and that the error log carries the training line, so the `off` arm's
        silence below is a decision and not an empty corpus."""
        endpoint = _start(lifecycle, tmp_path,
                          loc_arm=_flag("brix_cvmfs_dict", "on"))
        _warm(endpoint, REPO_A, [_cas_rel(body) for body in DICT_BODIES])
        response = _fetch(endpoint, REPO_A, DICT_CURRENT)
        assert response.status_code == 200, (
            f"{response.status_code}\n{_errlog(endpoint)}")
        assert response.content, "an empty dictionary is not a dictionary"
        dict_id = response.headers.get("X-Brix-Dict-Id", "")
        assert len(dict_id) == 40 and all(c in "0123456789abcdef" for c in dict_id), (
            f"X-Brix-Dict-Id is not a content address: {dict_id!r}")
        assert _count(endpoint, "cvmfs-dict:") >= 1, _errlog(endpoint)

    @pytest.mark.parametrize("arm", CLOSED_ARMS)
    def test_a_closed_endpoint_refuses_the_whole_namespace_and_names_the_flag(
            self, lifecycle, tmp_path, mock, arm):
        """error: 403 with the cause naming the directive — and not only for
        `current`.  A client that already knows a dictionary id (from a previous
        revision, or from a sibling cache) must not be able to reach one by
        naming it, so the arm is read at both spellings of the endpoint."""
        endpoint = _start(lifecycle, tmp_path,
                          loc_arm=_flag("brix_cvmfs_dict", arm))
        _warm(endpoint, REPO_A, [_cas_rel(body) for body in DICT_BODIES[:3]])
        known_id = hashlib.sha1(b"a dictionary that was never trained").hexdigest()
        for path in (DICT_CURRENT, f".cvmfs-dict/{known_id}"):
            response = _fetch(endpoint, REPO_A, path)
            assert response.status_code == 403, (
                f"{path} answered {response.status_code} with the dict "
                f"endpoint {arm}\n{_errlog(endpoint)}")
        causes = _causes(endpoint)
        assert causes.count(DICT_DISABLED) == 2, (
            f"both spellings of the endpoint must refuse for the same stated "
            f"reason; causes: {causes}\n{_errlog(endpoint)}")

    @pytest.mark.parametrize("arm", CLOSED_ARMS)
    def test_a_closed_endpoint_never_trains(self, lifecycle, tmp_path, mock, arm):
        """security-negative: the refusal is not a filter in front of a running
        trainer.  Twelve objects through a closed location must leave no
        training line at all — otherwise `off` would be hiding a dictionary it
        had still built out of the tenant's bytes."""
        endpoint = _start(lifecycle, tmp_path,
                          loc_arm=_flag("brix_cvmfs_dict", arm))
        _warm(endpoint, REPO_A, [_cas_rel(body) for body in DICT_BODIES])
        _settle()
        assert _count(endpoint, "cvmfs-dict:") == 0, (
            "a closed dict endpoint trained a dictionary anyway\n"
            f"{_errlog(endpoint)}")


# --------------------------------------------------------------------------- #
# C. brix_cvmfs_delta                                                          #
# --------------------------------------------------------------------------- #

DELTA_BASE_HEADER = "X-Brix-Delta-Base"


def _delta_probe(endpoint):
    """Fill both revisions, then ask for the newer one naming the older as the
    base — the exact exchange a CVMFS client makes on a catalogue update."""
    _warm(endpoint, REPO_A, [_cas_rel(REV_N), _cas_rel(REV_N1)])
    return _fetch(endpoint, REPO_A, _cas_rel(REV_N1),
                  headers={DELTA_BASE_HEADER: hashlib.sha1(REV_N).hexdigest()})


class TestTheDeltaEncoding:
    """The one flag whose `off` arm answers 200 either way — which is why its
    reading is the body and the headers, not the status."""

    def test_on_answers_the_base_probe_with_a_delta(self, lifecycle, tmp_path,
                                                    mock):
        """success: the control.  ~1% churn between two 370 KB revisions must
        come back an order of magnitude smaller and labelled as an encoding the
        client has to reverse."""
        endpoint = _start(lifecycle, tmp_path,
                          loc_arm=_flag("brix_cvmfs_delta", "on"))
        response = _delta_probe(endpoint)
        assert response.status_code == 200, (
            f"{response.status_code}\n{_errlog(endpoint)}")
        # requests decodes transfer encodings it knows; zstd-delta is not one,
        # so raw is what arrived on the wire.
        assert response.headers.get("Content-Encoding") == "zstd-delta", (
            f"headers: {dict(response.headers)}\n{_errlog(endpoint)}")
        assert response.headers.get(DELTA_BASE_HEADER), dict(response.headers)
        assert response.headers.get("Vary"), (
            "a response that varies on a request header must say so or a "
            f"shared cache will serve it to a client with a different base: "
            f"{dict(response.headers)}")
        assert len(response.content) < len(REV_N1) // 10, (
            f"{len(response.content)} bytes is not a delta of "
            f"{len(REV_N1)}")

    @pytest.mark.parametrize("arm", CLOSED_ARMS)
    def test_a_closed_encoder_ignores_the_base_and_serves_the_object(
            self, lifecycle, tmp_path, mock, arm):
        """error: the header is ignored, not refused.

        This is the arm an operator is actually choosing between — `off` must
        not 406 a client that offered a base, because every CVMFS client offers
        one once it has a previous revision.
        """
        endpoint = _start(lifecycle, tmp_path,
                          loc_arm=_flag("brix_cvmfs_delta", arm))
        response = _delta_probe(endpoint)
        assert response.status_code == 200, (
            f"a closed encoder answered {response.status_code} to a request "
            f"carrying a delta base\n{_errlog(endpoint)}")
        assert response.headers.get("Content-Encoding") is None, (
            f"headers: {dict(response.headers)}")
        assert response.headers.get(DELTA_BASE_HEADER) is None, (
            f"headers: {dict(response.headers)}")

    @pytest.mark.parametrize("arm", CLOSED_ARMS)
    def test_a_closed_encoder_serves_the_whole_object_byte_for_byte(
            self, lifecycle, tmp_path, mock, arm):
        """security-negative: an unlabelled short body would be worse than a
        refusal.  A client that offered a base and got 200 with no
        Content-Encoding will write the bytes to its cache under the object's
        own content address, so those bytes have to BE the object."""
        endpoint = _start(lifecycle, tmp_path,
                          loc_arm=_flag("brix_cvmfs_delta", arm))
        response = _delta_probe(endpoint)
        assert response.content == REV_N1, (
            f"{len(response.content)} bytes, sha1 "
            f"{hashlib.sha1(response.content).hexdigest()} != "
            f"{hashlib.sha1(REV_N1).hexdigest()}\n{_errlog(endpoint)}")


# --------------------------------------------------------------------------- #
# D. brix_cvmfs_scrub                                                          #
# --------------------------------------------------------------------------- #

SCRUB_SUPPORT = ("brix_cvmfs_scrub_interval 1;", "brix_cvmfs_scrub_rate 4;")
SCRUB_PASS = "scrub pass"


def _corrupt(path):
    """Overwrite a cached object in place, keeping its size — the scrub's whole
    job is to notice that the bytes no longer hash to the name."""
    path.write_bytes(b"\x00" * path.stat().st_size)


class TestTheCacheScrub:
    """The background verifier.  Its cursor and rate belong to
    test_cvmfs_scrub.py; the arm is whether it runs at all."""

    def test_on_walks_the_cache_and_evicts_a_corrupted_object(
            self, lifecycle, tmp_path, mock):
        """success: the control."""
        endpoint = _start(lifecycle, tmp_path,
                          loc_arm=_flag("brix_cvmfs_scrub", "on", *SCRUB_SUPPORT))
        rels = _base_rels(REPO_A)
        _warm(endpoint, REPO_A, rels)
        victim = _resident(tmp_path, REPO_A, rels[0])
        assert victim is not None, f"nothing was cached\n{_errlog(endpoint)}"
        _corrupt(victim)
        assert _await_gone(victim), (
            f"the scrub left a corrupted object in the cache\n"
            f"{_errlog(endpoint)}")
        assert _count(endpoint, SCRUB_PASS) >= 1, _errlog(endpoint)

    @pytest.mark.parametrize("arm", CLOSED_ARMS)
    def test_a_closed_scrub_never_runs_a_pass(self, lifecycle, tmp_path, mock,
                                              arm):
        """error: nothing is scheduled, so nothing is checked.

        The wait is the same one the `on` arm is evicted inside, which is what
        makes "still there" a reading rather than an unfinished measurement.
        """
        endpoint = _start(lifecycle, tmp_path,
                          loc_arm=_flag("brix_cvmfs_scrub", arm, *SCRUB_SUPPORT))
        rels = _base_rels(REPO_A)
        _warm(endpoint, REPO_A, rels)
        victim = _resident(tmp_path, REPO_A, rels[0])
        assert victim is not None, f"nothing was cached\n{_errlog(endpoint)}"
        _corrupt(victim)
        assert not _await_gone(victim, timeout=8.0), (
            "a scrub ran with the flag off — the interval and rate lines are "
            f"written on every arm, so this is the flag\n{_errlog(endpoint)}")
        assert _count(endpoint, SCRUB_PASS) == 0, _errlog(endpoint)

    @pytest.mark.parametrize("arm", CLOSED_ARMS)
    def test_a_closed_scrub_still_serves_the_corrupted_bytes(
            self, lifecycle, tmp_path, mock, arm):
        """security-negative: what the operator is actually turning off.

        With no scrub, a cached object whose bytes have rotted is served on the
        next read; the client's own content-address check is the only thing left
        between it and a corrupt catalogue.  Pinning that here is what makes the
        `on` arm a safety property rather than a background chore.
        """
        endpoint = _start(lifecycle, tmp_path,
                          loc_arm=_flag("brix_cvmfs_scrub", arm, *SCRUB_SUPPORT))
        rels = _base_rels(REPO_A)
        _warm(endpoint, REPO_A, rels)
        victim = _resident(tmp_path, REPO_A, rels[0])
        assert victim is not None, f"nothing was cached\n{_errlog(endpoint)}"
        size = victim.stat().st_size
        _corrupt(victim)
        response = _fetch(endpoint, REPO_A, rels[0])
        assert response.status_code == 200, (
            f"{response.status_code}\n{_errlog(endpoint)}")
        # `_corrupt` wrote the object's length in NUL bytes, so this is the rot
        # itself arriving at the client — not merely a digest that fails to match.
        assert response.content == b"\x00" * size, (
            "the corrupted copy was not served — either the read path verifies "
            "content addresses on its own or the eviction happened without a "
            f"scrub; re-measure this section\n{_errlog(endpoint)}")


# --------------------------------------------------------------------------- #
# E. brix_cvmfs_learn                                                          #
# --------------------------------------------------------------------------- #

LEARN_SUPPORT = ("brix_cvmfs_scrub on;", "brix_cvmfs_scrub_interval 1;",
                 "brix_cvmfs_scrub_rate 4;")
LEARN_LINE = "cvmfs-learn"


def _train_then_evict(endpoint, tmp_path, first, second):
    """Teach the successor model that `second` follows `first`, then take
    `second` out of the cache.

    The training rounds go down keep-alive connections because the model is
    connection-keyed, and the eviction goes through the scrub (corrupt the
    cached copy and let the verifier drop it) because that is the one way to
    empty a slot without also telling the cache the object was wanted.
    """
    _warm(endpoint, REPO_A, [first, second])
    for _ in range(2):
        conn = _session(endpoint)
        try:
            for rel in (first, second):
                status, _ = _session_get(conn, REPO_A, rel)
                assert status == 200, f"{rel}: {status}\n{_errlog(endpoint)}"
        finally:
            conn.close()
    resident = _resident(tmp_path, REPO_A, second)
    assert resident is not None, f"nothing was cached\n{_errlog(endpoint)}"
    _corrupt(resident)
    assert _await_gone(resident), (
        f"the scrub never evicted the successor\n{_errlog(endpoint)}")
    return resident


class TestThePrefetchLearner:
    """A read of A must pull B in behind it once the model has seen the pair —
    or must not, which is the arm."""

    def test_on_prewarms_the_successor_of_a_single_read(self, lifecycle,
                                                        tmp_path, mock):
        """success: the control.  The model itself belongs to
        test_cvmfs_learn.py; what is read here is that a lone GET of A puts B
        back in the cache without anyone asking for B."""
        endpoint = _start(lifecycle, tmp_path,
                          loc_arm=_flag("brix_cvmfs_learn", "on", *LEARN_SUPPORT))
        first, second = _base_rels(REPO_A)[:2]
        slot = _train_then_evict(endpoint, tmp_path, first, second)
        conn = _session(endpoint)
        try:
            status, _ = _session_get(conn, REPO_A, first)
            assert status == 200, f"{status}\n{_errlog(endpoint)}"
        finally:
            conn.close()
        assert _await_present(slot), (
            f"the successor was never prewarmed\n{_errlog(endpoint)}")
        assert _count(endpoint, LEARN_LINE) >= 1, _errlog(endpoint)

    @pytest.mark.parametrize("arm", CLOSED_ARMS)
    def test_a_closed_learner_leaves_the_successor_cold(self, lifecycle,
                                                        tmp_path, mock, arm):
        """error: the same training, the same eviction, the same lone read —
        and nothing comes back.  The scrub lines on every arm are what prove the
        instance was otherwise doing its job."""
        endpoint = _start(lifecycle, tmp_path,
                          loc_arm=_flag("brix_cvmfs_learn", arm, *LEARN_SUPPORT))
        first, second = _base_rels(REPO_A)[:2]
        slot = _train_then_evict(endpoint, tmp_path, first, second)
        conn = _session(endpoint)
        try:
            status, _ = _session_get(conn, REPO_A, first)
            assert status == 200, f"{status}\n{_errlog(endpoint)}"
        finally:
            conn.close()
        assert not _await_present(slot, timeout=6.0), (
            "the successor was prewarmed with the learner off\n"
            f"{_errlog(endpoint)}")
        assert _count(endpoint, LEARN_LINE) == 0, _errlog(endpoint)

    @pytest.mark.parametrize("arm", CLOSED_ARMS)
    def test_a_closed_learner_does_not_reach_the_origin_uninvited(
            self, lifecycle, tmp_path, mock, arm):
        """security-negative: a prefetcher is an origin-load amplifier, and
        turning it off has to stop the REQUESTS, not just the cache writes.  The
        origin's own log is the only place that difference is visible."""
        endpoint = _start(lifecycle, tmp_path,
                          loc_arm=_flag("brix_cvmfs_learn", arm, *LEARN_SUPPORT))
        first, second = _base_rels(REPO_A)[:2]
        _train_then_evict(endpoint, tmp_path, first, second)
        mock.reset()
        conn = _session(endpoint)
        try:
            status, _ = _session_get(conn, REPO_A, first)
            assert status == 200, f"{status}\n{_errlog(endpoint)}"
        finally:
            conn.close()
        _settle(2.0)
        asked = [path for path in mock.paths() if path.endswith(second)]
        assert asked == [], (
            f"a closed learner still fetched the successor from the origin: "
            f"{asked}\n{_errlog(endpoint)}")


# --------------------------------------------------------------------------- #
# F. brix_cvmfs_swarm                                                          #
# --------------------------------------------------------------------------- #

ROSTER = ".swarm/roster"
NOT_CVMFS = "path is not a CVMFS traffic shape"


def _swarm_support():
    """The seed ring.  Written on every arm, including the closed ones: the
    directive parses with the flag off (§K) and leaving it out would make the
    reading "no peers" rather than "swarm off".

    The ring names this node (the ledger's own port, which the lifecycle harness
    has already rebased to the real one) and one member that is not listening,
    because a roster of one live node cannot show a ring that was seeded from
    the directive rather than from the listener it happens to be on.
    """
    return (f"brix_cache_peers self={HOST}:{PORT} {HOST}:{DEAD_PORT};",
            "brix_cvmfs_swarm_interval 1;")


def _roster(endpoint, timeout=30):
    """The roster is a reserved name directly under the cvmfs prefix, not under
    a repository, so it does not go through `_fetch`."""
    url = f"http://{HOST}:{endpoint.port}/cvmfs/{ROSTER}"
    try:
        return requests.get(url, timeout=timeout)
    except requests.RequestException as exc:
        raise AssertionError(
            f"the listener did not answer the roster on port {endpoint.port}: "
            f"{exc!r}\n{_errlog(endpoint)}") from exc


class TestTheSwarmRoster:
    """The peer ring publishes itself at a reserved name under the cvmfs prefix,
    which is what makes its `off` arm readable over HTTP at all."""

    def test_on_publishes_a_live_ring_naming_this_node(self, lifecycle,
                                                       tmp_path, mock):
        """success: the control.  The gossip belongs to the swarm corpus; what
        is read here is that the roster answers and that the seed ring was
        taken from brix_cache_peers."""
        endpoint = _start(lifecycle, tmp_path,
                          loc_arm=_flag("brix_cvmfs_swarm", "on",
                                        *_swarm_support()))
        _fetch(endpoint, REPO_A)
        _settle(2.5)
        response = _roster(endpoint)
        assert response.status_code == 200, (
            f"{response.status_code}: {response.text[:200]}\n"
            f"{_errlog(endpoint)}")
        assert response.headers.get("Content-Type", "").startswith("text/plain")
        assert response.text.startswith("swarm-roster-v1"), response.text
        assert f"{HOST}:{PORT} alive" in response.text, (
            f"the ring does not name this node as alive:\n{response.text}")

    @pytest.mark.parametrize("arm", CLOSED_ARMS)
    def test_a_closed_swarm_leaves_the_roster_name_unclassifiable(
            self, lifecycle, tmp_path, mock, arm):
        """error, and the third refusal vocabulary.

        ``brix_cvmfs_swarm off`` does not disable the roster — it never
        registers it, so ``cvmfs_gate_meta`` (gate.c:262-289) does not intercept
        the path and classification rejects it exactly as it would a typo.  The
        answer names neither the directive nor the feature, which is the one
        thing an operator debugging a silent ring has to be told.
        """
        endpoint = _start(lifecycle, tmp_path,
                          loc_arm=_flag("brix_cvmfs_swarm", arm,
                                        *_swarm_support()))
        _fetch(endpoint, REPO_A)
        _settle(2.5)
        response = _roster(endpoint)
        assert response.status_code == 403, (
            f"a closed roster answered {response.status_code}\n"
            f"{_errlog(endpoint)}")
        causes = _causes(endpoint)
        assert NOT_CVMFS in causes, f"causes: {causes}\n{_errlog(endpoint)}"
        assert not any("swarm" in cause for cause in causes), (
            f"the refusal now mentions the feature — pin the new wording here: "
            f"{causes}")

    @pytest.mark.parametrize("arm", CLOSED_ARMS)
    def test_a_closed_swarm_never_seeds_a_ring(self, lifecycle, tmp_path, mock,
                                               arm):
        """security-negative: the peers stay unread.

        ``brix_cache_peers`` names hosts this node would otherwise gossip cache
        contents to.  With the flag off the ring must never be seeded, so the
        directive is inert config rather than a list this node is quietly
        talking to behind a 403.
        """
        endpoint = _start(lifecycle, tmp_path,
                          loc_arm=_flag("brix_cvmfs_swarm", arm,
                                        *_swarm_support()))
        _fetch(endpoint, REPO_A)
        _settle(2.5)
        assert _count(endpoint, "seeded") == 0, _errlog(endpoint)
        assert _count(endpoint, "live ring") == 0, _errlog(endpoint)


# --------------------------------------------------------------------------- #
# G. brix_cvmfs_unified_origin                                                 #
# --------------------------------------------------------------------------- #

# Bounds so the closed arm's failure lands inside a test rather than inside the
# default 25s client hold and 300s fill lifetime.  Written on every arm.
UNIFIED_SUPPORT = (f"brix_cvmfs_upstream_allow {HOST};",
                   "brix_cvmfs_origin_connect_timeout 1;",
                   "brix_cvmfs_client_hold 4;",
                   "brix_cvmfs_fill_max_life 8;")


class TestTheUnifiedOriginProxy:
    """In proxy mode a request names its own upstream.  `on` serves it from the
    location's configured origin instead; `off` goes to the named one."""

    def test_on_serves_a_named_dead_origin_from_the_locations_own_backend(
            self, lifecycle, tmp_path, mock):
        """success: the control, and the whole point of the feature — a client
        pointed at a Stratum-1 that is down still gets its bytes."""
        endpoint = _start(lifecycle, tmp_path,
                          loc_arm=_flag("brix_cvmfs_unified_origin", "on",
                                        *UNIFIED_SUPPORT))
        _fetch(endpoint, REPO_A)
        cold = _base_rels(REPO_A)[1]
        status, body, _ = _absolute_form(endpoint, f"{HOST}:{DEAD_PORT}",
                                         REPO_A, cold)
        assert status == 200, (
            f"{status}: {body[:200]!r}\n{_errlog(endpoint)}")
        assert body, "an empty body is not a fill"

    @pytest.mark.parametrize("arm", CLOSED_ARMS)
    def test_a_closed_proxy_honours_the_named_origin_and_times_out_on_it(
            self, lifecycle, tmp_path, mock, arm):
        """error: the request goes where the client said, and the client said a
        socket that refuses.  This is the arm, and it is why the flag exists."""
        endpoint = _start(lifecycle, tmp_path,
                          loc_arm=_flag("brix_cvmfs_unified_origin", arm,
                                        *UNIFIED_SUPPORT))
        _fetch(endpoint, REPO_A)
        cold = _base_rels(REPO_A)[1]
        status, _, _ = _absolute_form(endpoint, f"{HOST}:{DEAD_PORT}",
                                      REPO_A, cold)
        assert status == 504, (
            f"a closed unified origin answered {status} for an origin that is "
            f"not listening\n{_errlog(endpoint)}")

    @pytest.mark.parametrize("arm", ("on",) + CLOSED_ARMS)
    def test_no_arm_answers_for_an_authority_outside_the_allowlist(
            self, lifecycle, tmp_path, mock, arm):
        """security-negative: `on` is not an open proxy.

        Serving a named origin's path from a local backend is exactly the shape
        of an open relay, so the allowlist has to be checked BEFORE the
        substitution — measured on all three arms, because a check that only
        holds while the feature is off is not a check.

        The authority is `localhost` on purpose: it resolves to the very address
        the allowlist DOES name, so a check that had been written against the
        resolved address rather than the requested name would pass this request
        and this case would catch it.
        """
        endpoint = _start(lifecycle, tmp_path,
                          loc_arm=_flag("brix_cvmfs_unified_origin", arm,
                                        *UNIFIED_SUPPORT))
        _fetch(endpoint, REPO_A)
        unlisted = "localhost"  # net-literal-allow: the subject under test is a NAME an allowlist keyed on names must refuse while it resolves to the allowlisted address
        status, _, _ = _absolute_form(endpoint, f"{unlisted}:{MOCK_PORT}",
                                      REPO_A, _base_rels(REPO_A)[1])
        assert status == 403, (
            f"an authority outside brix_cvmfs_upstream_allow answered {status} "
            f"with the flag {arm}\n{_errlog(endpoint)}")


# --------------------------------------------------------------------------- #
# H. brix_scvmfs                                                               #
# --------------------------------------------------------------------------- #

SCVMFS_SUPPORT = ("brix_scvmfs_authz none;",)


class TestTheSecureCvmfsLayer:
    """Secure-CVMFS is a LAYER on cvmfs whose preamble requires TLS.  On a
    cleartext listener that makes the flag's arm the whole listener's fate."""

    def test_on_refuses_every_request_on_a_cleartext_listener(
            self, lifecycle, tmp_path, mock):
        """success (of the gate): the preamble (secure.c:284-322) answers 400
        when ``r->connection->ssl`` is NULL, before any repo or path is
        considered.  Even the manifest — the one object a client fetches before
        it has any credentials at all — is refused."""
        endpoint = _start(lifecycle, tmp_path,
                          loc_arm=_flag("brix_scvmfs", "on", *SCVMFS_SUPPORT))
        for path in (MANIFEST, _base_rels(REPO_A)[0]):
            response = _fetch(endpoint, REPO_A, path)
            assert response.status_code == 400, (
                f"{path} answered {response.status_code} on a cleartext "
                f"listener with brix_scvmfs on\n{_errlog(endpoint)}")

    @pytest.mark.parametrize("arm", CLOSED_ARMS)
    def test_a_closed_layer_leaves_the_cleartext_export_serving(
            self, lifecycle, tmp_path, mock, arm):
        """error: the same listener, the same requests, 200.  This is what
        makes the previous test the flag rather than the listener."""
        endpoint = _start(lifecycle, tmp_path,
                          loc_arm=_flag("brix_scvmfs", arm, *SCVMFS_SUPPORT))
        for path in (MANIFEST, _base_rels(REPO_A)[0]):
            response = _fetch(endpoint, REPO_A, path)
            assert response.status_code == 200, (
                f"{path} answered {response.status_code} with brix_scvmfs "
                f"{arm}\n{_errlog(endpoint)}")
            assert response.content, "an empty body is not a fill"


# --------------------------------------------------------------------------- #
# I. What a child location can take back — DEFECT CANDIDATE #80                #
# --------------------------------------------------------------------------- #

# One probe per flag, each returning a value that differs between "the server's
# `on` reached this location" and "the location's `off` won".  The support lines
# ride at server level with the `on`, so the location writes exactly one word.
INHERIT_SUPPORT = {
    "brix_cvmfs_scrub": SCRUB_SUPPORT,
    "brix_cvmfs_learn": LEARN_SUPPORT,
    "brix_cvmfs_swarm": None,          # filled in at call time — needs the port
    "brix_cvmfs_unified_origin": UNIFIED_SUPPORT,
}

