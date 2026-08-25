# tests/test_oci_mirror_delegate.py — delegated pull and authorize-on-hit
# (phase-104 D16).
#
# The subject is PRIVACY ACROSS A SHARED CACHE: the mirror holds no user
# secret, replays a downstream Basic credential only to the upstream token
# endpoint, and refuses every byte — and every listing line — of a private
# repository to any principal the UPSTREAM has not vouched for, cache hit or
# miss alike. Every denial is one uniform 401 that reveals nothing, so the
# assertions here compare denial shapes as much as they read statuses.
#
# Ports: oci_mirror block — multi-user mock 14105, delegate front 14113.
import base64
import time

import pytest

from fleet_lifecycle_ports import SHARED_PARSE_PLACEHOLDER_PORT
from oci.mirror_lane import (
    Mirror, cache_files, ctl, err_code, get, hits, mirror_spec, spawn_mock,
    start_mirror, stop_mocks,
)

MOCK_PORT = 14105
NGINX_PORT = 14113

MANIFEST = "/v2/lab/app/manifests/v1"
TAGS = "/v2/lab/app/tags/list"

#: The delegate stanza every front in this file carries. The mock speaks
#: cleartext http, so the TLS mandate is stated away with the same
#: test-fixture flag the upstream side uses — and the one lane that must see
#: the mandate ENFORCED builds its spec without this line.
DELEGATE = (
    "brix_oci_token_zone oci_tokens 1m;"
    "brix_oci_mirror_delegate on;"
    "brix_oci_delegate_insecure on;"
)

#: One private repository, two accounts: alice may read it, bob is a real
#: account with a real password who simply was not granted this repo.
PRIVATE_ARGS = ("--auth", "--user", "alice:a-pw", "--user", "bob:b-pw",
                "--private", "lab/app=alice")

pytestmark = [
    pytest.mark.uses_lifecycle_harness,
    pytest.mark.xdist_group("lc-oci-mirror-delegate"),
]


@pytest.fixture
def mocks():
    """Spawn mock registries on demand; every one is reaped at teardown."""
    procs = []

    def _spawn(port, *extra):
        proc, base = spawn_mock(port, *extra)
        procs.append(proc)
        return base

    yield _spawn
    stop_mocks(*procs)


def front(lifecycle, tmp_path, extra="") -> Mirror:
    return start_mirror(lifecycle, "lc-oci-delegate", NGINX_PORT, MOCK_PORT,
                        tmp_path / "cache", extra_lines=DELEGATE + extra)


def basic(user, password):
    cred = base64.b64encode(("%s:%s" % (user, password)).encode()).decode()
    return {"Authorization": "Basic " + cred}


def token_count(base):
    return ctl(base, "token_count")["count"]


def data_plane(base):
    return [h for h in hits(base) if h["path"].startswith("/v2/")]


def token_plane(base):
    return [h for h in hits(base) if h["path"].startswith("/token")]


def auth_schemes(rows):
    return {h["headers"]["auth_scheme"] for h in rows}


# ---- the grant ------------------------------------------------------------


def test_the_granted_user_pulls_a_private_manifest(mocks, lifecycle,
                                                   tmp_path):
    """The success leg: alice's own credential opens alice's repository.

    The credential itself must go to the TOKEN plane and nowhere else — the
    data plane sees Bearer or nothing, which is the whole D16 secrecy claim
    stated as a log assertion.
    """
    upstream = mocks(MOCK_PORT, *PRIVATE_ARGS)
    mirror = front(lifecycle, tmp_path)

    status, _, body = get(mirror.base + MANIFEST,
                          headers=basic("alice", "a-pw"))

    assert status == 200
    assert b"layers" in body
    assert auth_schemes(data_plane(upstream)) <= {None, "Bearer"}
    assert auth_schemes(token_plane(upstream)) == {"Basic"}


def test_a_public_repo_still_serves_anonymously(mocks, lifecycle, tmp_path):
    """Delegate mode is not a login wall: public stays public.

    An anonymous proof is minted upstream exactly as docker itself would, so
    a mirror in delegate mode is a drop-in for the open images too.
    """
    mocks(MOCK_PORT, *PRIVATE_ARGS)
    mirror = front(lifecycle, tmp_path)

    status, _, _ = get(mirror.base + "/v2/lab/multi/manifests/latest")

    assert status == 200


def test_the_proof_is_cached_and_the_token_shared(mocks, lifecycle,
                                                  tmp_path):
    """One mint covers the proof AND the fill AND the next request.

    The proof gate lends its bearer to the credential-blind entry the fill
    provider probes, so a granted pull costs one dance — not one for the
    proof plus one per object.
    """
    upstream = mocks(MOCK_PORT, *PRIVATE_ARGS)
    mirror = front(lifecycle, tmp_path)

    first, _, _ = get(mirror.base + MANIFEST, headers=basic("alice", "a-pw"))
    second, _, _ = get(mirror.base + MANIFEST, headers=basic("alice", "a-pw"))

    assert (first, second) == (200, 200)
    assert token_count(upstream) == 1


# ---- the uniform refusal --------------------------------------------------


def test_wrong_password_and_wrong_user_are_indistinguishable(mocks,
                                                             lifecycle,
                                                             tmp_path):
    """Every denial is the SAME 401 — no oracle distinguishes 'bad password'
    from 'real account, not your repo'.

    The upstream answers those two differently (401 at the token endpoint vs
    a valid token 403'd on the data plane); the mirror must flatten both, or
    a probing client learns which accounts exist.
    """
    mocks(MOCK_PORT, *PRIVATE_ARGS)
    mirror = front(lifecycle, tmp_path)

    pw_status, pw_hdrs, pw_body = get(mirror.base + MANIFEST,
                                      headers=basic("alice", "wrong"))
    user_status, user_hdrs, user_body = get(mirror.base + MANIFEST,
                                            headers=basic("bob", "b-pw"))

    assert pw_status == user_status == 401
    assert err_code(pw_body) == err_code(user_body) == "DENIED"
    assert pw_body == user_body
    assert pw_hdrs.get("WWW-Authenticate") == \
        user_hdrs.get("WWW-Authenticate") == 'Basic realm="brix-oci"'


def test_anonymous_gets_the_challenge_not_the_bytes(mocks, lifecycle,
                                                    tmp_path):
    """No credential on a private repo earns the Basic challenge.

    docker/podman answer that challenge from their login store with no
    ceremony — which is exactly why the downstream contract is Basic.
    """
    mocks(MOCK_PORT, *PRIVATE_ARGS)
    mirror = front(lifecycle, tmp_path)

    status, headers, body = get(mirror.base + MANIFEST)

    assert status == 401
    assert err_code(body) == "DENIED"
    assert headers.get("WWW-Authenticate") == 'Basic realm="brix-oci"'


def test_a_bearer_scheme_downstream_is_refused_not_forwarded(mocks,
                                                             lifecycle,
                                                             tmp_path):
    """A downstream Bearer is not a credential this surface can delegate.

    Guessing what to do with an unknown scheme is how a secret ends up on
    the wrong plane; the only safe answer is the same uniform 401.
    """
    upstream = mocks(MOCK_PORT, *PRIVATE_ARGS)
    mirror = front(lifecycle, tmp_path)

    status, headers, _ = get(mirror.base + MANIFEST,
                             headers={"Authorization": "Bearer junk"})

    assert status == 401
    assert headers.get("WWW-Authenticate") == 'Basic realm="brix-oci"'
    assert token_count(upstream) == 0


# ---- authorize-on-hit -----------------------------------------------------


def test_a_cache_hit_still_asks_who_is_asking(mocks, lifecycle, tmp_path):
    """The security core: bytes already in the shared cache are NOT a grant.

    alice warms the cache; bob (valid account, no grant) and an anonymous
    client must both be refused the very object that is sitting on disk —
    otherwise the mirror converts one authorized pull into a public leak.
    """
    mocks(MOCK_PORT, *PRIVATE_ARGS)
    mirror = front(lifecycle, tmp_path)

    warm, _, _ = get(mirror.base + MANIFEST, headers=basic("alice", "a-pw"))
    assert warm == 200
    assert cache_files(mirror.cache), "the warm pull must have cached bytes"

    bob_status, _, bob_body = get(mirror.base + MANIFEST,
                                  headers=basic("bob", "b-pw"))
    anon_status, _, _ = get(mirror.base + MANIFEST)

    assert (bob_status, anon_status) == (401, 401)
    assert err_code(bob_body) == "DENIED"


def test_revocation_propagates_within_the_proof_ttl(mocks, lifecycle,
                                                    tmp_path):
    """The upstream stays the oracle: a revoked grant dies with the proof.

    Inside the TTL the cached proof is honoured (that is the documented
    bound, not a bug); once it lapses the next request re-asks the upstream
    and the revocation lands — no restart, no cache purge.
    """
    proc, _ = spawn_mock(MOCK_PORT, *PRIVATE_ARGS)
    mirror = front(lifecycle, tmp_path,
                   extra="brix_oci_delegate_proof_ttl 2s;")
    try:
        warm, _, _ = get(mirror.base + MANIFEST,
                         headers=basic("alice", "a-pw"))
        assert warm == 200
    finally:
        stop_mocks(proc)

    # The upstream revokes alice: same accounts, nobody may read lab/app.
    proc, _ = spawn_mock(MOCK_PORT, "--auth", "--user", "alice:a-pw",
                         "--private", "lab/app=")
    try:
        inside, _, _ = get(mirror.base + MANIFEST,
                           headers=basic("alice", "a-pw"))
        time.sleep(2.5)
        after, _, body = get(mirror.base + MANIFEST,
                             headers=basic("alice", "a-pw"))
    finally:
        stop_mocks(proc)

    assert inside == 200, "within the TTL the proof is honoured by design"
    assert after == 401
    assert err_code(body) == "DENIED"


def test_the_listing_surface_is_gated_too(mocks, lifecycle, tmp_path):
    """tags/list is where a private repo's METADATA would leak.

    The object routes carry digests a client must already know; the listing
    hands out names and tags to anyone who asks — so it is proven under the
    same per-(credential, repository) gate, not just the object routes.
    """
    mocks(MOCK_PORT, *PRIVATE_ARGS)
    mirror = front(lifecycle, tmp_path)

    alice_status, _, alice_body = get(mirror.base + TAGS,
                                      headers=basic("alice", "a-pw"))
    bob_status, _, bob_body = get(mirror.base + TAGS,
                                  headers=basic("bob", "b-pw"))

    assert alice_status == 200
    assert b"v1" in alice_body
    assert bob_status == 401
    assert err_code(bob_body) == "DENIED"


def test_a_cold_worker_survives_a_listing_first(lifecycle, tmp_path):
    """The very first request a worker ever sees may be a tags/list.

    Both task-posting gates (delegate and the plain tags relay) log from a
    thread whose log used to be bound only by the first FILL — a
    listing-first cold worker dereferenced a NULL log and segfaulted
    (phase-104 §D16 TRAP, both instances). No delegate stanza and no mock
    on purpose: the unreachable-upstream leg is the plain relay's one
    unconditional thread-side log line, so pre-fix this request killed the
    worker instead of answering 502.
    """
    mirror = start_mirror(lifecycle, "lc-oci-deleg-cold", NGINX_PORT,
                          MOCK_PORT, tmp_path / "cache")

    status, _, body = get(mirror.base + TAGS)

    assert status == 502
    assert err_code(body) == "UNAVAILABLE"


# ---- the TLS mandate ------------------------------------------------------


def test_delegate_without_tls_is_a_config_refusal(lifecycle, tmp_path):
    """A delegated credential on cleartext is already burned.

    The refusal lands at nginx -t — where the operator is looking — not at
    the first request, and the message names the one deliberate escape
    hatch (the test-fixture flag this whole lane rides).
    """
    spec = mirror_spec("lc-oci-deleg-tls", SHARED_PARSE_PLACEHOLDER_PORT,
                       SHARED_PARSE_PLACEHOLDER_PORT, tmp_path / "cache",
                       extra_lines="brix_oci_mirror_delegate on;")
    lifecycle.register(spec)
    lifecycle.launcher.render_nginx(spec)
    res = lifecycle.launcher.nginx_test(spec, check=False)
    output = res.stdout + res.stderr

    assert res.returncode != 0, output
    assert "brix_oci_mirror_delegate" in output
    assert "brix_oci_delegate_insecure" in output
