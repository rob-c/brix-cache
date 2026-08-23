# tests/test_oci_mirror_authdance.py — the upstream Bearer token dance, its
# SHM cache and its refusals (phase-104 D1.5).
#
# The subject is CREDENTIAL FLOW: which secret reached which plane, how many
# times the dance ran, and what a client is told when it could not run at all.
# Every assertion is read off the mock's request log (`auth_scheme` records the
# SCHEME, never the secret) or off its /ctl/token_count, because "the pull
# worked" is not evidence that the credential went where policy says it may.
#
# Ports: oci_mirror block — registry mock 14101, evil realm 14102 (on a second
# loopback address), CDN twin 14103 (on a third), nginx front 14111.
import hashlib
import json
import os
import time

import pytest

from fleet_lifecycle_ports import SHARED_PARSE_PLACEHOLDER_PORT
from oci.mirror_lane import (
    CDN_HOST, EVIL_HOST, Mirror, cache_files, ctl, ctl_post, err_code,
    error_log, get, hits, manifest_layers, mirror_spec, spawn_mock,
    start_mirror, stop_mocks,
)

MOCK_PORT = 14101
EVIL_PORT = 14102
CDN_PORT = 14103
NGINX_PORT = 14111

#: Without a zone the dance still works but caches nothing, so every reuse
#: assertion in this file depends on it being configured.
TOKEN_ZONE = "brix_oci_token_zone oci_tokens 1m;"

BASIC_USER = "ci-bot"
BASIC_PASS = "s3cr3t-pull-only"

MANIFEST = "/v2/lab/app/manifests/v1"

pytestmark = [
    pytest.mark.uses_lifecycle_harness,
    pytest.mark.xdist_group("lc-oci-mirror-authdance"),
]


@pytest.fixture
def mocks():
    """Spawn mock registries on demand; every one is reaped at teardown.

    Each test needs a differently-configured upstream (token spelling, realm,
    Basic policy), so the mock is per-test rather than module-scoped — the
    fixed ports are reusable because HTTPServer sets SO_REUSEADDR.
    """
    procs = []

    def _spawn(port, *extra, bind=None):
        proc, base = spawn_mock(port, *extra, bind=bind)
        procs.append(proc)
        return base

    yield _spawn
    stop_mocks(*procs)


def front(lifecycle, tmp_path, auth_lines="", extra="") -> Mirror:
    return start_mirror(lifecycle, "lc-oci-authdance", NGINX_PORT, MOCK_PORT,
                        tmp_path / "cache", auth_lines=auth_lines,
                        extra_lines=TOKEN_ZONE + extra)


def pwfile(tmp_path):
    """The token-endpoint password, in the 0600 file the directive demands."""
    path = tmp_path / "oci-pull.pw"
    path.write_text(BASIC_PASS + "\n", encoding="utf-8")
    os.chmod(path, 0o600)
    return path


def token_count(base):
    return ctl(base, "token_count")["count"]


def data_plane(base):
    """Log rows for the registry API only — the token endpoint is not it."""
    return [h for h in hits(base) if h["path"].startswith("/v2/")]


def schemes(rows):
    return {h["headers"]["auth_scheme"] for h in rows}


def blob_url(mirror, manifest_body):
    return mirror.base + "/v2/lab/app/blobs/" + \
        manifest_layers(manifest_body)[0]["digest"]


def test_cold_dance_runs_once_and_the_token_is_reused(mocks, lifecycle,
                                                      tmp_path):
    """One dance per (upstream, scope), not one per object.

    A cold image pull is a manifest plus every blob it names; re-running the
    dance for each of them would triple the round trips on the one operation
    that is already the slowest thing a container host does.
    """
    upstream = mocks(MOCK_PORT, "--auth")
    mirror = front(lifecycle, tmp_path)

    status, _, manifest = get(mirror.base + MANIFEST)
    after_manifest = token_count(upstream)
    config_digest = json.loads(manifest)["config"]["digest"]
    blob_status, _, _ = get(blob_url(mirror, manifest))
    cfg_status, _, _ = get(mirror.base + "/v2/lab/app/blobs/" + config_digest)

    assert (status, blob_status, cfg_status) == (200, 200, 200)
    assert after_manifest == 1
    assert token_count(upstream) == 1
    # Whatever the data plane saw, it was never our Basic credential.
    assert schemes(data_plane(upstream)) <= {None, "Bearer"}


def test_token_cache_is_keyed_per_repository(mocks, lifecycle, tmp_path):
    """A token minted for one repository must not be spent on another.

    The upstream scopes what it issues; reusing a `lab/app` token for
    `lab/multi` would either fail confusingly or — on a registry that ignores
    scope — quietly widen our access beyond what we asked for.
    """
    upstream = mocks(MOCK_PORT, "--auth")
    mirror = front(lifecycle, tmp_path)

    get(mirror.base + MANIFEST)
    first = token_count(upstream)
    get(mirror.base + "/v2/lab/multi/manifests/latest")

    assert first == 1
    assert token_count(upstream) == 2


def test_expired_token_forces_a_second_dance(mocks, lifecycle, tmp_path):
    """The cache honours expiry; it does not serve a dead bearer forever.

    `expires_in: 1` floors at the module's 5 s minimum TTL, so the wait is
    real time — the alternative (a mock clock) would test the harness, not
    the cache.
    """
    upstream = mocks(MOCK_PORT, "--auth", "--token-ttl", "1")
    mirror = front(lifecycle, tmp_path)

    _, _, manifest = get(mirror.base + MANIFEST)
    before = token_count(upstream)

    time.sleep(6)
    status, _, _ = get(blob_url(mirror, manifest))

    assert (before, status) == (1, 200)
    assert token_count(upstream) == 2


def test_access_token_spelling_without_expires_in(mocks, lifecycle, tmp_path):
    """Quay's `access_token` and an absent `expires_in` are both in the wild.

    A registry that omits the lifetime gets the spec's 60 s default, which
    must still produce a CACHED token — treating "no expiry stated" as "do not
    cache" would re-dance for every blob of every Quay pull.
    """
    upstream = mocks(MOCK_PORT, "--auth", "--token-key", "access_token",
                     "--token-ttl", "0")
    mirror = front(lifecycle, tmp_path)

    status, _, manifest = get(mirror.base + MANIFEST)
    blob_status, _, _ = get(blob_url(mirror, manifest))

    assert (status, blob_status) == (200, 200)
    assert token_count(upstream) == 1


@pytest.mark.parametrize("fault", ["http500", "corrupt"])
def test_token_endpoint_failure_is_our_502_not_their_challenge(mocks,
                                                               lifecycle,
                                                               tmp_path,
                                                               fault):
    """A dance we could not complete is OUR failure, reported as ours.

    Two things must not happen: the client must not be told 403 (it would read
    "you are not allowed" for an image it is perfectly allowed to pull), and
    the upstream's `WWW-Authenticate` must not be relayed (the client would
    chase a realm it has no credentials for, aimed by a host we do not trust).
    """
    upstream = mocks(MOCK_PORT, "--auth")
    ctl_post(upstream, "fault",
             {"kind": fault, "persist": True, "path_re": "^/token"})
    mirror = front(lifecycle, tmp_path)

    status, headers, body = get(mirror.base + MANIFEST)

    assert status == 502
    assert err_code(body) == "UNAVAILABLE"
    assert "WWW-Authenticate" not in headers


@pytest.mark.parametrize("realm", ["-", "not-a-url"])
def test_unusable_challenge_maps_to_502(mocks, lifecycle, tmp_path, realm):
    """No realm, or a realm that is not an absolute URL, ends the dance.

    Guessing the endpoint from the request host is what an attacker-supplied
    challenge is trying to provoke; there is nothing to mint here, so the
    honest answer is that the upstream is unusable.
    """
    upstream = mocks(MOCK_PORT, "--auth", "--realm", realm)
    mirror = front(lifecycle, tmp_path)

    status, headers, body = get(mirror.base + MANIFEST)

    assert status == 502
    assert err_code(body) == "UNAVAILABLE"
    assert "WWW-Authenticate" not in headers
    assert token_count(upstream) == 0


def test_toomanyrequests_maps_to_429_with_retry_after(mocks, lifecycle,
                                                      tmp_path):
    """An upstream rate limit reaches the client as a rate limit.

    The fill tier's default answer to an upstream error is to retry with
    backoff and, on exhaustion, send a keep-alive 504 — precisely the
    behaviour that burns the remaining quota of a registry that has already
    said "slow down". `Retry-After` is OURS, not the upstream's: our next
    attempt is what the client's retry actually costs (DRIFT vs D1.5's
    "echoed", which would need the header threaded across the fill's
    thread-pool boundary).
    """
    upstream = mocks(MOCK_PORT, "--auth")
    ctl_post(upstream, "fault", {"kind": "toomanyrequests", "persist": True,
                                 "path_re": "/manifests/"})
    mirror = front(lifecycle, tmp_path)

    status, headers, body = get(mirror.base + MANIFEST)

    assert status == 429
    assert err_code(body) == "TOOMANYREQUESTS"
    assert headers["Retry-After"] == "5"
    # The dance still ran — the limit is on the data plane, not the token one.
    assert token_count(upstream) == 1


def test_cdn_redirect_carries_no_authorization(mocks, lifecycle, tmp_path):
    """A blob 302 to a CDN is a hop to a different principal.

    Registries hand blobs off to object storage that authenticates by signed
    URL; forwarding our bearer there would hand a pull credential to a host
    the upstream merely named, and those requests are logged by someone else.
    """
    cdn = mocks(CDN_PORT, "--cdn", bind=CDN_HOST)
    upstream = mocks(MOCK_PORT, "--auth", "--blob-redirect",
                     "http://%s:%d" % (CDN_HOST, CDN_PORT))
    mirror = front(lifecycle, tmp_path)

    _, _, manifest = get(mirror.base + MANIFEST)
    digest = manifest_layers(manifest)[0]["digest"]
    status, _, body = get(mirror.base + "/v2/lab/app/blobs/" + digest)

    assert status == 200
    assert "sha256:" + hashlib.sha256(body).hexdigest() == digest
    assert ctl(cdn, "saw_authorization")["count"] == 0
    assert schemes(hits(cdn)) == {None}
    assert token_count(upstream) == 1          # the registry leg did dance


def test_signed_cdn_redirect_arrives_with_its_signature(mocks, lifecycle,
                                                       tmp_path):
    """A CDN blob URL carries its authorization in the QUERY.

    DockerHub hands blobs to CloudFront with `?Expires=…&Signature=…`, so a hop
    that resolves the Location but keeps only the path arrives unsigned and is
    refused — and the mirror then reports "the origin denied this object" about
    an image that is perfectly public. The twin refuses an unsigned request on
    purpose: without that, this test would pass while dropping the signature.
    """
    cdn = mocks(CDN_PORT, "--cdn", "--require-signature", bind=CDN_HOST)
    upstream = mocks(MOCK_PORT, "--auth", "--blob-redirect-sign",
                     "--blob-redirect",
                     "http://%s:%d" % (CDN_HOST, CDN_PORT))
    mirror = front(lifecycle, tmp_path)

    _, _, manifest = get(mirror.base + MANIFEST)
    digest = manifest_layers(manifest)[0]["digest"]
    status, _, body = get(mirror.base + "/v2/lab/app/blobs/" + digest)

    assert status == 200
    assert "sha256:" + hashlib.sha256(body).hexdigest() == digest
    assert all("Signature=" in h["path"] for h in hits(cdn, method="GET"))
    # Carrying the query does not soften the credential rule: the signature IS
    # the CDN's authorization, and ours has no business travelling with it.
    assert ctl(cdn, "saw_authorization")["count"] == 0
    assert token_count(upstream) == 1


def test_cdn_refusal_is_reported_and_nothing_is_cached(mocks, lifecycle,
                                                      tmp_path):
    """When the hop IS refused, the client hears it and the cache stays empty.

    The upstream redirects without signing, so the twin answers 403. A pull
    that cannot be completed must not leave a partial or placeholder object
    behind — the next client would be served a hole with a valid-looking name.
    """
    mocks(CDN_PORT, "--cdn", "--require-signature", bind=CDN_HOST)
    upstream = mocks(MOCK_PORT, "--auth", "--blob-redirect",
                     "http://%s:%d" % (CDN_HOST, CDN_PORT))
    mirror = front(lifecycle, tmp_path)

    _, _, manifest = get(mirror.base + MANIFEST)
    digest = manifest_layers(manifest)[0]["digest"]
    status, _, body = get(mirror.base + "/v2/lab/app/blobs/" + digest)

    assert status == 403
    assert err_code(body) == "DENIED"
    assert token_count(upstream) == 1
    assert not any(name.endswith(digest) for name in cache_files(mirror.cache))


def test_jwt_sized_bearer_is_presented_whole(mocks, lifecycle, tmp_path):
    """A 3 KB bearer is an ordinary bearer, not an edge case.

    Registry tokens are JWTs — DockerHub's runs ~2.7 KB — and a client that
    clips one does not send a shorter credential, it sends an invalid one. The
    401 that earns is indistinguishable from a genuine denial, so the pull
    fails permanently against every real registry while every short-token mock
    in the suite stays green.
    """
    upstream = mocks(MOCK_PORT, "--auth", "--token-len", "3000")
    mirror = front(lifecycle, tmp_path)

    status, _, manifest = get(mirror.base + MANIFEST)

    assert status == 200
    assert manifest_layers(manifest) != []
    assert token_count(upstream) == 1
    assert schemes(hits(upstream, path_prefix="/v2/")) == {None, "Bearer"}


def test_third_party_realm_is_refused_and_never_contacted(mocks, lifecycle,
                                                          tmp_path):
    """The realm is the upstream naming a host to hand a credential to.

    The evil realm here is a REACHABLE listener: if the refusal were an
    accident of DNS or a dead port this test would pass for the wrong reason.
    Its log must stay empty, and our Basic credential must be configured — a
    negative that proves nothing leaked needs something to leak.
    """
    evil = mocks(EVIL_PORT, bind=EVIL_HOST)
    upstream = mocks(MOCK_PORT, "--auth", "--realm",
                     "http://%s:%d/token" % (EVIL_HOST, EVIL_PORT))
    mirror = front(lifecycle, tmp_path, auth_lines="brix_oci_mirror_auth %s %s;"
                   % (BASIC_USER, pwfile(tmp_path)))

    status, _, body = get(mirror.base + MANIFEST)

    assert status == 502
    assert err_code(body) == "UNAVAILABLE"
    assert hits(evil) == []
    assert "signal=oci_realm_refused" in error_log(mirror.endpoint)


def test_token_redirect_loop_is_bounded_and_reported_as_ours(mocks, lifecycle,
                                                            tmp_path):
    """A token endpoint that redirects to itself ends at OUR hop budget.

    The redirect stays on the upstream's own host, so the realm allowlist has
    nothing to refuse and every hop is legitimately followed; only the budget
    can stop it. Three things are asserted, and the middle one is why this test
    exists: the walk TERMINATES (a bounded number of requests reach the mock,
    not an unbounded spin), the client is told 502 rather than handed the last
    3xx as though it were the token endpoint's answer, and the refusal names
    itself in the log so the operator sees a loop rather than a generic
    upstream failure.
    """
    upstream = mocks(MOCK_PORT, "--auth", "--token-redirect-loop")
    mirror = front(lifecycle, tmp_path)

    status, headers, body = get(mirror.base + MANIFEST)

    assert status == 502
    assert err_code(body) == "UNAVAILABLE"
    assert "WWW-Authenticate" not in headers
    # OCI_TOKEN_MAX_HOPS is 3, so the budget admits hops 0..3 — four requests
    # and no more. Pinning the exact count is what distinguishes "the loop is
    # bounded" from "the loop happened to end".
    token_hits = [h for h in hits(upstream)
                  if h["path"].split("?")[0] == "/token"]
    assert len(token_hits) == 4, token_hits
    assert "signal=oci_token_redirect_loop" in error_log(mirror.endpoint)


def test_basic_credentials_reach_only_the_token_endpoint(mocks, lifecycle,
                                                         tmp_path):
    """Basic authenticates US to the token service, and to nothing else.

    The registry's data plane sees the minted bearer; a mirror that also sent
    the long-lived Basic pair there would put a reusable secret in every proxy
    log between here and the origin.
    """
    upstream = mocks(MOCK_PORT, "--auth", "--basic",
                     "%s:%s" % (BASIC_USER, BASIC_PASS))
    mirror = front(lifecycle, tmp_path, auth_lines="brix_oci_mirror_auth %s %s;"
                   % (BASIC_USER, pwfile(tmp_path)))

    status, _, manifest = get(mirror.base + MANIFEST)
    blob_status, _, _ = get(blob_url(mirror, manifest))

    assert (status, blob_status) == (200, 200)
    assert token_count(upstream) == 1
    token_rows = [h for h in hits(upstream)
                  if h["path"].startswith("/token")]
    assert schemes(token_rows) == {"Basic"}
    assert schemes(data_plane(upstream)) <= {None, "Bearer"}


def test_wrong_password_fails_closed_without_a_challenge(mocks, lifecycle,
                                                         tmp_path):
    """A rejected Basic pair ends the dance; it does not fall back to anonymous.

    Retrying the pull without the credential would silently downgrade a
    private mirror to whatever the upstream serves the public, and the 401
    from the token endpoint must not reach the client as a challenge it could
    answer.
    """
    upstream = mocks(MOCK_PORT, "--auth", "--basic", "someone-else:wrong")
    mirror = front(lifecycle, tmp_path, auth_lines="brix_oci_mirror_auth %s %s;"
                   % (BASIC_USER, pwfile(tmp_path)))

    status, headers, body = get(mirror.base + MANIFEST)

    assert status == 502
    assert err_code(body) == "UNAVAILABLE"
    assert "WWW-Authenticate" not in headers
    assert token_count(upstream) == 0
    assert schemes(data_plane(upstream)) == {None}


# ---- the explicit realm allowlist (D15.11) ------------------------------- #
#
# The derived rule — same host, its registrable parent, a sibling under that
# parent — is what every registry that hosts its own token service needs. A
# site whose registry delegates to an unrelated identity host has no spelling
# of that shape at all, and "unmirrorable" is how a check like this ends up
# deleted rather than configured. So there is one directive that widens the
# boundary by one named host, and these rows are about who may write it and
# what it can and cannot say.


def offdomain(mocks):
    """An upstream whose token service answers on an address of its own.

    One mock process serving two listeners, because the token it mints has to
    be one its own data plane accepts — two processes would fail this test for
    the wrong reason (an unknown bearer), not for the realm boundary.
    """
    return mocks(MOCK_PORT, "--auth",
                 "--token-port", str(EVIL_PORT), "--token-bind", EVIL_HOST,
                 "--realm", "http://%s:%d/token" % (EVIL_HOST, EVIL_PORT))


def test_an_allowlisted_off_domain_realm_completes_the_dance(mocks, lifecycle,
                                                             tmp_path):
    """Named by the operator, the off-domain token service is honoured.

    And it is honoured LOUDLY: the widened boundary leaves an INFO line naming
    the host, because a trust decision that only shows up as a working pull is
    one nobody can audit afterwards.
    """
    upstream = offdomain(mocks)
    mirror = front(lifecycle, tmp_path,
                   extra="brix_oci_upstream_auth_realm %s;" % EVIL_HOST)

    status, _, _ = get(mirror.base + MANIFEST)

    log = error_log(mirror.endpoint)
    assert status == 200
    assert token_count(upstream) == 1
    assert "signal=oci_realm_refused" not in log
    assert "honoured by brix_oci_upstream_auth_realm" in log


def test_an_allowlist_entry_admits_that_host_and_no_other(mocks, lifecycle,
                                                          tmp_path):
    """The list is exact hosts, so naming one does not admit its neighbours.

    127.0.0.4 and 127.0.0.3 are siblings by any string rule loose enough to be
    convenient; the refusal here is what proves the compare is equality.
    """
    upstream = offdomain(mocks)
    mirror = front(lifecycle, tmp_path,
                   extra="brix_oci_upstream_auth_realm 127.0.0.4;")

    status, _, body = get(mirror.base + MANIFEST)

    assert status == 502
    assert err_code(body) == "UNAVAILABLE"
    assert token_count(upstream) == 0
    assert "signal=oci_realm_refused" in error_log(mirror.endpoint)


def parse_refusal(lifecycle, tmp_path, name, entry):
    spec = mirror_spec(name, SHARED_PARSE_PLACEHOLDER_PORT,
                       SHARED_PARSE_PLACEHOLDER_PORT, tmp_path / "cache",
                       extra_lines="brix_oci_upstream_auth_realm %s;" % entry)
    lifecycle.register(spec)
    lifecycle.launcher.render_nginx(spec)
    res = lifecycle.launcher.nginx_test(spec, check=False)
    return res, res.stdout + res.stderr


def test_a_wildcard_entry_is_refused_at_parse_time(lifecycle, tmp_path):
    """`*.docker.io` is not an allowlist entry — it is the check turned off.

    A pattern entry is how one directive quietly re-admits every host under a
    domain the operator does not run, so the grammar has no pattern form and
    says so at nginx -t rather than at the first dance.
    """
    res, output = parse_refusal(lifecycle, tmp_path, "lc-oci-realm-wild",
                                "*.docker.io")

    assert res.returncode != 0, output
    assert "brix_oci_upstream_auth_realm" in output
    assert "no wildcard" in output


def test_an_entry_that_spells_a_port_is_refused_at_parse_time(lifecycle,
                                                              tmp_path):
    """The trust rule compares hosts, so a port in an entry is a false promise.

    Accepting `auth.example:8443` would read as pinning the port while the
    compare ignored it; an operator who believes they have narrowed the
    boundary has widened it by the whole host.
    """
    res, output = parse_refusal(lifecycle, tmp_path, "lc-oci-realm-port",
                                "%s:%d" % (EVIL_HOST, EVIL_PORT))

    assert res.returncode != 0, output
    assert "brix_oci_upstream_auth_realm" in output
    assert "no port" in output
