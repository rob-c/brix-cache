from split_continuation import reexport as _reexport
_reexport(globals(), "_test_server_leg_faults_helpers")

def test_clean_fetch_through_the_origin_leg_is_byte_exact(origin_leg):
    rc, exact, got = origin_leg.download()
    assert rc == 0 and exact, f"rc={rc} bytes={got}"


def test_clean_tpc_pull_through_the_proxy_commits_byte_exact(tpc_leg):
    rc, exact, got = tpc_leg.copy()
    assert rc == 0 and exact, f"rc={rc} committed={got}"


def test_the_front_serves_from_the_origin_not_from_a_local_copy(origin_leg):
    """Non-vacuity: with `brix_stage off` the front holds no copy of the object,
    so every byte the client got really crossed the proxied origin leg. Without
    this the whole module could be measuring a local read."""
    local = [n for n in os.listdir(origin_leg.front.data)
             if not n.startswith(".")]
    assert NAME not in local, f"front export is not empty of the object: {local}"


# --------------------------------------------------------------------------- #
# Error — a severed upstream fetch fails the operation.                        #
# --------------------------------------------------------------------------- #
def test_origin_leg_sever_fails_the_read(origin_leg):
    origin_leg.fp.set_truncate(MID_CUT, "down")
    rc, exact, got = origin_leg.download()
    assert rc != 0 and not exact, f"rc={rc} bytes={got}"


def test_tpc_pull_leg_sever_fails_the_copy(tpc_leg):
    tpc_leg.fp.set_truncate(MID_CUT, "down")
    rc, exact, got = tpc_leg.copy()
    assert rc != 0 and not exact, f"rc={rc} committed={got}"


def test_tpc_pull_leg_cut_during_the_source_login_fails_the_copy(tpc_leg):
    """The early cut lands in the destination's own login to the source, before
    a single payload byte — the destination must fail rather than commit an
    empty object for a file it never opened."""
    tpc_leg.fp.set_truncate(EARLY_CUT, "down")
    rc, exact, got = tpc_leg.copy()
    assert rc != 0 and not exact, f"rc={rc} committed={got}"


# --------------------------------------------------------------------------- #
# Security — nothing partial is ever committed or delivered.                   #
# --------------------------------------------------------------------------- #
def test_origin_leg_sever_delivers_no_partial_file(origin_leg):
    """The failure this module exists to exclude: a short upstream fetch turned
    into a successful short read. The client cannot tell the difference, so the
    only defence is the front refusing to finish."""
    origin_leg.fp.set_truncate(MID_CUT, "down")
    rc, _exact, got = origin_leg.download()
    assert got == 0, f"delivered {got} bytes of a severed fetch (rc={rc})"


def test_tpc_pull_leg_sever_commits_nothing_at_the_destination(tpc_leg):
    """Same failure on the copy plane, and the more dangerous one: a committed
    short object is indistinguishable from a complete transfer forever after."""
    tpc_leg.fp.set_truncate(MID_CUT, "down")
    rc, _exact, got = tpc_leg.copy()
    assert got == 0, f"committed {got} bytes of a severed pull (rc={rc})"


# --------------------------------------------------------------------------- #
# Security — corruption on a leg the client cannot see.                        #
#                                                                              #
# Truncation and corruption behave completely differently here, and it is the   #
# reason this section is separate. A SEVERED origin fetch fails the read (see   #
# above): the front notices the short upstream and refuses. A CORRUPTED one is  #
# length-preserving, so there is nothing for the front to notice — the bytes    #
# are relayed and the client is told 0. The defence has to be an explicit       #
# checksum, and the tests below pin which options actually provide one.         #
# --------------------------------------------------------------------------- #
def test_a_corrupted_origin_leg_is_delivered_to_the_client_silently(origin_leg):
    """THE EXPOSURE, measured rather than assumed: bytes flipped between the
    front and its http:// origin reach the client as a full-length file with a
    clean rc 0. Nothing in the path checks them — the origin leg carries no
    integrity envelope of its own, and the client's own transport was pristine
    throughout, so there is nothing for the client to detect either.

    Pinned as a test because it is the shape of the failure operators care about
    and the justification for the next test. If this ever starts failing because
    the read was refused, that is an improvement — but it is a behaviour change
    on a documented default and should be a deliberate one."""
    origin_leg.fp.set_corrupt(CORRUPT_PCT, "down")
    rc, exact, got = origin_leg.download()
    assert rc == 0, f"expected the corrupted fetch to be relayed, got rc={rc}"
    assert got == SIZE, f"expected a full-length file, got {got} bytes"
    assert not exact, ("nothing was corrupted — CORRUPT_PCT is too low for this "
                       "object size and the assertions here are vacuous")


def test_verify_catches_corruption_on_the_origin_leg(origin_leg):
    """The defence that works: `--verify` asks the server for the object's
    checksum after the transfer. The server computes it from the origin, the
    client from what landed, and the two disagree — so the corrupted download is
    refused and nothing is left behind.

    Note what this does NOT rely on: the client-to-front leg is clean in this
    test, so the mismatch can only have come from the leg the client cannot
    see. That is precisely the leg an end-to-end checksum exists to cover."""
    origin_leg.fp.set_corrupt(CORRUPT_PCT, "down")
    rc, exact, got = origin_leg.download(extra=("--verify",))
    assert rc != 0, "the post-transfer checksum comparison passed on bad data"
    assert not exact and got == 0, f"left {got} bytes behind (rc={rc})"


def test_bare_cksum_prints_a_digest_and_does_not_verify_anything(origin_leg):
    """The security-negative, and a genuine footgun: `--cksum adler32` with no
    mode suffix is a PRINT, not a comparison (`copy_cksum_verify.c` — only
    `:source`/`:end2end` query the server, and `:<value>` compares a literal).
    So it returns 0 on the same corrupted download that `--verify` refuses.

    That is documented behaviour, not a defect — it is pinned here because the
    option reads like a check, and an operator who reaches for it expecting one
    would be silently unprotected on exactly the leg this module is about."""
    origin_leg.fp.set_corrupt(CORRUPT_PCT, "down")
    rc, exact, got = origin_leg.download(extra=("--cksum", "adler32"))
    assert rc == 0 and got == SIZE, f"rc={rc} bytes={got}"
    assert not exact, "vacuous: nothing was corrupted"


def test_tpc_pull_leg_commits_corruption_with_the_verify_knob_off(tpc_leg):
    """The TPC destination here runs the DEFAULT config, with
    `brix_tpc_verify_checksum` off — and a corrupted pull is therefore committed
    as a complete object. That is deliberate stock-parity behaviour, not a gap:
    the knob and its fail-closed path are covered by
    `tests/test_tpc_pull_integrity.py` (history-storage-and-caching.md #13),
    which drives a kXR-response-aware proxy able to corrupt a single frame while
    leaving the `kXR_stat` and `kXR_Qcksum` replies truthful.

    What this test adds is the RAW-transport path that the surgical proxy
    cannot produce: flips sprayed across the whole stream, framing included. The
    contract to pin is that the outcome is the same either way — the default
    commits, and no client-side option compensates (`--verify` and
    `--cksum:source` are both no-ops on a copy where the client moves no bytes,
    measured)."""
    tpc_leg.fp.set_corrupt(CORRUPT_PCT, "down")
    rc, exact, got = tpc_leg.copy()
    assert rc == 0 and got == SIZE, f"rc={rc} committed={got}"
    assert not exact, "vacuous: nothing was corrupted"


# --------------------------------------------------------------------------- #
# The same origin leg one driver over: s3:// instead of http://.               #
#                                                                              #
# Not a duplicate of the section above. sd_s3 and sd_http share no fetch code,  #
# and the measurements differ in two ways that matter:                         #
#                                                                              #
#   * `--pgrw` returns IMMEDIATELY here (0.1 s) instead of stalling ~180 s, so  #
#     the architectural claim the http section could only assert in prose is    #
#     assertable — and the stall is pinned as an sd_http defect rather than a   #
#     property of pgread over any remote backend.                              #
#   * `--verify` refuses 19 times in 20 rather than 20 in 20; the twentieth is  #
#     the fail-open below, which is the most interesting result in the module.  #
# --------------------------------------------------------------------------- #
def test_clean_fetch_through_the_s3_origin_leg_is_byte_exact(s3_origin_leg):
    rc, exact, got = s3_origin_leg.download()
    assert rc == 0 and exact, f"rc={rc} bytes={got}"


def test_the_front_serves_from_the_s3_origin_not_from_a_local_copy(s3_origin_leg):
    """Non-vacuity, as for the http front: with `brix_stage off` the object is
    not in the front's export, so every byte really crossed the proxied leg."""
    local = [n for n in os.listdir(s3_origin_leg.front.data)
             if not n.startswith(".")]
    assert NAME not in local, f"front export is not empty of the object: {local}"


def test_s3_origin_leg_sever_delivers_no_partial_file(s3_origin_leg):
    """A short upstream S3 body fails the read rather than becoming a successful
    short one — the same refusal sd_http makes, reached through entirely
    different code (an S3 GET whose declared length is not met)."""
    s3_origin_leg.fp.set_truncate(MID_CUT, "down")
    rc, exact, got = s3_origin_leg.download()
    assert rc != 0 and not exact, f"rc={rc} bytes={got}"
    assert got == 0, f"delivered {got} bytes of a severed fetch (rc={rc})"


def test_a_corrupted_s3_origin_leg_is_delivered_to_the_client_silently(s3_origin_leg):
    """The exposure, measured on the S3 driver too: flipped bytes between the
    front and its s3:// origin reach the client as a full-length file under a
    clean rc 0. Nothing in the S3 fetch path notices — the object's stored ETag
    is not consulted on read, and the client's own transport was pristine."""
    s3_origin_leg.fp.set_corrupt(CORRUPT_PCT, "down")
    rc, exact, got = s3_origin_leg.download()
    assert rc == 0, f"expected the corrupted fetch to be relayed, got rc={rc}"
    assert got == SIZE, f"expected a full-length file, got {got} bytes"
    assert not exact, "vacuous: nothing was corrupted"


def test_pgrw_does_not_protect_the_s3_origin_leg(s3_origin_leg):
    """`--pgrw` is the strongest per-block integrity the protocol has, and it is
    structurally unable to cover this leg: the per-page CRC32c is computed by the
    FRONT over bytes it has ALREADY read from the origin, so an upstream flip is
    faithfully CRC'd and delivered. The client verifies a true statement about
    corrupt data.

    This is the assertion the http section cannot make — there `--pgrw` hits the
    sd_http stall (see KNOWN ISSUE) and never returns a usable verdict. Here it
    returns in ~0.1 s, which is also what proves the stall is an sd_http defect
    and not how pgread behaves over a remote backend."""
    s3_origin_leg.fp.set_corrupt(CORRUPT_PCT, "down")
    rc, exact, got = s3_origin_leg.download(extra=("--pgrw",))
    assert rc == 0 and got == SIZE, f"rc={rc} bytes={got}"
    assert not exact, "vacuous: nothing was corrupted"


def test_verify_on_the_s3_origin_leg_refuses_or_states_it_could_not_check(s3_origin_leg):
    """THE FAIL-OPEN, and the reason this is a union rather than `rc != 0`.

    `--verify` asks the server for the object's checksum after the transfer, and
    the server computes that by RE-READING the object — over the same damaged
    leg. Measured over 20 runs: 19 mismatched and were refused, and once the
    re-read itself died and the client reported `checksum computation failed`,
    then *kept the corrupted file and exited 0*. That is deliberate policy
    (`download_reconcile_cksum`, copy_local.c: UNVERIFIED warns and clears the
    status, because a query hiccup is not a transfer failure) — but the two
    events are correlated, not independent: the damage `--verify` exists to catch
    is the same damage that disables it. sd_s3 issues many ranged GETs per read,
    so there are ~30x more response headers to hit than on the single-GET http
    path, which is why the http leg refused 20 times out of 20 and this one 19.

    Asserting `rc != 0` here would be a 5%-flaky test. Asserting the union is
    still strong, because the escape hatch is narrow: a clean rc 0 is allowed
    ONLY if the client said out loud that it could not check. A silent pass on
    corrupt data fails this test, which is the regression worth catching."""
    s3_origin_leg.fp.set_corrupt(CORRUPT_PCT, "down")
    rc, exact, got, err = s3_origin_leg.run(extra=("--verify",))
    assert not exact, "vacuous: nothing was corrupted"
    if rc != 0:
        assert got == 0, f"refused but left {got} bytes behind (rc={rc})"
        return
    assert "NOT verified" in err, (
        "corrupt data passed --verify with rc 0 and no warning: " + repr(err))
