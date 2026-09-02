"""kXR_dirlist per-connection chunk reuse (metadata hyperopt round 7).

The dirlist handler keeps ONE cached 64KB chunk accumulator per connection
(ctx->rd.dirlist_chunk) and reuses it whenever the out-ring holds no parked
response, instead of charging a fresh 64KB pool allocation per request against
BRIX_MAX_CONN_POOL_BYTES. These probes pin the behaviors that reuse must not
break, all on a SINGLE wire session so consecutive requests really do hit the
cached buffer:

  * repeat listings (plain and dstat interleaved — the dstat lead-in sentinel
    is re-seeded into the reused buffer) stay byte-stable;
  * an error reply between two listings leaves the cached chunk intact;
  * a dirlist flood on one connection survives far past the old ~1000-request
    pool-cap kill (the cap used to close the connection with kXR_NoMemory once
    per-request charges crossed 64MB — reuse makes the flood O(1) memory).

Harness: official_interop_lib fixture from _test_conf_dirlist_helpers (both
servers provisioned; only OUR server is probed here).
"""

from split_continuation import reexport as _reexport
_reexport(globals(), "_test_conf_dirlist_helpers")

pytestmark = pytest.mark.xdist_group("dirlist_chunk_reuse")


def _drain_names(body):
    return {tok.strip() for tok in
            body.replace(b"\x00", b"\n").decode("utf-8", "replace").split("\n")
            if tok.strip() and not _is_artifact(tok.strip())}


# 1) SUCCESS — repeated listings on one connection are byte-stable, with dstat
#    rounds interleaved so the lead-in sentinel re-seeds the reused chunk.
def test_same_connection_repeat_listing_stable(srv):
    s = _session(OUR_PORT)
    try:
        _dirlist_raw(s, WROOT, options=0)
        first = _drain_dirlist(s)
        assert _drain_names(first) >= WROOT_BASELINE, "baseline listing short"

        for i in range(30):
            if i % 10 == 9:
                _dirlist_raw(s, WROOT, options=kXR_dstat)
                body = _drain_dirlist(s)
                lines = [l for l in body.replace(b"\x00", b"\n")
                         .decode("utf-8", "replace").split("\n") if l]
                assert lines and lines[0] == ".", \
                    f"dstat lead-in sentinel missing on reused chunk (round {i})"
            else:
                _dirlist_raw(s, WROOT, options=0)
                assert _drain_dirlist(s) == first, \
                    f"listing diverged on reuse round {i}"
    finally:
        s.close()


# 2) ERROR — an error reply between two listings must leave the cached chunk
#    (and the connection) intact: the follow-up listing is byte-identical.
def test_error_between_listings_leaves_chunk_intact(srv):
    s = _session(OUR_PORT)
    try:
        _dirlist_raw(s, WROOT, options=0)
        first = _drain_dirlist(s)

        _dirlist_raw(s, "/no_such_dir_" + L.worker_tag(), options=0)
        try:
            _drain_dirlist(s)
            assert False, "missing directory did not error"
        except _DirlistError:
            pass

        _dirlist_raw(s, WROOT, options=0)
        assert _drain_dirlist(s) == first, \
            "listing after an error reply diverged from the pre-error listing"
    finally:
        s.close()


# 3) SECURITY-NEG (resource exhaustion) — 1200 dirlists on ONE connection.
#    Before chunk reuse each request charged XRD_RESPONSE_HDR_LEN + 64KB
#    against the 64MB BRIX_MAX_CONN_POOL_BYTES cap, so request ~1023 killed
#    the connection with kXR_NoMemory; the flood must now be O(1) memory and
#    every round must answer.
def test_dirlist_flood_single_connection_survives_pool_cap(srv):
    s = _session(OUR_PORT)
    try:
        for i in range(1200):
            _dirlist_raw(s, "/empty_dir", options=0)
            try:
                body = _drain_dirlist(s)
            except (EOFError, _DirlistError) as e:
                raise AssertionError(
                    f"dirlist flood died at round {i}: {e}") from e
            assert _drain_names(body) == set(), \
                f"empty dir listing not empty on flood round {i}"
    finally:
        s.close()
