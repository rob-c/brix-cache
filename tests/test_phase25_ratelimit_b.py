from split_continuation import reexport as _reexport
_reexport(globals(), "_test_phase25_ratelimit_helpers")

def test_keycache_volume_not_collapsed(lifecycle, tmp_path):
    # VOLUME rules are path-dependent and must NOT be cached: a per-prefix bucket
    # must still throttle its own prefix while leaving non-matching paths free.
    data = tmp_path / "data"; data.mkdir()
    (data / "hot").mkdir(); (data / "cold").mkdir()
    (data / "hot" / "a.txt").write_text("hot\n")
    (data / "cold" / "b.txt").write_text("cold\n")
    port = _start_stream(
        lifecycle, data, "lc-rl-volume",
        "        brix_rate_limit_rule zone=rlv key=volume:/hot rate=1r/s burst=1;\n",
        "    brix_rate_limit_zone zone=rlv:1m;\n")
    s = _xrd_login(HOST, port)
    st1, _ = _xrd_open(s, "/hot/a.txt")        # matches /hot, burst spent
    assert st1 == KXR_OK, ("first /hot open within burst", st1)
    st2, _ = _xrd_open(s, "/hot/a.txt")        # /hot bucket overflow → wait
    assert st2 == KXR_WAIT, ("second /hot open must throttle", st2)
    st3, _ = _xrd_open(s, "/cold/b.txt")       # no /hot match → never throttled
    assert st3 != KXR_WAIT, ("non-matching prefix must not be collapsed", st3)
    s.close()
