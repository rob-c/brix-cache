from split_continuation import reexport as _reexport
_reexport(globals(), "_test_phase24_mirror_helpers")

def test_stream_data_write_disconnect_midwrite_no_replay(lifecycle, tmp_path):
    """A client that writes then RST-drops WITHOUT kXR_close: the accumulator's
    live heap buffers are freed by the teardown cleanup path (never leaked), and
    because no close was ever observed no replay is launched — the shadow stays
    empty. The worker keeps serving afterwards."""
    primary, metrics, sdata = _start_wmirror_pair(
        lifecycle, tmp_path, "lc-mir-stream-wrdrop", "on")
    assert _xrd_open_write_drop(
        HOST, primary, "/wmir-drop.bin", b"Q" * 4096, rst=True,
        do_close=False) == 0, "primary open/write failed before the drop"
    time.sleep(1.5)   # a (wrongly) launched replay would have fired by now
    assert not (sdata / "wmir-drop.bin").exists(), \
        "a write with no close must never reach the shadow"
    assert (_scrape_metric(metrics, "brix_mirror_requests_total", "stream") or 0) == 0, \
        "an unclosed (abandoned) write launches no replay"
    _primary_still_serves(HOST, primary, sdata, "wmir-drop-live")


def test_stream_data_write_close_then_immediate_disconnect_replays(lifecycle, tmp_path):
    """A client that sends kXR_close (launching the detached replay, which STEALS
    the accumulator buffer) then immediately RST-drops: the replay owns the stolen
    heap buffer on its own lifetime and completes to the shadow byte-exact even
    though the client connection is already gone — the classic UAF path."""
    primary, metrics, sdata = _start_wmirror_pair(
        lifecycle, tmp_path, "lc-mir-stream-wrcdrop", "on")
    body = bytes((i * 53 + 7) & 0xFF for i in range(6000))
    assert _xrd_open_write_drop(
        HOST, primary, "/wmir-cdrop.bin", body, rst=True,
        do_close=True) == 0, "primary open/write/close failed"
    got = _wait_metric(metrics, "brix_mirror_requests_total", "stream", 1)
    assert got is not None and got >= 1, \
        "detached replay did not fire after the client vanished"
    shadow_file = sdata / "wmir-cdrop.bin"
    assert _wait_file(shadow_file, len(body)), \
        "replay never landed on the shadow after an immediate client disconnect"
    assert shadow_file.read_bytes() == body, "replayed file not byte-exact"
    _primary_still_serves(HOST, primary, sdata, "wmir-cdrop-live")


def test_stream_data_write_disconnect_churn_survives(lifecycle, tmp_path):
    """Stress the alloc/free/cleanup churn: many open->write->RST-drop cycles in
    a row with no close. Every cycle allocates then frees a per-file accumulator
    on the teardown path; the sanitizer catches any double-free / UAF / leak in
    the churn, and the final liveness write proves the worker never fell over."""
    primary, metrics, sdata = _start_wmirror_pair(
        lifecycle, tmp_path, "lc-mir-stream-wrchurn", "on")
    for i in range(12):
        # Vary size (some cross the internal grow boundary) and alternate RST/FIN
        # so both abrupt-reset and graceful-close teardown are exercised.
        _xrd_open_write_drop(HOST, primary, f"/wmir-churn-{i}.bin",
                             b"Z" * (1024 * (i + 1)), rst=(i % 2 == 0),
                             do_close=False)
    time.sleep(1.0)
    assert (_scrape_metric(metrics, "brix_mirror_requests_total", "stream") or 0) == 0, \
        "no churn cycle sent a close, so none may launch a replay"
    _primary_still_serves(HOST, primary, sdata, "wmir-churn-live")
