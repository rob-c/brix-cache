"""The reaper observation waits for all entries without hiding a stuck carrier."""

from test_cache_reap_metrics import _wait_for_reaped


def _clock(monkeypatch, remove):
    """Advance a deterministic clock and perform scheduled fixture cleanup."""
    ticks = [0.0]
    monkeypatch.setattr("test_cache_reap_metrics.time.monotonic", lambda: ticks[0])

    def sleep(seconds):
        ticks[0] += seconds
        remove(ticks[0])

    monkeypatch.setattr("test_cache_reap_metrics.time.sleep", sleep)
    return ticks


def test_waits_for_later_directory_entries(tmp_path, monkeypatch):
    """Success: an already removed first entry cannot end the observation."""
    first, later = tmp_path / "first", tmp_path / "later"
    later.touch()
    ticks = _clock(monkeypatch, lambda now: later.unlink(missing_ok=True) if now >= 1 else None)
    assert _wait_for_reaped((first, later), lambda path: False, 3)
    assert ticks[0] >= 1


def test_stuck_data_file_reaches_deadline(tmp_path, monkeypatch):
    """Error: a reaper failure stays observable and is bounded by the deadline."""
    path = tmp_path / "stuck"
    path.touch()
    ticks = _clock(monkeypatch, lambda now: None)
    assert not _wait_for_reaped((path,), lambda item: False, 2)
    assert ticks[0] == 2
    assert path.exists()


def test_metadata_only_remnant_cannot_be_reported_as_reaped(tmp_path, monkeypatch):
    """Negative: disappearing data does not conceal a surviving metadata carrier."""
    path = tmp_path / "absent-data"
    _clock(monkeypatch, lambda now: None)
    assert not _wait_for_reaped((path,), lambda item: True, 2)
