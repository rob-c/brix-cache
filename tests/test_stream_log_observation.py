"""A readiness row or stale transfer cannot stand in for new session evidence."""

import stream_log_observation as stream
from types import SimpleNamespace

import pytest


READY = "proto=root auth=- user=- vo=- tls=off out=0 in=0"
TRANSFER = "proto=root auth=none user=- vo=- tls=off out=4096 in=0"


def test_a_transfer_is_selected_even_when_a_readiness_row_is_last():
    """The final TCP readiness close must not replace the actual data row."""
    assert stream._transfer_line([TRANSFER, READY]) == TRANSFER


def test_only_readiness_rows_are_not_transfer_evidence():
    """Missing, sentinel and zero byte counts cannot produce a false pass."""
    assert stream._transfer_line([READY, "out=-", "out=garbage"]) == ""


def test_a_previous_transfer_cannot_authorize_a_new_observation(monkeypatch):
    """Security-negative: correct historical bytes cannot hide a missing row."""
    ticks = iter([0, 0, 1])
    monkeypatch.setattr(stream, "time", SimpleNamespace(
        monotonic=lambda: next(ticks), sleep=lambda _: None))
    monkeypatch.setattr(stream, "_log_lines", lambda _: [TRANSFER, READY])
    assert stream._wait_for_transfer_line(None, before=1, timeout=0.5) == ""


def test_the_log_phase_can_publish_the_transfer_after_readiness(monkeypatch):
    """An early readiness row does not end the bounded observation window."""
    ticks = iter([0, 0, 0.1])
    rows = iter([[READY], [READY, TRANSFER]])
    monkeypatch.setattr(stream, "time", SimpleNamespace(
        monotonic=lambda: next(ticks), sleep=lambda _: None))
    monkeypatch.setattr(stream, "_log_lines", lambda _: next(rows))
    assert stream._wait_for_transfer_line(None, before=0, timeout=0.5) == TRANSFER


@pytest.mark.parametrize("snapshots, before, expected", [
    ([[], ["foreign ERR AUTH"]], 0, ["foreign ERR AUTH"]),
    ([[], []], 0, None),
    ([["foreign ERR AUTH"], ["foreign ERR AUTH"]], 1, None),
    ([["other ERR AUTH"], ["other ERR AUTH"]], 0, None),
])
def test_refusal_observation_requires_a_fresh_matching_record(
        monkeypatch, snapshots, before, expected):
    """Delayed flushes may pass; absent, stale and wrong-peer rows cannot."""
    ticks = iter([0, 0, 0.1, 1])
    rows = iter(snapshots)
    monkeypatch.setattr(stream, "time", SimpleNamespace(
        monotonic=lambda: next(ticks), sleep=lambda _: None))
    assert stream.wait_for_log_value(
        lambda: next(rows), lambda lines: [line for line in lines
                                          if line == "foreign ERR AUTH"],
        before=before, timeout=0.5) == expected


def _json_records(tmp_path, text):
    """Exercise the actual file observer, not a duplicate JSON parser."""
    logs = tmp_path / "logs"
    logs.mkdir()
    (logs / "error.log").write_text(text)
    return stream._brix_access_json(SimpleNamespace(prefix=tmp_path))


def test_json_access_records_are_read_through_the_structured_message(tmp_path):
    """Native diagnostic escaping must not silently disable JSON assertions."""
    text = (r'message="brix_access_json: {\x22remote\x22:\x22127.0.0.1\x22}"'
            ' truncated=0, client: fixture')
    assert _json_records(tmp_path, text) == [{"remote": "127.0.0.1"}]  # net-literal-allow: exact logged-address payload being decoded, not a dial target


def test_malformed_or_wrong_type_access_messages_are_not_records(tmp_path):
    """Unrelated errors and arrays cannot stand in for an access event."""
    text = 'brix_access_json: {bad}\nbrix_access_json: [{"remote":"wrong"}]\n'
    assert _json_records(tmp_path, text) == []


def test_braces_inside_a_json_string_do_not_truncate_the_event(tmp_path):
    """A path containing a closing brace cannot suppress the whole proof."""
    text = 'brix_access_json: {"path":"/contains}brace","remote":"fixture"}, suffix'
    assert _json_records(tmp_path, text) == [{"path": "/contains}brace", "remote": "fixture"}]


def test_checksum_observer_waits_for_the_querys_own_close(monkeypatch):
    """Readiness and metadata closes cannot end checksum observation early."""
    ticks = iter([0, 0, 0.1])
    rows = iter([["ck=-"], ["ck=-", "ck=sha256:abc"]])
    monkeypatch.setattr(stream, "time", SimpleNamespace(
        monotonic=lambda: next(ticks), sleep=lambda _: None))
    monkeypatch.setattr(stream, "_uniform_lines", lambda _: next(rows))
    assert stream._latest_uniform_checksum(None, timeout=0.5) == "sha256:abc"


def test_an_older_checksum_cannot_satisfy_a_new_query(monkeypatch):
    """Security-negative: exclude historical digests, even if well-formed."""
    ticks = iter([0, 0, 1])
    monkeypatch.setattr(stream, "time", SimpleNamespace(
        monotonic=lambda: next(ticks), sleep=lambda _: None))
    monkeypatch.setattr(stream, "_uniform_lines", lambda _: ["ck=sha256:old", "ck=-"])
    assert stream._latest_uniform_checksum(None, before=1, timeout=0.5) is None


def test_unrelated_rows_do_not_supply_a_checksum():
    """Absent and sentinel checksum values remain missing evidence."""
    assert stream._checksum_in(["op=read out=1", "ck=-"]) is None


def test_uniform_operation_waits_for_its_own_session_close(monkeypatch):
    ticks = iter([0, 0, 0.1])
    old, fresh = 'op=read st=ok served=0', 'op=read st=ok served=2048'
    rows = iter([[old], [old, fresh]])
    monkeypatch.setattr(stream, 'time', SimpleNamespace(
        monotonic=lambda: next(ticks), sleep=lambda _: None))
    monkeypatch.setattr(stream, '_uniform_lines', lambda _: next(rows))
    assert stream._wait_uniform_op(None, 'read', before=1, timeout=0.5) == fresh


def test_stale_uniform_read_is_not_evidence_of_a_new_transfer(monkeypatch):
    ticks = iter([0, 0, 1])
    monkeypatch.setattr(stream, 'time', SimpleNamespace(
        monotonic=lambda: next(ticks), sleep=lambda _: None))
    monkeypatch.setattr(stream, '_uniform_lines', lambda _: ['op=read st=ok served=2048'])
    assert stream._wait_uniform_op(None, 'read', before=1, timeout=0.5) is None


def test_wrong_operation_or_error_cannot_supply_a_successful_read(monkeypatch):
    ticks = iter([0, 0, 1])
    monkeypatch.setattr(stream, 'time', SimpleNamespace(
        monotonic=lambda: next(ticks), sleep=lambda _: None))
    monkeypatch.setattr(stream, '_uniform_lines', lambda _: [
        'op=stat st=ok served=2048', 'op=read st=forbidden served=0'])
    assert stream._wait_uniform_op(None, 'read', status='ok', timeout=0.5) is None
