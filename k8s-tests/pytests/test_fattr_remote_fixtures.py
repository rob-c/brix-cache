"""Fattr fixture data must reach the remote service, including failed writes."""

import pytest


def test_fattr_fixture_writes_remote_bytes(svc):
    from _test_fattr_query_helpers import make_file

    assert make_file('fattr-fixture.txt', b'\x00remote\xff') == '/fattr-fixture.txt'
    assert svc.read('fattr-fixture.txt') == b'\x00remote\xff'


def test_fattr_fixture_removal_is_remote_and_missing_is_harmless(svc):
    from _test_fattr_query_helpers import make_file, rm_file

    make_file('fattr-fixture.txt')
    rm_file('fattr-fixture.txt')
    rm_file('fattr-fixture.txt')
    assert not svc.exists('fattr-fixture.txt')


def test_fattr_fixture_cannot_fall_back_to_local_write(svc, monkeypatch):
    import klib
    from _test_fattr_query_helpers import make_file

    def denied(*args, **kwargs):
        return klib._Result(1, '', 'permission denied')

    monkeypatch.setattr(klib, '_exec', denied)
    with pytest.raises(OSError, match='mkdir'):
        make_file('fattr-fixture.txt')
