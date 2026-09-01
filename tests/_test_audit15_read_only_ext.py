# _test_audit15_read_only_ext.py — continuation split off test_audit15_read_only.py
# for the 600-line ratchet (phase-109 housekeeping; the file crossed the cap in
# the phase-105 read-only wave).  Loaded into the parent's namespace via
# split_continuation.load — same fixtures, same collection module.

# ---------------------------------------------------------------------------
# Expired-lock reaping is a WRITE (phase-105 Appendix H.2): the read verbs    #
# that normally reap a stale lock (GET, lockdiscovery PROPFIND) must leave    #
# even a decodable, long-expired lock xattr byte-identical on a read-only    #
# export.  The writable control proves the fixture record IS reapable, so    #
# survival above is the policy's doing rather than an unparseable payload.   #
# ---------------------------------------------------------------------------

_LOCK_XATTR = "user.nginx_xrootd.lock"      # WEBDAV_LOCK_XATTR_KEY (webdav.h)


def _seed_expired_lock(data):
    """Plant a schema-v2 lock xattr on seed.txt that expired an hour ago."""
    payload = ("v=2|token=opaquelocktoken:00000000-dead-beef-0000-0000phase105"
               f"|owner=phase105|expires={int(time.time()) - 3600}"
               "|scope=exclusive|depth=infinity|null=0").encode()
    os.setxattr(data / "seed.txt", _LOCK_XATTR, payload)
    return payload


def _lock_after_read_sweep(base, data):
    """GET + explicit lockdiscovery PROPFIND (the expired-lock cleanup call
    sites in lock_discovery.c), then the lock xattr's current value, or None
    once a reap removed it."""
    assert requests.get(f"{base}/seed.txt", timeout=5).text == SEED
    r = requests.request(
        "PROPFIND", f"{base}/seed.txt", timeout=5,
        headers={"Depth": "0", "Content-Type": "text/xml"},
        data=b'<?xml version="1.0"?><D:propfind xmlns:D="DAV:">'
             b"<D:prop><D:lockdiscovery/></D:prop></D:propfind>")
    assert r.status_code == 207, r.status_code
    try:
        return os.getxattr(data / "seed.txt", _LOCK_XATTR)
    except OSError:
        return None


def test_read_only_export_keeps_an_expired_lock_xattr(lifecycle, tmp_path):
    """Security-negative: expired-lock cleanup is a mutation, and a read-only
    endpoint performs none — not even against metadata it itself planted."""
    port = _start_http(lifecycle, tmp_path, "lc-audit15-readonly-lock-reap",
                       _RO_KNOBS, seed_files=(("seed.txt", SEED),),
                       port=PORT_LAST + 14)
    data = tmp_path / "data"
    payload = _seed_expired_lock(data)

    after = _lock_after_read_sweep(f"http://{HOST}:{port}", data)
    assert after == payload, \
        "a read verb on a read-only export reaped or rewrote the lock xattr"


def test_writable_export_reaps_the_same_expired_lock(lifecycle, tmp_path):
    """Success control: writes allowed, the identical stale record is reaped by
    the same read sweep."""
    port = _start_http(lifecycle, tmp_path, "lc-audit15-rw-lock-reap",
                       _RW_KNOBS, seed_files=(("seed.txt", SEED),),
                       port=PORT_LAST + 15)
    data = tmp_path / "data"
    _seed_expired_lock(data)

    after = _lock_after_read_sweep(f"http://{HOST}:{port}", data)
    assert after is None, "the writable control did not reap the expired lock"
