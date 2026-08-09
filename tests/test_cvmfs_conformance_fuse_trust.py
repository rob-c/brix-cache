from split_continuation import reexport as _reexport
_reexport(globals(), "_test_cvmfs_conformance_fuse_trust_helpers")

@pytest.mark.parametrize("cid", _ids(HEALTHY))
def test_clean_repo_check_healthy(matrix, cid):
    rc, stderr, stdout = matrix[cid]
    assert rc == 0, f"{cid}: clean repo must --check clean (stderr={stderr!r})"
    assert "HEALTHY" in stdout
    assert "trust chain .... OK" in stdout


@pytest.mark.parametrize("cid", _ids(REFUSED))
def test_tamper_refused(matrix, cid):
    """SAFETY: a tampered trust artifact must be refused — nonzero exit, and a
    clean diagnostic (never a crash, never HEALTHY)."""
    rc, stderr, stdout = matrix[cid]
    assert rc != 0, f"{cid}: tamper was ACCEPTED (rc=0) — {stdout[:120]!r}"
    assert "HEALTHY" not in stdout
    diag = stderr + stdout
    assert ("trust/catalog error" in diag) or ("cannot read master key" in diag), \
        f"{cid}: no stable diagnostic (stderr={stderr!r})"


# distinct/stable exit-diagnostic pins (the trust chain's error taxonomy).
_STABLE_CODES = {
    "man_sig_mid": -9,          # manifest signature verify
    "man_hashline_mid": -9,     # signed text no longer matches signature
    "man_field_C": -7,          # root-catalog hash unparseable → manifest reject
    "wl_sig_mid": -5,           # whitelist master-signature verify
    "wl_hashline_mid": -5,
    "wl_expiry": -4,            # whitelist parse (bad expiry field)
    "wl_fp": -5,               # whitelist BODY edit caught by body-binding (master sig)
    "wl_nline": -5,            # whitelist N-line edit → body no longer matches signed hash
    "wrong_pubkey": -5,
    "resign_foreign_master": -5,
    "pubkey_empty": -5,
    "pubkey_garbage": -5,
    "pubkey_ec_not_rsa": -5,
    "replace_cert_not_in_wl": -9,
    "substitute_cert": -5,      # attacker fp appended to whitelist body, unsigned
    "man_field_S": -9,          # manifest BODY edit caught by body-binding (cert sig)
    "expired_whitelist": -6,    # wall-clock expiry now enforced
    "replay_downgrade": -11,    # manifest 'S' ≠ root-catalog revision
}


@pytest.mark.parametrize("cid,code", list(_STABLE_CODES.items()))
def test_refusal_diagnostic_is_stable(matrix, cid, code):
    rc, stderr, stdout = matrix[cid]
    assert rc != 0
    assert f"trust/catalog error {code}" in (stderr + stdout), \
        f"{cid}: expected code {code}; got {stderr!r}"


def test_missing_pubkey_distinct_message(matrix):
    rc, stderr, _ = matrix["pubkey_missing"]
    assert rc != 0
    assert "cannot read master key" in stderr


# ---------------------------------------------------------------------------
# CLOSED trust-chain gaps (were DIVERGENCE strict-xfail; brix now matches official
# CVMFS). Each is covered by the generic REFUSED matrix + a stable-code pin above:
#   man_field_B/S/N/T/D  — manifest body bound to signature (verify.c) → -9
#   wl_nline             — whitelist body bound to master signature      → -5
#   substitute_cert      — keyless fp-append to whitelist body refused   → -5
#   expired_whitelist    — wall-clock expiry enforced (client.c)         → -6
#   replay_downgrade     — manifest 'S' cross-checked vs catalog revision → -11
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# real FUSE mount confirmation — the serve path, and the no-orphan guarantee.
# ---------------------------------------------------------------------------
_FUSE_READY = (os.path.exists("/dev/fuse")
               and shutil.which("fusermount3") is not None)
requires_fuse = pytest.mark.skipif(not _FUSE_READY, reason="fuse prerequisites missing")



@requires_fuse
def test_mount_clean_serves_exact_bytes(bin_mount):
    forge, web, pub = _forge()
    with _Mount(bin_mount, web, pub) as m:
        assert m.mounted, "clean forged repo must mount"
        assert sorted(os.listdir(m.mnt)) == ["hello", "sub"]
        assert open(os.path.join(m.mnt, "hello"), "rb").read() == b"hello trust\n"
        assert open(os.path.join(m.mnt, "sub", "leaf"), "rb").read() == b"leaf bytes\n"


@requires_fuse
def test_mount_content_tamper_read_errors_not_wrong_bytes(bin_mount):
    """A flipped content object: the trust chain is intact so the mount comes up,
    but the fetch-layer hash-verify fails on read → EIO, NEVER corrupt bytes."""
    forge, web, pub = _forge()
    key = next(k for k in forge.cas if len(k) == 40)
    forge.flip_byte(key, 6)
    with _Mount(bin_mount, web, pub) as m:
        assert m.mounted
        with pytest.raises(OSError) as ei:
            data = open(os.path.join(m.mnt, "hello"), "rb").read()
            assert data != b"hello trust\n", "corrupt object served as clean bytes!"
        assert ei.value.errno == 5  # EIO


@requires_fuse
def test_mount_missing_content_object_read_errors(bin_mount):
    forge, web, pub = _forge()
    key = next(k for k in forge.cas if len(k) == 40)
    forge.delete_cas(key)
    with _Mount(bin_mount, web, pub) as m:
        assert m.mounted
        with pytest.raises(OSError):
            open(os.path.join(m.mnt, "hello"), "rb").read()


# each broken-trust class: the mount must be refused and leave NO orphan.

@requires_fuse
@pytest.mark.parametrize("broken", [_broken_wrong_pubkey, _broken_manifest_sig,
                                    _broken_whitelist_sig, _broken_catalog_obj],
                         ids=["wrong_pubkey", "manifest_sig", "whitelist_sig", "catalog_obj"])
def test_broken_repo_mount_refused_no_orphan(bin_mount, broken):
    web, pub = broken()
    with _Mount(bin_mount, web, pub) as m:
        if m.proc is not None:
            m.proc.wait(30)
        assert not m.mounted, "broken repo must NOT mount"
        assert m.mnt not in open("/proc/mounts").read(), "orphaned mount left behind!"
        assert os.listdir(m.mnt) == [], "mountpoint not empty after refusal"
        assert m.proc.returncode not in (None, 0), "refused mount must exit nonzero"


@requires_fuse
def test_valid_mount_after_refusal_not_poisoned(bin_mount):
    """After a refused mount, a fresh valid mount of the SAME fqrn with a clean
    cache must succeed — no poisoned client/cache state persists."""
    bad_web, bad_pub = _broken_manifest_sig()
    with _Mount(bin_mount, bad_web, bad_pub) as bad:
        if bad.proc is not None:
            bad.proc.wait(30)
        assert not bad.mounted

    forge, web, pub = _forge()
    with _Mount(bin_mount, web, pub, cache=os.path.join(_workdir("ft_clean."), "c")) as good:
        assert good.mounted, "clean re-mount after a refusal must succeed"
        assert open(os.path.join(good.mnt, "hello"), "rb").read() == b"hello trust\n"
