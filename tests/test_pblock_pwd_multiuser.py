"""pblock multi-user/VO enforcement end-to-end over root:// + password auth.

Confirms the pblock catalog-internal ownership extensions (synthetic uid/gid
registry, POSIX mode-bit enforcement, owner-only chmod/xattr, sticky-root
delete gate) through the real protocol stack: the native client authenticates
via ``pwd`` (XrdSecpwd) as several distinct accounts against ONE pblock export,
and every assertion is a behavioural check of what each account may do.

VO (group) membership comes from the optional 4th field of ``brix_pwd_file``
(``user:salthex:hashhex[:vo1,vo2]``): alice + carol share VO ``atlas``, bob is
in VO ``cms``, and dave is a legacy 3-field entry (no VO → user-private group).

Each behaviour keeps the mandated trio — success, error, and security-negative.
The fixture spawns a throwaway nginx on a private high port (no shared fleet)
and skips cleanly if the native client is not built.
"""
import hashlib
import os
import subprocess

import pytest

from server_launcher import LifecycleHarness
from server_registry import NginxInstanceSpec
from settings import HOST

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
NATIVE_XRDCP = os.path.join(REPO, "client", "bin", "xrdcp")
NATIVE_XRDFS = os.path.join(REPO, "client", "bin", "xrdfs")

# account → (password, VO CSV or None for a legacy 3-field pwd-file entry)
ACCOUNTS = {
    "alice": ("alice-pw-1", "atlas"),
    "carol": ("carol-pw-2", "atlas"),
    "bob":   ("bob-pw-3",   "cms"),
    "dave":  ("dave-pw-4",  None),
}

pytestmark = [pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-pblock-pwd")]


def _run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=120, **kw)


def _pwd_hash(password, salt):
    """The exact KDF stock XrdSecpwd uses: PBKDF2-HMAC-SHA1, 10000 iters, 24 B."""
    return hashlib.pbkdf2_hmac("sha1", password.encode(), salt, 10000, 24)


def _env(user):
    pw, _vos = ACCOUNTS[user]
    e = dict(os.environ)
    e.pop("XrdSecCREDS", None)
    e["XRDC_PWD"] = pw
    e["XRDC_PWD_USER"] = user
    return e


@pytest.fixture(scope="module")
def pb_server(tmp_path_factory):
    if not os.path.exists(NATIVE_XRDCP) or not os.path.exists(NATIVE_XRDFS):
        pytest.skip("native client/bin/{xrdcp,xrdfs} must be built (make -C client)")

    base = tmp_path_factory.mktemp("pbpwd")
    export = base / "export"
    export.mkdir()

    salt = bytes(range(8))
    lines = ["# multi-account pwd db (4th field = VO list)"]
    for user, (pw, vos) in ACCOUNTS.items():
        entry = f"{user}:{salt.hex()}:{_pwd_hash(pw, salt).hex()}"
        if vos is not None:
            entry += f":{vos}"
        lines.append(entry)
    pwdfile = base / "pwd.db"
    pwdfile.write_text("\n".join(lines) + "\n")

    harness = LifecycleHarness()
    try:
        ep = harness.start(NginxInstanceSpec(
            name="lc-pblock-pwd",
            template="nginx_pblock_pwd.conf",
            protocol="root", readiness="tcp",
            data_root=str(export),
            template_values={"PWD_FILE": str(pwdfile)}))
        yield {"url": f"root://{HOST}:{ep.port}", "export": export}
    finally:
        harness.close()


def _upload(server, user, remote, content, tmp_path):
    src = tmp_path / f"up-{user}-{os.path.basename(remote)}"
    src.write_text(content)
    return _run([NATIVE_XRDCP, "--auth", "pwd", "-f", str(src),
                 f"{server['url']}/{remote}"], env=_env(user))


def _download(server, user, remote, tmp_path):
    out = tmp_path / f"dl-{user}-{os.path.basename(remote)}"
    r = _run([NATIVE_XRDCP, "--auth", "pwd", "-f",
              f"{server['url']}/{remote}", str(out)], env=_env(user))
    return r, out


def _fs(server, user, *args):
    return _run([NATIVE_XRDFS, "--auth", "pwd", server["url"], *args],
                env=_env(user))


# ---- success: every account works and owns what it uploads ------------------ #

def test_multiuser_upload_download_roundtrip(pb_server, tmp_path):
    """Each account can create its own file on the pblock export and read it
    back byte-exact — the identity path (pwd principal → catalog uid) must not
    get in the way of an owner's own I/O."""
    for user in ACCOUNTS:
        content = f"data-of-{user}\n"
        r = _upload(pb_server, user, f"/{user}.dat", content, tmp_path)
        assert r.returncode == 0, f"{user} upload failed: {r.stderr}"
        r, out = _download(pb_server, user, f"/{user}.dat", tmp_path)
        assert r.returncode == 0, f"{user} readback failed: {r.stderr}"
        assert out.read_text() == content


def test_owner_can_chmod_and_delete_own_file(pb_server, tmp_path):
    """Owner-only namespace rights work end-to-end: alice chmods and deletes a
    file she created."""
    assert _upload(pb_server, "alice", "/mine.dat", "x\n", tmp_path).returncode == 0
    r = _fs(pb_server, "alice", "chmod", "/mine.dat", "600")
    assert r.returncode == 0, f"owner chmod failed: {r.stderr}"
    r = _fs(pb_server, "alice", "rm", "/mine.dat")
    assert r.returncode == 0, f"owner rm failed: {r.stderr}"
    r, _ = _download(pb_server, "alice", "/mine.dat", tmp_path)
    assert r.returncode != 0, "deleted file must be gone"


# ---- error: cross-user writes/deletes must fail ------------------------------ #

def test_cross_user_overwrite_and_delete_denied(pb_server, tmp_path):
    """bob (VO cms) must not overwrite or delete alice's file.  Default client
    create mode is 0644, so bob MAY read it (other-read) — exactly POSIX — but
    every mutating op is refused (no other-write; sticky root blocks unlink)."""
    assert _upload(pb_server, "alice", "/a.dat", "alice-owns-this\n",
                   tmp_path).returncode == 0

    r = _upload(pb_server, "bob", "/a.dat", "bob-was-here\n", tmp_path)
    assert r.returncode != 0, "bob overwrote alice's file"

    r = _fs(pb_server, "bob", "rm", "/a.dat")
    assert r.returncode != 0, "bob deleted alice's file (sticky root must gate)"

    r, out = _download(pb_server, "bob", "/a.dat", tmp_path)
    assert r.returncode == 0, f"0644 other-read should succeed: {r.stderr}"
    assert out.read_text() == "alice-owns-this\n"


def test_chmod_600_blocks_other_users(pb_server, tmp_path):
    """Once alice tightens her file to 0600, bob loses even read access while
    alice keeps hers — mode-bit changes must take effect on the live export."""
    assert _upload(pb_server, "alice", "/secret.dat", "top-secret\n",
                   tmp_path).returncode == 0
    assert _fs(pb_server, "alice", "chmod", "/secret.dat", "600").returncode == 0

    r, _ = _download(pb_server, "bob", "/secret.dat", tmp_path)
    assert r.returncode != 0, "bob read alice's 0600 file"

    r, out = _download(pb_server, "alice", "/secret.dat", tmp_path)
    assert r.returncode == 0, f"owner locked out of own 0600 file: {r.stderr}"
    assert out.read_text() == "top-secret\n"


# ---- VO (group) semantics ----------------------------------------------------- #

def test_same_vo_group_access(pb_server, tmp_path):
    """alice and carol share VO atlas: a 0660 group file alice creates is
    readable AND writable by carol, while bob (VO cms) gets nothing.  This is
    the group=VO mapping working over the full pwd→identity→catalog chain."""
    assert _upload(pb_server, "alice", "/shared.dat", "team-atlas-v1\n",
                   tmp_path).returncode == 0
    assert _fs(pb_server, "alice", "chmod", "/shared.dat", "660").returncode == 0

    r, out = _download(pb_server, "carol", "/shared.dat", tmp_path)
    assert r.returncode == 0, f"same-VO read failed: {r.stderr}"
    assert out.read_text() == "team-atlas-v1\n"

    r = _upload(pb_server, "carol", "/shared.dat", "team-atlas-v2\n", tmp_path)
    assert r.returncode == 0, f"same-VO group-write failed: {r.stderr}"
    r, out = _download(pb_server, "alice", "/shared.dat", tmp_path)
    assert r.returncode == 0 and out.read_text() == "team-atlas-v2\n", \
        "alice must see carol's group-write"

    r, _ = _download(pb_server, "bob", "/shared.dat", tmp_path)
    assert r.returncode != 0, "bob (VO cms) read an atlas 0660 file"
    r = _upload(pb_server, "bob", "/shared.dat", "cms-intrusion\n", tmp_path)
    assert r.returncode != 0, "bob (VO cms) wrote an atlas 0660 file"


def test_group_readonly_denies_group_write(pb_server, tmp_path):
    """0640 splits the group's R and W rights: carol (same VO) may read but her
    write must be refused — group membership alone never grants W, only the
    mode bits do.  bob (other VO) gets neither."""
    assert _upload(pb_server, "alice", "/ro.dat", "read-only-for-atlas\n",
                   tmp_path).returncode == 0
    assert _fs(pb_server, "alice", "chmod", "/ro.dat", "640").returncode == 0

    r, out = _download(pb_server, "carol", "/ro.dat", tmp_path)
    assert r.returncode == 0 and out.read_text() == "read-only-for-atlas\n", \
        f"same-VO group-read failed: {r.stderr}"
    r = _upload(pb_server, "carol", "/ro.dat", "carol-write\n", tmp_path)
    assert r.returncode != 0, "0640 must deny group-write even to a same-VO member"

    r, _ = _download(pb_server, "bob", "/ro.dat", tmp_path)
    assert r.returncode != 0, "bob (VO cms) read an atlas 0640 file"
    r = _upload(pb_server, "bob", "/ro.dat", "bob-write\n", tmp_path)
    assert r.returncode != 0, "bob (VO cms) wrote an atlas 0640 file"

    r, out = _download(pb_server, "alice", "/ro.dat", tmp_path)
    assert r.returncode == 0 and out.read_text() == "read-only-for-atlas\n", \
        "content must be unchanged after the denied writes"


def test_group_dir_gates_creates_by_vo(pb_server, tmp_path):
    """A 0770 directory owned by alice (group atlas) admits creates from carol
    (same VO) but refuses bob (VO cms) — the parent-W check runs against the
    directory's group, not just its owner."""
    assert _fs(pb_server, "alice", "mkdir", "/atlasdir").returncode == 0
    assert _fs(pb_server, "alice", "chmod", "/atlasdir", "770").returncode == 0

    r = _upload(pb_server, "carol", "/atlasdir/c.dat", "carol-in-atlas\n", tmp_path)
    assert r.returncode == 0, f"same-VO create in 0770 dir failed: {r.stderr}"

    r = _upload(pb_server, "bob", "/atlasdir/b.dat", "bob-intrusion\n", tmp_path)
    assert r.returncode != 0, "bob (VO cms) created a file in an atlas 0770 dir"

    r, _ = _download(pb_server, "bob", "/atlasdir/c.dat", tmp_path)
    assert r.returncode != 0, "bob (VO cms) read inside an atlas 0770 dir"


def test_legacy_entry_gets_private_group(pb_server, tmp_path):
    """dave's pwd-file line has no VO field (legacy 3-field form): he must still
    authenticate, and his 0660 file must NOT open up to any VO member — the
    private group (gid == uid) contains only dave."""
    assert _upload(pb_server, "dave", "/dave.dat", "daves-data\n",
                   tmp_path).returncode == 0
    assert _fs(pb_server, "dave", "chmod", "/dave.dat", "660").returncode == 0

    for other in ("alice", "bob"):
        r, _ = _download(pb_server, other, "/dave.dat", tmp_path)
        assert r.returncode != 0, f"{other} read dave's private-group 0660 file"

    r, out = _download(pb_server, "dave", "/dave.dat", tmp_path)
    assert r.returncode == 0 and out.read_text() == "daves-data\n"


# ---- security-negative: privilege operations by non-owners -------------------- #

def test_non_owner_chmod_denied(pb_server, tmp_path):
    """bob must not be able to open up alice's file by chmodding it — the
    owner-only setattr gate is the last line of defence."""
    assert _upload(pb_server, "alice", "/guard.dat", "guarded\n",
                   tmp_path).returncode == 0
    assert _fs(pb_server, "alice", "chmod", "/guard.dat", "600").returncode == 0

    r = _fs(pb_server, "bob", "chmod", "/guard.dat", "777")
    assert r.returncode != 0, "non-owner chmod must be refused"

    r, _ = _download(pb_server, "bob", "/guard.dat", tmp_path)
    assert r.returncode != 0, "file must still be 0600 after bob's chmod attempt"


def test_xattr_write_owner_only(pb_server, tmp_path):
    """xattrs follow the same W/R gates: the owner sets one, a same-VO reader
    may read it (0644 → other-read), but a non-owner set/remove is refused."""
    assert _upload(pb_server, "alice", "/tagged.dat", "tagged\n",
                   tmp_path).returncode == 0

    r = _fs(pb_server, "alice", "xattr", "set", "/tagged.dat", "user.color", "blue")
    assert r.returncode == 0, f"owner setxattr failed: {r.stderr}"

    r = _fs(pb_server, "carol", "xattr", "get", "/tagged.dat", "user.color")
    assert r.returncode == 0 and "blue" in r.stdout, \
        f"readable file's xattr must be gettable: {r.stderr}"

    r = _fs(pb_server, "bob", "xattr", "set", "/tagged.dat", "user.color", "red")
    assert r.returncode != 0, "non-owner setxattr must be refused"
    r = _fs(pb_server, "bob", "xattr", "rm", "/tagged.dat", "user.color")
    assert r.returncode != 0, "non-owner removexattr must be refused"

    r = _fs(pb_server, "alice", "xattr", "get", "/tagged.dat", "user.color")
    assert r.returncode == 0 and "blue" in r.stdout, "xattr must be unchanged"
