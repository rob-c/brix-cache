"""Static guard: phase-115 W5.4 — same-origin server copy, and why SSH is not.

W5.4 asked for two things.  One shipped and one is deferred, and as in W5.2 and
W5.3 the asymmetry is a design decision that has to be pinned in the tree rather
than remembered:

  * **Server copy** shipped.  Before it the driver's `server_copy` slot was
    NULL, so `brix_vfs_copy_driver` turned every WebDAV COPY on a gsiftp-backed
    export into ENOTSUP — the operation was not slow, it was ABSENT.  It is a
    gateway relay, not origin-side zero-copy (the `sd_xroot_copy_body`
    precedent): the win is that the bytes never cross the client's link.
  * **GridFTP-over-SSH** is deferred, and could not be otherwise here.  It needs
    a per-session child process, and `src/fs/xfer/xfer.h` records why no worker
    may fork: nginx's master SIGCHLD handler walks every SHM zone as an
    `ngx_slab_pool_t` and several module zones overwrite that header, so reaping
    ANY worker child SIGSEGVs the master.  The sanctioned seam — a double-forked
    reparented agent shuttling fixed-size frames, with no fd passing — cannot
    carry a session-lifetime bidirectional fd for a blocking threadpool driver.
    A `socat`/`ssh -L` sidecar cannot substitute: the data channel dials the
    control channel's PINNED peer (W5.3), which would be 127.0.0.1 while the
    origin advertises the storage host.  Same "deferred by design, boundary
    pinned" shape as W5.2's ESTO, W5.3's SPOR, and phase 114's reaper.

The live proof is tests/test_phase115_gsiftp_server_copy.py; this file is what
fails when a property is refactored away rather than exercised.
"""

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
GSIFTP = REPO_ROOT / "src/fs/backend/gsiftp"

COPY_C = GSIFTP / "sd_gsiftp_copy.c"
DRIVER_C = GSIFTP / "sd_gsiftp.c"
INTERNAL_H = GSIFTP / "sd_gsiftp_internal.h"
STAGED_C = GSIFTP / "sd_gsiftp_staged.c"
XFER_H = REPO_ROOT / "src/fs/xfer/xfer.h"
CONFIG = REPO_ROOT / "config"


def _body(path: Path, function: str) -> str:
    """The source of one top-level function, brace-matched."""
    text = path.read_text()
    match = re.search(rf"^{re.escape(function)}\(", text, re.M)
    assert match, f"{function} not found in {path.name} — it moved or was renamed"
    start = text.index("{", match.end())
    depth = 0
    for i in range(start, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return text[start:i + 1]
    raise AssertionError(f"unbalanced braces in {function}")


# ---- the slot is filled, and the tree actually builds it ---------------------

def test_the_driver_advertises_and_fills_the_server_copy_slot():
    """Both halves, because either alone is a silent no-op.

    A filled function pointer without the capability bit is never reached —
    callers ask `caps` first.  A capability bit without the pointer is worse: it
    promises an operation and then dereferences NULL.
    """
    driver = DRIVER_C.read_text()
    assert "BRIX_SD_CAP_SERVER_COPY" in driver, \
        "the gsiftp driver no longer advertises server copy"
    assert ".server_copy = sd_gsiftp_server_copy," in driver, \
        "the server_copy slot is unwired; WebDAV COPY falls back to ENOTSUP"
    assert ".server_copy_cred = sd_gsiftp_server_copy_cred," in driver, \
        "the credentialled slot is unwired, so a per-user COPY would run as " \
        "the export's own proxy — a confused deputy"


def test_the_copy_module_is_registered_in_the_build():
    """A source file nobody compiles is a test that cannot fail.

    W5.3 shipped gftp_spas.c with its callers landing before the source list
    did, and the tree stopped linking; the same order is enforced here.
    """
    assert "gsiftp/sd_gsiftp_copy.c" in CONFIG.read_text(), \
        "sd_gsiftp_copy.c is not in the module source list"


def test_the_credentialled_entry_forwards_the_caller_credential():
    """`_cred` must reach the proxy selector, not drop to the export's proxy.

    Both entry points funnel into one `_impl` taking the credential, so the
    uncredentialled one passes NULL explicitly rather than by omission.
    """
    body = _body(COPY_C, "sd_gsiftp_server_copy_cred")
    assert "cred" in body and "sd_gsiftp_server_copy_impl" in body, \
        "the credentialled copy no longer forwards its credential"
    impl = _body(COPY_C, "sd_gsiftp_server_copy_impl")
    assert "sd_gsiftp_select_proxy(state, cred" in impl, \
        "the copy no longer selects the proxy from the caller's credential"


# ---- publication is atomic, and a failure leaves no litter -------------------

def test_the_destination_is_published_through_a_temp_name():
    """A COPY that STORs straight onto an existing object destroys it.

    For the length of the transfer the destination would be a partial file, and
    it stays that way if the transfer fails.  The driver already publishes
    staged writes through a random temp name plus RNFR/RNTO; this reuses it.
    """
    body = _body(COPY_C, "sd_gsiftp_copy_publish")
    assert "sd_gsiftp_temp_path" in body, \
        "the copy no longer stores to a temp name before publishing"
    assert "RNFR %s" in body and "RNTO %s" in body, \
        "the copy no longer publishes by rename"
    assert re.search(r"gftp_store\(session,\s*temp_path", body), \
        "the copy stores onto the destination path directly; an overwriting " \
        "COPY would replace a whole object with a partial one"


def test_one_temp_name_generator_serves_both_publishers():
    """Two generators would be two chances to collide on one origin.

    The staged-write path and the copy path publish into the same namespace, so
    the name comes from the same function rather than a second implementation.
    """
    assert re.search(r"^sd_gsiftp_temp_path\(", STAGED_C.read_text(), re.M), \
        "sd_gsiftp_temp_path is no longer defined in the staged-write path"
    assert "int sd_gsiftp_temp_path(" in INTERNAL_H.read_text(), \
        "sd_gsiftp_temp_path is no longer shared with the copy path"


def test_a_failed_publish_removes_its_own_temp():
    """Otherwise every failed COPY leaves litter only we can recognise."""
    body = _body(COPY_C, "sd_gsiftp_copy_publish")
    assert 'DELE %s", temp_path' in body, \
        "a failed publish no longer deletes the temp object it created"


# ---- a short origin answer must never be published --------------------------

def test_the_transfer_is_size_checked_against_a_prior_stat():
    """`gftp_retrieve` is a BOUNDED read, so a short answer is a short file.

    The origin reports no error of its own for stopping early, so the mismatch
    has to be caught here or the truncation gets published over the
    destination's previous contents.
    """
    body = _body(COPY_C, "sd_gsiftp_copy_fetch")
    assert "received != size" in body and "sink.written != size" in body, \
        "the copy no longer rejects a transfer shorter than the source stat"
    assert "EIO" in body, \
        "a truncated transfer no longer reports an error"


def test_the_size_comes_from_a_stat_taken_before_the_transfer():
    """And before the scratch file: a missing source costs one round trip.

    It is also the only place the expected length can come from — passing 0 as
    the limit would read NOTHING, because gftp_retrieve loops `total < limit`.
    """
    impl = _body(COPY_C, "sd_gsiftp_server_copy_impl")
    stat_at = impl.index("sd_gsiftp_stat_impl")
    assert "tmpfile()" in impl, "the copy no longer spills to a scratch file"
    assert stat_at < impl.index("tmpfile()"), \
        "the scratch file is created before the source is known to exist"
    assert stat_at < impl.index("sd_gsiftp_copy_fetch"), \
        "the transfer no longer knows how many bytes it must receive"


def test_a_copy_onto_its_own_path_is_refused():
    """It would work, and it would rewrite a healthy object for no gain.

    Scratch, temp, rename over the original: any failure in the middle damages
    the only copy of a file the caller never asked to modify.
    """
    body = _body(COPY_C, "sd_gsiftp_copy_paths")
    assert "strcmp(remote_src, remote_dst) == 0" in body, \
        "a copy onto its own path is no longer refused"
    assert "EINVAL" in body, \
        "the degenerate copy no longer reports why it was refused"


# ---- SECURITY: the copy dials nothing of its own ----------------------------

def test_the_copy_opens_no_connection_of_its_own():
    """Both legs run on ONE session opened by the driver's own helper.

    That helper is where the origin host, the DNS policy, the GSI requirement
    and the data-channel pin all live.  A `connect()` or a name lookup here
    would be a second, unpolicied path to a network peer inside a worker.
    """
    text = COPY_C.read_text()
    for needle in ("connect(", "getaddrinfo", "gethostbyname", "socket("):
        assert needle not in text, \
            f"sd_gsiftp_copy.c now calls {needle} instead of reusing " \
            "sd_gsiftp_session; the copy must inherit the export's policy"
    assert "sd_gsiftp_session(&session" in text, \
        "the copy no longer opens its session through the driver's helper"


def test_both_legs_share_one_control_session():
    """FTP is sequential on the control channel, so a second session is waste.

    It is also a second authentication and a second chance to land the legs on
    different origin instances behind a name that resolves to several.
    """
    impl = _body(COPY_C, "sd_gsiftp_server_copy_impl")
    assert impl.count("sd_gsiftp_session(") == 1, \
        "the copy now opens more than one control session"
    assert impl.count("gftp_session_close(") == 1, \
        "the copy's session is opened or closed more than once"


# ---- GridFTP-over-SSH is deferred, and the boundary is what says so ----------

def test_the_driver_never_forks_a_transport():
    """Pinned as an absence, because that is the whole claim.

    A fork/exec appearing in this driver means the deferral's premise is gone
    and the register may no longer say "by design" — or, far more likely, that
    a worker is about to SIGSEGV the master on the first reaped child.
    """
    offenders = {}
    for path in sorted(GSIFTP.glob("*.c")):
        hits = [line.strip() for line in path.read_text().splitlines()
                if re.search(r"\b(fork|execv?[ple]*|posix_spawn|system)\s*\(",
                             line)]
        if hits:
            offenders[path.name] = hits
    assert not offenders, \
        f"the gsiftp driver now spawns a child: {offenders} — see " \
        "src/fs/xfer/xfer.h on why no worker may be reaped"


def test_the_sshftp_scheme_is_not_accepted_anywhere():
    """Accepting the scheme without the transport is worse than refusing it.

    An export configured `sshftp://` that silently opened a cleartext TCP
    control channel would be a downgrade the operator asked against.
    """
    offenders = [path.name for path in sorted(GSIFTP.glob("*.[ch]"))
                 if "sshftp" in path.read_text()]
    assert not offenders, \
        f"the sshftp scheme now appears in {offenders} without a transport " \
        "to carry it; W5.4 records it as deferred"


def test_the_reason_for_the_deferral_is_still_true():
    """The deferral cites a documented hazard; a citation can go stale.

    If the SHM/SIGCHLD hazard is ever fixed, this row fails and W5.4's register
    entry has to be re-argued rather than inherited.
    """
    text = XFER_H.read_text()
    assert "SIGCHLD" in text and "SHM" in text, \
        "src/fs/xfer/xfer.h no longer documents the master's SIGCHLD/SHM " \
        "hazard — the SSH deferral's stated reason must be re-checked"
