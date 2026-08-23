def _contention_put(port, tokens, bodies, errors, index):
    subject = "alice" if index % 2 == 0 else "bob"
    try:
        http("PUT", "/pub/contend.txt", port, tokens[subject], bodies[subject])
    except Exception as error:  # noqa: BLE001
        errors.append(repr(error))


def _run_threads(threads):
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()


def _read_bytes(path):
    with open(path, "rb") as stream:
        return stream.read()


def _check_contended_file(data, bodies):
    path = os.path.join(data, "pub", "contend.txt")
    if not os.path.exists(path):
        ok(False, "contended file missing after the storm")
        return
    owner = os.stat(path).st_uid
    content = _read_bytes(path)
    ok(
        owner in (UID_ALICE, UID_BOB),
        f"contended file owned by a real writer (uid={owner})",
    )
    ok(content in bodies.values(), "contended file contains one whole writer value")


def _run_contention_storm(data, port, tokens):
    bodies = {
        "alice": b"AAAAAAAA-ALICE-WHOLE-VALUE\n",
        "bob": b"BBBBBBBB-BOB-WHOLE-VALUE\n",
    }
    errors = []
    threads = [
        threading.Thread(
            target=_contention_put,
            args=(port, tokens, bodies, errors, index),
        )
        for index in range(24)
    ]
    _run_threads(threads)
    _check_contended_file(data, bodies)
    ok(not errors, f"no exceptions during same-file contention ({errors[:2]})")


def _race_put(port, path, subject, token, results):
    http("PUT", path, port, token, f"{subject}\n".encode())
    results.append(subject)


def _run_identity_race(port, path, tokens):
    results = []
    threads = [
        threading.Thread(
            target=_race_put,
            args=(port, path, subject, tokens[subject], results),
        )
        for subject in ("alice", "bob")
    ]
    _run_threads(threads)


def _count_bad_race_owners(data, port, tokens):
    mismatches = 0
    for index in range(8):
        name = f"race_{index}.txt"
        _run_identity_race(port, f"/pub/{name}", tokens)
        path = os.path.join(data, "pub", name)
        if os.path.exists(path) and os.stat(path).st_uid not in (UID_ALICE, UID_BOB):
            mismatches += 1
    return mismatches


def _count_churn_owner_leaks(data, port, token):
    leaks = 0
    path = os.path.join(data, "alice", "churn.txt")
    for index in range(12):
        http("PUT", "/alice/churn.txt", port, token, f"churn{index}\n".encode())
        if os.path.exists(path) and os.stat(path).st_uid != UID_ALICE:
            leaks += 1
        http("DELETE", "/alice/churn.txt", port, token)
    return leaks


def _check_shared_handover(data, port, tokens):
    http("PUT", "/pub/handover.txt", port, tokens["alice"], b"alice-first\n")
    http("PUT", "/pub/handover.txt", port, tokens["bob"], b"bob-second\n")
    path = os.path.join(data, "pub", "handover.txt")
    if not os.path.exists(path):
        ok(False, "handover file missing")
        return
    owner = os.stat(path).st_uid
    real_writer = owner in (UID_ALICE, UID_BOB) and owner != UID_SVC
    ok(real_writer, f"shared-directory handover owned by a real writer (uid={owner})")


def run_samefile_contention(key, data, port, s3port):
    """Verify identity and atomic content under same-file concurrent writes."""
    tokens = {subject: mint(key, subject) for subject in ("alice", "bob")}
    _run_contention_storm(data, port, tokens)
    mismatches = _count_bad_race_owners(data, port, tokens)
    ok(
        mismatches == 0,
        f"same-path races never create worker/root files ({mismatches})",
    )
    leaks = _count_churn_owner_leaks(data, port, tokens["alice"])
    ok(leaks == 0, f"rapid churn remains alice-owned (leaks={leaks})")
    _check_shared_handover(data, port, tokens)


def _check_webdav_read(port, key, path, subject, marker, should_read, label):
    status, body = http("GET", path, port, mint(key, subject))
    received = marker in (body or b"")
    ok(received == should_read, f"{label} (HTTP {status})")


def _check_staff_webdav_reads(key, port):
    marker = b"STAFF-GROUP-READABLE"
    path = "/grp/staff_r.txt"
    _check_webdav_read(
        port, key, path, "alice", marker, True, "owner alice reads 0640 staff file"
    )
    _check_webdav_read(
        port, key, path, "carol", marker, True, "staff member carol reads 0640 file"
    )
    _check_webdav_read(
        port, key, path, "bob", marker, False, "non-member bob is denied 0640 file"
    )
    _check_webdav_read(
        port, key, path, "dave", marker, False, "non-member dave is denied 0640 file"
    )


def _check_root_read(path, subject, marker, should_read, label):
    result, stdout, _stderr = xrd_fs(["cat", path], subject)
    received = marker.decode() in (stdout or "")
    expected_result = result == 0 if should_read else result != 0
    ok(received == should_read and expected_result, f"{label} (rc={result})")


def _check_staff_root_reads():
    marker = b"STAFF-GROUP-READABLE"
    _check_root_read(
        "/grp/staff_r.txt", "carol", marker, True, "carol group read via root"
    )
    _check_root_read(
        "/grp/staff_r.txt", "bob", marker, False, "bob group denial via root"
    )


def _check_owner_only_reads(key, port):
    marker = b"STAFF-OWNER-ONLY"
    path = "/grp/staff_none.txt"
    _check_webdav_read(
        port, key, path, "carol", marker, False, "carol denied owner-only file"
    )
    _check_webdav_read(
        port, key, path, "alice", marker, True, "alice reads owner-only file"
    )


def _check_world_read(key, port):
    _check_webdav_read(
        port,
        key,
        "/grp/world_r.txt",
        "bob",
        b"WORLD-READABLE",
        True,
        "bob reads world-readable file",
    )


def _check_research_reads(key, port):
    marker = b"RESEARCH-GROUP-READABLE"
    path = "/grp/research_r.txt"
    _check_webdav_read(
        port, key, path, "dave", marker, True, "research member dave reads file"
    )
    _check_webdav_read(
        port, key, path, "alice", marker, False, "non-member alice is denied"
    )
    _check_webdav_read(
        port, key, path, "carol", marker, False, "non-member carol is denied"
    )
    _check_webdav_read(
        port, key, path, "bob", marker, True, "owner bob reads research file"
    )


def run_group_read_dac(key, data, port, s3port):
    """Verify owner, supplementary-group, and other read bits through protocols."""
    _check_staff_webdav_reads(key, port)
    if xrd_avail():
        _check_staff_root_reads()
    _check_owner_only_reads(key, port)
    _check_world_read(key, port)
    _check_research_reads(key, port)


def _check_shared_group_creates(key, data, port):
    identities = (("alice", UID_ALICE), ("bob", UID_BOB), ("carol", UID_CAROL))
    for subject, expected_owner in identities:
        name = f"{subject}_made.txt"
        status, _body = http(
            "PUT",
            f"/shareddir/{name}",
            port,
            mint(key, subject),
            f"{subject}-in-shared\n".encode(),
        )
        path = os.path.join(data, "shareddir", name)
        created = os.path.exists(path)
        owned = created and os.stat(path).st_uid == expected_owner
        ok(
            status in (200, 201, 204) and owned,
            f"{subject} creates owned shared file (HTTP {status})",
        )


def _check_nonmember_shared_denial(key, data, port):
    status, _body = http(
        "PUT", "/shareddir/dave_evil.txt", port, mint(key, "dave"), b"x\n"
    )
    created = os.path.exists(os.path.join(data, "shareddir", "dave_evil.txt"))
    ok(not created, f"non-member dave cannot write shared directory (HTTP {status})")


def _check_staff_directory_access(key, data, port):
    status, _body = http(
        "PUT", "/staffdir/carol_made.txt", port, mint(key, "carol"), b"c\n"
    )
    path = os.path.join(data, "staffdir", "carol_made.txt")
    ok(os.path.exists(path), f"staff member carol creates staff file (HTTP {status})")
    status, _body = http(
        "PUT", "/staffdir/bob_evil.txt", port, mint(key, "bob"), b"x\n"
    )
    created = os.path.exists(os.path.join(data, "staffdir", "bob_evil.txt"))
    ok(not created, f"non-member bob cannot write staff directory (HTTP {status})")
    status, _body = http("DELETE", "/staffdir/carol_made.txt", port, mint(key, "carol"))
    ok(
        not os.path.exists(path),
        f"carol deletes her staff-directory file (HTTP {status})",
    )


def _check_staff_directory_rewrite(key, data, port):
    status, _body = http(
        "PUT",
        "/staffdir/inside.txt",
        port,
        mint(key, "carol"),
        b"carol-rewrote\n",
    )
    path = os.path.join(data, "staffdir", "inside.txt")
    ok(
        status in (200, 201, 204) and os.path.exists(path),
        f"carol rewrites staff file (HTTP {status})",
    )
    status, _body = http(
        "PUT", "/staffdir/inside.txt", port, mint(key, "bob"), b"bob-pwn\n"
    )
    safe = not os.path.exists(path) or b"bob-pwn" not in _read_bytes(path)
    ok(safe, f"bob cannot rewrite staff file (HTTP {status})")


def run_group_write_dac(key, data, port, s3port):
    """Verify supplementary-group directory writes, deletes, and replacements."""
    _check_shared_group_creates(key, data, port)
    _check_nonmember_shared_denial(key, data, port)
    _check_staff_directory_access(key, data, port)
    _check_staff_directory_rewrite(key, data, port)


def _set_matrix_mode(path, mode):
    try:
        os.chown(path, UID_ALICE, GID_STAFF)
        os.chmod(path, mode)
    except OSError:
        pass


def _restore_matrix_mode(path):
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def _check_webdav_matrix_mode(key, port, mode, marker):
    accessors = (("alice", 0o400), ("carol", 0o040), ("bob", 0o004))
    for subject, read_bit in accessors:
        allowed = bool(mode & read_bit)
        status, body = http("GET", "/grp/matrix.txt", port, mint(key, subject))
        received = marker in (body or b"")
        decision = "allow" if allowed else "deny"
        result = "served" if received else "withheld"
        ok(
            received == allowed,
            f"mode {mode:04o} {subject}: {decision}/{result} (HTTP {status})",
        )


def _check_webdav_permission_matrix(key, path, port, marker):
    modes = (
        0o000,
        0o400,
        0o040,
        0o004,
        0o440,
        0o444,
        0o600,
        0o640,
        0o644,
        0o604,
        0o660,
        0o006,
    )
    for mode in modes:
        _set_matrix_mode(path, mode)
        _check_webdav_matrix_mode(key, port, mode, marker)
    _restore_matrix_mode(path)


def _check_root_matrix_mode(path, mode, marker):
    _set_matrix_mode(path, mode)
    allowed = bool(mode & 0o040)
    result, stdout, _stderr = xrd_fs(["cat", "/grp/matrix.txt"], "carol")
    received = marker.decode() in (stdout or "")
    decision = "allow" if allowed else "deny"
    ok(
        received == allowed,
        f"root mode {mode:04o} carol group-read {decision} (rc={result})",
    )


def _check_root_permission_matrix(path, marker):
    for mode in (0o040, 0o000, 0o640):
        _check_root_matrix_mode(path, mode, marker)
    _restore_matrix_mode(path)


def run_permission_matrix(key, data, port, s3port):
    """Verify gateway reads exactly follow POSIX owner/group/other mode bits."""
    path = os.path.join(data, "grp", "matrix.txt")
    marker = b"MATRIX-SECRET-BODY"
    _check_webdav_permission_matrix(key, path, port, marker)
    if xrd_avail():
        _check_root_permission_matrix(path, marker)
