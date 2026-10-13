@pytest.mark.parametrize(("behaviour", "owner"), [
    ("open_short_handle", "OPN-001"),
    ("ok", "OPN-002"),
    ("ok", "OPN-003"),
    ("ok", "OPN-004"),
    ("ok", "OPN-005"),
    ("stat_handle_mismatch", "OPN-006"),
    ("open_bad_compress", "OPN-007"),
    ("ok", "OPN-008"),
    ("ok", "OPN-009"),
    ("ok", "OPN-010"),
    ("ok", "OPN-011"),
    ("ok", "OPN-013"),
    ("ok", "OPN-014"),
    ("ok", "OPN-015"),
    ("ok", "OPN-016"),
    ("ok", "OPN-017"),
    ("open_advisory_corrupt", "OPN-018"),
    ("open_advisory_corrupt", "OPN-019"),
    ("ok", "OPN-022"),
    ("open_refresh_stale", "OPN-021"),
    ("open_cgi_storage_path", "OPN-023"),
    ("open_server_error_options", "OPN-024"),
    ("ok", "OPN-025"),
    ("open_bad_mode", "OPN-026"),
    ("ok", "OPN-027"),
    ("ok", "OPN-028"),
    ("ok", "OPN-029"),
    ("ok", "OPN-030"),
    ("close_reserved_corrupt", "OPN-031"),
    ("ok", "OPN-032"),
    ("idle_server_error", "OPN-033"),
])
def test_hostile_open_contract_is_rejected(tmp_path, behaviour, owner):
    result, rows = _run(tmp_path, behaviour, "OPN", owner, owner)
    assert result.returncode == 1, result.stderr + result.stdout
    assert rows[owner]["verdict"] == "divergent"


@pytest.mark.parametrize(("behaviour", "owner"), [
    ("mkdir_bad_mode", "MKD-006"),
    ("move_inconsistent", "MV-003"),
    ("rm_file_error", "RM-001"),
    ("rm_dir_wrong", "RM-004"),
    ("rmdir_file_ack", "RM-005"),
    ("chmod_not_reversible", "CHM-004"),
])
def test_hostile_namespace_contract_is_rejected(tmp_path, behaviour, owner):
    result, rows = _run(tmp_path, behaviour, owner.split("-")[0], owner,
                        owner)
    assert result.returncode == 1, result.stderr + result.stdout
    assert rows[owner]["verdict"] == "divergent"


@pytest.mark.parametrize(("behaviour", "owner"), [
    ("prepare_cancel_nonidempotent", "PRP-002"),
    ("prepare_missing_ack", "PRP-005"),
    ("prepare_notify_poison", "PRP-006"),
])
def test_hostile_prepare_contract_is_rejected(tmp_path, behaviour, owner):
    result, rows = _run(tmp_path, behaviour, "PRP", owner, owner)
    assert result.returncode == 1, result.stderr + result.stdout
    assert rows[owner]["verdict"] == "divergent"


@pytest.mark.parametrize(("family", "owner"), [
    ("RD", "RD-011"),
    ("PGR", "PGR-028"),
])
def test_large_offset_truncation_is_rejected(tmp_path, family, owner):
    result, rows = _run(tmp_path, "large_offset_wrong", family, owner, owner)
    assert result.returncode == 1, result.stderr + result.stdout
    assert rows[owner]["verdict"] == "divergent"


@pytest.mark.parametrize(("behaviour", "owner"), [
    ("locate_empty", "LOC-001"),
    ("locate_bad_shape", "LOC-002"),
    ("locate_ghost", "LOC-003"),
    ("locate_prefname_numeric", "LOC-007"),
    ("locate_missing_ok", "LOC-008"),
])
def test_hostile_locate_contract_is_rejected(tmp_path, behaviour, owner):
    result, rows = _run(tmp_path, behaviour, "LOC", owner, owner)
    assert result.returncode == 1, result.stderr + result.stdout
    assert rows[owner]["verdict"] == "divergent"


@pytest.mark.parametrize(("behaviour", "owner"), [
    ("dir_dstat_count_mismatch", "DIR-002"),
    ("dir_dstat_bad_sentinel", "DIR-003"),
    ("dir_file_success", "DIR-006"),
    ("dir_large_single_frame", "DIR-007"),
    ("dir_escape_success", "DIR-009"),
])
def test_hostile_directory_contract_is_rejected(tmp_path, behaviour, owner):
    result, rows = _run(tmp_path, behaviour, "DIR", owner, owner)
    assert result.returncode == 1, result.stderr + result.stdout
    assert rows[owner]["verdict"] == "divergent"


def test_altered_and_prehandshake_requests_are_rejected(tmp_path):
    result, rows = _run(tmp_path, families="HSK",
                        verify_negative=("HSK-005", "HSK-007"))
    assert result.returncode == 1, result.stderr + result.stdout
    assert rows["HSK-005"]["verdict"] == "divergent"
    assert rows["HSK-007"]["verdict"] == "divergent"


@pytest.mark.parametrize(("behaviour", "owner"), [
    ("handshake_aux_missing", "HSK-001"),
    ("handshake_aux_legacy", "HSK-002"),
    ("handshake_aux_bad_version", "HSK-003"),
])
def test_malformed_server_handshake_is_retained(tmp_path, behaviour, owner):
    result, rows = _run(tmp_path, behaviour, "HSK",
                        verify_negative=owner)
    assert result.returncode == 1, result.stderr + result.stdout
    assert rows[owner]["verdict"] == "divergent"


def test_short_handshake_cannot_poison_next_connection(tmp_path):
    result, rows = _run(tmp_path, "handshake_poison_recovery", "HSK",
                        verify_negative="HSK-004")
    assert result.returncode == 1, result.stderr + result.stdout
    assert rows["HSK-004"]["verdict"] == "divergent"


def test_second_handshake_cannot_be_served(tmp_path):
    result, rows = _run(tmp_path, "second_handshake_ok", "HSK",
                        verify_negative="HSK-006")
    assert result.returncode == 1, result.stderr + result.stdout
    assert rows["HSK-006"]["verdict"] == "divergent"


def test_reused_session_id_is_detected(tmp_path):
    result, rows = _run(tmp_path, families="LOG", only="LOG-002",
                        verify_negative="LOG-002")
    assert result.returncode == 1
    assert rows["LOG-002"]["verdict"] == "divergent"
    assert rows["LOG-002"]["reason"] == "duplicate-session-id"


@pytest.mark.parametrize("owner", [
    "LOG-003", "LOG-014", "LOG-018", "LOG-019", "LOG-020",
])
def test_hostile_login_session_contract_is_rejected(tmp_path, owner):
    result, rows = _run(tmp_path, "ok", "LOG", owner, owner,
                        request_limit=256, wall_seconds=20)
    assert result.returncode == 1, result.stderr + result.stdout
    assert rows[owner]["verdict"] == "divergent"


@pytest.mark.parametrize(("behaviour", "owner"), [
    ("login_short_aux", "LOG-001"),
    ("login_shape_refuse", "LOG-007"),
    ("prelogin_auth_ok", "LOG-013"),
])
def test_hostile_login_wire_contract_is_rejected(tmp_path, behaviour, owner):
    result, rows = _run(tmp_path, behaviour, "LOG", owner, owner,
                        request_limit=256, wall_seconds=20)
    assert result.returncode == 1, result.stderr + result.stdout
    assert rows[owner]["verdict"] == "divergent"
