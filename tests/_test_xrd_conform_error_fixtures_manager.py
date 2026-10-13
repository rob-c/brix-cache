def test_manager_partial_outage_redirects_to_live_holder(tmp_path):
    """Success: one down holder does not prevent a live-holder redirect."""
    down = free_port(HOST)
    with PgOrigin(PAYLOAD, behaviour="ok") as live:
        with ManagerOutageOrigin(
                [live.port, down], kXR_redirect) as manager:
            result, rows = _run_manager_outage(tmp_path, "CMS-003", manager)
    assert result.returncode == 0, result.stderr + result.stdout
    assert rows["CMS-003"]["verdict"] == "conformant"
    assert "holders=2 served=1" in rows["CMS-003"]["received"]


def test_manager_all_holders_down_returns_defined_error(tmp_path):
    """Success: an all-down holder set returns a bounded wire error."""
    ports = [free_port(HOST), free_port(HOST)]
    with ManagerOutageOrigin(ports, kXR_error) as manager:
        result, rows = _run_manager_outage(tmp_path, "CMS-004", manager)
    assert result.returncode == 0, result.stderr + result.stdout
    assert rows["CMS-004"]["verdict"] == "conformant"
    assert "holders=2 served=0" in rows["CMS-004"]["received"]


@pytest.mark.parametrize("clause, live_count, open_status", [
    ("CMS-003", 1, kXR_error),
    ("CMS-004", 0, kXR_redirect),
])
def test_manager_outage_rejects_wrong_first_hop_answer(
        tmp_path, clause, live_count, open_status):
    """Security-negative: topology evidence cannot excuse a wrong answer."""
    down = free_port(HOST)
    with contextlib.ExitStack() as stack:
        ports = [down]
        if live_count:
            live = stack.enter_context(PgOrigin(PAYLOAD, behaviour="ok"))
            ports.append(live.port)
        else:
            ports.append(free_port(HOST))
        manager = stack.enter_context(ManagerOutageOrigin(ports, open_status))
        result, rows = _run_manager_outage(
            tmp_path, clause, manager, verify=True,
        )
    assert result.returncode == 1
    assert rows[clause]["verdict"] == "divergent"


def test_manager_ghost_holder_is_reported(tmp_path):
    """Security-negative: every advertised holder must serve the object."""
    down = free_port(HOST)
    with ManagerOutageOrigin([down], kXR_redirect) as manager:
        result, rows = _run_manager_outage(
            tmp_path, "CMS-001", manager, verify=True,
        )
    assert result.returncode == 1
    assert rows["CMS-001"]["verdict"] == "divergent"
    assert rows["CMS-001"]["reason"] == "manager-holder-set-has-ghost"


def test_manager_empty_success_for_missing_object_is_reported(tmp_path):
    """Security-negative: an empty success is not a NotFound answer."""
    with PgOrigin(PAYLOAD, behaviour="ok") as holder:
        sequences = [[holder.port], []]
        with ManagerOutageOrigin(
                [holder.port], kXR_redirect, sequences) as manager:
            result, rows = _run_manager_outage(
                tmp_path, "CMS-002", manager, verify=True,
            )
    assert result.returncode == 1
    assert rows["CMS-002"]["verdict"] == "divergent"
    assert rows["CMS-002"]["reason"] == "empty-holder-set-wrong-answer"


def test_manager_direct_object_service_is_reported(tmp_path):
    """Security-negative: a manager-only role must not serve open directly."""
    with PgOrigin(PAYLOAD, behaviour="ok") as holder:
        with ManagerOutageOrigin([holder.port], 0) as manager:
            result, rows = _run_manager_outage(
                tmp_path, "CMS-006", manager, verify=True,
            )
    assert result.returncode == 1
    assert rows["CMS-006"]["verdict"] == "divergent"
    assert rows["CMS-006"]["reason"] == "manager-only-open-served-directly"


def test_redundant_manager_holder_mismatch_is_reported(tmp_path):
    """Security-negative: redundant managers cannot expose split views."""
    with contextlib.ExitStack() as stack:
        first = stack.enter_context(PgOrigin(PAYLOAD, behaviour="ok"))
        second = stack.enter_context(PgOrigin(PAYLOAD, behaviour="ok"))
        primary = stack.enter_context(ManagerOutageOrigin(
            [first.port], kXR_redirect,
        ))
        alternate = stack.enter_context(ManagerOutageOrigin(
            [second.port], kXR_redirect,
        ))
        result, rows = _run_manager_outage(
            tmp_path, "CMS-005", primary, verify=True,
            also_manager=alternate,
        )
    assert result.returncode == 1
    assert rows["CMS-005"]["verdict"] == "divergent"
    assert rows["CMS-005"]["reason"] == \
        "redundant-manager-holder-set-mismatch"


def test_manager_map_matches_independent_xrdmapc_output(tmp_path):
    """Success: the shipped map tool and direct locate return one exact set."""
    with PgOrigin(PAYLOAD, behaviour="ok") as holder:
        with ManagerOutageOrigin([holder.port], kXR_redirect) as manager:
            result, rows = _run_manager_outage(tmp_path, "CMS-007", manager)
    assert result.returncode == 0, result.stderr + result.stdout
    assert rows["CMS-007"]["verdict"] == "conformant"


def test_manager_map_tool_failure_is_inconclusive(tmp_path):
    """Error: a failed independent map query cannot become a false pass."""
    with PgOrigin(PAYLOAD, behaviour="ok") as holder:
        sequences = [[holder.port], None]
        with ManagerOutageOrigin(
                [holder.port], kXR_redirect, sequences) as manager:
            result, rows = _run_manager_outage(tmp_path, "CMS-007", manager)
    assert result.returncode == 0, result.stderr + result.stdout
    assert rows["CMS-007"]["verdict"] == "inconclusive"
    assert rows["CMS-007"]["reason"] == "xrdmapc-map-failed"


def test_manager_map_rejects_changed_holder_set(tmp_path):
    """Security-negative: a map/locate split-view turns CMS-007 red."""
    with contextlib.ExitStack() as stack:
        first = stack.enter_context(PgOrigin(PAYLOAD, behaviour="ok"))
        second = stack.enter_context(PgOrigin(PAYLOAD, behaviour="ok"))
        sequences = [[first.port], [second.port]]
        manager = stack.enter_context(ManagerOutageOrigin(
            [first.port], kXR_redirect, sequences,
        ))
        result, rows = _run_manager_outage(
            tmp_path, "CMS-007", manager, verify=True,
        )
    assert result.returncode == 1
    assert rows["CMS-007"]["verdict"] == "divergent"
    assert rows["CMS-007"]["reason"] == \
        "xrdmapc-locate-holder-set-mismatch"


def _readonly_options(webdav, s3, oci, ftp, omit=None):
    endpoints = (
        ("webdav", f"http://{HOST}:{webdav.port}/fixture"),
        ("s3", f"http://{HOST}:{s3.port}/fixture"),
        ("oci", f"http://{HOST}:{oci.port}/v2/repo/manifests/tag"),
        ("gridftp", f"ftp://{HOST}:{ftp.port}/fixture"),
    )
    options = []
    for plane, target in endpoints:
        if plane != omit:
            options.extend(("--readonly-fixture", f"{plane}={target}"))
    return options


def test_complete_readonly_protocol_spelling_matrix(tmp_path):
    """Success: WebDAV, S3, OCI, and GridFTP use their exact denials."""
    with contextlib.ExitStack() as stack:
        primary = stack.enter_context(PgOrigin(PAYLOAD, behaviour="ok"))
        webdav = stack.enter_context(HttpErrorOrigin(403))
        s3 = stack.enter_context(HttpErrorOrigin(
            403, b"<Error><Code>AccessDenied</Code></Error>",
        ))
        oci = stack.enter_context(HttpErrorOrigin(
            403, b'{"errors":[{"code":"DENIED"}]}',
        ))
        ftp = stack.enter_context(FtpReadonlyOrigin())
        result, rows = _run_fixture_options(
            tmp_path, "ERR-044", primary,
            _readonly_options(webdav, s3, oci, ftp), mutate=True,
        )
    assert result.returncode == 0, result.stderr + result.stdout
    assert rows["ERR-044"]["verdict"] == "conformant"
    assert rows["ERR-044"]["received"] == "planes=4/4 exact=4/4"


def test_readonly_matrix_requires_every_plane(tmp_path):
    """Error: three valid planes cannot stand in for an absent fourth one."""
    with contextlib.ExitStack() as stack:
        primary = stack.enter_context(PgOrigin(PAYLOAD, behaviour="ok"))
        webdav = stack.enter_context(HttpErrorOrigin(403))
        s3 = stack.enter_context(HttpErrorOrigin(
            403, b"<Error><Code>AccessDenied</Code></Error>",
        ))
        oci = stack.enter_context(HttpErrorOrigin(403, b'"code":"DENIED"'))
        ftp = stack.enter_context(FtpReadonlyOrigin())
        result, rows = _run_fixture_options(
            tmp_path, "ERR-044", primary,
            _readonly_options(webdav, s3, oci, ftp, omit="oci"), mutate=True,
            verify=True,
        )
    assert result.returncode == 1
    assert rows["ERR-044"]["verdict"] == "divergent"
    assert rows["ERR-044"]["received"] == "planes=3/4 exact=3/4"


def test_readonly_matrix_rejects_cosmetic_403(tmp_path):
    """Security-negative: a generic S3 403 is not AccessDenied evidence."""
    with contextlib.ExitStack() as stack:
        primary = stack.enter_context(PgOrigin(PAYLOAD, behaviour="ok"))
        webdav = stack.enter_context(HttpErrorOrigin(403))
        s3 = stack.enter_context(HttpErrorOrigin(403, b"forbidden"))
        oci = stack.enter_context(HttpErrorOrigin(403, b'"code":"DENIED"'))
        ftp = stack.enter_context(FtpReadonlyOrigin())
        result, rows = _run_fixture_options(
            tmp_path, "ERR-044", primary,
            _readonly_options(webdav, s3, oci, ftp), mutate=True, verify=True,
        )
    assert result.returncode == 1
    assert rows["ERR-044"]["verdict"] == "divergent"
    assert rows["ERR-044"]["received"] == "planes=4/4 exact=3/4"
