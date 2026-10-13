"""Phase-118 cross-plane denial and authentication error fixtures."""
import contextlib

from settings import HOST
from test_xrd_conform_error_fixtures import (
    AuthFailureOrigin,
    CrossVerbOrigin,
    HttpErrorOrigin,
    PAYLOAD,
    PgOrigin,
    _run_fixture_options,
)

def _denied_options(root, http, s3, omit=None):
    endpoints = (
        ("root", f"root://{HOST}:{root.port}//fixture"),
        ("http", f"http://{HOST}:{http.port}/fixture"),
        ("s3", f"s3://{HOST}:{s3.port}/bucket/fixture"),
    )
    options = []
    for plane, target in endpoints:
        if plane != omit:
            options.extend(("--denied-fixture", f"{plane}={target}"))
    return options


def test_cross_plane_denied_identity_uses_exact_native_spellings(tmp_path):
    """Success: the declared identity is denied precisely on all three planes."""
    with contextlib.ExitStack() as stack:
        primary = stack.enter_context(PgOrigin(PAYLOAD, behaviour="ok"))
        root = stack.enter_context(CrossVerbOrigin(PAYLOAD, behaviour="ok"))
        http = stack.enter_context(HttpErrorOrigin(403))
        s3 = stack.enter_context(HttpErrorOrigin(
            403, b"<Error><Code>AccessDenied</Code></Error>",
        ))
        result, rows = _run_fixture_options(
            tmp_path, "XPR-005", primary,
            _denied_options(root, http, s3), profile="full",
        )
    assert result.returncode == 0, result.stderr + result.stdout
    assert rows["XPR-005"]["verdict"] == "conformant"
    assert rows["XPR-005"]["received"] == "planes=3/3 exact=3/3"


def test_cross_plane_denied_identity_rejects_cosmetic_s3_403(tmp_path):
    """Security-negative: a generic S3 403 is not AccessDenied evidence."""
    with contextlib.ExitStack() as stack:
        primary = stack.enter_context(PgOrigin(PAYLOAD, behaviour="ok"))
        root = stack.enter_context(CrossVerbOrigin(PAYLOAD, behaviour="ok"))
        http = stack.enter_context(HttpErrorOrigin(403))
        s3 = stack.enter_context(HttpErrorOrigin(403, b"forbidden"))
        result, rows = _run_fixture_options(
            tmp_path, "XPR-005", primary,
            _denied_options(root, http, s3), profile="full", verify=True,
        )
    assert result.returncode == 1
    assert rows["XPR-005"]["verdict"] == "divergent"
    assert rows["XPR-005"]["received"] == "planes=3/3 exact=2/3"


def test_cross_plane_denied_identity_requires_all_planes(tmp_path):
    """Error honesty: two exact denials remain inconclusive, never passing."""
    with contextlib.ExitStack() as stack:
        primary = stack.enter_context(PgOrigin(PAYLOAD, behaviour="ok"))
        root = stack.enter_context(CrossVerbOrigin(PAYLOAD, behaviour="ok"))
        http = stack.enter_context(HttpErrorOrigin(403))
        s3 = stack.enter_context(HttpErrorOrigin(
            403, b"<Error><Code>AccessDenied</Code></Error>",
        ))
        result, rows = _run_fixture_options(
            tmp_path, "XPR-005", primary,
            _denied_options(root, http, s3, omit="s3"), profile="full",
        )
    assert result.returncode == 2, result.stderr + result.stdout
    assert rows["XPR-005"]["verdict"] == "inconclusive"
    assert rows["XPR-005"]["received"] == "planes=2/3 exact=2/3"


def test_auth_failures_are_classified_for_every_supplied_protocol(tmp_path):
    """Success: two enabled protocols both return authentication-class errors."""
    with contextlib.ExitStack() as stack:
        primary = stack.enter_context(PgOrigin(PAYLOAD, behaviour="ok"))
        unix = stack.enter_context(AuthFailureOrigin("unix", 3030))
        host = stack.enter_context(AuthFailureOrigin("host", 3010))
        options = [
            "--auth-fixture", f"unix=root://{HOST}:{unix.port}//fixture",
            "--auth-fixture", f"host=root://{HOST}:{host.port}//fixture",
        ]
        result, rows = _run_fixture_options(
            tmp_path, "ERR-047", primary, options,
        )
    assert result.returncode == 0, result.stderr + result.stdout
    assert rows["ERR-047"]["verdict"] == "conformant"
    assert rows["ERR-047"]["received"] == "protocols=2 exact=2"


def test_auth_failure_rejects_generic_filesystem_error(tmp_path):
    """Error: kXR_FSError is never an acceptable authentication failure."""
    with PgOrigin(PAYLOAD, behaviour="ok") as primary:
        with AuthFailureOrigin("unix", 3005) as auth:
            options = [
                "--auth-fixture", f"unix=root://{HOST}:{auth.port}//fixture",
            ]
            result, rows = _run_fixture_options(
                tmp_path, "ERR-047", primary, options, verify=True,
            )
    assert result.returncode == 1
    assert rows["ERR-047"]["verdict"] == "divergent"


def test_auth_fixture_label_must_be_advertised(tmp_path):
    """Security-negative: a fixture cannot claim a protocol it did not offer."""
    with PgOrigin(PAYLOAD, behaviour="ok") as primary:
        with AuthFailureOrigin("host", 3030) as auth:
            options = [
                "--auth-fixture", f"unix=root://{HOST}:{auth.port}//fixture",
            ]
            result, rows = _run_fixture_options(
                tmp_path, "ERR-047", primary, options, verify=True,
            )
    assert result.returncode == 1
    assert rows["ERR-047"]["verdict"] == "divergent"


def test_auth_fixture_must_cover_every_advertised_protocol(tmp_path):
    """Security-negative: an advertised protocol cannot be omitted from probes."""
    with PgOrigin(PAYLOAD, behaviour="ok") as primary:
        with AuthFailureOrigin("unix&P=host", 3030) as auth:
            options = [
                "--auth-fixture", f"unix=root://{HOST}:{auth.port}//fixture",
            ]
            result, rows = _run_fixture_options(
                tmp_path, "ERR-047", primary, options, verify=True,
            )
    assert result.returncode == 1
    assert rows["ERR-047"]["verdict"] == "divergent"
