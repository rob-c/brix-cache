"""Keep disposable runtime diagnostics private and free of credentials."""

import json
import os

import pytest


def _dump_runtime_environment(path, environment):
    """Write only explicitly public test settings, never a shared /tmp file."""
    keys = ("PYTEST_XDIST_WORKER", "TEST_NGINX_BIN", "TEST_ROOT")
    public = {key: environment[key] for key in keys if key in environment}
    with path.open("x", encoding="utf-8") as destination:
        json.dump(public, destination, sort_keys=True)


def test_dump(tmp_path):
    """A diagnostic belongs to this fixture, even across users and workers."""
    destination = tmp_path / "runtime-environment.json"
    _dump_runtime_environment(destination, os.environ)
    diagnostic = json.loads(destination.read_text(encoding="utf-8"))
    assert diagnostic.get("TEST_ROOT") == os.environ.get("TEST_ROOT")
    assert set(diagnostic) <= {"PYTEST_XDIST_WORKER", "TEST_NGINX_BIN", "TEST_ROOT"}


def test_dump_refuses_to_overwrite_an_existing_file(tmp_path):
    """A collision must preserve the original evidence rather than clobber it."""
    destination = tmp_path / "runtime-environment.json"
    destination.write_text("original", encoding="utf-8")
    with pytest.raises(FileExistsError):
        _dump_runtime_environment(destination, {})
    assert destination.read_text(encoding="utf-8") == "original"


def test_dump_excludes_credentials_and_worker_path_injection(tmp_path):
    """Unknown environment keys and hostile worker names cannot escape tmp_path."""
    destination = tmp_path / "runtime-environment.json"
    _dump_runtime_environment(destination, {
        "AWS_SECRET_ACCESS_KEY": "fixture-secret-do-not-copy",
        "BRIX_TOKEN": "fixture-token-do-not-copy",
        "PYTEST_XDIST_WORKER": "../../outside\nsecret",
    })
    assert json.loads(destination.read_text(encoding="utf-8")) == {
        "PYTEST_XDIST_WORKER": "../../outside\nsecret",
    }
    assert list(tmp_path.iterdir()) == [destination]
