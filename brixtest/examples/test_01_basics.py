"""Examples 1-4: the managed lifecycle and the three artifact kinds."""

import os
from pathlib import Path

from brixtest import KiB, case, file_artifact, noise, process, text_artifact

HERE = Path(__file__).parent


@case(isolation=process(), keep="never")
def test_01_minimal_managed_case(run):
    """A case body always runs in a supervised helper with a private workspace."""
    assert os.getpid() != int(os.environ["BRIXTEST_CONTROLLER_PID"])
    assert run.root.is_dir()
    assert run.workspace.is_dir()
    assert run.backend == "local"


MESSAGE = text_artifact("message", "hello from a text artifact\n", filename="message.txt")


@case(artifacts=[MESSAGE], keep="never")
def test_02_text_artifact(run):
    materialized = run.artifact(MESSAGE)
    assert materialized.path.read_text() == "hello from a text artifact\n"
    assert materialized.kind == "text"


COPIED = file_artifact("copied", HERE / "assets" / "copied.txt")


@case(artifacts=[COPIED], keep="never")
def test_03_file_artifact(run):
    materialized = run.artifact("copied")
    assert materialized.path.read_text().startswith("This file was copied")
    assert materialized.path != (HERE / "assets" / "copied.txt")


NOISE_A = noise("noise_a", size=64 * KiB, seed=2026)
NOISE_B = noise("noise_b", size=64 * KiB, seed=2026)


@case(artifacts=[NOISE_A, NOISE_B], keep="never")
def test_04_deterministic_noise_artifacts(run):
    first = run.artifact(NOISE_A)
    second = run.artifact(NOISE_B)
    assert first.size == second.size == 64 * KiB
    assert first.sha256 == second.sha256
    assert first.path.read_bytes() == second.path.read_bytes()
