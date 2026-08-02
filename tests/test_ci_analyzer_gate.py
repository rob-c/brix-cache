"""Guards for the B-1 static-analyzer blocking-flip (hyper-hardening B-1).

fanalyzer.yml (gcc -fanalyzer) and codechecker.yml (Clang SA + clang-tidy) were
flipped from advisory weekly-cron to BLOCKING per-PR gates. The flip is only
safe because each job now runs in `container: almalinux:9` — the dev distro whose
gcc 11.5.0 / clang 21.1.8 produced the frozen ratchet baselines, so the finding
set reproduces. These guards assert the four load-bearing properties of that
flip so a future edit can't silently regress the gate to advisory or drop the
toolchain pin (which would red every PR on version-drift noise):

  1. blocking      — no `continue-on-error`
  2. per-PR        — pull_request + push triggers present
  3. pinned        — runs in the almalinux:9 container (baseline reproducible)
  4. ratchet kept  — still invokes the run_*.py ratchet runner (not a raw sweep)
"""

from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]

GATES = {
    ".github/workflows/fanalyzer.yml": ("fanalyzer", "run_fanalyzer.py"),
    ".github/workflows/codechecker.yml": ("codechecker", "run_codechecker.py"),
}


def _load(path: str) -> dict:
    return yaml.safe_load((ROOT / path).read_text())


def _triggers(doc: dict) -> dict:
    # PyYAML parses the bare `on:` key as boolean True under YAML 1.1.
    return doc.get("on", doc.get(True, {}))


def test_gates_are_blocking_and_pinned():
    for path, (job_name, runner) in GATES.items():
        doc = _load(path)
        job = doc["jobs"][job_name]

        # 1. blocking
        assert "continue-on-error" not in job, f"{path}: gate is still advisory"

        # 2. per-PR
        trig = _triggers(doc)
        assert "pull_request" in trig, f"{path}: missing pull_request trigger"
        assert "push" in trig, f"{path}: missing push trigger"

        # 3. pinned toolchain — the dev distro container makes the baseline reproducible
        container = job.get("container")
        image = container if isinstance(container, str) else (container or {}).get("image", "")
        assert "almalinux:9" in str(image), f"{path}: toolchain not pinned to almalinux:9"

        # 4. ratchet kept
        steps = " ".join(str(s.get("run", "")) for s in job["steps"])
        assert runner in steps, f"{path}: no longer invokes the ratchet runner {runner}"


def test_baselines_still_present():
    # The ratchet gates against these frozen baselines; blocking is meaningless
    # if they vanish.
    assert (ROOT / "tools/ci/fanalyzer_baseline.txt").exists()
    assert (ROOT / "tools/ci/codechecker_baseline.txt").exists()
