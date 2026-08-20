"""Unit tests for the fleet_prep cross-session artifact snapshot.

The snapshot exists so repeated sessions skip the ~11 s crypto-artifact
regeneration (PKI blitz, proxies, signing keys, JWKs, issued JWTs) that a
wiped TEST_ROOT otherwise forces every run.  These tests pin the contract:

  * success — a stored snapshot is restored on the next prepare() without
    re-invoking any generator;
  * error — a stale (TTL-expired) or corrupt snapshot regenerates instead of
    restoring;
  * security-negative — a generator-source change refuses the old snapshot
    (no stale credentials), and an incomplete generation is never
    snapshotted in the first place.

Everything runs against faked generators under tmp_path: no openssl, no
subprocesses, no shared cache directory.
"""

import json
import time
from pathlib import Path

import pytest

import fleet_prep


@pytest.fixture
def prep_env(tmp_path, monkeypatch):
    """Fake generators + isolated cache dir; returns a driver object."""
    root = tmp_path / "root"
    cache_root = tmp_path / "cache"
    calls = []

    def fake_regenerate_pki(pki_dir, env):
        calls.append("pki")
        pki = Path(pki_dir)
        (pki / "ca").mkdir(parents=True, exist_ok=True)
        (pki / "user").mkdir(parents=True, exist_ok=True)
        (pki / "ca" / "ca.pem").write_text("cert")
        (pki / "user" / "proxy_std.pem").write_text("proxy")

    def fake_make_token(token_dir, subcmd, *args, env):
        calls.append(f"token-{subcmd}")
        argv = list(map(str, args))
        if "--output" in argv:
            Path(argv[argv.index("--output") + 1]).write_text("jwt")
        elif subcmd == "init":
            Path(token_dir, "signing_key.pem").write_text("key")

    def fake_run(argv, **kwargs):
        calls.append("run")
        # The real fleet-artifacts forge writes the two-issuer registry the
        # token-registry instance parses at conf time; the fake writes it too,
        # because its absence is a sentinel (see _missing_sentinels).
        if "fleet-artifacts" in map(str, argv):
            Path(str(argv[-1]), "scitokens.cfg").write_text("[Global]\n")
        return None

    # Stamp inputs the tests can mutate without touching real repo files.
    gen_a = tmp_path / "gen_a.py"
    gen_b = tmp_path / "gen_b.py"
    gen_a.write_text("a = 1\n")
    gen_b.write_text("b = 1\n")

    monkeypatch.setattr(fleet_prep, "regenerate_pki", fake_regenerate_pki)
    monkeypatch.setattr(fleet_prep, "_make_token", fake_make_token)
    monkeypatch.setattr(fleet_prep, "_run", fake_run)
    monkeypatch.setattr(fleet_prep, "_GENERATOR_SOURCES", (gen_a, gen_b))
    monkeypatch.setattr(
        fleet_prep, "_cache_dir",
        lambda test_root, pki_dir: cache_root / "lane")

    class Driver:
        def __init__(self):
            self.root = root
            self.calls = calls
            self.cache = cache_root / "lane"
            self.generator = gen_a

        def prepare(self):
            import os
            fleet_prep.prepare(dict(os.environ, TEST_ROOT=str(root)))

        def wipe_tree(self):
            import shutil
            shutil.rmtree(root, ignore_errors=True)

        def generated(self):
            return "pki" in calls

        def reset_calls(self):
            calls.clear()

    return Driver()


def test_snapshot_round_trip_skips_generation(prep_env):
    """Success: second session restores the snapshot, generators never run."""
    prep_env.prepare()
    assert prep_env.generated()
    assert (prep_env.cache / "meta.json").exists()

    prep_env.wipe_tree()
    prep_env.reset_calls()
    prep_env.prepare()
    assert not prep_env.generated(), "restore should skip regenerate_pki"
    assert (prep_env.root / "pki" / "user" / "proxy_std.pem").exists()
    assert (prep_env.root / "tokens" / "upstream.jwt").exists()


def test_stale_or_corrupt_snapshot_regenerates(prep_env):
    """Error: TTL expiry and meta corruption both fall back to generation."""
    prep_env.prepare()
    meta_path = prep_env.cache / "meta.json"

    # Age the snapshot past the TTL (proxies live 12 h; TTL is 4 h).
    meta = json.loads(meta_path.read_text())
    meta["created"] = time.time() - fleet_prep._CACHE_TTL_SECONDS - 1
    meta_path.write_text(json.dumps(meta))
    prep_env.wipe_tree()
    prep_env.reset_calls()
    prep_env.prepare()
    assert prep_env.generated(), "expired snapshot must regenerate"

    # Corrupt meta entirely: restore must degrade, never raise.
    meta_path.write_text("{not json")
    prep_env.wipe_tree()
    prep_env.reset_calls()
    prep_env.prepare()
    assert prep_env.generated(), "corrupt snapshot must regenerate"


def test_generator_change_refuses_old_credentials(prep_env):
    """Security-negative: edited generator source invalidates the snapshot,
    so a code change can never be masked by restored stale credentials."""
    prep_env.prepare()
    prep_env.generator.write_text("a = 2  # changed\n")
    prep_env.wipe_tree()
    prep_env.reset_calls()
    prep_env.prepare()
    assert prep_env.generated(), "changed generator must force regeneration"


def test_incomplete_generation_is_never_snapshotted(prep_env, monkeypatch):
    """Security-negative: a tolerated generator failure (missing sentinel)
    must not poison the cache for later sessions."""
    def broken_pki(pki_dir, env):
        prep_env.calls.append("pki")
        pki = Path(pki_dir)
        (pki / "ca").mkdir(parents=True, exist_ok=True)
        (pki / "ca" / "ca.pem").write_text("cert")
        # user/proxy_std.pem deliberately absent — make_proxy "failed".

    monkeypatch.setattr(fleet_prep, "regenerate_pki", broken_pki)
    prep_env.prepare()
    assert not (prep_env.cache / "meta.json").exists(), \
        "incomplete artifacts must never be snapshotted"


def test_partial_fleet_artifacts_is_never_snapshotted(prep_env, monkeypatch):
    """Security-negative: the fleet-artifacts forge is tolerated, so an
    interrupted one leaves jwks_multi.json behind without scitokens.cfg.  That
    half-tree must not be snapshotted — restored later it fails every fleet
    start with ``brix_token_config: open .../scitokens.cfg`` at conf time, and
    a lane whose cache holds it can never recover on its own (observed
    2026-08-18 on two lanes)."""
    def killed_forge(argv, **kwargs):
        calls_argv = list(map(str, argv))
        prep_env.calls.append("run")
        if "fleet-artifacts" in calls_argv:
            Path(calls_argv[-1], "jwks_multi.json").write_text("{}")
            # scitokens.cfg deliberately absent — the forge died mid-write.

    monkeypatch.setattr(fleet_prep, "_run", killed_forge)
    prep_env.prepare()
    assert not (prep_env.cache / "meta.json").exists(), \
        "a half-written token forge must never be snapshotted"


def test_snapshot_without_the_registry_is_refused(prep_env):
    """Error: a snapshot that lost scitokens.cfg after the fact is refused on
    restore, so the lane regenerates instead of restoring a tree the fleet
    cannot start on."""
    prep_env.prepare()
    (prep_env.cache / "tokens" / "scitokens.cfg").unlink()
    prep_env.wipe_tree()
    prep_env.reset_calls()
    prep_env.prepare()
    assert prep_env.generated(), "registry-less snapshot must regenerate"


def test_cache_disabled_by_env_knob(prep_env, monkeypatch):
    """BRIX_FLEET_PREP_CACHE=0 forces full regeneration and stores nothing."""
    monkeypatch.setenv("BRIX_FLEET_PREP_CACHE", "0")
    prep_env.prepare()
    assert prep_env.generated()
    assert not prep_env.cache.exists()
    prep_env.wipe_tree()
    prep_env.reset_calls()
    prep_env.prepare()
    assert prep_env.generated(), "disabled cache must regenerate every time"
