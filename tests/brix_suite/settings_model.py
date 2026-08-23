"""``SuiteSettings`` — the configuration object over the grown values (§9.2.1).

The 258 ``settings`` exports stay module attributes (computed verbatim in
``brix_suite.settings_values``, ladder-rebased by ``port_ladder``); this
module gives them ONE typed, frozen view plus the §5.8 Tier-2 runtime
knobs that today are scattered ``os.environ`` reads across the conftest
constellation, launcher, prep and ``lib_py``.  Nothing consumes the
Tier-2 fields yet — dependents keep their own reads until they migrate —
so every default here MUST mirror its read site exactly (§5.8 is the
checklist).  Validation is warn-only for one full phase (TS-3 rule 6).
"""

from __future__ import annotations

import dataclasses
import os
import warnings
from typing import Mapping, Optional

from brixtest.config.ports import PortLedger

def _guard_derive_1(overrides):
    if "port_start" in overrides and "ports" not in overrides:
        _warn_lane_sanity(overrides["port_start"])
        overrides["ports"] = _ladder_ledger(overrides["port_start"])

def _guard_derive_2(overrides, new_root):
    if "registry_root" not in overrides:
        overrides["registry_root"] = os.path.join(new_root, "registry")

def _guard_derive_3(overrides):
    if "registry_manifest" not in overrides:
        overrides["registry_manifest"] = os.path.join(
            overrides["registry_root"], "manifest.json")

def _guard_derive_4(overrides, new_root):
    if "sanitize_log_dir" not in overrides:
        overrides["sanitize_log_dir"] = os.path.join(new_root, "sanitize")

def _guard_derive_5(overrides, new_root):
    if "valgrind_log_dir" not in overrides:
        overrides["valgrind_log_dir"] = os.path.join(new_root, "valgrind")


__all__ = ["SuiteSettings", "build_suite_settings"]

# One socket, two spellings (settings_values.py: davs:// call-site clarity).
# Mirrors the local ``aliases`` dict in port_ladder.rebase_settings; the
# TS-3 triad cross-checks the two stay in agreement.
_PORT_ALIASES = {"XRDHTTP_HTTPS_PORT": "XRDHTTP_HTTP_PORT"}


def _owner_port_names(namespace: Mapping[str, object]) -> list:
    """The ladder owners, in definition order — the exact filter
    ``port_ladder.rebase_settings`` applies to the settings namespace."""
    return [
        name for name, value in namespace.items()
        if "_PORT" in name
        and name != "TEST_PORT_START"
        and isinstance(value, int)
        and name not in _PORT_ALIASES
    ]


def _ledger_from_values(namespace: Mapping[str, object], port_start: int) -> PortLedger:
    """A ledger equal to the already-rebased constants.  ``env={}`` because
    the values are final: the ladder overwrote any per-name override and
    republished the result into the environment, so re-reading env here
    would be a second (idempotent at best, wrong at worst) application."""
    offsets = {
        name: int(namespace[name]) - port_start
        for name in _owner_port_names(namespace)
    }
    return PortLedger(port_start, offsets, aliases=dict(_PORT_ALIASES), env={})


def _ladder_ledger(port_start: int) -> Optional[PortLedger]:
    """The ledger a fresh lane at ``port_start`` would get: pure ladder
    math (``_port(SETTINGS_OFFSET, i)`` = start + offset + i + 1), owner
    order taken from the canonical namespace.

    A base below the core ledger's 1024 floor returns ``None`` instead of
    refusing: today such a lane imports fine and only fails when a server
    tries to bind, and TS-3 rule 6 says construction may not add a new
    refusal — ``_warn_lane_sanity`` has already logged the problem."""
    if port_start < 1024:
        return None
    import brix_suite.settings as _canonical  # bootstraps sys.path for port_ladder
    import port_ladder
    import brix_suite.settings_values as _values
    del _canonical
    offsets = {
        name: port_ladder.SETTINGS_OFFSET + index + 1
        for index, name in enumerate(_owner_port_names(vars(_values)))
    }
    return PortLedger(port_start, offsets, aliases=dict(_PORT_ALIASES), env={})


@dataclasses.dataclass(frozen=True)
class SuiteSettings:
    # -- lane identity ----------------------------------------------------
    test_root: str
    port_start: int
    host: str = "127.0.0.1"                    # TEST_HOST
    host6: str = "::1"                         # TEST_HOST6
    bind_host: str = "127.0.0.1"               # TEST_BIND_HOST (falls back to host)
    bind_host6: str = "::1"                    # TEST_BIND_HOST6 (falls back to host6)
    server_host: str = "localhost"             # TEST_SERVER_HOST or "localhost"
    remote_server: bool = False                # TEST_SERVER_HOST is set
    # -- registry behavior ------------------------------------------------
    registry_enabled: bool = True              # TEST_SERVER_REGISTRY != "0"
    registry_start: bool = True                # TEST_REGISTRY_START != "0"
    registry_keep_logs: bool = False           # TEST_REGISTRY_KEEP_LOGS == "1"
    registry_strict_templates: bool = True     # TEST_REGISTRY_STRICT_TEMPLATES != "0"
    registry_root: str = ""                    # TEST_REGISTRY_ROOT, default <root>/registry
    registry_manifest: str = ""                # TEST_REGISTRY_MANIFEST, default <registry>/manifest.json
    # -- binaries ---------------------------------------------------------
    nginx_bin: str = "/tmp/nginx-1.28.3/objs/nginx"   # TEST_NGINX_BIN
    asan_nginx_bin: str = ""                   # TEST_ASAN_NGINX_BIN
    brix_bin: str = "xrootd"                   # TEST_BRIX_BIN
    xrdfs_bin: str = "xrdfs"                   # TEST_XRDFS_BIN
    xrdcp_bin: str = "xrdcp"                   # TEST_XRDCP_BIN
    # -- the port ledger (all fixed ports live here, not as loose fields) --
    ports: Optional[PortLedger] = None
    # -- §5.8 Tier-2 runtime knobs, each mirroring its read site ----------
    skip_server_setup: bool = False            # TEST_SKIP_SERVER_SETUP == "1"
    own_fleet: bool = False                    # TEST_OWN_FLEET == "1"
    fleet_stability_secs: float = 5.0          # TEST_FLEET_STABILITY_SECS
    fleet_start_timeout: float = 900.0         # TEST_FLEET_START_TIMEOUT
    sentinel: bool = True                      # BRIX_FLEET_SENTINEL != "0"
    sentinel_poll: float = 2.0                 # BRIX_FLEET_SENTINEL_POLL
    sentinel_grace: float = 8.0                # BRIX_FLEET_SENTINEL_GRACE
    sentinel_fraction: float = 0.5             # BRIX_FLEET_SENTINEL_FRACTION
    sentinel_min_down: int = 8                 # BRIX_FLEET_SENTINEL_MIN_DOWN
    sentinel_abort: bool = False               # BRIX_FLEET_SENTINEL_ABORT == "1"
    fleet_prep_cache: bool = True              # BRIX_FLEET_PREP_CACHE != "0"
    fleet_start_workers: Optional[int] = None  # BRIX_FLEET_START_WORKERS (unset = auto)
    xdg_cache_home: Optional[str] = None       # XDG_CACHE_HOME (unset = platform default)
    xdist_worker: Optional[str] = None         # PYTEST_XDIST_WORKER (set by xdist itself)
    sanitize: Optional[str] = None             # SANITIZE (truthiness at sites)
    sanitize_log_dir: str = ""                 # SANITIZE_LOG_DIR, default <root>/sanitize
    valgrind: Optional[str] = None             # VALGRIND (truthiness at sites)
    valgrind_log_dir: str = ""                 # VALGRIND_LOG_DIR, default <root>/valgrind
    nginx_conf_pregenerated: Optional[str] = None  # NGINX_CONF_PREGENERATED
    nginx_conf_rel: str = "conf/nginx.conf"    # NGINX_CONF_REL
    ref_runas_user: str = "nobody"             # REF_RUNAS_USER
    large_file_seed: int = 42                  # LARGE_FILE_SEED
    skip_xrdfs_check: bool = False             # SKIP_XRDFS_CHECK (truthy)
    brix_test_user: str = "brixtest"           # BRIX_TEST_USER
    brix_test_tree: str = "/srv/brix-test"     # BRIX_TEST_TREE
    fwd_port_base: int = 21960                 # FWD_PORT_BASE
    # -- legacy path overrides that bypass settings (a duplication these
    # fields retire; None = "not overridden", fallbacks stay at the sites)
    legacy_configs_dir: Optional[str] = None       # CONFIGS_DIR
    legacy_pki_dir: Optional[str] = None           # PKI_DIR
    legacy_nginx_bin: Optional[str] = None         # NGINX_BIN
    legacy_brix_bin: Optional[str] = None          # BRIX_BIN
    legacy_xrdcp_bin: Optional[str] = None         # XRDCP_BIN
    legacy_xrootd_bin: Optional[str] = None        # XROOTD_BIN
    legacy_ref_bin: Optional[str] = None           # REF_BIN
    legacy_ref_dir: Optional[str] = None           # REF_DIR
    legacy_xrdhttp_dir: Optional[str] = None       # XRDHTTP_DIR
    legacy_xrdhttp_data_dir: Optional[str] = None  # XRDHTTP_DATA_DIR

    # -- derived paths (all rooted at test_root, as in settings_values) ----
    @property
    def pki_dir(self) -> str:
        return os.path.join(self.test_root, "pki")

    @property
    def data_root(self) -> str:
        return os.path.join(self.test_root, "data")

    @property
    def tokens_dir(self) -> str:
        return os.path.join(self.test_root, "tokens")

    @property
    def tmp_dir(self) -> str:
        return os.path.join(self.test_root, "tmp")

    @property
    def artifacts_dir(self) -> str:
        return os.path.join(self.test_root, "artifacts")

    @property
    def cwd_dir(self) -> str:
        return os.path.join(self.test_root, "cwd")

    @property
    def fleet_ready_marker(self) -> str:
        return os.path.join(self.registry_root, ".fleet-ready")

    @property
    def log_dir(self) -> str:
        # The main instance's logs under the registry launcher, not the
        # bash-era flat <root>/logs (see settings_values.py LOG_DIR).
        return os.path.join(self.registry_root, "main", "logs")

    @classmethod
    def from_env(cls, env: Optional[Mapping[str, str]] = None) -> "SuiteSettings":
        """Parse a settings object from ``env`` (default: ``os.environ``).

        The ONLY environment read in the package.  Never writes the
        environment — the legacy republish (TEST_ROOT, TMPDIR, the ladder's
        NAME/TEST_NAME pairs) stays in ``settings_values`` until dependents
        migrate off it.  A malformed integer raises the same ``ValueError``
        an ``import settings`` raises today.
        """
        e = os.environ if env is None else env
        test_root = os.path.abspath(os.path.expanduser(
            e.get("TEST_ROOT", "/tmp/xrd-test")))
        port_start = int(e.get("TEST_PORT_START", "10000"))
        _warn_lane_sanity(port_start)
        registry_root = e.get("TEST_REGISTRY_ROOT",
                              os.path.join(test_root, "registry"))
        server_host_env = e.get("TEST_SERVER_HOST")
        host = e.get("TEST_HOST", "127.0.0.1")
        host6 = e.get("TEST_HOST6", "::1")
        workers = e.get("BRIX_FLEET_START_WORKERS")
        return cls(
            test_root=test_root,
            port_start=port_start,
            host=host,
            host6=host6,
            bind_host=e.get("TEST_BIND_HOST") or host,
            bind_host6=e.get("TEST_BIND_HOST6") or host6,
            server_host=server_host_env if server_host_env else "localhost",
            remote_server=server_host_env is not None,
            registry_enabled=e.get("TEST_SERVER_REGISTRY", "1") != "0",
            registry_start=e.get("TEST_REGISTRY_START", "1") != "0",
            registry_keep_logs=e.get("TEST_REGISTRY_KEEP_LOGS", "0") == "1",
            registry_strict_templates=e.get("TEST_REGISTRY_STRICT_TEMPLATES", "1") != "0",
            registry_root=registry_root,
            registry_manifest=e.get("TEST_REGISTRY_MANIFEST",
                                    os.path.join(registry_root, "manifest.json")),
            nginx_bin=e.get("TEST_NGINX_BIN", "/tmp/nginx-1.28.3/objs/nginx"),
            asan_nginx_bin=e.get("TEST_ASAN_NGINX_BIN", ""),
            brix_bin=e.get("TEST_BRIX_BIN", "xrootd"),
            xrdfs_bin=e.get("TEST_XRDFS_BIN", "xrdfs"),
            xrdcp_bin=e.get("TEST_XRDCP_BIN", "xrdcp"),
            ports=_ladder_ledger(port_start),
            skip_server_setup=e.get("TEST_SKIP_SERVER_SETUP") == "1",
            own_fleet=e.get("TEST_OWN_FLEET") == "1",
            fleet_stability_secs=float(e.get("TEST_FLEET_STABILITY_SECS", "5")),
            fleet_start_timeout=float(e.get("TEST_FLEET_START_TIMEOUT", "900")),
            sentinel=e.get("BRIX_FLEET_SENTINEL", "1") != "0",
            sentinel_poll=float(e.get("BRIX_FLEET_SENTINEL_POLL", "2.0")),
            sentinel_grace=float(e.get("BRIX_FLEET_SENTINEL_GRACE", "8")),
            sentinel_fraction=float(e.get("BRIX_FLEET_SENTINEL_FRACTION", "0.5")),
            sentinel_min_down=int(e.get("BRIX_FLEET_SENTINEL_MIN_DOWN", "8")),
            sentinel_abort=e.get("BRIX_FLEET_SENTINEL_ABORT", "0") == "1",
            fleet_prep_cache=e.get("BRIX_FLEET_PREP_CACHE", "1") != "0",
            fleet_start_workers=int(workers) if workers else None,
            xdg_cache_home=e.get("XDG_CACHE_HOME"),
            xdist_worker=e.get("PYTEST_XDIST_WORKER"),
            sanitize=e.get("SANITIZE"),
            sanitize_log_dir=e.get("SANITIZE_LOG_DIR",
                                   os.path.join(test_root, "sanitize")),
            valgrind=e.get("VALGRIND"),
            valgrind_log_dir=e.get("VALGRIND_LOG_DIR",
                                   os.path.join(test_root, "valgrind")),
            nginx_conf_pregenerated=e.get("NGINX_CONF_PREGENERATED"),
            nginx_conf_rel=e.get("NGINX_CONF_REL", "conf/nginx.conf"),
            ref_runas_user=e.get("REF_RUNAS_USER", "nobody"),
            large_file_seed=int(e.get("LARGE_FILE_SEED", "42")),
            skip_xrdfs_check=bool(e.get("SKIP_XRDFS_CHECK")),
            brix_test_user=e.get("BRIX_TEST_USER", "brixtest"),
            brix_test_tree=e.get("BRIX_TEST_TREE", "/srv/brix-test"),
            fwd_port_base=int(e.get("FWD_PORT_BASE", "21960")),
            legacy_configs_dir=e.get("CONFIGS_DIR"),
            legacy_pki_dir=e.get("PKI_DIR"),
            legacy_nginx_bin=e.get("NGINX_BIN"),
            legacy_brix_bin=e.get("BRIX_BIN"),
            legacy_xrdcp_bin=e.get("XRDCP_BIN"),
            legacy_xrootd_bin=e.get("XROOTD_BIN"),
            legacy_ref_bin=e.get("REF_BIN"),
            legacy_ref_dir=e.get("REF_DIR"),
            legacy_xrdhttp_dir=e.get("XRDHTTP_DIR"),
            legacy_xrdhttp_data_dir=e.get("XRDHTTP_DATA_DIR"),
        )

    def derive(self, **overrides) -> "SuiteSettings":
        """A copy with ``overrides`` applied; lane-dependent derivations
        follow.  A new ``port_start`` rebuilds the ladder ledger; a new
        ``test_root`` recomputes the root-derived defaults — unless the
        caller overrode those fields explicitly, which always wins (C2)."""
        _guard_derive_1(overrides)
        if "test_root" in overrides:
            new_root = overrides["test_root"]
            _guard_derive_2(overrides, new_root)
            _guard_derive_3(overrides)
            _guard_derive_4(overrides, new_root)
            _guard_derive_5(overrides, new_root)
        return dataclasses.replace(self, **overrides)


def _warn_lane_sanity(port_start: int) -> None:
    # Warn-only for one full phase (TS-3 rule 6): a refusal that does not
    # fire today may only log.  The ladder needs PORT_COUNT contiguous
    # unprivileged ports above port_start.
    if not 1024 <= port_start <= 60000:
        warnings.warn(
            f"TEST_PORT_START={port_start} is outside the sane lane range "
            "[1024, 60000]; the port ladder may collide with privileged or "
            "ephemeral ports (warn-only during TS-3)",
            stacklevel=3,
        )


def build_suite_settings(namespace: Mapping[str, object]) -> SuiteSettings:
    """The default instance, built over the VALUES the verbatim body just
    computed (not re-parsed from env): the dataclass is a view, the module
    attributes stay the runtime the 690 dependents observe (§10.2)."""
    base = SuiteSettings.from_env(os.environ)
    return base.derive(
        # Everything env-parsed by from_env matches the body's own parse by
        # construction; the fields below are pinned to the body's computed
        # values so the view can never drift from the module attributes.
        test_root=str(namespace["TEST_ROOT"]),
        port_start=int(namespace["TEST_PORT_START"]),
        host=str(namespace["HOST"]),
        host6=str(namespace["HOST6"]),
        bind_host=str(namespace["BIND_HOST"]),
        bind_host6=str(namespace["BIND_HOST6"]),
        server_host=str(namespace["SERVER_HOST"]),
        remote_server=bool(namespace["REMOTE_SERVER"]),
        registry_enabled=bool(namespace["REGISTRY_ENABLED"]),
        registry_start=bool(namespace["REGISTRY_START"]),
        registry_keep_logs=bool(namespace["REGISTRY_KEEP_LOGS"]),
        registry_strict_templates=bool(namespace["REGISTRY_STRICT_TEMPLATES"]),
        registry_root=str(namespace["REGISTRY_ROOT"]),
        registry_manifest=str(namespace["REGISTRY_MANIFEST"]),
        nginx_bin=str(namespace["NGINX_BIN"]),
        asan_nginx_bin=str(namespace["ASAN_NGINX_BIN"]),
        brix_bin=str(namespace["BRIX_BIN"]),
        xrdfs_bin=str(namespace["XRDFS_BIN"]),
        xrdcp_bin=str(namespace["XRDCP_BIN"]),
        ports=_ledger_from_values(namespace, int(namespace["TEST_PORT_START"])),
    )
