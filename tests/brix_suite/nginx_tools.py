"""The single copy of the launcher's nginx helpers (TS-4 item 3).

These three functions were duplicated verbatim in four modules —
``server_launcher.py`` and the three ``_server_launcher_part2_mixin*``
shards — because the launcher was split at the 600-LOC line by copying
its header into each piece.  Four copies of a body is four places to fix
a bug in, and `check_duplication` never saw them: its unit is the
function, and four identical functions in four files each look like one.

They are thin adapters onto ``cmdscripts.live_common``, which owns the
mechanics.  What lives here is the *reason* each call exists — the part
that was worth keeping and that the copies had already begun to lose
(three of the four carried a one-line summary of the relink incident;
one carried the whole story).

The ``live_common`` imports stay function-local: ``cmdscripts`` imports
the launcher, so a module-level import closes a cycle.  It also means a
test can monkeypatch ``live_common.freeze_nginx`` and be observed here,
which ``test_live_common.py`` relies on.
"""

from __future__ import annotations

from brix_suite.settings import NGINX_BIN

__all__ = [
    "_inject_nginx_load_modules",
    "_inject_nginx_runtime_paths",
    "_nginx_bin",
]


def _nginx_bin() -> str:
    """The nginx binary to exec: a per-process frozen copy of ``NGINX_BIN``.

    The shared build tree's ``objs/nginx`` can be relinked by a concurrent
    incremental build at any moment; ``exec`` during the relink window fails
    with EACCES (and ``ldd``-style probes misread the half-written file), which
    surfaced as whole-lane storms of ``PermissionError: /tmp/.../objs/nginx``
    the instant an external ``make`` ran. ``freeze_nginx`` copies + validates
    the binary once per process, so every launcher spawn is immune to relinks;
    it falls back to the live path only if no stable copy can be taken.
    """
    from cmdscripts.live_common import freeze_nginx  # noqa: PLC0415 — lazy, avoids cycle
    return str(freeze_nginx(NGINX_BIN))


def _inject_nginx_load_modules(config_path: str) -> None:
    """Prepend the runner-selected dynamic modules to a rendered nginx config."""
    from cmdscripts.live_common import inject_nginx_load_modules  # noqa: PLC0415
    inject_nginx_load_modules(config_path)


def _inject_nginx_runtime_paths(config_path: str, prefix: str) -> None:
    """Keep packaged-nginx runtime files inside its registry-owned prefix."""
    from cmdscripts.live_common import inject_nginx_runtime_paths  # noqa: PLC0415
    inject_nginx_runtime_paths(config_path, prefix)
