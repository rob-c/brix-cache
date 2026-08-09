"""Standalone ``nginx -t`` config-parse checks — no server boot, no registry.

Bucket 3 of the fixed-port/registry-only test-harness refactor: directive
validation is a pure ``nginx -t`` property.  Render a named template into a
throwaway prefix, run the config check, and hand back the ``CompletedProcess``
so a test asserts on ``returncode`` + the ``[emerg]`` diagnostic.

This replaces ``LifecycleHarness.expect_config_failure`` for parse-only tests:
nothing is registered, no throwaway ``-{pid}`` instance is created, and no spec
joins the session boot set.  Rendering is non-strict (the template supplies its
own placeholders), exactly as the launcher's ``expect_config_failure`` did.
"""

import subprocess
from pathlib import Path
import json

from config_templates import render_config_to_path
from cmdscripts.live_common import inject_nginx_load_modules
from settings import NGINX_BIN


def nginx_t(template, root, **template_values):
    """Render ``template`` under ``root`` and run ``nginx -t`` against it.

    ``root`` is a throwaway prefix (a test's ``tmp_path``); the rendered config
    lands at ``root/conf/nginx.conf`` and nginx resolves relative paths against
    ``-p root``.  Returns the ``CompletedProcess`` (``check=False``) so callers
    assert accept (``returncode == 0``) or reject (``!= 0`` + stderr needle).
    """
    root = Path(root)
    config = root / "conf" / "nginx.conf"
    render_config_to_path(template, config, strict=False, **template_values)
    # Distribution nginx builds default their pid file to /run/nginx.pid even
    # for `nginx -t`.  Tests run as an ordinary user, so make the otherwise
    # irrelevant parse-time PID path part of the throwaway test prefix.
    body = config.read_text(encoding="utf-8")
    if not any(line.lstrip().startswith("pid ") for line in body.splitlines()):
        config.write_text(
            f"pid {json.dumps(str(root / 'logs' / 'nginx.pid'))};\n{body}",
            encoding="utf-8",
        )
    inject_nginx_load_modules(config)
    return subprocess.run(
        [str(NGINX_BIN), "-t", "-p", str(root), "-c", "conf/nginx.conf"],
        capture_output=True,
        text=True,
        timeout=30,
    )
