# ARCHIVE — the pre-TS-4 flat body of ``tests/server_launcher_part2.py``, kept byte-identical so
# the "verbatim move" claim in the TS-4 decision note is checkable on disk
# rather than only in git history.  Nothing imports this; the live launcher is
# ``brix_suite.launcher``.  ``test_ci_ts4_launcher_move.py`` diffs every moved
# method against this text.
"""Python lifecycle owner for registry-backed test servers."""

from __future__ import annotations

import os
from pathlib import Path
import re
import shutil
import signal
import socket
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, replace
from typing import Sequence

import pytest

from config_templates import render_config_to_path
from fleet_lifecycle_ports import lifecycle_ports_for
from fleet_values import session_template_values
from server_registry import (
    NginxInstanceSpec,
    build_manifest,
    declared_ports,
    endpoint_for,
    read_manifest,
    register_nginx,
    registered_specs,
    replace_spec,
    unregister,
    write_manifest,
)
from settings import BRIX_BIN, NGINX_BIN, PKI_DIR, REGISTRY_STRICT_TEMPLATES

from _server_launcher_part2_mixina import _RegistryLauncherMixinA
from _server_launcher_part2_mixinb import _RegistryLauncherMixinB
from _server_launcher_part2_mixinc import _RegistryLauncherMixinC

class RegistryLauncher(_RegistryLauncherMixinA, _RegistryLauncherMixinB, _RegistryLauncherMixinC):
    pass
