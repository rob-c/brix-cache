"""
surface — load and cross-check the stock-vs-project CLI surface map.

Bridges ``surface_map.yaml`` (the curated classification) with
``flag_inventory`` (the live parse of the stock sources).  The surface test
uses these helpers to prove:

  * every stock flag/command is classified in the map (no untested surface),
  * the map classifies nothing that stock no longer has (no stale entries), and
  * every project-only extra is actually advertised by our client's --help.
"""

import os

import yaml

_YAML = os.path.join(os.path.dirname(os.path.abspath(__file__)), "surface_map.yaml")
_map = None


def load():
    global _map
    if _map is None:
        with open(_YAML, "r") as fh:
            _map = yaml.safe_load(fh) or {}
    return _map


def xrdcp_flags():
    """{flag_name: {status, ...}} for stock xrdcp flags."""
    return load().get("xrdcp", {}).get("flags", {})


def xrdcp_extras():
    """{our_flag: description} for project-only xrdcp flags."""
    return load().get("xrdcp", {}).get("extras", {})


def xrdfs_commands():
    return load().get("xrdfs", {}).get("commands", {})


def xrdfs_extras():
    return load().get("xrdfs", {}).get("extras", {})
