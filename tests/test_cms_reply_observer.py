"""CMS conformance requests must snapshot replies before sending a request."""

import ast
from pathlib import Path

import pytest


def _named_node(nodes, kind, name):
    """Select one named definition at its actual lexical level."""
    for node in nodes:
        if isinstance(node, kind) and node.name == name:
            return node
    raise AssertionError(f"missing {kind.__name__}: {name}")


def _load_method(method):
    """Execute exactly the selected assertion with its wire constants."""
    source = Path(__file__).with_name("test_cms_hostile_conformance_b.py")
    tree = ast.parse(source.read_text())
    owner = _named_node(tree.body, ast.ClassDef, "TestNodeLegEsotericManager")
    selected = _named_node(owner.body, ast.FunctionDef, method)
    namespace = dict(_SID=0x1000, CMS_RR_SPACE="space", CMS_RR_AVAIL="avail",
                     CMS_RR_STATS="stats", CMS_RSP_DATA="data",
                     CMS_RR_UPDATE="update", CMS_RR_STATUS="status")
    exec(compile(ast.Module(body=[selected], type_ignores=[]), str(source), "exec"), namespace)
    return namespace[method]


class Peer:
    """Reply arrival is controlled independently of the assertion under test."""

    def __init__(self, response, mode):
        self.response = response
        self.mode = mode
        self.frames = [(0, response)] if mode == "stale" else []

    def send_to_node(self, sid, code, modifier):
        before = len(self.frames)
        if self.mode == "instant":
            self.frames.append((sid, self.response))
        return before

    def collect_reply(self, code, timeout, after=None):
        if after is None:
            after = len(self.frames)
        return next((frame for frame in self.frames[after:] if frame[1] == code), None)


@pytest.mark.parametrize("method,response", [
    ("test_manager_space_query_answered", "avail"),
    ("test_manager_stats_query_answered", "data"),
    ("test_manager_update_answered_with_status", "status"),
])
@pytest.mark.parametrize("mode", ["instant", "missing", "stale"])
def test_pre_send_baseline_observes_fast_replies_but_never_stale_ones(method, response, mode):
    """Replies may arrive inside sendall; old login frames prove nothing."""
    assertion = _load_method(method)
    peer = Peer(response, mode)
    if mode == "instant":
        assertion(None, peer)
    else:
        with pytest.raises(AssertionError):
            assertion(None, peer)
