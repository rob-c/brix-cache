"""Docs + tool preflight. Docs via reads(); require-tools logic via labtools."""
from labtools import require_tools


def test_readme_documents_core_commands(reads):
    reads("README.md").shows("xrd-lab up", "xrd-lab deploy dev",
                             "xrd-lab test smoke", "xrd-lab down dev")


def test_retired_manifests_and_driver_are_gone(absent):
    assert absent("k8s-manifests/lab-5-vms.yaml", "k8s-manifests/fixed-ip-vms.yaml", "xrd-k8s")


def test_walkthrough_pins_k8s_version(reads):
    reads("docs/walkthrough.md").shows("v1.31.4")


def test_require_tools_reports_present_and_missing():
    assert require_tools.missing(["python3"]) == []
    assert require_tools.missing(["definitely_not_a_real_binary_xyz"]) == \
        ["definitely_not_a_real_binary_xyz"]
