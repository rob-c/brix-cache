"""paths — the lab's directory layout in one place, so tests never build paths."""
from pathlib import Path

LAB = Path(__file__).resolve().parents[2]   # k8s-tests/
REPO = LAB.parent                            # repo root
SUITE = LAB / "remote-suite"


def tool(name):
    return LAB / "tools" / name


def config(name):
    return LAB / "charts" / "topology-role" / "configs" / name


def chart(name):
    return LAB / "charts" / name


def scenario_file(name):
    return LAB / "scenarios" / name


def image_dir(name):
    return LAB / "images" / name
