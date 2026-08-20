"""Example 8: spec round-trip and the two validation tiers (F1).

Constructor-time checks refuse what a spec alone can prove wrong;
``Registry.validate(lane)`` finds what only the lane or the kind
table can see, and ships warn-only.
"""

from __future__ import annotations

import pytest

from brixtest.errors import SpecError
from brixtest.fleet.registry import InstanceSpec, Registry


def test_08_specs_roundtrip_and_validate(brix):
    spec = InstanceSpec(
        name="beta", kind="process",
        ports={"primary": brix.fleet.lane.port_base + brix.fleet.lane.port_span + 1},
        command=("/bin/true",), tags=("example",),
    )
    assert InstanceSpec.from_dict(spec.to_dict()) == spec
    with pytest.raises(SpecError):
        InstanceSpec(name="Bad Name", kind="process")
    with pytest.raises(SpecError):
        InstanceSpec(name="beta", kind="process", ports={"primary": 99999})
    with pytest.raises(SpecError):
        InstanceSpec.from_dict({"name": "beta", "kind": "process", "bogus_key": 1})
    # Lane-aware validation sees the deliberately out-of-range port.
    registry = Registry()
    registry.register(spec)
    findings = registry.validate(brix.fleet.lane)
    assert any("outside the lane" in finding for finding in findings)
