"""Provider output projection for Kubernetes workload rendering."""

from typing import Mapping


def provider_outputs(owner) -> Mapping[str, Mapping[str, object]]:
    """Return immutable provider outputs as ordinary rendering mappings."""
    return {
        name: dict(instance.outputs)
        for name, instance in owner._providers.instances.items()
    }
