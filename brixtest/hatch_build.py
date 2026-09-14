"""Keep the API contract reference available in standalone source distributions."""

from pathlib import Path

from hatchling.builders.hooks.plugin.interface import BuildHookInterface


class CustomBuildHook(BuildHookInterface):
    """Include canonical documentation without recreating it in the checkout."""

    def initialize(self, version, build_data):
        project = Path(self.root)
        reference = project.parent / "docs/09-developer-guide/brixtest/api-reference.md"
        if reference.is_file():
            build_data["force_include"][str(reference)] = "docs/api-reference.md"
            return
        if (project / "docs/api-reference.md").is_file():
            return
        raise FileNotFoundError(
            "The API reference is required from the repository docs or an extracted sdist"
        )
