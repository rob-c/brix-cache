"""Archive immutable executable inputs needed by an exact managed rerun."""

from __future__ import annotations

from urllib.parse import quote


def archive_replay_inputs(manager) -> None:
    """Copy captured executables and libraries into the session object store."""
    for name, captured in sorted(manager.binary_store._captured.items()):
        if not captured.sha256:
            continue
        manager.evidence.attach(
            captured.path, name="binary-%s" % name,
            role="replay-binary:%s" % name,
            description="immutable executable for exact BriXTest rerun",
        )
        for index, library in enumerate(captured.libraries):
            manager.evidence.attach(
                library, name="binary-%s-library-%04d" % (name, index),
                role="replay-library:%s" % name,
                description="immutable shared library for exact BriXTest rerun",
            )
        for index, (destination, path) in enumerate(
            sorted(getattr(captured, "runtime_files", {}).items()),
        ):
            manager.evidence.attach(
                path, name="binary-%s-runtime-%04d" % (name, index),
                role="replay-runtime:%s:%s" % (name, quote(destination, safe="")),
                description="immutable runtime data for exact BriXTest rerun",
            )


__all__ = ["archive_replay_inputs"]
