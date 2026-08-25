"""Translate OCI execution-group members into an owned anchor container."""

from brixtest.errors import SpecError
from brixtest.runtime.launchers import (
    ServerLaunchContext, ServerLaunchPlan, ServerLaunchRequest,
)


def prepare_container_group_member(
    launcher, context: ServerLaunchContext, request: ServerLaunchRequest,
    anchor: ServerLaunchPlan,
) -> ServerLaunchPlan:
    """Run a supervised member inside an already planned group container."""
    launcher.validate(request.declaration)
    if context.root not in (request.cwd, *request.cwd.parents):
        raise SpecError(
            "server launch cwd", request.cwd, "must be confined below the run root",
        )
    if anchor.launcher != launcher.name or not anchor.metadata.get("container_name"):
        raise SpecError(
            "server %s placement.group" % request.declaration.name,
            request.declaration.placement.group,
            "requires an anchor planned by the same container runtime",
        )
    env_file = launcher._environment_file(context, request)
    container_name = str(anchor.metadata["container_name"])
    argv = [
        launcher.name, "exec", "--env-file", str(env_file),
        "--workdir", str(request.cwd), container_name, *request.argv,
    ]
    return ServerLaunchPlan(
        argv, {}, request.cwd, launcher.name,
        metadata={
            "isolation": launcher.name, "image": anchor.metadata.get("image", ""),
            "container_name": container_name, "env_file": str(env_file),
            "group_member": True,
        },
    )


__all__ = ["prepare_container_group_member"]
