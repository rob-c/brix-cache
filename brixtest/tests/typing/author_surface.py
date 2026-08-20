"""Static-only sample covering the canonical test-author workflow."""

from brixtest import (
    Placement,
    Run,
    Server,
    Service,
    case,
    endpoint,
    execution,
    param,
    server,
    server_config,
    text_artifact,
    tool,
)

payload = text_artifact("payload", "hello")
origin: Server = server(
    "origin",
    execution=execution("origin-daemon", "--port", "{port}"),
    config=server_config("listen={port}\n", filename="origin.conf"),
    endpoints=(endpoint("http", scheme="http"),),
    env={"REQUEST_SIZE": param("request_size")},
)
reader = tool(
    "reader",
    execution=execution("reader", origin.url("http"), payload.ref()),
    placement=Placement(backend="local"),
)


@case(origin, reader, payload)
def test_typed_author_surface(run: Run) -> None:
    service: Service = run.server(origin)
    assert service.url(role="http").startswith("http://")
    assert run.tool(reader).run().check().ok
    assert run.artifact(payload).verify()
