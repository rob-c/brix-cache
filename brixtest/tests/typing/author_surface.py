"""Static-only sample covering the canonical test-author workflow."""

from brixtest import (
    OutputExpectation,
    Placement,
    Run,
    Server,
    Service,
    binary,
    case,
    endpoint,
    execution,
    expect_output,
    native_test,
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


native_output: OutputExpectation = expect_output("PASS", excludes=("FAIL",))
native_source = text_artifact(
    "native-source", "int main(void) { return 0; }\n", filename="native.c",
)
native_compiler = binary("native-compiler", "/usr/bin/cc")
test_typed_native = native_test(
    "typed-native",
    sources=(native_source.ref(),),
    resources=(native_source, native_compiler),
    compiler=native_compiler,
    defines={"MATRIX_VALUE": param("matrix_value")},
    compile_args=("-Wall", param("optimization")),
    stdout=native_output,
    observe=(),
    keep="never",
)
