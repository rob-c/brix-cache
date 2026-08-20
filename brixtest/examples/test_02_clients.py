"""Examples 5-8: captured binaries and named, shell-free clients."""

import sys

from brixtest import (
    artifact_ref,
    binary,
    case,
    client,
    execution,
    text_artifact,
    tool,
)

PYTHON = binary("example_python", sys.executable, discover_libraries=False)
CAPTURED_CLIENT = tool(
    "captured_python",
    execution=execution(PYTHON, "-c", "print('captured binary')"),
)


@case(CAPTURED_CLIENT, keep="never")
def test_05_captured_binary(run):
    result = run.tool(CAPTURED_CLIENT).run()
    captured = run.binary(PYTHON)
    assert result.stdout.strip() == "captured binary"
    assert captured.path != PYTHON.path
    assert captured.sha256


ECHO = client(
    "echo",
    command=[sys.executable, "-c", "import sys; print('|'.join(sys.argv[1:]))"],
)


@case(clients=[ECHO], keep="never")
def test_06_named_client_stdout(run):
    result = run.client("echo").run("one", "two")
    assert result.stdout.strip() == "one|two"


CLIENT_MESSAGE = text_artifact("client_message", "client environment\n")
ENV_CLIENT = client(
    "environment",
    command=[sys.executable, "-c", "import os; print(open(os.environ['MESSAGE']).read())"],
    env={"MESSAGE": artifact_ref(CLIENT_MESSAGE)},
)


@case(ENV_CLIENT, CLIENT_MESSAGE, keep="never")
def test_07_client_environment_template(run):
    result = run.client(ENV_CLIENT).run()
    assert result.stdout.strip() == "client environment"


FILTER = client(
    "filter",
    command=[
        sys.executable, "-c",
        "import sys; data=sys.stdin.read().upper(); print(data); sys.exit(7 if 'FAIL' in data else 0)",
    ],
)


@case(clients=[FILTER], keep="never")
def test_08_client_stdin_and_expected_error(run):
    success = run.client(FILTER).run(input="hello")
    expected_error = run.client(FILTER).run(input="fail", check=False)
    assert success.stdout.strip() == "HELLO"
    assert expected_error.stdout.strip() == "FAIL"
    assert expected_error.returncode == 7
