"""The xdist topology broker retains ownership across worker/controller loss."""

import json
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

from brixtest import case, server, static_config, tcp
from brixtest.topology.broker import RemoteTopology, TopologyBroker

_LISTENER = (
    "import socket,sys,time;"
    "s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);"
    "s.bind(('127.0.0.1',int(sys.argv[1])));s.listen();time.sleep(300)"
)


def _definition(tmp_path: Path):
    config = tmp_path / "server.conf"
    config.write_text("owned\n")
    origin = server(
        "origin", command=(sys.executable, "-c", _LISTENER, "{port}"),
        config=static_config(config), readiness=tcp(), scope="session",
    )

    @case(origin, observe=(), keep="always")
    def declared(run):
        return None

    return declared.__brixtest_case__


def _connects(port: int) -> bool:
    with socket.socket() as client:
        return client.connect_ex(("127.0.0.1", port)) == 0


def _await_closed(port: int, timeout: float = 15.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not _connects(port):
            return
        time.sleep(0.05)
    raise AssertionError("broker-owned server still accepts connections")


def test_broker_reaps_resources_when_worker_never_reports_finished(tmp_path):
    broker = TopologyBroker(tmp_path / "session")
    settings = broker.worker_settings("gw0", 1)
    remote = RemoteTopology(
        str(settings["address"]), str(settings["token"]), "gw0",
    )
    remote.register([("test_crash.py::test_case", _definition(tmp_path))], 1)
    port = remote.for_test("test_crash.py::test_case")["services"]["origin"]["ports"][
        "primary"
    ]
    assert _connects(port)
    records = broker.close()
    _await_closed(port)
    assert len(records) == 1
    assert records[0]["scheduled_tests"] == ["test_crash.py::test_case"]


def _controller_script() -> str:
    return """
import json,os,sys
from pathlib import Path
from brixtest import case,server,static_config,tcp
from brixtest.topology.broker import RemoteTopology,TopologyBroker
LISTENER=%r
def main():
 root=Path(sys.argv[1]);config=root/'server.conf';config.write_text('owned\\n')
 origin=server('origin',command=(sys.executable,'-c',LISTENER,'{port}'),config=static_config(config),readiness=tcp(),scope='session')
 @case(origin,observe=(),keep='always')
 def declared(run): return None
 broker=TopologyBroker(root/'session');settings=broker.worker_settings('gw0',1)
 remote=RemoteTopology(str(settings['address']),str(settings['token']),'gw0')
 remote.register([('test_crash.py::test_case',declared.__brixtest_case__)],1)
 manifest=remote.for_test('test_crash.py::test_case')
 (root/'ready.json').write_text(json.dumps({'manifest':manifest,'address':settings['address']}))
 os._exit(17)
if __name__ == '__main__': main()
""" % _LISTENER


def test_linux_parent_death_reaps_broker_pool_and_socket(tmp_path):
    if not sys.platform.startswith("linux"):
        return
    script = tmp_path / "controller.py"
    script.write_text(_controller_script())
    environment = dict(os.environ)
    source = Path(__file__).resolve().parents[1] / "src"
    environment["PYTHONPATH"] = os.pathsep.join((str(source), environment.get("PYTHONPATH", "")))
    result = subprocess.run(
        [sys.executable, str(script), str(tmp_path)], env=environment,
        capture_output=True, text=True, timeout=40, check=False,
    )
    assert result.returncode == 17, result.stdout + result.stderr
    ready = json.loads((tmp_path / "ready.json").read_text())
    port = ready["manifest"]["services"]["origin"]["ports"]["primary"]
    _await_closed(port)
    deadline = time.monotonic() + 10.0
    address = Path(ready["address"])
    while address.exists() and time.monotonic() < deadline:
        time.sleep(0.05)
    assert not address.exists()
