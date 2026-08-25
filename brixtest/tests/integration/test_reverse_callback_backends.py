"""One declaration proving server-to-server reverse callbacks across backends."""

import sys
import time

from brixtest import binary, case, endpoint, probe, server, tcp


_LISTENER = (
    "import socket,sys\n"
    "sock=socket.socket(socket.AF_INET,socket.SOCK_STREAM)\n"
    "sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)\n"
    "sock.bind((sys.argv[1],int(sys.argv[2])))\n"
    "sock.listen(8)\n"
    "print('callback-ready',flush=True)\n"
    "while True:\n"
    " connection,_=sock.accept()\n"
    " with connection:\n"
    "  payload=connection.recv(4096)\n"
    "  if payload:\n"
    "   print('callback:'+payload.hex(),flush=True)\n"
    "   connection.sendall(b'ack')\n"
)
_CALLER = (
    "import socket,sys,time\n"
    "deadline=time.monotonic()+30\n"
    "while True:\n"
    " try:\n"
    "  connection=socket.create_connection((sys.argv[1],int(sys.argv[2])),1)\n"
    "  break\n"
    " except OSError:\n"
    "  if time.monotonic()>=deadline: raise\n"
    "  time.sleep(.1)\n"
    "with connection:\n"
    " connection.sendall(b'brixtest-reverse-callback')\n"
    " assert connection.recv(3)==b'ack'\n"
    "print('callback-delivered',flush=True)\n"
    "while True: time.sleep(1)\n"
)
_PYTHON_IMAGE = (
    "python@sha256:ffb752e139c0a19692a43af8d8523b274222dd68eebad5d583b45c2201c6e30a"
)
PYTHON = binary(
    "callback_python", path=sys.executable, image=_PYTHON_IMAGE,
    image_path="/usr/local/bin/python3",
)
CALLBACK = server(
    "callback_listener",
    command=(PYTHON, "-u", "-c", _LISTENER, "{host}", "{port}"),
    endpoints=(endpoint("callback"),), readiness=tcp("callback", timeout=30),
)
CALLER = server(
    "callback_caller",
    command=(PYTHON, "-u", "-c", _CALLER, CALLBACK.host, CALLBACK.port("callback")),
    depends_on=(CALLBACK,), probe=probe("none", timeout=30),
)


@case(CALLBACK, CALLER, PYTHON, backend="auto", timeout=60, keep="never")
def test_server_can_reach_a_managed_reverse_callback(run):
    expected = b"brixtest-reverse-callback".hex()
    listener = run.server(CALLBACK)
    deadline = time.monotonic() + 10
    while "callback:" + expected not in listener.read_log():
        assert time.monotonic() < deadline
        time.sleep(0.05)
    assert "callback-delivered" in run.server(CALLER).read_log()
