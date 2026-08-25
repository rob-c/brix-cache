"""Supervised UDP-to-Kubernetes exec gateway used for controller access."""

from __future__ import annotations

import argparse
import re
import socket
import subprocess
import sys
from typing import List, Optional

_MAX_DATAGRAM = 65507
_REMOTE = (
    "import socket,sys;"
    "h=sys.argv[1];p=int(sys.argv[2]);t=float(sys.argv[3]);"
    "f=socket.AF_INET6 if ':' in h else socket.AF_INET;"
    "s=socket.socket(f,socket.SOCK_DGRAM);s.settimeout(t);"
    "s.sendto(sys.stdin.buffer.read(),(h,p));"
    "sys.stdout.buffer.write(s.recv(65507))"
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="brixtest-udp-gateway")
    parser.add_argument("--kubectl", default="kubectl")
    parser.add_argument("--context", default="")
    parser.add_argument("--namespace", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--target-host", required=True)
    parser.add_argument("--target-port", required=True, type=int)
    parser.add_argument("--timeout", default=2.0, type=float)
    return parser


def _validate(args: argparse.Namespace) -> None:
    label = r"[a-z0-9]([-a-z0-9]*[a-z0-9])?"
    if re.fullmatch(label, args.namespace) is None:
        raise ValueError("namespace must be a Kubernetes DNS label")
    if re.fullmatch(label, args.target) is None:
        raise ValueError("target must be a Kubernetes DNS label")
    if args.target_host not in ("127.0.0.1", "::1"):
        raise ValueError("target host must be a Pod loopback address")
    if not 0 < args.target_port < 65536:
        raise ValueError("target port must be between 1 and 65535")
    if not 0 < args.timeout <= 60:
        raise ValueError("timeout must be greater than zero and at most 60 seconds")


def _command(args: argparse.Namespace) -> list[str]:
    command = [args.kubectl]
    if args.context:
        command.extend(("--context", args.context))
    command.extend((
        "-n", args.namespace, "exec", "-i", "deployment/%s" % args.target,
        "-c", "brixtest-filesystem", "--", "python3", "-c", _REMOTE,
        args.target_host, str(args.target_port), str(args.timeout),
    ))
    return command


def _exchange(args: argparse.Namespace, payload: bytes) -> Optional[bytes]:
    completed = subprocess.run(
        _command(args), input=payload, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, timeout=args.timeout + 2.0, check=False,
    )
    if completed.returncode == 0:
        return completed.stdout
    print(completed.stderr.decode(errors="replace").strip(), file=sys.stderr, flush=True)
    return None


def _serve(args: argparse.Namespace) -> int:
    listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    listener.bind(("127.0.0.1", 0))
    print("BRIXTEST UDP READY %d" % listener.getsockname()[1], flush=True)
    while True:
        payload, peer = listener.recvfrom(_MAX_DATAGRAM)
        response = _exchange(args, payload)
        if response is not None:
            listener.sendto(response, peer)


def main(argv: Optional[List[str]] = None) -> int:
    args = _parser().parse_args(argv)
    try:
        _validate(args)
        return _serve(args)
    except (OSError, subprocess.SubprocessError, ValueError) as exc:
        print("brixtest UDP gateway: %s" % exc, file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
