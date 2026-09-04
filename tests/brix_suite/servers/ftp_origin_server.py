"""Small RFC-959 origin used to prove the outbound FTP storage driver.

This is deliberately an origin, not a fake of the driver API: every test crosses
real control and passive data sockets.  It implements only the portable MODE-S
commands BriX consumes and confines every pathname beneath the supplied root.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import os
from pathlib import Path, PurePosixPath
import socket
import socketserver

from ephemeral_port import free_port
from brix_suite.settings import HOST


class _RejectedPath(ValueError):
    pass


class FtpOriginHandler(socketserver.StreamRequestHandler):
    timeout = 15

    def setup(self):
        super().setup()
        self.data_listener = None
        self.rest_offset = 0
        self.rename_source = None

    def finish(self):
        self._close_data_listener()
        super().finish()

    def _reply(self, code: int, text: str) -> None:
        self.wfile.write(f"{code} {text}\r\n".encode("ascii"))
        self.wfile.flush()

    def _audit(self, verb: str, arg: str) -> None:
        if self.server.audit_path is None:
            return
        safe_arg = "<redacted>" if verb == "PASS" else arg
        with self.server.audit_path.open("a", encoding="utf-8") as audit:
            audit.write(f"{verb} {safe_arg}\n")

    def _close_data_listener(self) -> None:
        if self.data_listener is not None:
            self.data_listener.close()
            self.data_listener = None

    def _open_data_listener(self) -> int:
        self._close_data_listener()
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((self.server.bind_host, free_port()))
        listener.listen(1)
        listener.settimeout(self.timeout)
        self.data_listener = listener
        return listener.getsockname()[1]

    def _data_connection(self):
        if self.data_listener is None:
            raise OSError("EPSV or PASV required")
        listener = self.data_listener
        self.data_listener = None
        connection, _ = listener.accept()
        listener.close()
        connection.settimeout(self.timeout)
        return connection

    @staticmethod
    def _raw_path_is_invalid(raw: str) -> bool:
        if not raw.startswith("/"):
            return True
        if "\\" in raw:
            return True
        return "\x00" in raw

    @staticmethod
    def _logical_path_is_invalid(logical: PurePosixPath) -> bool:
        return any(part in {"", ".", ".."} for part in logical.parts[1:])

    def _path(self, raw: str) -> Path:
        if self._raw_path_is_invalid(raw):
            raise _RejectedPath(raw)
        logical = PurePosixPath(raw)
        if self._logical_path_is_invalid(logical):
            raise _RejectedPath(raw)
        root = self.server.root.resolve()
        candidate = root.joinpath(*logical.parts[1:]).resolve(strict=False)
        if os.path.commonpath((root, candidate)) != str(root):
            raise _RejectedPath(raw)
        return candidate

    def _require_path(self, raw: str) -> Path | None:
        try:
            return self._path(raw)
        except (OSError, _RejectedPath, ValueError):
            self._reply(550, "Path unavailable")
            return None

    def _command_user(self, _arg: str) -> None:
        self._reply(331, "Anonymous password required")

    def _command_pass(self, _arg: str) -> None:
        self._reply(230, "Anonymous login accepted")

    def _command_type(self, arg: str) -> None:
        self._reply(200 if arg.upper() == "I" else 504, "Type set")

    def _command_mode(self, arg: str) -> None:
        self._reply(200 if arg.upper() == "S" else 504, "Mode set")

    def _command_feat(self, _arg: str) -> None:
        self.wfile.write(b"211-Features\r\n EPSV\r\n MLSD\r\n REST STREAM\r\n211 End\r\n")
        self.wfile.flush()

    def _command_epsv(self, _arg: str) -> None:
        port = self._open_data_listener()
        self._reply(229, f"Entering Extended Passive Mode (|||{port}|)")

    def _command_pasv(self, _arg: str) -> None:
        port = self._open_data_listener()
        self._reply(227, f"Entering Passive Mode (127,0,0,1,{port >> 8},{port & 255})")

    def _command_rest(self, arg: str) -> None:
        try:
            offset = int(arg, 10)
        except ValueError:
            offset = -1
        if offset < 0:
            self._reply(501, "Invalid restart marker")
            return
        self.rest_offset = offset
        self._reply(350, "Restart marker accepted")

    def _command_size(self, arg: str) -> None:
        path = self._require_path(arg)
        if path is None:
            return
        try:
            size = path.stat().st_size
            if not path.is_file():
                raise OSError
        except OSError:
            self._reply(550, "Not a file")
            return
        self._reply(213, str(size))

    def _command_mdtm(self, arg: str) -> None:
        path = self._require_path(arg)
        if path is None:
            return
        try:
            stamp = datetime.fromtimestamp(path.stat().st_mtime, timezone.utc)
        except OSError:
            self._reply(550, "Path unavailable")
            return
        self._reply(213, stamp.strftime("%Y%m%d%H%M%S"))

    @staticmethod
    def _mlsd_line(path: Path) -> bytes:
        stat = path.stat()
        kind = "dir" if path.is_dir() else "file"
        stamp = datetime.fromtimestamp(stat.st_mtime, timezone.utc)
        facts = f"type={kind};size={stat.st_size};modify={stamp:%Y%m%d%H%M%S};"
        return f"{facts} {path.name}\r\n".encode("utf-8")

    def _command_mlsd(self, arg: str) -> None:
        path = self._require_path(arg)
        if path is None:
            return
        try:
            entries = sorted(path.iterdir(), key=lambda item: item.name)
        except OSError:
            self._reply(550, "Not a directory")
            return
        self._reply(150, "Opening data connection")
        try:
            with self._data_connection() as data:
                for entry in entries:
                    data.sendall(self._mlsd_line(entry))
        except OSError:
            self._reply(426, "Data connection failed")
            return
        self._reply(226, "Listing complete")

    def _command_retr(self, arg: str) -> None:
        path = self._require_path(arg)
        if path is None:
            return
        offset, self.rest_offset = self.rest_offset, 0
        self._reply(150, "Opening data connection")
        try:
            with path.open("rb") as source, self._data_connection() as data:
                source.seek(offset)
                for chunk in iter(lambda: source.read(65536), b""):
                    data.sendall(chunk)
        except OSError:
            self._reply(426, "Data connection failed")
            return
        self._reply(226, "Transfer complete")

    def _command_stor(self, arg: str) -> None:
        path = self._require_path(arg)
        if path is None:
            return
        self._reply(150, "Opening data connection")
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("wb") as output, self._data_connection() as data:
                for chunk in iter(lambda: data.recv(65536), b""):
                    output.write(chunk)
        except OSError:
            self._reply(426, "Data connection failed")
            return
        self._reply(226, "Transfer complete")

    def _command_mkd(self, arg: str) -> None:
        path = self._require_path(arg)
        if path is None:
            return
        try:
            path.mkdir()
        except OSError:
            self._reply(550, "Cannot create directory")
            return
        self._reply(257, "Directory created")

    def _command_dele(self, arg: str) -> None:
        self._remove(arg, directory=False)

    def _command_rmd(self, arg: str) -> None:
        self._remove(arg, directory=True)

    def _remove(self, arg: str, *, directory: bool) -> None:
        path = self._require_path(arg)
        if path is None:
            return
        try:
            path.rmdir() if directory else path.unlink()
        except OSError:
            self._reply(550, "Cannot remove path")
            return
        self._reply(250, "Path removed")

    def _command_rnfr(self, arg: str) -> None:
        path = self._require_path(arg)
        if path is None or not path.exists():
            if path is not None:
                self._reply(550, "Source unavailable")
            return
        self.rename_source = path
        self._reply(350, "Rename destination required")

    def _command_rnto(self, arg: str) -> None:
        destination = self._require_path(arg)
        source, self.rename_source = self.rename_source, None
        if destination is None:
            return
        if source is None:
            self._reply(503, "RNFR required")
            return
        try:
            source.replace(destination)
        except OSError:
            self._reply(550, "Rename failed")
            return
        self._reply(250, "Rename complete")

    def _command_quit(self, _arg: str) -> None:
        self._reply(221, "Goodbye")

    def handle(self):
        commands = {
            "USER": self._command_user, "PASS": self._command_pass,
            "TYPE": self._command_type, "MODE": self._command_mode,
            "FEAT": self._command_feat, "EPSV": self._command_epsv,
            "PASV": self._command_pasv, "REST": self._command_rest,
            "SIZE": self._command_size, "MDTM": self._command_mdtm,
            "MLSD": self._command_mlsd, "RETR": self._command_retr,
            "STOR": self._command_stor, "MKD": self._command_mkd,
            "DELE": self._command_dele, "RMD": self._command_rmd,
            "RNFR": self._command_rnfr, "RNTO": self._command_rnto,
            "NOOP": lambda _arg: self._reply(200, "OK"),
            "PBSZ": lambda _arg: self._reply(200, "OK"),
            "PROT": lambda _arg: self._reply(200, "OK"),
            "DCAU": lambda _arg: self._reply(200, "OK"),
            "QUIT": self._command_quit,
        }
        self._reply(220, "BriX test FTP origin ready")
        while True:
            raw = self.rfile.readline(8192)
            if not raw:
                return
            try:
                line = raw.decode("utf-8").rstrip("\r\n")
            except UnicodeDecodeError:
                self._reply(501, "Invalid command")
                continue
            verb, _, arg = line.partition(" ")
            verb = verb.upper()
            self._audit(verb, arg)
            command = commands.get(verb)
            if command is None:
                self._reply(502, "Command not implemented")
                continue
            command(arg)
            if verb == "QUIT":
                return


class FtpOriginServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, host: str, port: int, root: Path,
                 audit_path: Path | None = None):
        self.bind_host = host
        self.root = root
        self.audit_path = audit_path
        super().__init__((host, port), FtpOriginHandler)


def main() -> int:
    parser = argparse.ArgumentParser(description="confined test FTP origin")
    parser.add_argument("port", type=int)
    parser.add_argument("root", type=Path)
    parser.add_argument("--host", default=HOST)
    parser.add_argument("--audit", type=Path)
    args = parser.parse_args()
    args.root.mkdir(parents=True, exist_ok=True)
    with FtpOriginServer(args.host, args.port, args.root,
                         audit_path=args.audit) as server:
        server.serve_forever(poll_interval=0.1)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
