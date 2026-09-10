"""Small RFC-959 / GridFTP origin used to prove the outbound FTP storage driver.

This is deliberately an origin, not a fake of the driver API: every test crosses
real control and passive data sockets.  It implements the portable MODE-S
commands BriX consumes, GFD.020 MODE E extended block mode (phase-115 W5.1),
and confines every pathname beneath the supplied root.

Four switches exist ONLY so the driver's refusals and fallbacks can be proven,
and each defaults to the permissive/conforming behaviour:

  * `mode_e=False` — answer `MODE E` 504, so a `mode=e` store line meets an
    origin that cannot do it and must fail rather than silently fall back;
  * `data_tls=None` — `PROT P` is refused (534), so a `prot=p` store line
    proves it never downgrades to a cleartext data channel;
  * `eb_fault=` — emit a MODE E block stream a conforming sender never would
    (see ftp_origin_mode_e.FAULTS);
  * `eret=True` — advertise and implement `ERET P` (phase-115 W5.2).  Off by
    default so the MODE E suites keep meeting the RFC 959 REST+RETR path they
    were written against; the two ERET misbehaviours a driver has to survive are
    addressed BY NAME instead (see ERET_FAULTS).
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import os
from pathlib import Path, PurePosixPath
import socket
import socketserver

from ephemeral_port import free_port
from brix_suite.servers import ftp_origin_mode_e as eb
from brix_suite.servers import ftp_origin_retrieve
from brix_suite.servers import ftp_origin_striped as spas
from brix_suite.settings import HOST


#: Re-exported from ftp_origin_retrieve, which owns the code that injects them.
#: Kept here because `ftp_origin_server.ERET_FAULTS` is the name the W5.2 suite
#: already imports, and a move is not a reason to break a caller.
ERET_FAULTS = ftp_origin_retrieve.ERET_FAULTS


class _RejectedPath(ValueError):
    pass


class FtpOriginHandler(ftp_origin_retrieve.FtpOriginRetrieveMixin,
                       socketserver.StreamRequestHandler):
    timeout = 15

    def setup(self):
        super().setup()
        self.data_listener = None
        self.stripes = []
        self.rest_offset = 0
        self.rename_source = None
        self.mode = "S"
        self.prot = "C"

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
        # A later EPSV/PASV/SPAS SUPERSEDES the previous advertisement, so any
        # stripe listener nobody dialled is closed here rather than left to the
        # connection's end.  A driver that falls back from SPAS to EPSV would
        # otherwise leave n-1 sockets listening for the length of the session.
        spas.close_listeners(self.stripes)
        self.stripes = []

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
        if self.prot == "P":
            # PROT P is a straight TLS session on the data socket presenting the
            # same credential as the control channel — never a second dialect.
            connection = self.server.data_tls.wrap_socket(connection,
                                                          server_side=True)
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
        want = arg.upper()
        if want == "S" or (want == "E" and self.server.mode_e):
            self.mode = want
            self._reply(200, "Mode set")
            return
        # An origin that cannot do MODE E must say so; the driver may not
        # quietly transfer in MODE S after asking for E.
        self._reply(504, "Mode not implemented")

    def _command_feat(self, _arg: str) -> None:
        """211 feature list.

        The optional half is a table rather than a run of ifs because it is one
        rule applied four times — "advertise it only if this origin was started
        with it" — and a fifth feature should be a row, not a new branch.
        """
        lines = ["211-Features", " EPSV", " MLSD", " REST STREAM"]
        optional = ((self.server.mode_e, [" MODE E"]),
                    (self.server.eret, [" ERET"]),
                    (self.server.spas, [" SPAS"]),
                    (self.server.feat_decoy, FEAT_DECOY),
                    (self.server.data_tls is not None, [" DCAU", " PROT"]))
        for enabled, names in optional:
            if enabled:
                lines += names
        lines.append("211 End")
        # CRLF, per RFC 959 §4.2 — not a detail of this fixture.  A probe that
        # only recognises a feature name followed by a space, a tab or a NUL
        # matches nothing at all against a conforming door, and the fallback it
        # then takes is silent; ftp_origin_feat_bytes() below exists so that
        # this line cannot quietly become "\n" and re-hide it.
        self.wfile.write(("\r\n".join(lines) + "\r\n").encode("ascii"))
        self.wfile.flush()

    def _command_epsv(self, _arg: str) -> None:
        port = self._open_data_listener()
        self._reply(229, f"Entering Extended Passive Mode (|||{port}|)")

    def _command_pasv(self, _arg: str) -> None:
        port = self._open_data_listener()
        self._reply(227, f"Entering Passive Mode (127,0,0,1,{port >> 8},{port & 255})")

    def _command_spas(self, _arg: str) -> None:
        """GFD.020 §5.1 striped passive: several listeners, one reply.

        Refused when the origin was not started striped, because a door that
        answers SPAS after leaving it out of FEAT is a different (and also
        tested) shape from one that advertises it.
        """
        if not self.server.spas:
            self._reply(502, "Command not implemented")
            return
        self._close_data_listener()
        self.stripes = spas.open_listeners(self.server.bind_host,
                                           self.server.spas, self.timeout)
        self.wfile.write(spas.spas_reply(self.stripes,
                                         self.server.spas_host))
        self.wfile.flush()

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


    def _command_stor(self, arg: str) -> None:
        path = self._require_path(arg)
        if path is None:
            return
        self._reply(150, "Opening data connection")
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("wb") as output, self._data_connection() as data:
                if self.mode == "E":
                    output.write(eb.recv_transfer(data))
                else:
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

    def _command_prot(self, arg: str) -> None:
        want = (arg or "C").upper()
        if want == "C":
            self.prot = "C"
            self._reply(200, "Protection level set")
            return
        if want == "P" and self.server.data_tls is not None:
            self.prot = "P"
            self._reply(200, "Protection level set")
            return
        # 534 is the RFC 2228 "request denied for policy reasons".  Refusing it
        # here is the only way to prove the driver fails CLOSED rather than
        # transferring in the clear after asking for protection.
        self._reply(534, "Protection level not supported")

    def _command_dcau(self, arg: str) -> None:
        want = (arg or "N").upper()
        if want == "N" or (want == "A" and self.server.data_tls is not None):
            self._reply(200, "Data channel authentication set")
            return
        self._reply(504, "DCAU mode not supported")

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
            "ERET": self._command_eret, "SPAS": self._command_spas,
            "STOR": self._command_stor, "MKD": self._command_mkd,
            "DELE": self._command_dele, "RMD": self._command_rmd,
            "RNFR": self._command_rnfr, "RNTO": self._command_rnto,
            "NOOP": lambda _arg: self._reply(200, "OK"),
            "PBSZ": lambda _arg: self._reply(200, "OK"),
            "PROT": self._command_prot,
            "DCAU": self._command_dcau,
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


#: FEAT rows that CONTAIN a feature name without ADVERTISING it.
#:
#: RFC 2389 §3.2 makes a feature line a verb plus optional parameters, so the
#: probe matches the leading TOKEN of a line and never a substring of the reply.
#: These are the four ways that rule is broken by a probe written with strstr:
#: a longer verb sharing the prefix, the name as an ARGUMENT of another verb,
#: the same for the striped extension, and a vendor-prefixed spelling.  An
#: origin started with `--feat-decoy` and WITHOUT `--eret`/`--spas` answers 502
#: to both commands, so a driver that lit either bit on one of these rows is
#: caught by the origin's own audit log and not merely by a slower transfer.
FEAT_DECOY = (" ERETSTAT", " SITE ERET", " SPASV", " X-ERET")


class FtpOriginServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, host: str, port: int, root: Path,
                 audit_path: Path | None = None, **options):
        self.bind_host = host
        self.root = root
        self.audit_path = audit_path
        self.mode_e = options.pop("mode_e", True)
        self.data_tls = options.pop("data_tls", None)
        self.eb_fault = options.pop("eb_fault", None)
        self.eb_chunk = options.pop("eb_chunk", eb.CHUNK)
        self.eret = options.pop("eret", False)
        self.spas = options.pop("spas", 0)
        self.feat_decoy = options.pop("feat_decoy", False)
        self.spas_host = options.pop("spas_host", None) or host
        if options:
            raise TypeError(f"unknown options {sorted(options)}")
        super().__init__((host, port), FtpOriginHandler)


def _data_tls_context(cert: Path | None, key: Path | None):
    """A server-side TLS context for the PROT P data channel, or None.

    Deliberately the SAME certificate the operator points the control channel
    at: the driver pins the data peer's DN to the control channel's, so a
    separate data certificate would (correctly) be refused, and a test origin
    that used one could not prove the pin holds.
    """
    if cert is None:
        return None
    import ssl

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(cert), str(key) if key else None)
    return context


def ftp_origin_feat_bytes(host: str, port: int, timeout: float = 10.0) -> bytes:
    """The RAW bytes of one origin's FEAT reply, terminators and all.

    A census witness, not a convenience: the whole ERET/SPAS extension turned on
    the probe recognising a name followed by a CR, and every functional test in
    the suite reads the same right bytes whether the extension was negotiated or
    silently skipped.  Returning the reply unparsed lets a test assert what is
    actually on the wire, so the fixture cannot drift to bare LF and take the
    coverage with it.
    """
    import socket

    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        reply = b""
        sock.recv(4096)                      # 220 greeting
        sock.sendall(b"FEAT\r\n")
        while b"211 End" not in reply:
            more = sock.recv(4096)
            if not more:
                break
            reply += more
        sock.sendall(b"QUIT\r\n")
    return reply


def main() -> int:
    parser = argparse.ArgumentParser(description="confined test FTP origin")
    parser.add_argument("port", type=int)
    parser.add_argument("root", type=Path)
    parser.add_argument("--host", default=HOST)
    parser.add_argument("--audit", type=Path)
    parser.add_argument("--no-mode-e", action="store_true",
                        help="answer MODE E 504 (an origin that cannot do it)")
    parser.add_argument("--data-cert", type=Path,
                        help="enable PROT P/DCAU A on the data channel")
    parser.add_argument("--data-key", type=Path)
    parser.add_argument("--eb-fault", choices=sorted(eb.FAULTS),
                        help="emit a non-conforming MODE E block stream")
    parser.add_argument("--eb-chunk", type=int, default=eb.CHUNK)
    parser.add_argument("--eret", action="store_true",
                        help="advertise and implement ERET P (phase-115 W5.2)")
    parser.add_argument("--spas", type=int, default=0, metavar="N",
                        help="advertise SPAS and stripe over N data "
                             "connections (phase-115 W5.3)")
    parser.add_argument("--feat-decoy", action="store_true",
                        help="advertise look-alike feature rows (ERETSTAT, "
                             "SITE ERET, ...) that must light no bit")
    parser.add_argument("--spas-host", default=None, metavar="ADDR",
                        help="advertise the stripes on ADDR instead of the "
                             "bind host — the FTP-bounce negative")
    args = parser.parse_args()
    args.root.mkdir(parents=True, exist_ok=True)
    with FtpOriginServer(args.host, args.port, args.root,
                         audit_path=args.audit,
                         mode_e=not args.no_mode_e,
                         data_tls=_data_tls_context(args.data_cert,
                                                    args.data_key),
                         eb_fault=args.eb_fault,
                         eb_chunk=args.eb_chunk,
                         eret=args.eret,
                         spas=args.spas,
                         feat_decoy=args.feat_decoy,
                         spas_host=args.spas_host) as server:
        server.serve_forever(poll_interval=0.1)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
