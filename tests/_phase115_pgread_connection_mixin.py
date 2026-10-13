"""Behaviour shard loaded into the Phase-115 scripted origin."""

class PgOriginConnectionMixin:
    def _serve(self, conn):
        conn.settimeout(15)
        try:
            self._initialize_connection_context()
            self._reject_poisoned_connection()
            if not self._perform_handshake(conn):
                return
            self._request_loop(conn)
        except (OSError, ConnectionError, struct.error):
            return
        finally:
            self._release_bound_connection(conn)
            try:
                conn.close()
            except OSError:
                pass

    def _initialize_connection_context(self):
        with self._lock:
            self._connection_context.index = self.connections
            self.connections += 1
        self._connection_context.postlogin_protocols = 0
        self._connection_context.corrupt_reads = False
        self._connection_context.pathid = 0
        self._connection_context.notify_poisoned = False
        self._connection_context.flow_stats = 0

    def _reject_poisoned_connection(self):
        failures = {
            "handshake_poison_recovery": "controlled leaked handshake state",
            "frame_poison_recovery": "controlled wedged framing state",
        }
        message = failures.get(self.behaviour)
        if message is not None and self._connection_context.index == 3:
            raise ConnectionError(message)

    def _perform_handshake(self, conn):
        handshake = self._exact(conn, 20)
        if self._tls_handshake_refused(handshake):
            return False
        if self._missing_aux_handshake():
            return False
        if self._legacy_aux_handshake(conn):
            return False
        version = self._handshake_version()
        conn.sendall(struct.pack("!HHI", 0, 0, 8)
                     + struct.pack("!II", version, 1))
        return True

    def _tls_handshake_refused(self, handshake):
        return (self.behaviour in ("claim_tls_broken", "claim_gototls_broken")
                and handshake.startswith(b"\x16\x03"))

    def _missing_aux_handshake(self):
        return (self.behaviour == "handshake_aux_missing"
                and self._connection_context.index == 1)

    def _legacy_aux_handshake(self, conn):
        legacy = (self.behaviour == "handshake_aux_legacy"
                  and self._connection_context.index == 1)
        if legacy:
            conn.sendall(b"\x00" * 12)
        return legacy

    def _handshake_version(self):
        bad = (self.behaviour == "handshake_aux_bad_version"
               and self._connection_context.index == 1)
        return 0x00000200 if bad else 0x00000310

    def _request_loop(self, conn):
        authenticated = False
        while not self._closing:
            hdr = self._exact(conn, 24)
            sid = hdr[:2]
            reqid = struct.unpack("!H", hdr[2:4])[0]
            dlen = struct.unpack("!I", hdr[20:24])[0]
            if self._accept_oversized_request(conn, sid, reqid, dlen):
                return
            body = self._exact(conn, dlen) if dlen else b""
            authenticated = self._dispatch(
                conn, sid, reqid, hdr, body, authenticated,
            )

    def _accept_oversized_request(self, conn, sid, reqid, dlen):
        if not self._oversized_write(reqid, dlen) \
                and not self._extreme_frame(dlen):
            return False
        conn.sendall(ok_frame(sid))
        return True

    def _oversized_write(self, reqid, dlen):
        return (self.behaviour == "write_oversized_accept"
                and reqid == kXR_write and dlen > 16777216)

    def _extreme_frame(self, dlen):
        return self.behaviour == "frame_accept_extreme" and dlen >= 0x7fffffff

    def _release_bound_connection(self, conn):
        pathid = getattr(self._connection_context, "pathid", 0)
        if not pathid:
            return
        with self._lock:
            if self.bound_connections.get(pathid) is conn:
                del self.bound_connections[pathid]
