"""Behaviour shard loaded into the Phase-115 scripted origin."""

class PgOriginDispatchMixin:
    def _consume_writev_payload(self, conn, reqid, body):
        if reqid != kXR_writev:
            return
        total = sum(
            struct.unpack("!I", body[index + 4:index + 8])[0]
            for index in range(0, len(body), 16)
            if index + 16 <= len(body)
        )
        if total:
            self._exact(conn, total)

    def _dispatch_protocol(self, conn, sid, hdr, _body, authenticated):
        self.protocol_calls += 1
        index = getattr(self._connection_context, "index", 0)
        count = getattr(self._connection_context, "postlogin_protocols", 0)
        if authenticated:
            count += 1
            self._connection_context.postlogin_protocols = count
        reply_sid = self._protocol_reply_sid(sid, authenticated, index)
        if self._protocol_disconnect(authenticated, index, count):
            raise ConnectionError("controlled protocol response failure")
        response = self._protocol_fault_response(
            reply_sid, hdr, authenticated, index,
        )
        conn.sendall(response)

    def _protocol_reply_sid(self, sid, authenticated, index):
        bad = self.behaviour == "frame_bad_echo" and authenticated and index > 0
        return bytes([sid[0] ^ 1, sid[1]]) if bad else sid

    def _protocol_disconnect(self, authenticated, index, count):
        cases = (
            self.behaviour == "protocol_aux_missing" and index > 0,
            self.behaviour == "frame_protocol_close" and authenticated and index > 0,
            self.behaviour == "frame_bytewise_reject" and authenticated and index == 2,
            self.behaviour == "frame_drop_second_protocol"
            and authenticated and index > 0 and count == 2,
        )
        return any(cases)

    def _protocol_fault_response(self, sid, hdr, authenticated, index):
        handlers = {
            "protocol_aux_short": self._protocol_aux_short_response,
            "frame_protocol_error": self._protocol_error_response,
            "frame_reject_padding": self._protocol_padding_response,
            "protocol_refuse_legacy": self._protocol_legacy_response,
            "protocol_unknown_reject": self._protocol_expect_response,
        }
        handler = handlers.get(self.behaviour)
        response = handler(sid, hdr, authenticated, index) if handler else None
        if response is not None:
            return response
        return ok_frame(sid, self._protocol_body(hdr))

    @staticmethod
    def _protocol_aux_short_response(sid, _hdr, _authenticated, index):
        return ok_frame(sid, b"\x00" * 4) if index > 0 else None

    @staticmethod
    def _protocol_error_response(sid, _hdr, authenticated, index):
        if authenticated and index > 0:
            return error_frame(sid, kXR_Unsupported, b"protocol refused")
        return None

    @staticmethod
    def _protocol_padding_response(sid, hdr, authenticated, _index):
        if authenticated and hdr[10:20] == b"\xff" * 10:
            return error_frame(sid, kXR_InvalidRequest, b"padding rejected")
        return None

    @staticmethod
    def _protocol_legacy_response(sid, hdr, _authenticated, _index):
        if struct.unpack("!I", hdr[4:8])[0] == 0x100:
            return error_frame(sid, kXR_Unsupported, b"legacy refused")
        return None

    @staticmethod
    def _protocol_expect_response(sid, hdr, _authenticated, _index):
        if hdr[9] > kXR_ExpMask:
            return error_frame(sid, kXR_Unsupported, b"unknown expect")
        return None

    def _dispatch_second_handshake(self, conn, sid, _hdr, _body, _auth):
        if self.behaviour == "second_handshake_ok":
            conn.sendall(ok_frame(sid))
            return
        self._send_unsupported(conn, sid)

    def _dispatch_login(self, conn, sid, _hdr, _body, _auth):
        index = getattr(self._connection_context, "index", 0)
        if self.behaviour == "login_short_aux" and index > 0:
            conn.sendall(ok_frame(sid, b"\x00" * 15))
            return
        if self.behaviour == "login_shape_refuse" and index > 0:
            conn.sendall(error_frame(sid, kXR_NotAuthorized,
                                     b"login shape refused"))
            return
        conn.sendall(ok_frame(sid, b"\x00" * 16))

    def _dispatch_auth(self, conn, sid, _hdr, _body, _auth):
        if self.behaviour == "prelogin_auth_ok":
            conn.sendall(ok_frame(sid))
            return
        self._send_unsupported(conn, sid)

    def _dispatch_query(self, conn, sid, hdr, body, _auth):
        infotype = struct.unpack("!H", hdr[4:6])[0]
        key = body.rstrip(b"\x00")
        response = self._query_response(infotype, key, body)
        conn.sendall(response(sid))

    def _query_response(self, infotype, key, body):
        if infotype == 7:
            return self._config_query_response(key)
        handlers = {
            ("query_wrong_sha", 3): lambda sid: ok_frame(sid, b"sha256 00"),
            ("query_same_crc", 3): lambda sid: ok_frame(sid, b"checksum 0000"),
            ("query_bad_space", 5): lambda sid: ok_frame(sid, b"oss.space=1 oss.free=2"),
            ("query_bad_qprep", 2): lambda sid: ok_frame(sid, b"bad status"),
        }
        if (self.behaviour == "query_unknown_success" and infotype == 3
                and b"brix-unknown" in body):
            return lambda sid: ok_frame(sid, b"sha256 00")
        if (self.behaviour == "query_optional_server_error"
                and infotype in (8, 16, 32, 64)):
            return lambda sid: error_frame(
                sid, kXR_ServerError, b"optional query failed",
            )
        return handlers.get(
            (self.behaviour, infotype),
            lambda sid: error_frame(sid, kXR_Unsupported, b"no"),
        )

    def _config_query_response(self, key):
        if key == b"bind_max":
            value = b"2" if self.behaviour == "concurrent_write_ack" else b"1"
            return lambda sid: ok_frame(sid, value)
        if key == b"brix.substreams":
            return lambda sid: ok_frame(sid, b"brix.substreams=rw")
        if self.behaviour.startswith("rdv_") and key == b"readv_ior_max":
            return lambda sid: ok_frame(sid, b"2097136")
        if self.behaviour.startswith("rdv_") and key == b"readv_iov_max":
            value = b"1023" if self.behaviour == "rdv_bad_019" else b"1024"
            return lambda sid: ok_frame(sid, value)
        return lambda sid: error_frame(sid, kXR_Unsupported, b"no")

    def _dispatch_prepare(self, conn, sid, hdr, body, _auth):
        handlers = {
            "query_bad_qprep": self._prepare_qprep,
            "prepare_cancel_nonidempotent": self._prepare_cancel,
            "prepare_missing_ack": self._prepare_missing,
            "prepare_notify_poison": self._prepare_notify,
        }
        handler = handlers.get(self.behaviour)
        if handler is None:
            self._send_unsupported(conn, sid)
            return
        handler(conn, sid, hdr, body)

    @staticmethod
    def _prepare_qprep(conn, sid, _hdr, _body):
        conn.sendall(ok_frame(sid, b"controlled-request-id\n"))

    def _prepare_cancel(self, conn, sid, hdr, _body):
        if not hdr[4] & 0x01:
            conn.sendall(ok_frame(sid, b"controlled-request-id\n"))
            return
        with self._lock:
            self.cancels += 1
            sequence = self.cancels
        if sequence == 1:
            conn.sendall(ok_frame(sid))
            return
        conn.sendall(error_frame(sid, kXR_NotFound, b"cancel id vanished"))

    def _prepare_missing(self, conn, sid, _hdr, body):
        if b".__prepare_missing__" in body:
            conn.sendall(ok_frame(sid, b"accepted-missing\n"))
            return
        self._send_unsupported(conn, sid)

    def _prepare_notify(self, conn, sid, _hdr, _body):
        self._connection_context.notify_poisoned = True
        conn.sendall(ok_frame(sid, b"notify-accepted\n"))

    def _dispatch_bind(self, conn, sid, _hdr, _body, _auth):
        pathid = self._allocate_pathid(conn)
        if self.behaviour == "bind_zero_pathid":
            conn.sendall(ok_frame(sid, b"\x00"))
            return
        if pathid == 0:
            conn.sendall(error_frame(sid, 3002, b"bind limit"))
            return
        self._connection_context.pathid = pathid
        conn.sendall(ok_frame(sid, bytes([pathid])))

    def _allocate_pathid(self, conn):
        with self._lock:
            pathid = self.next_pathid
            limited = (self.behaviour not in (
                "bind_limit_ignored", "bind_corrupt", "concurrent_write_ack",
            ) and self.bound_connections)
            if limited:
                return 0
            if pathid <= 253:
                self.next_pathid += 1
                self.bound_connections[pathid] = conn
            return pathid

    def _dispatch_ping(self, conn, sid, _hdr, _body, _auth):
        if self.behaviour == "frame_drop_surplus_ping":
            raise ConnectionError("controlled dropped surplus frame")
        conn.sendall(ok_frame(sid))

    def _dispatch_fattr(self, conn, sid, _hdr, _body, _auth):
        if self.behaviour == "fattr_server_error":
            conn.sendall(error_frame(sid, kXR_ServerError,
                                     b"fattr internal error"))
            return
        self._send_unsupported(conn, sid)

    def _dispatch_open(self, conn, sid, hdr, body, _auth):
        options = struct.unpack("!H", hdr[6:8])[0]
        handlers = {
            "reject_opaque": self._open_reject_opaque,
            "open_short_handle": self._open_short_handle,
            "open_refresh_stale": self._open_refresh_stale,
            "open_bad_compress": self._open_bad_compress,
            "open_server_error_options": self._open_server_error,
        }
        handler = handlers.get(self.behaviour)
        if handler is not None and handler(conn, sid, body, options):
            return
        self._record_open_advisory(options)
        conn.sendall(self._open_frame(sid))

    @staticmethod
    def _open_reject_opaque(conn, sid, body, _options):
        if b"?cap=controlled" not in body:
            return False
        conn.sendall(error_frame(sid, kXR_NotAuthorized, b"opaque rejected"))
        return True

    @staticmethod
    def _open_short_handle(conn, sid, _body, _options):
        conn.sendall(ok_frame(sid, b"\x01\x02\x03"))
        return True

    @staticmethod
    def _open_refresh_stale(conn, sid, body, _options):
        if b"brix-conform-open-refresh" not in body:
            return False
        conn.sendall(ok_frame(
            sid, struct.pack("!I", 7) + b"\x00" * 8 + b"0 3 0 0",
        ))
        return True

    @staticmethod
    def _open_bad_compress(conn, sid, _body, options):
        if not options & 0x0001:
            return False
        conn.sendall(ok_frame(
            sid, struct.pack("!II", 7, 1) + b"\xff\x00\x00\x00",
        ))
        return True

    @staticmethod
    def _open_server_error(conn, sid, _body, options):
        if options != 0x0001:
            return False
        conn.sendall(error_frame(sid, kXR_ServerError, b"option internal error"))
        return True

    def _record_open_advisory(self, options):
        if self.behaviour == "open_advisory_corrupt" \
                and options & (0x0040 | 0x4000):
            self._connection_context.corrupt_reads = True

    def _dispatch_stat(self, conn, sid, _hdr, body, _auth):
        handlers = {
            "frame_reject_nul": self._stat_reject_nul,
            "stat_not_found": self._stat_not_found,
            "frame_slow_drop": self._stat_slow_drop,
            "open_cgi_storage_path": self._stat_cgi_path,
        }
        handler = handlers.get(self.behaviour)
        if handler is not None and handler(conn, sid, body):
            return
        self._ordinary_stat(conn, sid, body)

    @staticmethod
    def _stat_reject_nul(conn, sid, body):
        if not body.endswith(b"\x00"):
            return False
        conn.sendall(error_frame(sid, kXR_ArgInvalid, b"terminal nul rejected"))
        return True

    @staticmethod
    def _stat_not_found(conn, sid, _body):
        conn.sendall(error_frame(sid, kXR_NotFound, b"not found"))
        return True

    @staticmethod
    def _stat_slow_drop(_conn, _sid, body):
        if body != b"/":
            return False
        raise ConnectionError("controlled unresolved slow payload")

    @staticmethod
    def _stat_cgi_path(conn, sid, body):
        if b"brix-conform-open-cgi" not in body:
            return False
        conn.sendall(error_frame(sid, kXR_NotFound, b"bare path not found"))
        return True

    def _ordinary_stat(self, conn, sid, body):
        with self._lock:
            self.stats += 1
            sequence = self.stats
        poisoned = (self.behaviour == "prepare_notify_poison"
                    and getattr(self._connection_context,
                                "notify_poisoned", False))
        if poisoned:
            conn.sendall(error_frame(sid, kXR_ServerError,
                                     b"notification poisoned session"))
            return
        if not self._flow_stat(conn, sid):
            conn.sendall(ok_frame(sid, self._stat_string(body, sequence) + b"\x00"))

    def _dispatch_locate(self, conn, sid, hdr, body, _auth):
        options = struct.unpack("!H", hdr[4:6])[0]
        if body.endswith(b".__brix_missing__") \
                and self.behaviour != "locate_missing_ok":
            conn.sendall(error_frame(sid, kXR_NotFound, b"not found"))
            return
        replies = {
            "locate_empty": b"",
            "locate_bad_shape": b"Xz127.0.0.1:1",
            "locate_ghost": b"Sr127.0.0.1:1",
        }
        if self.behaviour in replies:
            conn.sendall(ok_frame(sid, replies[self.behaviour]))
            return
        conn.sendall(ok_frame(sid, self._locate_body(options)))

    def _locate_body(self, options):
        self._locate_delay(options)
        host = self._locate_host(options)
        return f"Sr{host}:{self.port}".encode()

    def _locate_delay(self, options):
        if self.behaviour == "locate_nowait_slow" and options & 0x2000:
            time.sleep(2.2)

    def _locate_host(self, options):
        preferred = options & 0x0100 and self.behaviour != "locate_prefname_numeric"
        refreshed = self.behaviour == "locate_refresh_changes" and options & 0x0080
        return "localhost" if preferred or refreshed else "127.0.0.1"  # net-literal-allow: fixture contrasts preferred name and numeric address

    def _dispatch_dirlist(self, conn, sid, hdr, body, _auth):
        options = hdr[19]
        if self._dirlist_special(conn, sid, body, options):
            return
        if self._dirlist_path_error(conn, sid, body):
            return
        listing = self._dstat_listing() if options & 0x02 else b"fixture\n"
        conn.sendall(ok_frame(sid, listing))

    def _dirlist_special(self, conn, sid, body, options):
        if self.behaviour == "dir_large_single_frame" \
                and b"brix-conform-dir-large" in body:
            conn.sendall(ok_frame(sid, self._large_dir_listing()))
            return True
        if self.behaviour == "dir_control_inconsistent" \
                and b"brix-conform-dir" in body:
            listing = b".\n0 0 0 0\n" if options & 0x02 else b"fixture\n"
            conn.sendall(ok_frame(sid, listing))
            return True
        return False

    def _dirlist_path_error(self, conn, sid, body):
        if body.endswith(b"/..") and self.behaviour != "dir_escape_success":
            conn.sendall(error_frame(sid, kXR_NotAuthorized,
                                     b"parent traversal refused"))
            return True
        if body == b"/fixture" and self.behaviour != "dir_file_success":
            conn.sendall(error_frame(sid, kXR_isDirectory, b"not a directory"))
            return True
        return False

    @staticmethod
    def _large_dir_listing():
        names = []
        for index in range(276):
            prefix = f"{index:03d}-".encode()
            names.append(prefix + b"x" * (240 - len(prefix)))
        return b"\n".join(names) + b"\n"

    def _dstat_listing(self):
        return {
            "dir_dstat_count_mismatch": b".\n0 0 0 0\n",
            "dir_dstat_bad_sentinel": b"!\n0 0 0 0\nfixture\n8192 0 0 0\n",
        }.get(self.behaviour, b".\n0 0 0 0\nfixture\n8192 0 0 0\n")

    def _dispatch_read(self, conn, sid, hdr, body, _auth):
        self._read(conn, sid, hdr, body)

    def _dispatch_readv(self, conn, sid, _hdr, body, _auth):
        self._readv(conn, sid, body)

    @staticmethod
    def _dispatch_write(conn, sid, _hdr, _body, _auth):
        conn.sendall(ok_frame(sid))

    def _dispatch_writev(self, conn, sid, _hdr, _body, _auth):
        if self.behaviour == "writev_ack":
            conn.sendall(ok_frame(sid))
            return
        if self.behaviour == "writev_server_error":
            conn.sendall(error_frame(sid, kXR_ServerError,
                                     b"writev internal error"))
            return
        self._send_unsupported(conn, sid)

    def _dispatch_sync(self, conn, sid, _hdr, _body, _auth):
        if self.behaviour == "sync_server_error":
            conn.sendall(error_frame(sid, kXR_ServerError,
                                     b"sync internal error"))
            return
        self._send_unsupported(conn, sid)

    def _dispatch_checkpoint(self, conn, sid, hdr, _body, _auth):
        if self.behaviour == "checkpoint_server_error":
            conn.sendall(error_frame(sid, kXR_ServerError,
                                     b"checkpoint internal error"))
            return
        supported = self.behaviour in (
            "checkpoint_bad_capacity", "checkpoint_no_rollback",
            "checkpoint_accept",
        )
        if not supported:
            self._send_unsupported(conn, sid)
            return
        self._checkpoint_reply(conn, sid, hdr[19])

    def _checkpoint_reply(self, conn, sid, opcode):
        if opcode != 2:
            conn.sendall(ok_frame(sid))
            return
        capacity = ((1, 2) if self.behaviour == "checkpoint_bad_capacity"
                    else (1048576, 16))
        conn.sendall(ok_frame(sid, struct.pack("!II", *capacity)))

    def _dispatch_truncate(self, conn, sid, _hdr, _body, _auth):
        if self.behaviour == "large_offset_wrong":
            conn.sendall(ok_frame(sid))
            return
        self._send_unsupported(conn, sid)

    def _dispatch_pgwrite(self, conn, sid, hdr, _body, _auth):
        if self.behaviour not in ("pgwrite_ack", "pgwrite_unclaimed_ack"):
            self._send_unsupported(conn, sid)
            return
        offset = struct.unpack("!q", hdr[8:16])[0]
        conn.sendall(pgread_status_frame(
            sid, offset, 0, requestid=kXR_pgwrite - kXR_1stRequest,
        ))

    def _dispatch_pgread(self, conn, sid, hdr, body, _auth):
        self._pgread(conn, sid, hdr, body)

    def _dispatch_close(self, conn, sid, hdr, _body, _auth):
        if self.behaviour == "close_reserved_corrupt" \
                and hdr[8:20] != b"\x00" * 12:
            self._connection_context.corrupt_reads = True
        conn.sendall(ok_frame(sid))

    def _dispatch_mkdir(self, conn, sid, _hdr, _body, _auth):
        if self.behaviour in ("mkdir_bad_mode", "dir_large_single_frame"):
            conn.sendall(ok_frame(sid))
            return
        self._send_unsupported(conn, sid)

    def _dispatch_move(self, conn, sid, _hdr, _body, _auth):
        with self._lock:
            self.moves += 1
            sequence = self.moves
        if self.behaviour == "move_inconsistent" and sequence <= 2:
            conn.sendall(ok_frame(sid))
            return
        if self.behaviour == "move_inconsistent":
            conn.sendall(error_frame(sid, kXR_NotAuthorized, b"policy changed"))
            return
        self._send_unsupported(conn, sid)

    def _dispatch_remove(self, conn, sid, _hdr, body, _auth):
        file_error = (self.behaviour == "rm_file_error"
                      and b"brix-conform-ns/rm-file" in body)
        dir_error = (self.behaviour == "rm_dir_wrong"
                     and b"brix-conform-ns/empty" in body)
        if file_error or dir_error:
            conn.sendall(error_frame(sid, kXR_NotAuthorized,
                                     b"controlled refusal"))
            return
        conn.sendall(ok_frame(sid))

    def _dispatch_rmdir(self, conn, sid, _hdr, _body, _auth):
        if self.behaviour in ("rmdir_file_ack", "dir_large_single_frame"):
            conn.sendall(ok_frame(sid))
            return
        self._send_unsupported(conn, sid)

    def _dispatch_chmod(self, conn, sid, _hdr, _body, _auth):
        with self._lock:
            self.chmods += 1
            sequence = self.chmods
        if self.behaviour == "chmod_not_reversible" and sequence < 3:
            conn.sendall(ok_frame(sid))
            return
        if self.behaviour == "chmod_not_reversible":
            conn.sendall(error_frame(sid, kXR_NotAuthorized, b"restore refused"))
            return
        self._send_unsupported(conn, sid)

    def _dispatch_gpfile(self, conn, sid, _hdr, _body, _auth):
        if self.behaviour == "gpfile_ok":
            conn.sendall(ok_frame(sid))
            return
        if self.behaviour == "env_gpfile_server_error":
            conn.sendall(error_frame(sid, kXR_ServerError,
                                     b"gpfile internal error"))
            return
        self._send_unsupported(conn, sid)

    def _dispatch_unsupported(self, conn, sid, _hdr, _body, _auth):
        if self.behaviour == "frame_server_error_valid":
            conn.sendall(error_frame(sid, kXR_ServerError,
                                     b"generic server error"))
            return
        self._send_unsupported(conn, sid)

    @staticmethod
    def _send_unsupported(conn, sid):
        conn.sendall(error_frame(sid, kXR_Unsupported, b"no"))
