"""Behaviour shard loaded into the Phase-115 scripted origin."""

class PgOriginReadMixin:
    def _pgread(self, conn, sid, hdr, request_args=b""):
        with self._lock:
            self.pgreads += 1
            pgread_sequence = self.pgreads
        offset, rlen = struct.unpack("!qi", hdr[8:20])
        if ((offset < 0 or rlen < 0)
                and self.behaviour != "pg_accept_negative"):
            conn.sendall(error_frame(sid, kXR_ArgInvalid,
                                     b"invalid pgread range"))
            return
        if self._pgread_special(conn, sid, offset, rlen, request_args):
            return
        data = self._pgread_data(offset, rlen, request_args, pgread_sequence)
        self._send_pgread(conn, sid, offset, data)

    def _pgread_special(self, conn, sid, offset, rlen, request_args):
        handlers = {
            "pg_plain_ok": self._pgread_plain_ok,
            "pg_short_status": self._pgread_short_status,
            "pg_reject_zero": self._pgread_reject_zero,
            "pg_bad_args": self._pgread_bad_args,
            "pg_bad_any": self._pgread_bad_any,
            "refuse": self._pgread_refuse,
            "empty_partial": self._pgread_empty_partial,
        }
        handler = handlers.get(self.behaviour)
        return handler(conn, sid, offset, rlen, request_args) if handler else False

    @staticmethod
    def _pgread_plain_ok(conn, sid, _offset, _rlen, _args):
        conn.sendall(ok_frame(sid))
        return True

    @staticmethod
    def _pgread_short_status(conn, sid, _offset, _rlen, _args):
        conn.sendall(sid + struct.pack("!HI", kXR_status, 8) + b"\x00" * 8)
        return True

    @staticmethod
    def _pgread_reject_zero(conn, sid, _offset, rlen, _args):
        if rlen != 0:
            return False
        conn.sendall(error_frame(sid, kXR_ArgInvalid, b"zero pgread refused"))
        return True

    @staticmethod
    def _pgread_bad_args(conn, sid, _offset, _rlen, request_args):
        if len(request_args) not in (1, 2, 3):
            return False
        conn.sendall(error_frame(sid, kXR_ArgInvalid, b"argument shape refused"))
        return True

    @staticmethod
    def _pgread_bad_any(conn, sid, _offset, _rlen, request_args):
        if request_args != b"\xff":
            return False
        conn.sendall(error_frame(sid, kXR_ArgInvalid, b"any path refused"))
        return True

    @staticmethod
    def _pgread_refuse(conn, sid, _offset, _rlen, _args):
        conn.sendall(error_frame(
            sid, kXR_Unsupported, b"pgread not supported here",
        ))
        return True

    def _pgread_empty_partial(self, conn, sid, offset, _rlen, _args):
        while not self._closing:
            conn.sendall(pgread_status_frame(
                sid, offset, 0, kXR_PartialResult,
            ))
        return True

    def _pgread_data(self, offset, rlen, request_args, sequence):
        data = self.payload[offset:offset + max(rlen, 0)]
        targeted_shapes = {
            "pg_bad_008": (0, 8192),
            "pg_bad_009": (1, 4095),
            "pg_bad_010": (0, 4097),
            "pg_bad_011": (1, 4096),
            "pg_bad_012": (17, 31),
            "pg_bad_013": (4095, 2),
            "pg_bad_015": (len(self.payload) - 1, 1),
            "pg_bad_016": (0, 4095),
        }
        shape_corrupt = targeted_shapes.get(self.behaviour) == (offset, rlen)
        grid_corrupt = self.behaviour == "pg_bad_grid" and sequence >= 9
        retry_corrupt = (self.behaviour == "pg_bad_retry"
                         and request_args == b"\x00\x01")
        corrupt = any((shape_corrupt, grid_corrupt, retry_corrupt,
                       self.behaviour == "pg_valid_crc_corrupt"))
        return bytes([data[0] ^ 1]) + data[1:] if corrupt and data else data

    def _send_pgread(self, conn, sid, offset, data):
        corrupt = self.corrupt_page if self.behaviour == "corrupt" else -1
        pages = pack_pages(data, offset, corrupt)
        claimed = offset + kXR_pgPageSZ if self.behaviour == "bad_offset" \
            else offset
        kwargs = self._pgread_status_kwargs(sid)
        status_frame = pgread_status_frame(
            sid, claimed, len(pages), **kwargs,
        )
        if self.behaviour == "bad_status_crc":
            status_frame = status_frame[:8] + bytes([
                status_frame[8] ^ 0x80,
            ]) + status_frame[9:]
        conn.sendall(status_frame)
        conn.sendall(pages)

    def _pgread_status_kwargs(self, sid):
        return {
            "bad_body_sid": {"body_sid": bytes([sid[0] ^ 1, sid[1]])},
            "bad_requestid": {"requestid": 29},
            "bad_reserved": {"reserved": b"\x00\x00\x00\x01"},
            "bad_resptype": {"resptype": 9},
        }.get(self.behaviour, {})

    def _read(self, conn, sid, hdr, request_args=b""):
        with self._lock:
            self.reads += 1
            read_sequence = self.reads
        offset, rlen = struct.unpack("!qi", hdr[8:20])
        if self._read_error(conn, sid, offset, rlen):
            return
        data = self._read_data(offset, rlen, request_args, read_sequence)
        pathid = request_args[0] if request_args else 0
        target, data = self._read_target(conn, sid, pathid, data)
        if target is None:
            return
        data = self._corrupt_context_read(data)
        target.sendall(ok_frame(sid, data))

    def _read_error(self, conn, sid, offset, rlen):
        handlers = {
            "idle_server_error": self._read_idle_error,
            "rd_reject_zero": self._read_zero_error,
            "rd_error_maxlen": self._read_maxlen_error,
        }
        handler = handlers.get(self.behaviour)
        return handler(conn, sid, offset, rlen) if handler else False

    def _read_idle_error(self, conn, sid, _offset, _rlen):
        if getattr(self._connection_context, "index", 0) <= 0:
            return False
        conn.sendall(error_frame(sid, kXR_ServerError, b"idle handle lost"))
        return True

    @staticmethod
    def _read_zero_error(conn, sid, _offset, rlen):
        if rlen != 0:
            return False
        conn.sendall(error_frame(sid, kXR_ArgInvalid, b"zero read refused"))
        return True

    @staticmethod
    def _read_maxlen_error(conn, sid, _offset, rlen):
        if rlen != 0x7fffffff:
            return False
        conn.sendall(error_frame(sid, kXR_ServerError, b"large read failed"))
        return True

    def _read_data(self, offset, rlen, request_args, sequence):
        checkpoint = self.behaviour == "checkpoint_no_rollback" and sequence >= 2
        payload = b"after-checkpoint!" if checkpoint else self.payload
        data = payload[offset:offset + max(rlen, 0)]
        data = self._adjust_read_data(data, offset, rlen)
        if self._should_corrupt_read(offset, rlen, request_args, sequence) and data:
            return bytes([data[0] ^ 1]) + data[1:]
        return data

    def _adjust_read_data(self, data, offset, rlen):
        if (self.behaviour == "rd_invent_eof"
                and offset >= len(self.payload) and rlen > 0):
            return b"X"
        if (self.behaviour == "rd_straddle_extra"
                and offset == len(self.payload) - 1 and rlen == 2):
            return data + b"X"
        return data

    def _should_corrupt_read(self, offset, rlen, request_args, sequence):
        handlers = {
            "rd_bad_after_baseline": lambda: sequence >= 2,
            "rd_bad_006": lambda: offset == 0 and rlen == 1,
            "rd_bad_007": lambda: offset == len(self.payload) - 1 and rlen == 1,
            "rd_bad_008": lambda: offset in (4095, 4096, 4097),
            "rd_mutate_repeat": lambda: sequence == 13,
            "rd_bad_partition": lambda: sequence >= 16,
            "rd_bad_primary_args": lambda: bool(request_args)
            and request_args == b"\x00" * len(request_args),
            "rd_bad_readahead": lambda: len(request_args) > 4,
        }
        predicate = handlers.get(self.behaviour)
        return predicate() if predicate else False

    def _read_target(self, conn, sid, pathid, data):
        if not pathid:
            return conn, self._primary_read_data(data)
        with self._lock:
            target = self.bound_connections.get(pathid)
        if target is None:
            self._unbound_read_reply(conn, sid, data)
            return None, data
        if self.behaviour == "bind_wrong_stream":
            self._close_wrong_stream(target)
            return None, data
        if self.behaviour in ("bind_corrupt", "bind_ping_corrupt") and data:
            data = bytes([data[0] ^ 1]) + data[1:]
        return target, data

    def _primary_read_data(self, data):
        corrupt = (getattr(self._connection_context, "pathid", 0)
                   and self.behaviour == "bind_corrupt" and data)
        return bytes([data[0] ^ 1]) + data[1:] if corrupt else data

    def _unbound_read_reply(self, conn, sid, data):
        if self.behaviour in ("bind_stale_accept", "rd_accept_unbound"):
            conn.sendall(ok_frame(sid, data))
            return
        conn.sendall(error_frame(sid, kXR_ArgInvalid, b"unbound path id"))

    @staticmethod
    def _close_wrong_stream(target):
        try:
            target.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass

    def _corrupt_context_read(self, data):
        corrupt = getattr(self._connection_context, "corrupt_reads", False)
        return bytes([data[0] ^ 1]) + data[1:] if corrupt and data else data

    def _readv(self, conn, sid, request):
        """Serve typed readv replies and inject one clause-owned defect."""
        descriptors = self._readv_descriptors(conn, sid, request)
        if descriptors is None:
            return
        response = bytearray()
        for index, (handle, length, offset) in enumerate(descriptors):
            fragment = self._readv_fragment(
                conn, sid, index, handle, length, offset, descriptors,
            )
            if fragment is None:
                return
            response += fragment
        response = self._alter_readv_order(response, descriptors)
        response = self._truncate_readv(response)
        self._send_readv(conn, sid, response)

    def _readv_descriptors(self, conn, sid, request):
        if len(request) % 16 != 0:
            self._reject_partial_readv(conn, sid)
            return None
        count = len(request) // 16
        if count > 1024 and self.behaviour != "rdv_bad_011":
            conn.sendall(error_frame(sid, 3002, b"too many readv segments"))
            return None
        return [self._readv_descriptor(request, index) for index in range(count)]

    def _reject_partial_readv(self, conn, sid):
        if self.behaviour == "rdv_bad_017":
            conn.sendall(ok_frame(sid))
            return
        conn.sendall(error_frame(sid, kXR_ArgInvalid,
                                 b"partial readv descriptor"))

    @staticmethod
    def _readv_descriptor(request, index):
        descriptor = request[index * 16:(index + 1) * 16]
        return (
            descriptor[:4],
            struct.unpack("!I", descriptor[4:8])[0],
            struct.unpack("!Q", descriptor[8:16])[0],
        )

    def _readv_fragment(self, conn, sid, index, handle, length, offset,
                        descriptors):
        handled, fragment = self._readv_extreme(
            conn, sid, handle, length, offset,
        )
        if handled:
            return fragment
        if self._readv_overlimit(conn, sid, length):
            return None
        handled, fragment = self._readv_past_end(
            conn, sid, handle, length, offset,
        )
        if handled:
            return fragment
        data = self.payload[offset:offset + length]
        data = self._readv_data(data, index, length, offset, descriptors)
        reply_offset = self._readv_reply_offset(length, offset, descriptors)
        return handle + struct.pack("!IQ", len(data), reply_offset) + data

    def _readv_extreme(self, conn, sid, handle, length, offset):
        if length != 0xffffffff and offset != 0xffffffffffffffff:
            return False, b""
        if self.behaviour == "rdv_bad_016":
            return True, handle + struct.pack("!IQ", 0, offset)
        conn.sendall(error_frame(sid, kXR_ArgInvalid, b"invalid readv range"))
        return True, None

    def _readv_overlimit(self, conn, sid, length):
        over = (length > 2097136 and self.behaviour != "rdv_bad_013"
                and self.behaviour.startswith("rdv_"))
        if not over:
            return False
        conn.sendall(error_frame(sid, 3002, b"readv segment too large"))
        return True

    def _readv_past_end(self, conn, sid, handle, length, offset):
        if offset + length <= len(self.payload):
            return False, b""
        if self.behaviour in ("rdv_bad_009", "rdv_bad_010"):
            return True, handle + struct.pack("!IQ", 0, offset)
        conn.sendall(error_frame(sid, kXR_IOError, b"readv past end of file"))
        return True, None

    def _readv_data(self, data, index, length, offset, descriptors):
        data = self._empty_readv_data(data, length)
        return self._apply_readv_corruption(
            data, index, length, offset, descriptors,
        )

    def _empty_readv_data(self, data, length):
        if self.behaviour == "rdv_bad_008" and length == 0:
            return b"X"
        return data

    def _apply_readv_corruption(self, data, index, length, offset,
                                descriptors):
        if not data or not self._corrupt_readv(
                index, length, offset, descriptors):
            return data
        byte_index = 1 if self.behaviour == "rdv_bad_006" and len(data) > 1 else 0
        return (data[:byte_index] + bytes([data[byte_index] ^ 1])
                + data[byte_index + 1:])

    def _corrupt_readv(self, index, length, offset, descriptors):
        count = len(descriptors)
        predicates = {
            "rdv_bad_004": self._rdv_always_corrupt,
            "rdv_bad_001": self._rdv_first_corrupt,
            "rdv_bad_005": self._rdv_duplicate_corrupt,
            "rdv_bad_006": self._rdv_second_corrupt,
            "rdv_bad_012": self._rdv_limit_corrupt,
            "rdv_bad_014": self._rdv_second_corrupt,
            "rdv_bad_020": self._rdv_last_corrupt,
        }
        predicate = predicates.get(self.behaviour)
        if predicate is None:
            return False
        return predicate(index, length, offset, descriptors, count)

    @staticmethod
    def _rdv_always_corrupt(_index, _length, _offset, _descriptors, _count):
        return True

    @staticmethod
    def _rdv_first_corrupt(_index, _length, offset, _descriptors, count):
        return count == 1 and offset == 0

    @staticmethod
    def _rdv_duplicate_corrupt(index, length, offset, descriptors, count):
        return (count == 2 and index == 1
                and descriptors[0][1:] == (length, offset))

    @staticmethod
    def _rdv_second_corrupt(index, _length, _offset, _descriptors, count):
        return count == 2 and index == 1

    @staticmethod
    def _rdv_limit_corrupt(index, _length, _offset, descriptors, count):
        return (count == 2 and index == 1
                and sum(item[1] for item in descriptors) == 2097137)

    @staticmethod
    def _rdv_last_corrupt(index, _length, _offset, _descriptors, count):
        return count == 1024 and index == 1023

    def _readv_reply_offset(self, length, offset, descriptors):
        wrong = (self.behaviour == "rdv_bad_002"
                 and len(descriptors) == 1 and length == 1)
        return offset + 1 if wrong else offset

    def _alter_readv_order(self, response, descriptors):
        reverse = (self.behaviour in ("rdv_bad_003", "rdv_bad_007")
                   and len(descriptors) == 2
                   and descriptors[0][2] > descriptors[1][2])
        if not reverse:
            return response
        first_length = 16 + descriptors[0][1]
        return response[first_length:] + response[:first_length]

    def _truncate_readv(self, response):
        if self.behaviour == "rdv_truncated" and response:
            return response[:-1]
        return response

    def _send_readv(self, conn, sid, response):
        if self.behaviour == "rdv_bad_018" and len(response) > 1:
            split = len(response) // 2
            conn.sendall(sid + struct.pack("!HI", kXR_oksofar, split)
                         + bytes(response[:split]))
            conn.sendall(ok_frame(sid, bytes(response[split:])))
            return
        conn.sendall(ok_frame(sid, bytes(response)))
