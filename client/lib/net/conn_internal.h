#pragma once
/*
 * conn_internal.h — the seam between the connection lifecycle (conn.c) and the
 * bootstrap wire exchange (conn_bootstrap.c) after the 600-line-ratchet split.
 *
 * Requires: brix.h (brix_conn / brix_opts / brix_status) before inclusion.
 */

/* Send the 20B ClientInitHandShake + kXR_protocol as one segment and absorb the
 * (possibly reordered / combined) replies, recording server_flags + sec_level on
 * the connection. proto_sid is the streamid reserved for the protocol request. */
int brix_conn_handshake(brix_conn *c, uint16_t proto_sid, int want_tls,
                        brix_status *st);

/* Anonymous kXR_login (+ auth hand-off when the server demands a security
 * protocol); records the 16-byte session id on the connection. */
int brix_conn_login(brix_conn *c, const brix_opts *o, brix_status *st);
