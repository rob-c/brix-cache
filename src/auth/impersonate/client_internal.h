#ifndef BRIX_CLIENT_INTERNAL_H
#define BRIX_CLIENT_INTERNAL_H

/*
 * client_internal.h — private split contract between client.c and client_ops.c
 * after the file-size split.
 *
 * WHAT: Cross-declares the two worker-client core primitives that the op
 *       wrappers in client_ops.c call — request-frame construction and the
 *       single-reconnect request/reply exchange.
 * WHY:  client.c was 651 lines — over the file-size cap.  The connection/state
 *       singleton, the transport primitives (write_full/recv_reply), and the
 *       imp_build_req + imp_exchange core stay in client.c; every public
 *       brix_imp_* FS op wrapper (open/stat/mkdir/.../xattr) plus their private
 *       imp_call_status / imp_unpack_stat / imp_get_or_list / imp_status_errno
 *       helpers form one cohesive concern and move to client_ops.c.  Only these
 *       two symbols cross the boundary, so exactly those become non-static and
 *       are declared here.
 * HOW:  Both translation units include this header; neither symbol is exported
 *       beyond src/auth/impersonate/.  Requires imp_req_t / imp_rep_t from
 *       impersonate_proto.h before inclusion.
 */

#include "impersonate_proto.h"   /* imp_req_t, imp_rep_t */

#include <stddef.h>              /* size_t */
#include <stdint.h>              /* uint32_t, int64_t */

/* Build a request frame for the current principal (client.c). */
void imp_build_req(imp_req_t *req, uint32_t op, const char *path,
                   const char *path2, uint32_t flags, uint32_t mode,
                   int64_t length);

/*
 * One request/reply exchange with transparent single reconnect (client.c).  On
 * success returns 0 and fills *rep / *out_fd; on a transport failure returns -1
 * (errno=EIO).  `data_in`/`data_in_len` is an optional inbound payload;
 * `data_buf`/`data_bufsz` receive an optional outbound reply payload.
 */
int imp_exchange(const imp_req_t *req, imp_rep_t *rep, int *out_fd,
                 char *data_buf, size_t data_bufsz,
                 const void *data_in, size_t data_in_len);

#endif /* BRIX_CLIENT_INTERNAL_H */
