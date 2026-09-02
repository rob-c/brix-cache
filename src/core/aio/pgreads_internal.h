/*
 * pgreads_internal.h — seam between pgreads.c (thread entry + event-loop
 * completion halves of the kXR_pgread offload) and pgreads_pool_send.c
 * (the §1.2/§1.3 pool-thread send engine). Both entry points run ON A POOL
 * THREAD and touch nothing but the brix_pgread_aio_t task and its socket.
 */
#ifndef BRIX_AIO_PGREADS_INTERNAL_H
#define BRIX_AIO_PGREADS_INTERNAL_H

#include "aio.h"

/* §1.2: send the finished single [status|pages] frame from the pool thread. */
void brix_pgread_pool_send(brix_pgread_aio_t *t);
/* §1.3: chunked read+CRC-encode+send streamer; non-zero = it handled the
 * whole request in-thread (the done handler only accounts + resumes). */
ngx_flag_t brix_pgread_pool_stream(brix_pgread_aio_t *t);

#endif /* BRIX_AIO_PGREADS_INTERNAL_H */
