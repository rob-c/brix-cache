#ifndef BRIX_COMPAT_NS_STATUS_H
#define BRIX_COMPAT_NS_STATUS_H

/*
 * ns_status.h — neutral filesystem-mutation status codes.
 *
 * WHAT: The brix_ns_status_t enum, extracted from namespace_ops.h so it can be
 *       shared by the ngx-free protocol core (libxrdproto, error_mapping Sections
 *       1-2) without dragging in any ngx_* dependency.
 * WHY:  error_mapping maps these codes to kXR/HTTP statuses and is compiled into
 *       BOTH the nginx module and the standalone client build; the enum must
 *       therefore live in a header with zero nginx coupling.
 * HOW:  Pure C, no includes. namespace_ops.h includes this header so the full
 *       (ngx-coupled) namespace API continues to see the same single definition.
 */

typedef enum {
    BRIX_NS_OK = 0,
    BRIX_NS_NOT_FOUND,
    BRIX_NS_DENIED,
    BRIX_NS_EXISTS,
    BRIX_NS_CONFLICT,
    BRIX_NS_NOT_EMPTY,
    BRIX_NS_TOO_LONG,
    BRIX_NS_NO_SPACE,
    BRIX_NS_IO_ERROR
} brix_ns_status_t;

#endif /* BRIX_COMPAT_NS_STATUS_H */
