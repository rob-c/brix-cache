/*
 * rados_manifest_shim.cpp — C-ABI fallback for librados's C++-only manifest
 * ops (set_redirect / copy_from / tier_promote / unset_manifest).
 *
 * WHAT: Four plain-C functions the Python migration tools load via ctypes
 *       when the direct mangled-symbol bridge in pymigrate/radosbridge.py
 *       cannot be used (unknown inline-namespace version, or a failed
 *       pre-write self-test). Every function takes the C API's rados_ioctx_t
 *       handles, so Python passes the exact same pointers either way.
 *
 * WHY:  These operations have no librados C API and no python-rados binding;
 *       this shim is the ABI-robust escape hatch — it compiles against
 *       librados.hpp, so a future C++ ABI change costs a rebuild here rather
 *       than a code change in the tools.
 *
 * HOW:  IoCtx::from_rados_ioctx_t wraps the C handle in a C++ IoCtx (taking
 *       its own reference, released by the IoCtx destructor — balanced), the
 *       op is built on a stack ObjectWriteOperation and submitted with
 *       IoCtx::operate. Return value: librados rc (0 ok, -errno).
 *
 * Build (needs g++ and librados.hpp — package libradospp-devel on el9):
 *   g++ -shared -fPIC -std=c++17 -O2 rados_manifest_shim.cpp -lrados \
 *       -o rados_manifest_shim.so
 */
#include <rados/librados.h>
#include <rados/librados.hpp>

namespace {

int
operate_on(rados_ioctx_t dst, const char *dst_oid,
           librados::ObjectWriteOperation *op)
{
    librados::IoCtx io;
    librados::IoCtx::from_rados_ioctx_t(dst, io);
    return io.operate(dst_oid, op);
}

} /* namespace */

extern "C" {

int
shim_set_redirect(rados_ioctx_t dst, const char *dst_oid,
                  rados_ioctx_t src, const char *src_oid, uint64_t src_version)
{
    librados::IoCtx sio;
    librados::IoCtx::from_rados_ioctx_t(src, sio);
    librados::ObjectWriteOperation op;
    op.set_redirect(src_oid, sio, src_version, 0);
    return operate_on(dst, dst_oid, &op);
}

int
shim_copy_from(rados_ioctx_t dst, const char *dst_oid,
               rados_ioctx_t src, const char *src_oid, uint64_t src_version)
{
    librados::IoCtx sio;
    librados::IoCtx::from_rados_ioctx_t(src, sio);
    librados::ObjectWriteOperation op;
    op.copy_from(src_oid, sio, src_version, 0);
    return operate_on(dst, dst_oid, &op);
}

int
shim_tier_promote(rados_ioctx_t io, const char *oid)
{
    librados::ObjectWriteOperation op;
    op.tier_promote();
    return operate_on(io, oid, &op);
}

int
shim_unset_manifest(rados_ioctx_t io, const char *oid)
{
    librados::ObjectWriteOperation op;
    op.unset_manifest();
    return operate_on(io, oid, &op);
}

} /* extern "C" */
