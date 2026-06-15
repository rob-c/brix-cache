/*
 * Wire protocol layouts are split into named header fragments to keep each
 * unit approachable while preserving the original code and comments.
 * Do not include these fragments directly; wire.h owns the public header.
 */

#pragma once

#include "wire_core_requests.h"
#include "wire_write_extended_requests.h"
#include "wire_vendor_ext.h"   /* nginx-xrootd vendor ops: setattr/symlink/readlink/link */
