#include "vfs.h"

/*
 * Phase 3 keeps protocol-specific fd-cache behavior in place while introducing
 * the shared VFS handle.  This file is intentionally reserved for the later
 * cache unification step so the build already owns the src/fs/vfs/fd_cache.c slot.
 */
