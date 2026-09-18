/*
 * client/lib/platform/darwin/preload.h - DYLD_INSERT_LIBRARIES interposition
 *
 * A wrapper is named brixposix_<name>; darwin/preload_interpose.c pairs it
 * with libSystem's symbol in a __DATA,__interpose table, which dyld applies
 * to every image except the one carrying the table. A plain reference to
 * `name` from inside the shim therefore IS the real function (and, unlike a
 * dlsym by string, it names the same ABI variant the wrapper was compiled
 * against: `stat` is stat$INODE64 on x86_64).
 */
#ifndef BRIX_CLIENT_PLATFORM_DARWIN_PRELOAD_H
#define BRIX_CLIENT_PLATFORM_DARWIN_PRELOAD_H

#define BRIXPOSIX_WRAP(name)         brixposix_##name
#define BRIXPOSIX_REAL_RESOLVE(name) (name)

/* Darwin's dirent carries the seek cursor as d_seekoff and an explicit name
 * length (d_namlen) that its readdir consumers read instead of strlen. */
#define BRIXPOSIX_DIRENT_FINISH(de, cursor, namelen) \
    do { (de)->d_seekoff = (__uint64_t) (cursor); \
         (de)->d_namlen = (__uint16_t) (namelen); } while (0)

#endif /* BRIX_CLIENT_PLATFORM_DARWIN_PRELOAD_H */
