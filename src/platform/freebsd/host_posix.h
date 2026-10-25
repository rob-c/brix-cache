/* FreeBSD's answer to the PAL's Linux-shaped POSIX contract.
 * Native headers belong here; portable callers include platform_api.h.
 */
#pragma once
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <sys/extattr.h>
#include <sys/eventfd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdint.h>
#include "../openat2_abi.h"

#ifndef ENODATA
#define ENODATA ENOATTR
#endif
#ifndef ENOKEY
#define ENOKEY (ELAST + 20)
#endif
#define XATTR_CREATE 1
#define XATTR_REPLACE 2

ssize_t brix_freebsd_getxattr(const char *, const char *, void *, size_t, int);
ssize_t brix_freebsd_fgetxattr(int, const char *, void *, size_t);
int brix_freebsd_setxattr(const char *, const char *, const void *, size_t, int, int);
int brix_freebsd_fsetxattr(int, const char *, const void *, size_t, int);
ssize_t brix_freebsd_listxattr(const char *, char *, size_t, int);
ssize_t brix_freebsd_flistxattr(int, char *, size_t);
int brix_freebsd_removexattr(const char *, const char *, int);
int brix_freebsd_fremovexattr(int, const char *);

#define getxattr(p,n,v,s) brix_freebsd_getxattr(p,n,v,s,0)
#define lgetxattr(p,n,v,s) brix_freebsd_getxattr(p,n,v,s,1)
#define fgetxattr(f,n,v,s) brix_freebsd_fgetxattr(f,n,v,s)
#define setxattr(p,n,v,s,f) brix_freebsd_setxattr(p,n,v,s,f,0)
#define lsetxattr(p,n,v,s,f) brix_freebsd_setxattr(p,n,v,s,f,1)
#define fsetxattr(f,n,v,s,o) brix_freebsd_fsetxattr(f,n,v,s,o)
#define listxattr(p,l,s) brix_freebsd_listxattr(p,l,s,0)
#define llistxattr(p,l,s) brix_freebsd_listxattr(p,l,s,1)
#define flistxattr(f,l,s) brix_freebsd_flistxattr(f,l,s)
#define removexattr(p,n) brix_freebsd_removexattr(p,n,0)
#define lremovexattr(p,n) brix_freebsd_removexattr(p,n,1)
#define fremovexattr(f,n) brix_freebsd_fremovexattr(f,n)

/* These are request codes for the PAL adapters, not claimed native syscalls. */
#define PR_SET_KEEPCAPS 8
#define PR_CAPBSET_DROP 24
#define PR_SET_NO_NEW_PRIVS 38
#define PR_GET_NO_NEW_PRIVS 39
#define _LINUX_CAPABILITY_VERSION_3 0x20080522
#define CAP_CHOWN 0
#define CAP_DAC_OVERRIDE 1
#define CAP_DAC_READ_SEARCH 2
#define CAP_FOWNER 3
#define CAP_FSETID 4
#define CAP_SETGID 6
#define CAP_SETUID 7
#define CAP_SETPCAP 8
#define CAP_SYS_PTRACE 19
#define CAP_SYS_ADMIN 21
#define CAP_MKNOD 27
#define CAP_SETFCAP 31
#define CAP_LAST_CAP 40
struct __user_cap_header_struct { uint32_t version; int pid; };
struct __user_cap_data_struct { uint32_t effective, permitted, inheritable; };
