/*
 * broker_internal.h - private split contract for broker.c and its Phase-38 siblings.
 * Not a public API: include only from src/impersonate/.  See docs/refactor/phase-38-file-size-unix-modularity.md.
 */
#ifndef XROOTD_BROKER_INTERNAL_H
#define XROOTD_BROKER_INTERNAL_H

#include "impersonate.h"
#include "impersonate_proto.h"
#include "compat/log_diag.h"
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/fsuid.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/xattr.h>
#include <linux/openat2.h>
#include <linux/capability.h>
#include <sys/prctl.h>
#define IMP_BROKER_MAXCONN  1024
#define IMP_REFUSE_PRIV  (-2)

extern uid_t  imp_base_uid;
extern gid_t  imp_base_gid;
extern gid_t  imp_base_groups[XROOTD_IDMAP_MAXGROUPS];
extern int    imp_base_ngroups;
extern uid_t  imp_self_uid;
#ifndef RENAME_NOREPLACE
#define RENAME_NOREPLACE (1u << 0)
#endif


/* broker.c */
int imp_peer_allowed(int conn_fd);

/* broker_creds.c */
int imp_capset_setuid_setgid(int with_effective, ngx_log_t *log);
int imp_drop_to_service_user(ngx_log_t *log);
int imp_become(const xrootd_idmap_creds_t *cr);
void imp_restore(void);
const char * imp_rel(const char *path);

/* broker_ops.c */
int imp_openat2(int rootfd, const char *rel, uint32_t flags, uint32_t mode);
int imp_open_parent(int rootfd, const char *rel, char *scratch, const char **base);
void imp_fill_stat(imp_stat_t *o, const struct stat *s);
int imp_xattr_open(int rootfd, const char *rel);
int imp_xattr_name_ok(const char *name);
size_t imp_xattr_filter_user(char *list, size_t len);
int imp_do_rename(int sfd, const char *sbase, int dfd, const char *dbase, int noreplace);
int imp_do_op(int rootfd, const imp_req_t *req, imp_rep_t *rep, int *out_fd, char *data_out, size_t data_max, const char *data_in, size_t data_in_len);

/* broker.c */
int imp_read_full(int fd, void *buf, size_t n);
int imp_send_reply(int conn_fd, const imp_rep_t *rep, int fd, const void *data, size_t data_len);
int imp_serve_one(int conn_fd, int rootfd, ngx_log_t *log);

#endif /* XROOTD_BROKER_INTERNAL_H */
