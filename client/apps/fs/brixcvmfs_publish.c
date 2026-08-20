/* brixcvmfs_publish.c — `brixcvmfs repo` transaction family (phase-96 S4).
 * Unprivileged, tool-surface only (G14): no FUSE, no root.
 *
 *   brixcvmfs repo transaction <repo_dir>
 *       — open a transaction: take the lock, create the upper tree
 *         (<repo_dir>/.brixtxn/upper) that overlay writes populate.
 *   brixcvmfs repo abort <repo_dir>
 *       — discard the transaction (recursive removal of .brixtxn).
 *   brixcvmfs repo publish <repo_dir> [keys_dir] [--chunk-size N] [--dirtab F]
 *       — scan the upper tree into a changeset, run the publish engine,
 *         then retire the transaction. The manifest swap is the engine's
 *         last act, so a crash mid-publish leaves the old revision live and
 *         the transaction intact for a clean re-run.
 *
 * The lock (.brixtxn/lock, O_CREAT|O_EXCL) records "pid:\nboot:\n" for
 * forensics. A transaction is durable state (the staged writes live in the
 * upper tree), so an existing lock is NEVER broken automatically — it is
 * reported with its opener's pid and retired only by `abort` or `publish`.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L         /* kill/lstat & friends under -std=c11 */
#endif
#include "cvmfs/publish/publish.h"
#include "brixcvmfs_ingest_internal.h"   /* exports the tx lock/rm primitives */

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define TX_PATH 600

static int tx_err(const char *what, const char *detail) {
    fprintf(stderr, "brixcvmfs repo: %s%s%s\n", what,
            detail != NULL ? ": " : "", detail != NULL ? detail : "");
    return 1;
}

/* ---- lock ----------------------------------------------------------------- */

static void tx_boot_id(char *out, size_t outlen) {
    snprintf(out, outlen, "unknown");
    FILE *f = fopen("/proc/sys/kernel/random/boot_id", "r");
    if (f != NULL) {
        if (fgets(out, (int) outlen, f) != NULL)
            out[strcspn(out, "\n")] = '\0';
        fclose(f);
    }
}

int brixcvmfs_tx_lock_pid(const char *lockpath) {
    FILE *f = fopen(lockpath, "r");
    int pid = 0;
    if (f != NULL) {
        if (fscanf(f, "pid:%d", &pid) != 1) pid = 0;
        fclose(f);
    }
    return pid;
}

/* 1 = the lock's opener is provably gone: the recorded boot differs from
 * the running boot, or the pid no longer exists on this boot. Callers must
 * only judge locks with no durable upper tree behind them (a crashed
 * ingest); a `repo transaction` lock guards real staged state and is never
 * broken automatically. */
int brixcvmfs_tx_lock_stale(const char *lockpath) {
    char boot[64], cur[64];
    int pid = 0;
    FILE *f = fopen(lockpath, "r");
    if (f == NULL) return 0;
    boot[0] = '\0';
    int fields = fscanf(f, "pid:%d\nboot:%63s", &pid, boot);
    fclose(f);
    if (fields != 2) return 0;
    tx_boot_id(cur, sizeof(cur));
    if (strcmp(boot, cur) != 0) return 1;
    return pid > 0 && kill(pid, 0) != 0 && errno == ESRCH;
}

int brixcvmfs_tx_lock_take(const char *lockpath) {
    char boot[64], body[128];
    tx_boot_id(boot, sizeof(boot));
    int fd = open(lockpath, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0644);
    if (fd < 0) return -1;
    int len = snprintf(body, sizeof(body), "pid:%d\nboot:%s\n", (int) getpid(), boot);
    int rc = write(fd, body, (size_t) len) == len ? 0 : -1;
    close(fd);
    return rc;
}

/* ---- recursive transaction removal --------------------------------------- */

int brixcvmfs_tx_rm_tree(const char *path) {
    struct stat st;
    if (lstat(path, &st) != 0)
        return errno == ENOENT ? 0 : -1;
    if (!S_ISDIR(st.st_mode))
        return unlink(path);
    DIR *d = opendir(path);
    if (d == NULL) return -1;
    struct dirent *e;
    int rc = 0;
    while (rc == 0 && (e = readdir(d)) != NULL) {
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0)
            continue;
        char sub[TX_PATH * 2];
        if (snprintf(sub, sizeof(sub), "%s/%s", path, e->d_name)
            >= (int) sizeof(sub))
            rc = -1;
        else
            rc = brixcvmfs_tx_rm_tree(sub);
    }
    closedir(d);
    return rc == 0 ? rmdir(path) : rc;
}

/* ---- subcommands ---------------------------------------------------------- */

static int tx_transaction(const char *repo_dir) {
    char txn[TX_PATH], lock[TX_PATH + 16], upper[TX_PATH + 16];
    snprintf(txn, sizeof(txn), "%s/.brixtxn", repo_dir);
    snprintf(lock, sizeof(lock), "%s/lock", txn);
    snprintf(upper, sizeof(upper), "%s/upper", txn);
    if (mkdir(txn, 0755) != 0 && errno != EEXIST)
        return tx_err("cannot create transaction dir", txn);
    if (brixcvmfs_tx_lock_take(lock) != 0) {
        if (errno != EEXIST)
            return tx_err("cannot take transaction lock", lock);
        char who[64];
        snprintf(who, sizeof(who), "%d", brixcvmfs_tx_lock_pid(lock));
        return tx_err("repository is in a transaction (pid)", who);
    }
    if (mkdir(upper, 0755) != 0 && errno != EEXIST)
        return tx_err("cannot create upper tree", upper);
    printf("transaction open: %s\n", upper);
    return 0;
}

static int tx_abort(const char *repo_dir) {
    char txn[TX_PATH];
    struct stat st;
    snprintf(txn, sizeof(txn), "%s/.brixtxn", repo_dir);
    if (lstat(txn, &st) != 0 || !S_ISDIR(st.st_mode))
        return tx_err("no open transaction under", repo_dir);
    if (brixcvmfs_tx_rm_tree(txn) != 0)
        return tx_err("cannot remove transaction dir", txn);
    printf("transaction aborted\n");
    return 0;
}

static int tx_publish(const char *repo_dir, int argc, char **argv) {
    cvmfs_publish_opts_t o;
    memset(&o, 0, sizeof(o));
    o.repo_dir = repo_dir;
    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--chunk-size") == 0 && i + 1 < argc)
            o.chunk_size = atol(argv[++i]);
        else if (strcmp(argv[i], "--dirtab") == 0 && i + 1 < argc)
            o.dirtab = argv[++i];
        else if (argv[i][0] != '-' && o.keys_dir == NULL)
            o.keys_dir = argv[i];
        else
            return tx_err("unknown publish option", argv[i]);
    }

    char txn[TX_PATH], upper[TX_PATH + 16], err[1024];
    struct stat st;
    snprintf(txn, sizeof(txn), "%s/.brixtxn", repo_dir);
    snprintf(upper, sizeof(upper), "%s/upper", txn);
    if (lstat(upper, &st) != 0 || !S_ISDIR(st.st_mode))
        return tx_err("no open transaction under", repo_dir);

    cvmfs_changeset_t cs;
    if (cvmfs_changeset_scan(upper, &cs, err, sizeof(err)) != 0)
        return tx_err("changeset scan failed", err);
    long new_rev = 0;
    int rc = cvmfs_publish_run(&o, &cs, &new_rev, err, sizeof(err));
    cvmfs_changeset_free(&cs);
    if (rc != 0)
        return tx_err("publish failed", err);
    if (brixcvmfs_tx_rm_tree(txn) != 0)
        return tx_err("published, but cannot retire transaction dir", txn);
    printf("published revision %ld\n", new_rev);
    return 0;
}

static int tx_fsck(const char *repo_dir, int check_data) {
    char err[1024];
    if (cvmfs_fsck_run(repo_dir, check_data, err, sizeof(err)) != 0)
        return tx_err("fsck failed", err);
    printf(check_data ? "fsck clean (data verified)\n" : "fsck clean\n");
    return 0;
}

int brixcvmfs_txn_main(int argc, char **argv) {
    /* argv[0] = "repo" after the front-end shift. */
    const char *cmd = argc >= 2 ? argv[1] : "";
    if (strcmp(cmd, "transaction") == 0 && argc == 3)
        return tx_transaction(argv[2]);
    if (strcmp(cmd, "abort") == 0 && argc == 3)
        return tx_abort(argv[2]);
    if (strcmp(cmd, "publish") == 0 && argc >= 3)
        return tx_publish(argv[2], argc - 3, argv + 3);
    if (strcmp(cmd, "fsck") == 0 && argc == 3)
        return tx_fsck(argv[2], 0);
    if (strcmp(cmd, "fsck") == 0 && argc == 4 && strcmp(argv[3], "--data") == 0)
        return tx_fsck(argv[2], 1);
    fprintf(stderr,
        "usage: brixcvmfs repo transaction <repo_dir>\n"
        "       brixcvmfs repo abort       <repo_dir>\n"
        "       brixcvmfs repo publish    <repo_dir> [keys_dir]"
        " [--chunk-size N] [--dirtab F]\n"
        "       brixcvmfs repo fsck       <repo_dir> [--data]\n");
    return 2;
}
