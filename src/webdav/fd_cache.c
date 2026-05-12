/*
 * fd_cache.c - per-connection open-file cache for WebDAV GET fast paths.
 */

#include "webdav.h"

#include <openssl/ssl.h>

#include <fcntl.h>
#include <string.h>
#include <unistd.h>

static int webdav_fd_table_conn_index = -1;

/* webdav_fd_entry_is_open — true if the slot holds an open file descriptor. */
static ngx_flag_t
webdav_fd_entry_is_open(const webdav_fd_entry_t *entry)
{
    return entry->fd != NGX_INVALID_FILE;
}

/* webdav_fd_entry_close — close the slot's fd and mark it as empty. */
static void
webdav_fd_entry_close(webdav_fd_entry_t *entry)
{
    if (!webdav_fd_entry_is_open(entry)) {
        return;
    }

    ngx_close_file(entry->fd);
    entry->fd = NGX_INVALID_FILE;
}

/*
 * webdav_fd_entry_assign — populate a freshly-acquired (or evicted) slot with
 * a new fd, capturing the inode identity for stale-detection on next use.
 */
static void
webdav_fd_entry_assign(webdav_fd_entry_t *entry, const char *path,
    const struct stat *stat_buf, ngx_fd_t fd, uint64_t uri_hash)
{
    entry->fd = fd;
    entry->ino = stat_buf->st_ino;
    entry->dev = stat_buf->st_dev;
    entry->uri_hash = uri_hash;
    entry->open_time = ngx_current_msec;
    ngx_cpystrn((u_char *) entry->path, (u_char *) path,
                sizeof(entry->path));
}

static void
webdav_fd_table_cleanup(void *data)
{
    webdav_fd_table_t *table = data;
    int                slot_index;

    for (slot_index = 0; slot_index < WEBDAV_FD_TABLE_SIZE; slot_index++) {
        webdav_fd_entry_close(&table->fds[slot_index]);
    }
}

ngx_int_t
webdav_fd_table_init_ssl_index(ngx_log_t *log)
{
    if (webdav_fd_table_conn_index >= 0) {
        return NGX_OK;
    }

    webdav_fd_table_conn_index = SSL_get_ex_new_index(0, NULL, NULL,
                                                      NULL, NULL);
    if (webdav_fd_table_conn_index < 0) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "xrootd_webdav: fd table ex_data index failed, "
                      "fd caching across keepalive disabled");
    }

    return NGX_OK;
}

webdav_fd_table_t *
webdav_get_fd_table(ngx_connection_t *c)
{
    webdav_fd_table_t  *table;
    ngx_pool_cleanup_t *cleanup;
    int                 slot_index;

    if (c->ssl != NULL && webdav_fd_table_conn_index >= 0) {
        /*
         * The table is still owned by the nginx connection pool.  SSL ex_data
         * is only a back-pointer that lets later keepalive requests find the
         * same cache without reopening hot files.
         */
        table = SSL_get_ex_data(c->ssl->connection,
                                webdav_fd_table_conn_index);
        if (table != NULL) {
            return table;
        }
    }

    table = ngx_pcalloc(c->pool, sizeof(*table));
    if (table == NULL) {
        return NULL;
    }

    for (slot_index = 0; slot_index < WEBDAV_FD_TABLE_SIZE; slot_index++) {
        table->fds[slot_index].fd = NGX_INVALID_FILE;
    }
    table->count = 0;

    cleanup = ngx_pool_cleanup_add(c->pool, 0);
    if (cleanup == NULL) {
        return NULL;
    }
    cleanup->handler = webdav_fd_table_cleanup;
    cleanup->data = table;

    if (c->ssl != NULL && webdav_fd_table_conn_index >= 0) {
        SSL_set_ex_data(c->ssl->connection, webdav_fd_table_conn_index,
                        table);
    }

    return table;
}

ngx_fd_t
webdav_fd_table_get(webdav_fd_table_t *table, const char *path,
                    const struct stat *expected_stat)
{
    int slot_index;

    if (table == NULL) {
        XROOTD_WEBDAV_METRIC_INC(fd_cache_total[XROOTD_WEBDAV_FD_CACHE_MISS]);
        return NGX_INVALID_FILE;
    }

    for (slot_index = 0; slot_index < WEBDAV_FD_TABLE_SIZE; slot_index++) {
        webdav_fd_entry_t *entry = &table->fds[slot_index];

        /*
         * Path alone is not enough: a filename can be replaced between
         * requests.  The cached stat tuple ties the descriptor to the object
         * the resolver just approved for this URI.
         */
        if (webdav_fd_entry_is_open(entry)
            && entry->ino == expected_stat->st_ino
            && entry->dev == expected_stat->st_dev
            && ngx_strcmp(entry->path, path) == 0)
        {
            XROOTD_WEBDAV_METRIC_INC(fd_cache_total[XROOTD_WEBDAV_FD_CACHE_HIT]);
            return entry->fd;
        }
    }

    XROOTD_WEBDAV_METRIC_INC(fd_cache_total[XROOTD_WEBDAV_FD_CACHE_MISS]);
    return NGX_INVALID_FILE;
}

void
webdav_fd_table_put(webdav_fd_table_t *table, const char *path,
                    const struct stat *stat_buf, ngx_fd_t fd,
                    uint64_t uri_hash)
{
    int        slot_index;
    int        target_slot;
    int        oldest_slot = 0;
    ngx_msec_t oldest_open_time;

    if (table == NULL) {
        return;
    }

    for (slot_index = 0; slot_index < WEBDAV_FD_TABLE_SIZE; slot_index++) {
        webdav_fd_entry_t *entry = &table->fds[slot_index];

        if (webdav_fd_entry_is_open(entry)
            && ngx_strcmp(entry->path, path) == 0)
        {
            if (entry->fd != fd) {
                webdav_fd_entry_close(entry);
            }
            webdav_fd_entry_assign(entry, path, stat_buf, fd, uri_hash);
            XROOTD_WEBDAV_METRIC_INC(
                fd_cache_total[XROOTD_WEBDAV_FD_CACHE_UPDATE]);
            return;
        }
    }

    target_slot = -1;
    for (slot_index = 0; slot_index < WEBDAV_FD_TABLE_SIZE; slot_index++) {
        if (!webdav_fd_entry_is_open(&table->fds[slot_index])) {
            target_slot = slot_index;
            break;
        }
    }

    if (target_slot == -1) {
        oldest_open_time = table->fds[0].open_time;
        for (slot_index = 1; slot_index < WEBDAV_FD_TABLE_SIZE; slot_index++) {
            if (table->fds[slot_index].open_time < oldest_open_time) {
                oldest_open_time = table->fds[slot_index].open_time;
                oldest_slot = slot_index;
            }
        }

        target_slot = oldest_slot;
        webdav_fd_entry_close(&table->fds[target_slot]);
        XROOTD_WEBDAV_METRIC_INC(
            fd_cache_total[XROOTD_WEBDAV_FD_CACHE_EVICT]);
    } else {
        table->count++;
    }

    webdav_fd_entry_assign(&table->fds[target_slot], path, stat_buf, fd,
                           uri_hash);
    XROOTD_WEBDAV_METRIC_INC(
        fd_cache_total[XROOTD_WEBDAV_FD_CACHE_INSERT]);
}

uint64_t
webdav_uri_hash(const char *s)
{
    uint64_t h = 14695981039346656037ULL;

    /*
     * This is a cheap cache key, not an authority decision.  Callers must
     * still validate the cached fd with fstat/path metadata before serving.
     */
    while (*s) {
        h ^= (uint64_t) (unsigned char) *s++;
        h *= 1099511628211ULL;
    }

    return h;
}

ngx_fd_t
webdav_fd_table_get_by_uri(webdav_fd_table_t *table, uint64_t uri_hash,
                           struct stat *sb_out, const char **path_out)
{
    int slot_index;

    if (path_out != NULL) {
        *path_out = NULL;
    }

    if (table == NULL) {
        XROOTD_WEBDAV_METRIC_INC(fd_cache_total[XROOTD_WEBDAV_FD_CACHE_MISS]);
        return NGX_INVALID_FILE;
    }

    for (slot_index = 0; slot_index < WEBDAV_FD_TABLE_SIZE; slot_index++) {
        webdav_fd_entry_t *entry = &table->fds[slot_index];

        if (webdav_fd_entry_is_open(entry)
            && entry->uri_hash == uri_hash)
        {
            /*
             * Hash lookup is only the fast path.  fstat proves the descriptor
             * still names a live file before sendfile/read serving uses it.
             */
            if (fstat(entry->fd, sb_out) != 0
                || sb_out->st_nlink == 0)
            {
                webdav_fd_entry_close(entry);
                table->count--;
                XROOTD_WEBDAV_METRIC_INC(
                    fd_cache_total[XROOTD_WEBDAV_FD_CACHE_STALE]);
                return NGX_INVALID_FILE;
            }

            if (path_out != NULL) {
                *path_out = entry->path;
            }
            XROOTD_WEBDAV_METRIC_INC(fd_cache_total[XROOTD_WEBDAV_FD_CACHE_HIT]);
            return entry->fd;
        }
    }

    XROOTD_WEBDAV_METRIC_INC(fd_cache_total[XROOTD_WEBDAV_FD_CACHE_MISS]);
    return NGX_INVALID_FILE;
}

void
webdav_fd_table_evict(webdav_fd_table_t *table, const char *path)
{
    int slot_index;

    if (table == NULL) {
        return;
    }

    for (slot_index = 0; slot_index < WEBDAV_FD_TABLE_SIZE; slot_index++) {
        webdav_fd_entry_t *entry = &table->fds[slot_index];

        if (webdav_fd_entry_is_open(entry)
            && ngx_strcmp(entry->path, path) == 0)
        {
            webdav_fd_entry_close(entry);
            table->count--;
            XROOTD_WEBDAV_METRIC_INC(
                fd_cache_total[XROOTD_WEBDAV_FD_CACHE_EVICT]);
            return;
        }
    }
}

void
webdav_fadvise_willneed(ngx_log_t *log, ngx_fd_t fd, off_t offset, size_t len)
{
#if defined(POSIX_FADV_WILLNEED)
    int rc;

    if (fd == NGX_INVALID_FILE || len == 0) {
        return;
    }

    rc = posix_fadvise(fd, offset, (off_t) len, POSIX_FADV_WILLNEED);
    if (rc != 0) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0,
                       "xrootd_webdav: POSIX_FADV_WILLNEED ignored: %s",
                       strerror(rc));
    }
#else
    (void) log;
    (void) fd;
    (void) offset;
    (void) len;
#endif
}
