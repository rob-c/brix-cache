/*
 * brix_fault_replay.c — session record / replay.  See brix_fault_replay.h.
 */
#include "brix_fault_replay.h"

#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static const unsigned char REC_MAGIC[5] = { 'B', 'F', 'P', 'R', 1 };

static int             g_rec_fd   = -1;
static pthread_mutex_t g_rec_lock = PTHREAD_MUTEX_INITIALIZER;

static void
put_be(unsigned char *p, unsigned long long v, int width)
{
    for (int i = width - 1; i >= 0; i--) {
        p[i] = (unsigned char) (v & 0xFF);
        v >>= 8;
    }
}

static unsigned long long
get_be(const unsigned char *p, int width)
{
    unsigned long long v = 0;
    for (int i = 0; i < width; i++) {
        v = (v << 8) | p[i];
    }
    return v;
}

int
fp_replay_record_start(const char *path)
{
    pthread_mutex_lock(&g_rec_lock);
    if (g_rec_fd >= 0) {
        close(g_rec_fd);
        g_rec_fd = -1;
    }
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd >= 0) {
        if (write(fd, REC_MAGIC, sizeof(REC_MAGIC)) == (ssize_t) sizeof(REC_MAGIC)) {
            g_rec_fd = fd;
        } else {
            close(fd);
            fd = -1;
        }
    }
    pthread_mutex_unlock(&g_rec_lock);
    return fd >= 0 ? 0 : -1;
}

void
fp_replay_record_stop(void)
{
    pthread_mutex_lock(&g_rec_lock);
    if (g_rec_fd >= 0) {
        close(g_rec_fd);
        g_rec_fd = -1;
    }
    pthread_mutex_unlock(&g_rec_lock);
}

int
fp_replay_recording(void)
{
    return g_rec_fd >= 0;
}

void
fp_replay_record(int is_up, unsigned long long ts_ms,
                 const unsigned char *b, size_t n)
{
    pthread_mutex_lock(&g_rec_lock);
    if (g_rec_fd >= 0) {
        unsigned char h[13];
        h[0] = is_up ? 'u' : 'd';
        put_be(h + 1, ts_ms, 8);
        put_be(h + 9, (unsigned long long) n, 4);
        if (write(g_rec_fd, h, sizeof(h)) == (ssize_t) sizeof(h) && n > 0) {
            ssize_t w = write(g_rec_fd, b, n);
            (void) w;
        }
    }
    pthread_mutex_unlock(&g_rec_lock);
}

int
fp_replay_load(const char *path, fp_replay_store *s)
{
    memset(s, 0, sizeof(*s));
    FILE *f = fopen(path, "rb");
    if (!f) {
        return -1;
    }
    unsigned char magic[5];
    if (fread(magic, 1, sizeof(magic), f) != sizeof(magic) ||
        memcmp(magic, REC_MAGIC, sizeof(magic)) != 0) {
        fclose(f);
        return -1;
    }
    size_t cap = 0;
    for (;;) {
        unsigned char h[13];
        if (fread(h, 1, sizeof(h), f) != sizeof(h)) {
            break;
        }
        size_t         len   = (size_t) get_be(h + 9, 4);
        unsigned char *bytes = NULL;
        if (len > 0) {
            bytes = malloc(len);
            if (!bytes || fread(bytes, 1, len, f) != len) {
                free(bytes);
                break;
            }
        }
        if (s->n == cap) {
            size_t         ncap = cap ? cap * 2 : 64;
            fp_replay_rec *nr   = realloc(s->recs, ncap * sizeof(*nr));
            if (!nr) {
                free(bytes);
                break;
            }
            s->recs = nr;
            cap = ncap;
        }
        s->recs[s->n].is_up = (h[0] == 'u');
        s->recs[s->n].ts_ms = get_be(h + 1, 8);
        s->recs[s->n].bytes = bytes;
        s->recs[s->n].len   = len;
        s->n++;
    }
    fclose(f);
    return 0;
}

void
fp_replay_free(fp_replay_store *s)
{
    for (size_t i = 0; i < s->n; i++) {
        free(s->recs[i].bytes);
    }
    free(s->recs);
    s->recs = NULL;
    s->n = 0;
}
