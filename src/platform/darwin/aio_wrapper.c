/* Bounded Darwin async file I/O worker pool for the module PAL. */
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

typedef struct brix_aio_job brix_aio_job_t;

struct brix_aio_job {
    brix_aio_job_t *next;
    void           *buf;
    size_t          count;
    off_t           offset;
    ssize_t         result;
    void          (*callback)(int, ssize_t, void *);
    void           *user_data;
    int             fd;
    int             error;
    unsigned        write_op:1;
};

typedef struct brix_aio_ctx {
    pthread_mutex_t mutex;
    pthread_cond_t  queued_cond;
    pthread_cond_t  complete_cond;
    pthread_t      *workers;
    brix_aio_job_t *queued_head;
    brix_aio_job_t *queued_tail;
    brix_aio_job_t *complete_head;
    brix_aio_job_t *complete_tail;
    size_t          max_entries;
    size_t          outstanding;
    size_t          worker_count;
    int             stopping;
} brix_aio_ctx_t;

static ssize_t
aio_run_job(brix_aio_job_t *job)
{
    ssize_t result;

    do {
        result = job->write_op
            ? pwrite(job->fd, job->buf, job->count, job->offset) /* vfs-seam-allow: SEAM_CORRECT - PAL async storage implementation beneath VFS */
            : pread(job->fd, job->buf, job->count, job->offset); /* vfs-seam-allow: SEAM_CORRECT - PAL async storage implementation beneath VFS */
    } while (result < 0 && errno == EINTR);
    return result;
}

static brix_aio_job_t *
aio_pop_job(brix_aio_job_t **head, brix_aio_job_t **tail)
{
    brix_aio_job_t *job = *head;

    if (job != NULL) {
        *head = job->next;
        if (*head == NULL) *tail = NULL;
        job->next = NULL;
    }
    return job;
}

static void
aio_push_job(brix_aio_job_t **head, brix_aio_job_t **tail,
    brix_aio_job_t *job)
{
    job->next = NULL;
    if (*tail == NULL) *head = job;
    else (*tail)->next = job;
    *tail = job;
}

static void *
aio_worker(void *data)
{
    brix_aio_ctx_t *ctx = data;

    for (;;) {
        brix_aio_job_t *job;

        pthread_mutex_lock(&ctx->mutex);
        while (ctx->queued_head == NULL && !ctx->stopping) {
            pthread_cond_wait(&ctx->queued_cond, &ctx->mutex);
        }
        if (ctx->queued_head == NULL && ctx->stopping) {
            pthread_mutex_unlock(&ctx->mutex);
            return NULL;
        }
        job = aio_pop_job(&ctx->queued_head, &ctx->queued_tail);
        pthread_mutex_unlock(&ctx->mutex);
        job->result = aio_run_job(job);
        job->error = job->result < 0 ? errno : 0;
        pthread_mutex_lock(&ctx->mutex);
        aio_push_job(&ctx->complete_head, &ctx->complete_tail, job);
        pthread_cond_signal(&ctx->complete_cond);
        pthread_mutex_unlock(&ctx->mutex);
    }
}

static void
aio_release_ctx(brix_aio_ctx_t *ctx)
{
    pthread_cond_destroy(&ctx->complete_cond);
    pthread_cond_destroy(&ctx->queued_cond);
    pthread_mutex_destroy(&ctx->mutex);
    free(ctx->workers);
    free(ctx);
}

/* Create a bounded pool; at most four threads service max_entries requests. */
brix_aio_ctx_t *
brix_aio_create(size_t max_entries)
{
    brix_aio_ctx_t *ctx;
    size_t          i;

    if (max_entries == 0) {
        errno = EINVAL;
        return NULL;
    }
    ctx = calloc(1, sizeof(*ctx));
    if (ctx == NULL) return NULL;
    ctx->max_entries = max_entries;
    ctx->worker_count = max_entries < 4 ? max_entries : 4;
    ctx->workers = calloc(ctx->worker_count, sizeof(ctx->workers[0]));
    if (ctx->workers == NULL) {
        free(ctx);
        return NULL;
    }
    if (pthread_mutex_init(&ctx->mutex, NULL) != 0) {
        free(ctx->workers);
        free(ctx);
        errno = ENOMEM;
        return NULL;
    }
    if (pthread_cond_init(&ctx->queued_cond, NULL) != 0) {
        pthread_mutex_destroy(&ctx->mutex);
        free(ctx->workers);
        free(ctx);
        errno = ENOMEM;
        return NULL;
    }
    if (pthread_cond_init(&ctx->complete_cond, NULL) != 0) {
        pthread_cond_destroy(&ctx->queued_cond);
        pthread_mutex_destroy(&ctx->mutex);
        free(ctx->workers);
        free(ctx);
        errno = ENOMEM;
        return NULL;
    }
    for (i = 0; i < ctx->worker_count; i++) {
        if (pthread_create(&ctx->workers[i], NULL, aio_worker, ctx) != 0) {
            ctx->worker_count = i;
            pthread_mutex_lock(&ctx->mutex);
            ctx->stopping = 1;
            pthread_cond_broadcast(&ctx->queued_cond);
            pthread_mutex_unlock(&ctx->mutex);
            while (i > 0) pthread_join(ctx->workers[--i], NULL);
            aio_release_ctx(ctx);
            errno = EAGAIN;
            return NULL;
        }
    }
    return ctx;
}

static int
aio_submit(brix_aio_ctx_t *ctx, int fd, void *buf, size_t count, off_t offset,
    void (*callback)(int, ssize_t, void *), void *user_data, int write_op)
{
    brix_aio_job_t *job;

    if (ctx == NULL || fd < 0 || buf == NULL || callback == NULL || offset < 0) {
        errno = EINVAL;
        return -1;
    }
    job = calloc(1, sizeof(*job));
    if (job == NULL) return -1;
    job->fd = fd;
    job->buf = buf;
    job->count = count;
    job->offset = offset;
    job->callback = callback;
    job->user_data = user_data;
    job->write_op = write_op != 0;
    pthread_mutex_lock(&ctx->mutex);
    if (ctx->stopping || ctx->outstanding >= ctx->max_entries) {
        pthread_mutex_unlock(&ctx->mutex);
        free(job);
        errno = ctx->stopping ? ECANCELED : EAGAIN;
        return -1;
    }
    ctx->outstanding++;
    aio_push_job(&ctx->queued_head, &ctx->queued_tail, job);
    pthread_cond_signal(&ctx->queued_cond);
    pthread_mutex_unlock(&ctx->mutex);
    return 0;
}

/* Queue a positional read; completion runs on the caller of brix_aio_wait. */
int
brix_aio_read(brix_aio_ctx_t *ctx, int fd, void *buf, size_t count,
    off_t offset, void (*callback)(int, ssize_t, void *), void *user_data)
{
    return aio_submit(ctx, fd, buf, count, offset, callback, user_data, 0);
}

/* Queue a positional write without changing the descriptor's file offset. */
int
brix_aio_write(brix_aio_ctx_t *ctx, int fd, const void *buf, size_t count,
    off_t offset, void (*callback)(int, ssize_t, void *), void *user_data)
{
    return aio_submit(ctx, fd, (void *) buf, count, offset, callback,
        user_data, 1);
}

static void
aio_deadline(struct timespec *deadline, int timeout_ms)
{
    clock_gettime(CLOCK_REALTIME, deadline);
    deadline->tv_sec += timeout_ms / 1000;
    deadline->tv_nsec += (long) (timeout_ms % 1000) * 1000000L;
    if (deadline->tv_nsec >= 1000000000L) {
        deadline->tv_sec++;
        deadline->tv_nsec -= 1000000000L;
    }
}

/* Wait for available completions and dispatch callbacks, respecting timeout. */
int
brix_aio_wait(brix_aio_ctx_t *ctx, int timeout_ms)
{
    struct timespec deadline;
    int             completed = 0;
    int             wait_rc = 0;

    if (ctx == NULL) {
        errno = EINVAL;
        return -1;
    }
    if (timeout_ms >= 0) aio_deadline(&deadline, timeout_ms);
    pthread_mutex_lock(&ctx->mutex);
    while (ctx->complete_head == NULL && ctx->outstanding != 0 && wait_rc == 0) {
        wait_rc = timeout_ms < 0
            ? pthread_cond_wait(&ctx->complete_cond, &ctx->mutex)
            : pthread_cond_timedwait(&ctx->complete_cond, &ctx->mutex,
                &deadline);
    }
    while (ctx->complete_head != NULL) {
        brix_aio_job_t *job = aio_pop_job(&ctx->complete_head,
            &ctx->complete_tail);

        ctx->outstanding--;
        pthread_mutex_unlock(&ctx->mutex);
        errno = job->error;
        job->callback(job->fd, job->result, job->user_data);
        free(job);
        completed++;
        pthread_mutex_lock(&ctx->mutex);
    }
    pthread_mutex_unlock(&ctx->mutex);
    if (wait_rc != 0 && wait_rc != ETIMEDOUT) {
        errno = wait_rc;
        return -1;
    }
    return completed;
}

/* Drain queued work, dispatch every completion, then release the pool. */
void
brix_aio_destroy(brix_aio_ctx_t *ctx)
{
    size_t i;

    if (ctx == NULL) return;
    pthread_mutex_lock(&ctx->mutex);
    ctx->stopping = 1;
    pthread_cond_broadcast(&ctx->queued_cond);
    pthread_mutex_unlock(&ctx->mutex);
    for (i = 0; i < ctx->worker_count; i++) pthread_join(ctx->workers[i], NULL);
    while (ctx->outstanding != 0) (void) brix_aio_wait(ctx, -1);
    aio_release_ctx(ctx);
}
