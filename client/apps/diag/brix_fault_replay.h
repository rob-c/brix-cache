/*
 * brix_fault_replay.h — session record / replay for brix-fault-proxy.
 *
 * RECORD: append every byte segment the proxy forwards (in either direction,
 * after all faults have been applied — i.e. exactly what the peers saw) to a
 * capture file, each framed with its direction and a millisecond timestamp
 * relative to proxy start.  This gives a deterministic, byte-exact transcript of
 * a real session.
 *
 * REPLAY: load a capture back into memory so the proxy can act as a synthetic
 * peer — feeding a client the recorded upstream (or client) byte timeline with
 * the original inter-segment timing, no live upstream needed.  Turns a
 * once-seen, hard-to-reproduce server behaviour (a malformed response, an exact
 * partial-write pattern, a timing-dependent bug) into a repeatable fixture.
 *
 * File format: 5-byte magic "BFPR\1", then records of
 *   [dir:1 ('u'=client->upstream, 'd'=upstream->client)]
 *   [ts_ms:8 big-endian][len:4 big-endian][len payload bytes].
 *
 * Recording is process-global and mutex-guarded (many relay threads).  The
 * replay store is caller-owned and immutable once loaded.
 */
#ifndef BRIX_FAULT_REPLAY_H
#define BRIX_FAULT_REPLAY_H

#include <stddef.h>

/* Begin recording to `path` (truncating it), writing the magic.  Replaces any
 * current recording.  Returns 0 on success, -1 if the file could not be opened. */
int  fp_replay_record_start(const char *path);

/* Stop and close the current recording (no-op if not recording). */
void fp_replay_record_stop(void);

/* True while a recording is open. */
int  fp_replay_recording(void);

/* Append one framed segment to the recording (no-op if not recording).
 * Internally mutex-guarded, safe to call from any relay thread. */
void fp_replay_record(int is_up, unsigned long long ts_ms,
                      const unsigned char *b, size_t n);

/* One recorded segment held in memory. */
typedef struct {
    int                is_up;
    unsigned long long ts_ms;
    unsigned char     *bytes;
    size_t             len;
} fp_replay_rec;

/* An in-memory capture loaded from a file. */
typedef struct {
    fp_replay_rec *recs;
    size_t         n;
} fp_replay_store;

/* Load `path` into *s (zeroing it first).  Returns 0 on success, -1 on a missing
 * file or a bad magic.  Free with fp_replay_free(). */
int  fp_replay_load(const char *path, fp_replay_store *s);

/* Release a store loaded by fp_replay_load(). */
void fp_replay_free(fp_replay_store *s);

#endif /* BRIX_FAULT_REPLAY_H */
