/* Phase-118 credential-scrubbed divergence captures. */
#include "brix.h"
#include "conform/report.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#ifndef O_NOFOLLOW
#define O_NOFOLLOW 0
#endif

#define CAP_MAGIC "XRDCAP1\n"
#define CAP_MAGIC_SIZE 8U
#define CAP_WIRE_MAX (XRDC_DLEN_MAX + 64U)

typedef struct { uint8_t bits[65536U / 8U]; } sensitive_streams;
typedef struct {
    int direction;
    int request;
    uint16_t sid;
    uint16_t code;
    uint32_t length;
    uint8_t *wire;
} capture_frame;

/* WHAT: Read an exact big-endian u16. WHY: Reject truncated record fields.
 * HOW: Combine a fixed two-byte buffer. */
static int
read_u16(FILE *input, uint16_t *value)
{
    uint8_t bytes[2];

    if (fread(bytes, 1, sizeof(bytes), input) != sizeof(bytes)) return -1;
    *value = (uint16_t) ((uint16_t) bytes[0] << 8) | bytes[1];
    return 0;
}

/* WHAT: Read an exact big-endian u32. WHY: Bound wire record allocation.
 * HOW: Combine a fixed four-byte buffer. */
static int
read_u32(FILE *input, uint32_t *value)
{
    uint8_t bytes[4];

    if (fread(bytes, 1, sizeof(bytes), input) != sizeof(bytes)) return -1;
    *value = ((uint32_t) bytes[0] << 24) | ((uint32_t) bytes[1] << 16)
        | ((uint32_t) bytes[2] << 8) | bytes[3];
    return 0;
}

/* WHAT: Write the numeric half of a frame record. WHY: Preserve replay format.
 * HOW: Split sid, code and length into one network-order byte array. */
static int
write_numbers(FILE *output, uint16_t sid, uint16_t code, uint32_t length)
{
    uint8_t bytes[8] = {
        (uint8_t) (sid >> 8), (uint8_t) sid,
        (uint8_t) (code >> 8), (uint8_t) code,
        (uint8_t) (length >> 24), (uint8_t) (length >> 16),
        (uint8_t) (length >> 8), (uint8_t) length
    };

    return fwrite(bytes, 1, sizeof(bytes), output) == sizeof(bytes) ? 0 : -1;
}

/* WHAT: Classify connection-local opcodes. WHY: They carry credentials,
 * signatures or session identifiers. HOW: Match authoritative wire constants. */
static int
sensitive_opcode(uint16_t code)
{
    return code == kXR_protocol || code == kXR_login || code == kXR_auth
        || code == kXR_bind || code == kXR_endsess || code == kXR_sigver;
}

/* WHAT: Record a sensitive request stream. WHY: Response records lack opcode.
 * HOW: Set one bit in the complete 16-bit sid bitmap. */
static void
stream_mark(sensitive_streams *streams, uint16_t sid)
{
    streams->bits[sid >> 3] |= (uint8_t) (1U << (sid & 7U));
}

/* WHAT: Test sensitive-stream membership. WHY: Remove matching server replies.
 * HOW: Address the same bitmap bit used by stream_mark. */
static int
stream_sensitive(const sensitive_streams *streams, uint16_t sid)
{
    return (streams->bits[sid >> 3] & (uint8_t) (1U << (sid & 7U))) != 0;
}

/* WHAT: Consume exact bytes. WHY: Seeking beyond EOF would accept truncation.
 * HOW: Read bounded scratch chunks until complete. */
static int
discard_bytes(FILE *input, uint32_t length)
{
    uint8_t scratch[512];

    while (length > 0) {
        size_t chunk = length < sizeof(scratch) ? length : sizeof(scratch);

        if (fread(scratch, 1, chunk, input) != chunk) return -1;
        length -= (uint32_t) chunk;
    }
    return 0;
}

/* WHAT: Validate and discard one metadata record. WHY: Metadata may identify
 * credentials and is unnecessary for replay. HOW: Consume bounded key/value. */
static int
discard_meta(FILE *input)
{
    int key_length = fgetc(input);
    uint16_t value_length;

    if (key_length == EOF || discard_bytes(input, (uint32_t) key_length) != 0
        || read_u16(input, &value_length) != 0
        || discard_bytes(input, value_length) != 0) return -1;
    return 0;
}

/* WHAT: Decode one bounded frame record. WHY: Scrub and validator must share
 * identical truncation checks. HOW: Read fields, bound length, allocate bytes. */
static int
read_frame(FILE *input, capture_frame *frame)
{
    memset(frame, 0, sizeof(*frame));
    frame->direction = fgetc(input);
    frame->request = fgetc(input);
    if (frame->direction == EOF || frame->request == EOF) return -1;
    if (read_u16(input, &frame->sid) != 0) return -1;
    if (read_u16(input, &frame->code) != 0) return -1;
    if (read_u32(input, &frame->length) != 0) return -1;
    if (frame->length > CAP_WIRE_MAX) return -1;
    frame->wire = malloc(frame->length == 0 ? 1 : frame->length);
    if (frame->wire == NULL) return -1;
    if (fread(frame->wire, 1, frame->length, input) != frame->length) {
        free(frame->wire);
        frame->wire = NULL;
        return -1;
    }
    return 0;
}

/* WHAT: Emit one already-validated frame. WHY: Retained evidence must preserve
 * exact replay bytes. HOW: Write marker, scalar fields and wire body in order. */
static int
write_frame(FILE *output, const capture_frame *frame)
{
    if (fputc('F', output) == EOF) return -1;
    if (fputc(frame->direction, output) == EOF) return -1;
    if (fputc(frame->request, output) == EOF) return -1;
    if (write_numbers(output, frame->sid, frame->code, frame->length) != 0)
        return -1;
    return fwrite(frame->wire, 1, frame->length, output) == frame->length
        ? 0 : -1;
}

/* WHAT: Validate and conditionally retain one frame. WHY: Operation frames are
 * replayable evidence but session frames are secrets. HOW: Track sid and copy. */
static int
scrub_frame(FILE *input, FILE *output, sensitive_streams *streams)
{
    capture_frame frame;
    int rc = 0;

    if (read_frame(input, &frame) != 0) return -1;
    if (frame.request == 1 && frame.direction == '>'
        && sensitive_opcode(frame.code)) stream_mark(streams, frame.sid);
    if (!stream_sensitive(streams, frame.sid)) rc = write_frame(output, &frame);
    free(frame.wire);
    return rc;
}

/* WHAT: Validate one allegedly scrubbed frame. WHY: Credential self-checks
 * need the same structural parser as publication. HOW: Decode, classify, free. */
static int
validate_scrubbed_frame(FILE *input)
{
    capture_frame frame;
    int safe;

    if (read_frame(input, &frame) != 0) return 0;
    safe = !(frame.request == 1 && frame.direction == '>'
        && sensitive_opcode(frame.code));
    free(frame.wire);
    return safe;
}

/* WHAT: Scrub a complete XRDCAP1 stream. WHY: Never publish partial or
 * credential-bearing evidence. HOW: Verify magic and dispatch every record. */
static int
scrub_stream(FILE *input, FILE *output)
{
    char magic[CAP_MAGIC_SIZE];
    sensitive_streams streams;
    int type;

    memset(&streams, 0, sizeof(streams));
    if (fread(magic, 1, sizeof(magic), input) != sizeof(magic)
        || memcmp(magic, CAP_MAGIC, sizeof(magic)) != 0
        || fwrite(magic, 1, sizeof(magic), output) != sizeof(magic)) return -1;
    while ((type = fgetc(input)) != EOF) {
        if (type == 'M') {
            if (discard_meta(input) != 0) return -1;
        } else if (type == 'F') {
            if (scrub_frame(input, output, &streams) != 0) return -1;
        } else {
            return -1;
        }
    }
    return ferror(input) || fflush(output) != 0 ? -1 : 0;
}

/* WHAT: Scrub one clause artifact beneath a dirfd. WHY: Refuse symlink and
 * overwrite attacks. HOW: openat O_EXCL/O_NOFOLLOW mode 0600, scrub and fsync. */
static int
artifact_one(int dirfd, const char *raw_capture, const char *clause_id)
{
    char name[64];
    FILE *input, *output;
    int output_fd;
    int failed = 0;
    int failure_errno = 0;

    if ((size_t) snprintf(name, sizeof(name), "%s.xrdcap", clause_id)
        >= sizeof(name)) return -1;
    input = fopen(raw_capture, "rb");
    if (input == NULL) return -1;
    output_fd = openat(dirfd, name,
        O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
    if (output_fd < 0) {
        fclose(input);
        return -1;
    }
    output = fdopen(output_fd, "wb");
    if (output == NULL) {
        close(output_fd);
        fclose(input);
        return -1;
    }
    if (scrub_stream(input, output) != 0) {
        failure_errno = EBADMSG;
        failed = 1;
    } else if (fsync(fileno(output)) != 0) {
        failure_errno = errno;
        failed = 1;
    }
    if (fclose(input) != 0) {
        if (!failed) failure_errno = errno;
        failed = 1;
    }
    if (fclose(output) != 0) {
        if (!failed) failure_errno = errno;
        failed = 1;
    }
    if (failed) unlinkat(dirfd, name, 0);
    if (failed) errno = failure_errno == 0 ? EIO : failure_errno;
    return failed ? -1 : 0;
}

/* WHAT: Publish one scrubbed capture per divergent clause. WHY: Every red row
 * needs self-contained evidence. HOW: Securely open report dir and scrub anew. */
int
brix_conform_capture_artifacts(const char *out_dir, const char *raw_capture,
    const brix_conform_run_results *results, char *error, size_t error_size)
{
    int dirfd;
    size_t index;

    if (out_dir == NULL || raw_capture == NULL || results == NULL) return -1;
    dirfd = open(out_dir, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
    if (dirfd < 0) return -1;
    for (index = 0; index < results->count; index++) {
        if (results->results[index].verdict != BRIX_CONFORM_VERDICT_DIVERGENT)
            continue;
        if (artifact_one(dirfd, raw_capture,
                results->results[index].clause->id) != 0) {
            int saved = errno;

            close(dirfd);
            if (error != NULL && error_size > 0)
                snprintf(error, error_size, "capture artifact failed: %s",
                    strerror(saved));
            errno = saved;
            return -1;
        }
    }
    if (fsync(dirfd) != 0) {
        close(dirfd);
        return -1;
    }
    close(dirfd);
    if (error != NULL && error_size > 0) error[0] = '\0';
    return 0;
}

static int
write_reproducer_stream(FILE *output,
    const brix_conform_reproducer_frame *frames, size_t frame_count)
{
    size_t index;

    if (fwrite(CAP_MAGIC, 1, CAP_MAGIC_SIZE, output) != CAP_MAGIC_SIZE)
        return -1;
    for (index = 0; index < frame_count; index++) {
        capture_frame frame;

        if (frames[index].wire == NULL || frames[index].wire_length == 0
            || frames[index].wire_length > CAP_WIRE_MAX
            || sensitive_opcode(frames[index].code)) return -1;
        frame.direction = '>';
        frame.request = 1;
        frame.sid = frames[index].sid;
        frame.code = frames[index].code;
        frame.length = frames[index].wire_length;
        frame.wire = (uint8_t *) frames[index].wire;
        if (write_frame(output, &frame) != 0) return -1;
    }
    return fflush(output) == 0 && fsync(fileno(output)) == 0 ? 0 : -1;
}

/* WHAT: Publish minimized hostile requests as one standalone XRDCAP1 file.
 * WHY: ADV findings need exact, credential-free bytes that the normal playback
 *      command can re-issue without depending on the runner's private staging.
 * HOW: Create one fail-closed artifact and encode each request as an F record. */
int
brix_conform_capture_reproducer(const char *out_dir, const char *clause_id,
    const brix_conform_reproducer_frame *frames, size_t frame_count,
    char *error, size_t error_size)
{
    char name[64];
    int dirfd;
    int output_fd;
    FILE *output;
    int failed;
    int saved;

    if (out_dir == NULL || clause_id == NULL || frames == NULL
        || frame_count == 0
        || (size_t) snprintf(name, sizeof(name), "%s.xrdcap", clause_id)
            >= sizeof(name)) {
        errno = EINVAL;
        return -1;
    }
    dirfd = open(out_dir, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
    if (dirfd < 0) return -1;
    output_fd = openat(dirfd, name,
        O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
    if (output_fd < 0) {
        close(dirfd);
        return -1;
    }
    output = fdopen(output_fd, "wb");
    if (output == NULL) {
        saved = errno;
        close(output_fd);
        unlinkat(dirfd, name, 0);
        close(dirfd);
        errno = saved;
        return -1;
    }
    failed = write_reproducer_stream(output, frames, frame_count) != 0;
    saved = failed ? (errno == 0 ? EIO : errno) : 0;
    if (fclose(output) != 0 && !failed) {
        failed = 1;
        saved = errno;
    }
    if (!failed && fsync(dirfd) != 0) {
        failed = 1;
        saved = errno;
    }
    if (failed) unlinkat(dirfd, name, 0);
    if (close(dirfd) != 0 && !failed) {
        failed = 1;
        saved = errno;
    }
    if (failed && error != NULL && error_size > 0)
        snprintf(error, error_size, "reproducer artifact failed: %s",
            strerror(saved));
    if (!failed && error != NULL && error_size > 0) error[0] = '\0';
    if (failed) errno = saved;
    return failed ? -1 : 0;
}

/* WHAT: Verify a published capture has no metadata/session request. WHY: The
 * artifact gate must prove credential hygiene. HOW: Parse and reject either. */
int
brix_conform_capture_is_scrubbed(const char *path, char *error,
    size_t error_size)
{
    FILE *input = fopen(path, "rb");
    char magic[CAP_MAGIC_SIZE];
    int type;
    int safe = 1;

    if (input == NULL || fread(magic, 1, sizeof(magic), input) != sizeof(magic)
        || memcmp(magic, CAP_MAGIC, sizeof(magic)) != 0) safe = 0;
    while (safe && (type = fgetc(input)) != EOF) {
        if (type == 'M') {
            safe = 0;
        } else if (type == 'F') {
            safe = validate_scrubbed_frame(input);
        } else {
            safe = 0;
        }
    }
    if (input != NULL) fclose(input);
    if (!safe && error != NULL && error_size > 0)
        snprintf(error, error_size,
            "capture is malformed or contains session credentials");
    return safe;
}
