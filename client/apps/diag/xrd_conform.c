/* xrd conform — Phase-118 offline oracle/generator and planted-object engine. */
#include "xrd_internal.h"
#include "xrd_conform_internal.h"
#include "conform/conform.h"

#include <openssl/rand.h>
#include <sys/stat.h>

#ifndef O_NOFOLLOW
#define O_NOFOLLOW 0
#endif

#define CONFORM_KEY_FILE "brix-conform.key"

static void
conform_usage(FILE *out)
{
    fprintf(out,
        "usage: xrd conform plan [--budget exhaustive|pairwise|boundary] [--print-cases]\n"
        "       xrd conform plant <scratch-directory> [--large]\n"
        "       xrd conform adopt <scratch-directory> <run-key-hex> [--large]\n"
        "       xrd conform verify <scratch-directory> [--large]\n"
        "       xrd conform accept|full|watch <url> [options]\n"
        "run options: --profile <role> --reference strict|ecosystem|both\n"
        "             --budget exhaustive|pairwise|boundary --fail-on <mode>\n"
        "             --families <csv> --exclude <csv> --only <clause-id>\n"
        "             --verify-negative <clause-id> (repeatable, maximum 64)\n"
        "             --also <cross-plane-url> (repeatable, maximum 8)\n"
        "             --error-fixture <ERRNO>[@http]=<url> (repeatable, maximum 64)\n"
        "             --readonly-fixture <webdav|s3|oci|gridftp>=<url>\n"
        "             --auth-fixture <protocol>=<root-url> (repeatable, maximum 8)\n"
        "             --tls-cleartext-fixture <login|data|gpf|session|tpc>=<root-url>\n"
        "             --token-fixture <audience|expired|not-yet-valid|issuer>=<root-url>\n"
        "             --denied-fixture <root|http|s3>=<url> (one per plane)\n"
        "             --mutation-fixture <root|http|s3>=<url> (one per plane)\n"
        "             --open-fixture <readonly|staged-nowait|idle>=<root-url>\n"
        "             --locate-fixture <refresh|slow>=<root-url>\n"
        "             --move-fixture <destination-root-scratch-url>\n"
        "             --quota-target <root-url> --capacity-target <root-url>\n"
        "             --webdav-outside-fixture <http-url>\n"
        "             --cache-fixture <partial|filling|capacity|corrupt>\n"
        "             --tpc-fixture <source-denied|destination-abort|scoped-delegation|native-and-webdav|egress-blocked>\n"
        "             --scratch <path> --allow-mutate --allow-disrupt\n"
        "             --confirm-target <url> --adv-observer <http[s]://url>\n"
        "             --adv-fixture <generator-gap|nondeterministic|authority-bypass>\n"
        "             --run-key <32-hex> --out <dir>\n"
        "             --wall-seconds <n> --request-limit <n> --byte-limit <n>\n"
        "             --http-request-line-limit <bytes>\n"
        "watch options: --watch-interval-seconds <n> --watch-cycles <n>\n");
}

/* ---- Print one object's selected read grid ----
 *
 * WHAT: Returns and optionally prints selected offset/length cases for an object.
 * WHY: Object-grid nesting is independent from the plan command's shape summary.
 * HOW: Generate axes, apply budget selection, compute expected read answers.
 */
static size_t
conform_plan_object(const brix_conform_object *object, size_t object_index,
    size_t object_count, brix_conform_budget budget, int print_cases)
{
    int64_t offsets[BRIX_CONFORM_AXIS_MAX];
    int64_t lengths[BRIX_CONFORM_AXIS_MAX];
    size_t noff = brix_conform_offsets(object->size, offsets,
        BRIX_CONFORM_AXIS_MAX);
    size_t object_cases = 0;
    size_t offset_index;

    for (offset_index = 0; offset_index < noff; offset_index++) {
        size_t nlen = brix_conform_lengths(object->size, offsets[offset_index],
            lengths, BRIX_CONFORM_AXIS_MAX);
        size_t length_index;

        for (length_index = 0; length_index < nlen; length_index++) {
            brix_conform_read_answer answer;

            if (!brix_conform_case_selected(budget, object_index, object_count,
                    offset_index, noff, length_index, nlen,
                    offsets[offset_index], lengths[length_index], object->size))
                continue;
            answer = brix_conform_read_expected(object->size,
                offsets[offset_index], lengths[length_index]);
            if (print_cases) {
                printf("object=%s size=%llu offset=%lld length=%lld expected=%llu invalid=%d\n",
                    object->name, (unsigned long long) object->size,
                    (long long) offsets[offset_index],
                    (long long) lengths[length_index],
                    (unsigned long long) answer.expected_len, answer.invalid);
            }
            object_cases++;
        }
    }
    return object_cases;
}

static int
conform_plan(int argc, char **argv)
{
    const brix_conform_object *objects;
    const brix_conform_http_range_case *ranges;
    brix_conform_budget        budget = BRIX_CONFORM_PAIRWISE;
    brix_conform_page_case     pages[BRIX_CONFORM_SHAPE_MAX];
    brix_conform_vector_case   vectors[BRIX_CONFORM_SHAPE_MAX];
    size_t                     object_count;
    size_t                     page_count;
    size_t                     range_count;
    size_t                     vector_count;
    size_t                     total = 0;
    size_t                     oi;
    int                        print_cases = 0;
    int                        argi;

    for (argi = 3; argi < argc; argi++) {
        if (strcmp(argv[argi], "--print-cases") == 0) {
            print_cases = 1;
        } else if (strcmp(argv[argi], "--budget") == 0 && argi + 1 < argc) {
            if (brix_conform_budget_parse(argv[++argi], &budget) != 0) {
                BRIX_CLIENT_LOG("ERROR",
                    "xrd conform: invalid budget '%s'\n", argv[argi]);
                return 4;
            }
        } else {
            BRIX_CLIENT_LOG("ERROR",
                "xrd conform: unknown plan option '%s'\n", argv[argi]);
            return 4;
        }
    }

    objects = brix_conform_objects(&object_count);
    for (oi = 0; oi < object_count; oi++) {
        size_t object_cases = conform_plan_object(&objects[oi], oi,
            object_count, budget, print_cases);
        printf("object=%s size=%llu cases=%zu%s\n", objects[oi].name,
            (unsigned long long) objects[oi].size, object_cases,
            objects[oi].large ? " large" : "");
        total += object_cases;
    }
    printf("budget=%s objects=%zu cases=%zu\n",
        brix_conform_budget_name(budget), object_count, total);
    page_count = brix_conform_page_cases(budget, pages,
        BRIX_CONFORM_SHAPE_MAX);
    vector_count = brix_conform_vector_cases(budget, vectors,
        BRIX_CONFORM_SHAPE_MAX);
    ranges = brix_conform_http_range_cases(budget, &range_count);
    if (print_cases) {
        size_t i;

        for (i = 0; i < page_count; i++) {
            printf("page offset=%llu length=%llu first-off=%u full=%u last=%u\n",
                (unsigned long long) pages[i].offset,
                (unsigned long long) pages[i].length,
                pages[i].first_page_off, pages[i].full_pages,
                pages[i].last_page_bytes);
        }
        for (i = 0; i < vector_count; i++) {
            printf("vector count=%u element-size=%u total=%u geometry=%s handles=%u\n",
                vectors[i].element_count, vectors[i].element_size,
                vectors[i].total_bytes,
                brix_conform_vector_geometry_name(vectors[i].geometry),
                vectors[i].handle_count);
        }
        for (i = 0; i < range_count; i++) {
            printf("http-range expression=%s kind=%d\n", ranges[i].expression,
                (int) ranges[i].kind);
        }
    }
    printf("page-cases=%zu vector-cases=%zu http-range-cases=%zu\n",
        page_count, vector_count, range_count);
    return 0;
}

static int
write_all(int fd, const uint8_t *data, size_t len)
{
    size_t done = 0;

    while (done < len) {
        ssize_t n = write(fd, data + done, len - done);

        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return -1;
        done += (size_t) n;
    }
    return 0;
}

static int
plant_one(int dirfd, const brix_conform_object *object,
    const brix_conform_key *key)
{
    uint8_t  buffer[65536];
    char     name[64];
    uint64_t offset = 0;
    int      fd;

    if ((size_t) snprintf(name, sizeof(name), "brix-conform-%s", object->name)
        >= sizeof(name)) return -1;
    fd = openat(dirfd, name, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
    if (fd < 0) return -1;
    while (offset < object->size) {
        uint64_t remaining = object->size - offset;
        size_t   chunk = remaining < sizeof(buffer)
            ? (size_t) remaining : sizeof(buffer);

        brix_conform_fill(key, offset, buffer, chunk);
        if (write_all(fd, buffer, chunk) != 0) {
            int saved = errno;
            close(fd);
            unlinkat(dirfd, name, 0);
            errno = saved;
            return -1;
        }
        offset += chunk;
    }
    if (fsync(fd) != 0 || close(fd) != 0) {
        int saved = errno;
        unlinkat(dirfd, name, 0);
        errno = saved;
        return -1;
    }
    return 0;
}

static int
verify_one(int dirfd, const brix_conform_object *object,
    const brix_conform_key *key)
{
    uint8_t  buffer[65536];
    char     name[64];
    uint64_t offset = 0;
    int      fd;

    snprintf(name, sizeof(name), "brix-conform-%s", object->name);
    fd = openat(dirfd, name, O_RDONLY | O_NOFOLLOW);
    if (fd < 0) return -1;
    while (offset < object->size) {
        ssize_t n = read(fd, buffer, sizeof(buffer));

        if (n < 0 && errno == EINTR) continue;
        if (n <= 0 || brix_conform_verify(key, offset, buffer, (size_t) n,
                         NULL) != 0) {
            close(fd);
            errno = EIO;
            return -1;
        }
        offset += (uint64_t) n;
    }
    if (read(fd, buffer, 1) != 0) {
        close(fd);
        errno = EIO;
        return -1;
    }
    return close(fd);
}

static void
print_key(const brix_conform_key *key)
{
    char hex[BRIX_CONFORM_KEY_SIZE * 2U + 1U];

    brix_conform_key_format(key, hex);
    printf("run_key=%s\n", hex);
}

static int
write_key_file(int dirfd, const brix_conform_key *key)
{
    int fd = openat(dirfd, CONFORM_KEY_FILE,
        O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);

    if (fd < 0) return -1;
    if (write_all(fd, key->bytes, sizeof(key->bytes)) != 0 || fsync(fd) != 0
        || close(fd) != 0) {
        int saved = errno;

        close(fd);
        unlinkat(dirfd, CONFORM_KEY_FILE, 0);
        errno = saved;
        return -1;
    }
    return 0;
}

static int
read_key_file(int dirfd, brix_conform_key *key)
{
    uint8_t extra;
    size_t  done = 0;
    int     fd = openat(dirfd, CONFORM_KEY_FILE, O_RDONLY | O_NOFOLLOW);

    if (fd < 0) return -1;
    while (done < sizeof(key->bytes)) {
        ssize_t n = read(fd, key->bytes + done, sizeof(key->bytes) - done);

        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) {
            close(fd);
            errno = EINVAL;
            return -1;
        }
        done += (size_t) n;
    }
    if (read(fd, &extra, 1) != 0) {
        close(fd);
        errno = EINVAL;
        return -1;
    }
    return close(fd);
}

static int
catalogue_verify(int dirfd, const brix_conform_key *key, int include_large)
{
    const brix_conform_object *objects;
    size_t object_count;
    size_t i;

    objects = brix_conform_objects(&object_count);
    for (i = 0; i < object_count; i++) {
        if (objects[i].large && !include_large) {
            printf("object=%s verdict=SKIP reason=large-object-disabled\n",
                objects[i].name);
            continue;
        }
        if (verify_one(dirfd, &objects[i], key) != 0) {
            BRIX_CLIENT_LOG("ERROR",
                "xrd conform: object %s failed verification: %s\n",
                objects[i].name, strerror(errno));
            return 52;
        }
        printf("object=%s size=%llu verdict=PASS\n", objects[i].name,
            (unsigned long long) objects[i].size);
    }
    return 0;
}

static int
conform_plant(int argc, char **argv)
{
    const brix_conform_object *objects;
    brix_conform_key           key;
    size_t                     object_count;
    size_t                     i;
    int                        include_large = 0;
    int                        dirfd;

    if (argc < 4) {
        conform_usage(stderr);
        return 4;
    }
    if (argc == 5 && strcmp(argv[4], "--large") == 0) include_large = 1;
    else if (argc > 4) {
        BRIX_CLIENT_LOG("ERROR",
            "xrd conform: unknown plant option '%s'\n", argv[4]);
        return 4;
    }
    dirfd = open(argv[3], O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
    if (dirfd < 0) {
        BRIX_CLIENT_LOG("ERROR",
            "xrd conform: cannot securely open scratch directory: %s\n",
            strerror(errno));
        return 51;
    }
    if (RAND_bytes(key.bytes, sizeof(key.bytes)) != 1) {
        BRIX_CLIENT_LOG("ERROR",
            "xrd conform: cryptographic run-key generation failed\n");
        close(dirfd);
        return 51;
    }
    print_key(&key);
    objects = brix_conform_objects(&object_count);
    for (i = 0; i < object_count; i++) {
        if (objects[i].large && !include_large) {
            printf("object=%s verdict=SKIP reason=large-object-disabled\n",
                objects[i].name);
            continue;
        }
        if (plant_one(dirfd, &objects[i], &key) != 0
            || verify_one(dirfd, &objects[i], &key) != 0) {
            BRIX_CLIENT_LOG("ERROR", "xrd conform: object %s failed: %s\n",
                objects[i].name, strerror(errno));
            close(dirfd);
            return 52;
        }
        printf("object=%s size=%llu verdict=PASS\n", objects[i].name,
            (unsigned long long) objects[i].size);
    }
    if (write_key_file(dirfd, &key) != 0) {
        BRIX_CLIENT_LOG("ERROR", "xrd conform: cannot persist run key: %s\n",
            strerror(errno));
        close(dirfd);
        return 52;
    }
    close(dirfd);
    return 0;
}

static int
conform_verify_or_adopt(int argc, char **argv, int adopt)
{
    brix_conform_key key;
    int              include_large = 0;
    int              option_index = adopt ? 5 : 4;
    int              dirfd;
    int              rc;

    if (argc < option_index) {
        conform_usage(stderr);
        return 4;
    }
    if (argc == option_index + 1
        && strcmp(argv[option_index], "--large") == 0) include_large = 1;
    else if (argc > option_index) {
        BRIX_CLIENT_LOG("ERROR", "xrd conform: unknown option '%s'\n",
            argv[option_index]);
        return 4;
    }
    dirfd = open(argv[3], O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
    if (dirfd < 0) {
        BRIX_CLIENT_LOG("ERROR",
            "xrd conform: cannot securely open scratch directory: %s\n",
            strerror(errno));
        return 51;
    }
    if (adopt) {
        if (brix_conform_key_parse(argv[4], &key) != 0) {
            BRIX_CLIENT_LOG("ERROR",
                "xrd conform: run key must contain exactly 32 hex characters\n");
            close(dirfd);
            return 4;
        }
    } else if (read_key_file(dirfd, &key) != 0) {
        BRIX_CLIENT_LOG("ERROR",
            "xrd conform: cannot read persisted run key: %s\n",
            strerror(errno));
        close(dirfd);
        return 51;
    }
    rc = catalogue_verify(dirfd, &key, include_large);
    if (rc == 0 && adopt && write_key_file(dirfd, &key) != 0) {
        BRIX_CLIENT_LOG("ERROR",
            "xrd conform: cannot persist adopted run key: %s\n",
            strerror(errno));
        rc = 52;
    }
    if (rc == 0) print_key(&key);
    close(dirfd);
    return rc;
}

/* Dispatch offline corpus tools and fail-closed remote conformance shapes. */
int
xrd_conform(int argc, char **argv)
{
    if (argc < 3 || strcmp(argv[2], "help") == 0
        || strcmp(argv[2], "--help") == 0) {
        conform_usage(argc < 3 ? stderr : stdout);
        return argc < 3 ? 4 : 0;
    }
    if (strcmp(argv[2], "plan") == 0) return conform_plan(argc, argv);
    if (strcmp(argv[2], "plant") == 0) return conform_plant(argc, argv);
    if (strcmp(argv[2], "adopt") == 0)
        return conform_verify_or_adopt(argc, argv, 1);
    if (strcmp(argv[2], "verify") == 0)
        return conform_verify_or_adopt(argc, argv, 0);
    if (strcmp(argv[2], "accept") == 0 || strcmp(argv[2], "full") == 0
        || strcmp(argv[2], "watch") == 0) {
        xrd_conform_run run;
        int rc = xrd_conform_parse_run(argc, argv, &run);

        if (rc != 0) return rc;
        return xrd_conform_execute(&run);
    }
    BRIX_CLIENT_LOG("ERROR", "xrd conform: unknown mode '%s'\n", argv[2]);
    conform_usage(stderr);
    return 4;
}
