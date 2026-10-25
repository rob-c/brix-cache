/*
 * Closed errno-fixture vocabulary for the security assessment CLI.
 * Separates pure name validation from runtime error observations so parsing
 * and execution continue to use one authoritative descriptor table.
 */
#include "xrd_conform_error_fixtures.h"

/* WHAT: Return the immutable errno-fixture vocabulary and its row count.
 * WHY: The hard no-new-globals rule keeps even read-only tables owned by a
 *      function, while every parser/probe still shares one authoritative list.
 * HOW: Initialize one function-local constant array and return its base. */
const error_fixture_spec *
xrd_conform_error_specs(size_t *count)
{
    static const error_fixture_spec specs[] = {
        { "ENOENT", "ERR-001", kXR_NotFound },
        { "EINVAL", "ERR-002", kXR_ArgInvalid },
        { "EPERM", "ERR-003", kXR_NotAuthorized },
        { "EACCES", "ERR-004", kXR_NotAuthorized },
        { "EROFS", "ERR-005", kXR_fsReadOnly },
        { "EEXIST", "ERR-006", kXR_ItExists },
        { "ENOTEMPTY", "ERR-007", kXR_ItExists },
        { "EISDIR", "ERR-008", kXR_isDirectory },
        { "ENAMETOOLONG", "ERR-009", kXR_ArgTooLong },
        { "EIO", "ERR-010", kXR_IOError },
        { "ENOMEM", "ERR-011", kXR_NoMemory },
        { "ENOBUFS", "ERR-012", kXR_NoMemory },
        { "ENOSPC", "ERR-013", kXR_NoSpace },
        { "EDQUOT", "ERR-014", kXR_overQuota },
        { "ENOTSUP", "ERR-015", kXR_Unsupported },
        { "EBADF", "ERR-016", kXR_FileNotOpen },
        { "ETIMEDOUT", "ERR-017", kXR_ReqTimedOut },
        { "ETIME", "ERR-018", kXR_TimerExpired },
        { "ECANCELED", "ERR-019", kXR_Cancelled },
        { "ETXTBSY", "ERR-020", kXR_inProgress },
        { "EBADRQC", "ERR-021", kXR_InvalidRequest },
        { "ENOTBLK", "ERR-022", kXR_NotFile },
        { "ENODEV", "ERR-023", kXR_FSError },
        { "EFAULT", "ERR-024", kXR_ServerError },
        { "EDOM", "ERR-025", kXR_ChkSumErr },
        { "EILSEQ", "ERR-026", kXR_SigVerErr },
        { "ERANGE", "ERR-027", kXR_DecryptErr },
        { "EUSERS", "ERR-028", kXR_Overloaded },
        { "ENOATTR", "ERR-029", kXR_AttrNotFound },
        { "EPROTOTYPE", "ERR-030", kXR_TLSRequired },
        { "EADDRNOTAVAIL", "ERR-031", kXR_noReplicas },
        { "EAUTH", "ERR-032", kXR_AuthFailed },
        { "EIDRM", "ERR-033", kXR_Impossible },
        { "ENOTTY", "ERR-034", kXR_Conflict },
        { "ETOOMANYREFS", "ERR-035", kXR_TooManyErrs },
        { "ENETUNREACH", "ERR-036", kXR_noserver },
        { "EHOSTUNREACH", "ERR-036", kXR_noserver },
        { "ECONNREFUSED", "ERR-036", kXR_noserver },
        { "DEFAULT", "ERR-037", kXR_FSError },
    };

    *count = sizeof(specs) / sizeof(specs[0]);
    return specs;
}


/* WHAT: Locate the immutable fixture descriptor for one exact errno label.
 * WHY: CLI parsing and execution must accept the same closed vocabulary.
 * HOW: Compare bounded input against each literal without requiring a NUL. */
const error_fixture_spec *
xrd_conform_error_spec_find(const char *name, size_t length)
{
    const error_fixture_spec *specs;
    size_t count;
    size_t index;

    specs = xrd_conform_error_specs(&count);
    for (index = 0; index < count; index++)
        if (strlen(specs[index].name) == length
            && memcmp(specs[index].name, name, length) == 0)
            return &specs[index];
    return NULL;
}


/* WHAT: Validate one --error-fixture errno spelling.
 * WHY: A typo must fail before any network operation rather than leave a row
 *      silently inconclusive.
 * HOW: Delegate to the single immutable descriptor table. */
int
xrd_conform_error_fixture_name_valid(const char *name, size_t length)
{
    return name != NULL && xrd_conform_error_spec_find(name, length) != NULL;
}
