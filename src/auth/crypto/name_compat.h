/*
 * Version-neutral slash-form distinguished names for identity and policy.
 * Requires OpenSSL >= 1.1.1. Returns OPENSSL_free-owned strings when buffer is
 * NULL; bounded output fails closed instead of returning a truncated identity.
 * Legacy libraries retain their OID/ASN.1 rendering, but literal '/' and '+'
 * values must never alias structural RDN/AVA separators. No cached/global state.
 */
#pragma once

#include "auth/crypto/asn1_compat.h"
#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <limits.h>
#include <string.h>

#if OPENSSL_VERSION_NUMBER < 0x30000000L
/* ---- Detect the library's delimiter-escaping contract ----
 * WHAT: Return 1 for unescaped values, 0 for fixed libraries, or -1 on error.
 * WHY: Vendors may backport escaping without changing the OpenSSL major ABI.
 * HOW: 1. Render literal delimiters. 2. Compare supported representations.
 */
static inline int
brix_crypto_name_needs_escape(void)
{
    X509_NAME *probe = X509_NAME_new();
    char *text = NULL;
    int result = -1;

    if (probe != NULL
        && X509_NAME_add_entry_by_txt(probe, "CN", MBSTRING_ASC,
                                     (const unsigned char *) "/+", 2, -1, 0))
    {
        text = X509_NAME_oneline(probe, NULL, 0);
    }
    if (text != NULL) {
        if (strcmp(text, "/CN=/+") == 0) {
            result = 1;
        } else if (strcmp(text, "/CN=\\/\\+") == 0) {
            result = 0;
        }
    }
    OPENSSL_free(text);
    X509_NAME_free(probe);
    return result;
}

/* ---- Escape value delimiters, never structural name boundaries ----
 * WHAT: Append one rendered value; return 0 on allocation/write error.
 * WHY: Literal '/' and '+' cannot impersonate additional identity components.
 * HOW: 1. Walk the ASCII rendering. 2. Prefix only literal value delimiters.
 */
static inline int
brix_crypto_name_write_value(BIO *output, const char *value)
{
    for (const char *cursor = value; *cursor != '\0'; cursor++) {
        if ((*cursor == '/' || *cursor == '+') && BIO_write(output, "\\", 1) != 1) {
            return 0;
        }
        if (BIO_write(output, cursor, 1) != 1) {
            return 0;
        }
    }
    return 1;
}

/* ---- Render one AVA with the library's existing OID and ASN.1 rules ----
 * WHAT: Append an attribute and its original RDN delimiter; 1/0 verdict.
 * WHY: Splitting a complete legacy DN cannot distinguish embedded slashes.
 * HOW: 1. Render a single-entry name. 2. Separate its field. 3. Escape its value.
 */
static inline int
brix_crypto_name_write_entry(BIO *output, X509_NAME_ENTRY *entry, const char *separator)
{
    X509_NAME *single = X509_NAME_new();
    char *text = NULL, *value;
    int result = 0;

    if (single != NULL && X509_NAME_add_entry(single, entry, -1, 0)) {
        text = X509_NAME_oneline(single, NULL, 0);
    }
    X509_NAME_free(single);
    if (text == NULL) {
        return 0;
    }
    value = strchr(text, '=');
    if (text[0] == '/' && value != NULL && value - text < INT_MAX) {
        int field_length = (int) (value - text);
        result = BIO_write(output, separator, 1) == 1
                 && BIO_write(output, text + 1, field_length) == field_length
                 && brix_crypto_name_write_value(output, value + 1);
    }
    OPENSSL_free(text);
    return result;
}

/* ---- Normalize legacy names without changing ASN.1 rendering semantics ----
 * WHAT: Return an OPENSSL_free-owned string, or NULL on rendering failure.
 * WHY: Legacy identity mapping and signing policy need the same representation.
 * HOW: 1. Detect fixed builds. 2. Render each RDN/AVA. 3. Copy owned bytes.
 */
static inline char *
brix_crypto_name_legacy(const X509_NAME *name)
{
    int needs_escape = brix_crypto_name_needs_escape();
    BIO *output;
    char *data, *text = NULL;
    long length;
    int previous_set = -1;

    if (needs_escape < 1) {
        return needs_escape == 0 ? X509_NAME_oneline(name, NULL, 0) : NULL;
    }
    output = BIO_new(BIO_s_mem());
    if (output == NULL) {
        return NULL;
    }
    for (int index = 0; index < X509_NAME_entry_count(name); index++) {
        X509_NAME_ENTRY *entry = X509_NAME_get_entry(name, index);
        int current_set = X509_NAME_ENTRY_set(entry);
        const char *separator = index > 0 && current_set == previous_set ? "+" : "/";
        if (!brix_crypto_name_write_entry(output, entry, separator)) {
            BIO_free(output);
            return NULL;
        }
        previous_set = current_set;
    }
    length = BIO_get_mem_data(output, &data);
    if (length >= 0) {
        text = OPENSSL_malloc((size_t) length + 1);
        if (text != NULL) {
            if (length > 0) {
                memcpy(text, data, (size_t) length);
            }
            text[length] = '\0';
        }
    }
    BIO_free(output);
    return text;
}
#endif

/* ---- Obtain one owned, version-neutral identity string ----
 * WHAT: Return a complete slash-form DN or NULL; caller uses OPENSSL_free.
 * WHY: Policy, authorization, delegation and peer pins must not disagree.
 * HOW: 1. Reject missing names. 2. Select the ABI's actual rendering backend.
 */
static inline char *
brix_crypto_name_native_string(const X509_NAME *name)
{
    if (name == NULL) {
        return NULL;
    }
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    return X509_NAME_oneline(name, NULL, 0);
#else
    return brix_crypto_name_legacy(name);
#endif
}

/* ---- Recognize a literal backslash code unit, not a low byte of another glyph ----
 * WHAT: Return 1 only for U+005C in a one-, two- or four-byte name string.
 * WHY: BMP/UniversalString values must not mistake another code point for '\\'.
 * HOW: 1. Require zero high bytes. 2. Compare the final byte.
 */
static inline int
brix_crypto_name_backslash_unit(const unsigned char *unit, size_t width)
{
    for (size_t index = 0; index + 1 < width; index++) {
        if (unit[index] != 0) {
            return 0;
        }
    }
    return unit[width - 1] == '\\';
}

/* ---- Inspect the original ASN.1 value without converting its encoding ----
 * WHAT: Return a literal-backslash count, or -1 for malformed code-unit bounds.
 * WHY: Existing non-ASCII rendering must remain unchanged on both libraries.
 * HOW: 1. Select the ASN.1 unit width. 2. Validate length. 3. Count U+005C.
 */
static inline int
brix_crypto_name_backslashes(const ASN1_STRING *value, size_t *width)
{
    int type, length;
    const unsigned char *data;
    int count = 0;

    if (value == NULL) {
        return -1;
    }
    type = ASN1_STRING_type(value);
    length = brix_crypto_asn1_length(value);
    data = ASN1_STRING_get0_data(value);
    *width = type == V_ASN1_BMPSTRING ? 2 : type == V_ASN1_UNIVERSALSTRING ? 4 : 1;
    if (length < 0 || (size_t) length % *width != 0 || (length > 0 && data == NULL)) {
        return -1;
    }
    for (size_t offset = 0; offset < (size_t) length; offset += *width) {
        count += brix_crypto_name_backslash_unit(data + offset, *width);
    }
    return count;
}

/* ---- Detect whether this library already quotes literal backslashes ----
 * WHAT: Return 2 for raw backslashes, 1 for quoted ones, 0 on unknown/error.
 * WHY: Vendor backports must not silently change canonical identity spelling.
 * HOW: 1. Render one literal backslash. 2. Accept only known slash-form outputs.
 */
static inline int
brix_crypto_name_backslash_factor(void)
{
    X509_NAME *probe = X509_NAME_new();
    char *text = NULL;
    int result = 0;

    if (probe != NULL && X509_NAME_add_entry_by_txt(probe, "CN", MBSTRING_ASC,
                         (const unsigned char *) "\\", 1, -1, 0))
    {
        text = X509_NAME_oneline(probe, NULL, 0);
    }
    if (text != NULL) {
        if (strcmp(text, "/CN=\\") == 0) {
            result = 2;
        } else if (strcmp(text, "/CN=\\\\") == 0) {
            result = 1;
        }
    }
    OPENSSL_free(text);
    X509_NAME_free(probe);
    return result;
}

/* ---- Quote backslashes only in an owned temporary rendering entry ----
 * WHAT: Double U+005C code units, preserving the value's ASN.1 type; 1/0 verdict.
 * WHY: A trailing literal backslash cannot escape the next structural slash.
 * HOW: 1. Bound expansion. 2. Duplicate complete code units. 3. Replace owned data.
 */
static inline int
brix_crypto_name_quote_entry(X509_NAME_ENTRY *entry)
{
    const ASN1_STRING *value = X509_NAME_ENTRY_get_data(entry);
    size_t width, cursor = 0;
    int count = brix_crypto_name_backslashes(value, &width);
    int length;
    const unsigned char *data;
    unsigned char *quoted;
    size_t expanded;
    int result;

    if (count <= 0) {
        return count == 0;
    }
    length = brix_crypto_asn1_length(value);
    data = ASN1_STRING_get0_data(value);
    expanded = (size_t) length + (size_t) count * width;
    if (expanded > INT_MAX) {
        return 0;
    }
    quoted = OPENSSL_malloc(expanded);
    if (quoted == NULL) {
        return 0;
    }
    for (size_t offset = 0; offset < (size_t) length; offset += width) {
        memcpy(quoted + cursor, data + offset, width);
        cursor += width;
        if (brix_crypto_name_backslash_unit(data + offset, width)) {
            memcpy(quoted + cursor, data + offset, width);
            cursor += width;
        }
    }
    result = X509_NAME_ENTRY_set_data(entry, ASN1_STRING_type(value), quoted,
                                      (int) expanded);
    OPENSSL_free(quoted);
    return result;
}

/* ---- Make an owned rendering-only name with unambiguous literal backslashes ----
 * WHAT: Return a temporary name or NULL, retaining original RDN/AVA grouping.
 * WHY: The verified credential and its encoded signature input must never change.
 * HOW: 1. Copy each entry. 2. Preserve grouping. 3. Quote only the owned entries.
 */
static inline X509_NAME *
brix_crypto_name_quoted_copy(const X509_NAME *name)
{
    X509_NAME *copy = X509_NAME_new();
    int previous_set = -1;

    if (copy == NULL) {
        return NULL;
    }
    for (int index = 0; index < X509_NAME_entry_count(name); index++) {
        const X509_NAME_ENTRY *entry = X509_NAME_get_entry(name, index);
        /* Legacy dup takes mutable input; each ABI's getter matches its dup. */
        X509_NAME_ENTRY *quoted = X509_NAME_ENTRY_dup(X509_NAME_get_entry(name, index));
        int current_set = X509_NAME_ENTRY_set(entry);
        int join = index > 0 && current_set == previous_set ? -1 : 0;
        if (quoted == NULL || !brix_crypto_name_quote_entry(quoted)
            || !X509_NAME_add_entry(copy, quoted, -1, join))
        {
            X509_NAME_ENTRY_free(quoted);
            X509_NAME_free(copy);
            return NULL;
        }
        X509_NAME_ENTRY_free(quoted);
        previous_set = current_set;
    }
    return copy;
}

/* ---- Detect whether a name needs the backslash normalization path ----
 * WHAT: Return 1 for a literal backslash, 0 for none, or -1 for malformed data.
 * WHY: Ordinary identities keep the library's direct, allocation-light path.
 * HOW: 1. Inspect each original value. 2. Stop on the first backslash or error.
 */
static inline int
brix_crypto_name_has_backslash(const X509_NAME *name)
{
    for (int index = 0; index < X509_NAME_entry_count(name); index++) {
        size_t width;
        int count = brix_crypto_name_backslashes(
            X509_NAME_ENTRY_get_data(X509_NAME_get_entry(name, index)), &width);
        if (count != 0) {
            return count > 0 ? 1 : -1;
        }
    }
    return 0;
}

/* ---- Return an owned canonical name with literal and structural escapes distinct ----
 * WHAT: Return complete text or NULL; the caller frees it with OPENSSL_free.
 * WHY: Legacy oneline APIs alias a value slash with a backslash/RDN boundary.
 * HOW: 1. Inspect original values. 2. Normalize only when needed. 3. Render/free copy.
 */
static inline char *
brix_crypto_name_string(const X509_NAME *name)
{
    int needs_quote, factor;
    X509_NAME *copy;
    char *text;

    if (name == NULL) {
        return NULL;
    }
    needs_quote = brix_crypto_name_has_backslash(name);
    if (needs_quote < 0) {
        return NULL;
    }
    if (needs_quote == 0) {
        return brix_crypto_name_native_string(name);
    }
    factor = brix_crypto_name_backslash_factor();
    if (factor != 2) {
        return factor == 1 ? brix_crypto_name_native_string(name) : NULL;
    }
    copy = brix_crypto_name_quoted_copy(name);
    if (copy == NULL) {
        return NULL;
    }
    text = brix_crypto_name_native_string(copy);
    X509_NAME_free(copy);
    return text;
}

/* ---- Render owned or bounded identity output with explicit failure ----
 * WHAT: Return owned text for NULL buffer, otherwise buffer or NULL on error.
 * WHY: Truncated or stale output must never become another authenticated DN.
 * HOW: 1. Clear bounded output. 2. Render owned text. 3. Copy only when it fits.
 */
static inline char *
brix_crypto_name_oneline(const X509_NAME *name, char *buffer, size_t capacity)
{
    char *text;
    size_t length;

    if (buffer == NULL) {
        return brix_crypto_name_string(name);
    }
    if (capacity == 0) {
        return NULL;
    }
    buffer[0] = '\0';
    text = brix_crypto_name_string(name);
    if (text == NULL) {
        return NULL;
    }
    length = strlen(text);
    if (length >= capacity) {
        OPENSSL_free(text);
        return NULL;
    }
    memcpy(buffer, text, length + 1);
    OPENSSL_free(text);
    return buffer;
}
