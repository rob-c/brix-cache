/* Version-neutral bounded ASN.1 byte lengths; requires OpenSSL >= 1.1.1. */
#pragma once

#include <limits.h>
#include <openssl/asn1.h>

/* ---- Read a byte length without narrowing a modern size_t result ----
 * WHAT: Return the length, or -1 for a missing value or an int overflow.
 * WHY: OpenSSL 4.1 deprecated ASN1_STRING_length; our bounded DER consumers
 *      retain its signed-int contract and must never truncate a larger value.
 * HOW: 1. Reject NULL. 2. Use the selected ABI. 3. Check before narrowing.
 */
static inline int
brix_crypto_asn1_length(const ASN1_STRING *value)
{
    if (value == NULL) {
        return -1;
    }
#if OPENSSL_VERSION_NUMBER >= 0x40100000L
    size_t length = ASN1_STRING_get_length(value);
    return length <= INT_MAX ? (int) length : -1;
#else
    return ASN1_STRING_length(value);
#endif
}
