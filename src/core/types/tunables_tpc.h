/* Third-party-copy and tape-stage limits.
 *
 * Requires: include through core/types/tunables.h; sibling constants
 * and the caller-provided nginx/protocol/metrics types remain available
 * when dependent expressions and completion macros are expanded.
 */
#pragma once

/* BRIX_TPC_HOPS_MAX caps brix_tpc_max_hops: how many kXR_redirect hops the
 * native TPC pull may follow from the client-named source before the transfer
 * fails (F7). Bounds a redirect ring or a manager ping-pong. */
#define BRIX_TPC_HOPS_MAX            16

/*
 * TPC delegated token buffer size (bytes).
 * OAuth2/OIDC access tokens typically 1-4 KB; 64 KB provides 16x headroom.
 * Prevents buffer overflow on malformed or malicious oversized tokens.
 */
#define BRIX_TPC_TOKEN_MAX                     65536

/*
 * TPC token error message buffer size (bytes).
 * Error messages from oidc-agent/curl subprocesses typically <128 bytes.
 * 256 bytes provides 2x headroom for verbose error output.
 */
#define BRIX_TPC_TOKEN_ERR_MAX                 256

/*
 * TPC opaque parameter prefix length (bytes).
 * "tpc." prefix identifies TPC-specific query parameters.
 * Used in tpc_parse_token() for key matching.
 */
#define BRIX_TPC_PREFIX_LEN                    4

/*
 * TPC authority buffer size (bytes).
 * Maximum size for host[:port] authority string during URL decomposition.
 * Supports IPv6 bracket notation [::1]:port with room for 256-char hostnames.
 * Used in tpc_parse_src_spec() for temporary authority parsing buffer.
 */
#define BRIX_TPC_AUTHORITY_BUF_SIZE            320

/*
 * TPC key length constants for recognized parameters.
 * These are the bare key lengths after stripping "tpc." prefix.
 * Used in tpc_parse_token() for key matching validation.
 */
#define BRIX_TPC_KEY_LEN_SHORT                 3   /* src, dst, key, lfn, org */
#define BRIX_TPC_KEY_LEN_STAGE                 5   /* stage */
#define BRIX_TPC_KEY_LEN_TOKEN_MODE           10   /* token_mode */

/*
 * TPC minimum key length for valid "tpc.*" parameters.
 * Must be at least 5 chars: "tpc." (4) + at least 1 char for key name.
 * Used in tpc_parse_token() to reject malformed keys.
 */
#define BRIX_TPC_KEY_LEN_MIN                   5

/*
 * TPC RFC 8693 token exchange body buffer size (bytes).
 * Form-urlencoded body: grant_type + subject_token (JWT, ~1-3 KB) + resource
 * + audience + scope. Typical total 1.5-2 KB; 4 KB provides 2x headroom.
 * Used in tpc_rfc8693_stage_body() for temporary body formatting.
 */
#define BRIX_TPC_TOKEN_BODY_BUF_SIZE           4096

/*
 * TPC token exchange curl argv array size.
 * curl command line: curl -s -S -f -X POST -H Content-Type [-u auth] -d @file
 * -- endpoint_url NULL. Maximum 13 arguments including optional basic auth.
 * Used in tpc_rfc8693_build_argv() for curl invocation array.
 */
#define BRIX_TPC_TOKEN_CURL_ARGV_MAX           16

/*
 * TPC OIDC socket path buffer size (bytes).
 * Default: /run/user/1000/oidc/oidc_agent.sock (36 chars).
 * 256 bytes supports custom XDG_RUNTIME_DIR paths with long usernames.
 * Used in tpc_oidc_child_run() for socket path construction.
 */
#define BRIX_TPC_TOKEN_OIDC_SOCK_BUF_SIZE      256

/*
 * TPC OIDC environment variable buffer size (bytes).
 * Format: "VAR=value" where value can be long path (HOME, XDG_RUNTIME_DIR).
 * 280 bytes: 20 chars for "VAR=" + 256 chars for path value + 4 padding.
 * Used in tpc_oidc_exec_fallback() for environment variable construction.
 */
#define BRIX_TPC_TOKEN_ENV_BUF_SIZE            280

/*
 * TPC I/O timeout (seconds).
 * SO_RCVTIMEO/SO_SNDTIMEO for TPC socket read/write operations.
 * 60 seconds provides headroom for high-latency WAN transfers while
 * preventing indefinite hangs on unresponsive peers.
 * Used in tpc_set_rcvtimeo() and TPC socket setup.
 */
#define BRIX_TPC_IO_TIMEOUT_SEC                60

/*
 * TPC connect timeout (seconds).
 * poll() timeout for non-blocking connect() during TPC session establishment.
 * 5 seconds allows for network latency while failing fast on unreachable hosts.
 * Used in brix_tpc_connect() for parallel connection attempts.
 */
#define BRIX_TPC_CONNECT_TIMEOUT_SEC           5

/*
 * TPC bearer token buffer size (bytes).
 * Stack cap for a single JWT read from bearer file.
 * OAuth2/OIDC tokens typically 1-4 KB; 64 KB provides 16x headroom.
 * Prevents buffer overflow on malformed or malicious oversized tokens.
 * Used in gsi_outbound_certreq.c for token read operations.
 */
#define BRIX_TPC_BEARER_MAX                    65536

/*
 * TPC GSI auth body maximum size (bytes).
 * Shared upper bound on decoded GSI authentication body.
 * 256 KB accommodates large credential chains while preventing DoS.
 * Used in gsi_outbound_common.c for GSI auth body validation.
 */
#define BRIX_TPC_GSI_MAX_BODY                  262144

/*
 * Tape stage configuration path buffer size.
 * Path buffer for tape stage configuration.
 * 4096 bytes matches PATH_MAX for full path support.
 */
#define BRIX_TAPE_STAGE_PATH_BUF  4096

/*
 * Tape stage runtime configuration line buffer size.
 * Line buffer for reading runtime configuration.
 * 1024 bytes accommodates typical configuration lines.
 */
#define BRIX_TAPE_STAGE_LINE_BUF  1024

/*
 * Default tape stage TTL (milliseconds).
 * Time-to-live for staged tape data.
 * 600000ms = 10 minutes.
 */
#define BRIX_TAPE_STAGE_TTL_DEFAULT_MS  600000

/*
 * Default tape stage reap interval (milliseconds).
 * Interval for reaping expired staged data.
 * 300000ms = 5 minutes.
 */
#define BRIX_TAPE_STAGE_REAP_INTERVAL_MS  300000

/*
 * TPC (Third Party Copy) constants.
 */
#define BRIX_TPC_PREFIX_LEN         4       /* "tpc." prefix length */
#define BRIX_TPC_TOKEN_MAX          65536   /* Maximum TPC token size */
#define BRIX_TPC_TOKEN_ERR_MAX      256     /* TPC token error message buffer */
#define BRIX_TPC_MARKER_URL_MAX     4096    /* TPC marker URL buffer */
