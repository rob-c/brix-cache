/*
 * kxr_names.c — kXR wire-vocabulary name tables (see kxr_names.h).
 *
 * Single source of truth for the human names of kXR request opcodes, response
 * status codes, and error codes. Static lookup tables over
 * src/protocol/opcodes.h; ngx-free, so they build identically into the module
 * and into libxrdproto.
 */
#include <stddef.h>

#include "kxr_names.h"
#include "protocols/root/protocol/opcodes.h"

/*
 * WHAT: one code→name row of a kXR vocabulary table.
 * WHY:  lets all three name functions share a single lookup helper instead of
 *       three switch ladders.
 * HOW:  plain int code (all kXR vocabularies fit) plus its literal name.
 */
typedef struct {
    int         code;
    const char *name;
} kxr_name_entry_t;

static const kxr_name_entry_t  kxr_request_names[] = {
    { kXR_auth,     "kXR_auth"     },
    { kXR_query,    "kXR_query"    },
    { kXR_chmod,    "kXR_chmod"    },
    { kXR_close,    "kXR_close"    },
    { kXR_dirlist,  "kXR_dirlist"  },
    { kXR_gpfile,   "kXR_gpfile"   },
    { kXR_protocol, "kXR_protocol" },
    { kXR_login,    "kXR_login"    },
    { kXR_mkdir,    "kXR_mkdir"    },
    { kXR_mv,       "kXR_mv"       },
    { kXR_open,     "kXR_open"     },
    { kXR_ping,     "kXR_ping"     },
    { kXR_chkpoint, "kXR_chkpoint" },
    { kXR_read,     "kXR_read"     },
    { kXR_rm,       "kXR_rm"       },
    { kXR_rmdir,    "kXR_rmdir"    },
    { kXR_sync,     "kXR_sync"     },
    { kXR_stat,     "kXR_stat"     },
    { kXR_set,      "kXR_set"      },
    { kXR_write,    "kXR_write"    },
    { kXR_fattr,    "kXR_fattr"    },
    { kXR_prepare,  "kXR_prepare"  },
    { kXR_statx,    "kXR_statx"    },
    { kXR_endsess,  "kXR_endsess"  },
    { kXR_bind,     "kXR_bind"     },
    { kXR_readv,    "kXR_readv"    },
    { kXR_pgwrite,  "kXR_pgwrite"  },
    { kXR_locate,   "kXR_locate"   },
    { kXR_truncate, "kXR_truncate" },
    { kXR_sigver,   "kXR_sigver"   },
    { kXR_pgread,   "kXR_pgread"   },
    { kXR_writev,   "kXR_writev"   },
    { kXR_clone,    "kXR_clone"    },
};

static const kxr_name_entry_t  kxr_response_status_names[] = {
    { kXR_ok,       "ok"       },
    { kXR_oksofar,  "oksofar"  },
    { kXR_attn,     "attn"     },
    { kXR_authmore, "authmore" },
    { kXR_error,    "error"    },
    { kXR_redirect, "redirect" },
    { kXR_wait,     "wait"     },
    { kXR_waitresp, "waitresp" },
    { kXR_status,   "status"   },
};

static const kxr_name_entry_t  kxr_error_names[] = {
    { kXR_ArgInvalid,     "ArgInvalid"     },
    { kXR_ArgMissing,     "ArgMissing"     },
    { kXR_ArgTooLong,     "ArgTooLong"     },
    { kXR_FileLocked,     "FileLocked"     },
    { kXR_FileNotOpen,    "FileNotOpen"    },
    { kXR_FSError,        "FSError"        },
    { kXR_InvalidRequest, "InvalidRequest" },
    { kXR_IOError,        "IOError"        },
    { kXR_NoMemory,       "NoMemory"       },
    { kXR_NoSpace,        "NoSpace"        },
    { kXR_NotAuthorized,  "NotAuthorized"  },
    { kXR_NotFound,       "NotFound"       },
    { kXR_ServerError,    "ServerError"    },
    { kXR_Unsupported,    "Unsupported"    },
    { kXR_noserver,       "noserver"       },
    { kXR_NotFile,        "NotFile"        },
    { kXR_isDirectory,    "isDirectory"    },
    { kXR_Cancelled,      "Cancelled"      },
    { kXR_ItExists,       "ItExists"       },
    { kXR_ChkSumErr,      "ChkSumErr"      },
    { kXR_inProgress,     "inProgress"     },
    { kXR_overQuota,      "overQuota"      },
    { kXR_Overloaded,     "Overloaded"     },
    { kXR_fsReadOnly,     "fsReadOnly"     },
    { kXR_AttrNotFound,   "AttrNotFound"   },
    { kXR_TLSRequired,    "TLSRequired"    },
    { kXR_AuthFailed,     "AuthFailed"     },
    { kXR_Impossible,     "Impossible"     },
    { kXR_Conflict,       "Conflict"       },
    { kXR_TooManyErrs,    "TooManyErrs"    },
};

/*
 * WHAT: look a code up in a kXR name table.
 * WHY:  shared by the three vocabulary name functions so each stays a
 *       one-line wrapper over its table (replaces three switch ladders).
 * HOW:  linear scan (tables are small and lookups are log-path only);
 *       returns the caller's fallback string when the code is absent.
 */
static const char *
kxr_lookup(const kxr_name_entry_t *table, size_t n, int code,
           const char *fallback)
{
    size_t  i;

    for (i = 0; i < n; i++) {
        if (table[i].code == code) {
            return table[i].name;
        }
    }

    return fallback;
}

#define KXR_TABLE_N(t)  (sizeof(t) / sizeof((t)[0]))

const char *
brix_kxr_request_name(int reqid)
{
    return kxr_lookup(kxr_request_names, KXR_TABLE_N(kxr_request_names),
                      reqid, "req?");
}

const char *
brix_kxr_response_status_name(int status)
{
    return kxr_lookup(kxr_response_status_names,
                      KXR_TABLE_N(kxr_response_status_names),
                      status, "status?");
}

const char *
brix_kxr_error_name(int kxr)
{
    return kxr_lookup(kxr_error_names, KXR_TABLE_N(kxr_error_names),
                      kxr, "Unknown");
}
