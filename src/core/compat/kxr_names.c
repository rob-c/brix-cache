/*
 * kxr_names.c — kXR wire-vocabulary name tables (see kxr_names.h).
 *
 * Single source of truth for the human names of kXR request opcodes, response
 * status codes, and error codes. Pure switch tables over src/protocol/opcodes.h;
 * ngx-free, so they build identically into the module and into libxrdproto.
 */
#include "kxr_names.h"
#include "protocols/root/protocol/opcodes.h"

const char *
xrootd_kxr_request_name(int reqid)
{
    switch (reqid) {
    case kXR_auth:     return "kXR_auth";
    case kXR_query:    return "kXR_query";
    case kXR_chmod:    return "kXR_chmod";
    case kXR_close:    return "kXR_close";
    case kXR_dirlist:  return "kXR_dirlist";
    case kXR_gpfile:   return "kXR_gpfile";
    case kXR_protocol: return "kXR_protocol";
    case kXR_login:    return "kXR_login";
    case kXR_mkdir:    return "kXR_mkdir";
    case kXR_mv:       return "kXR_mv";
    case kXR_open:     return "kXR_open";
    case kXR_ping:     return "kXR_ping";
    case kXR_chkpoint: return "kXR_chkpoint";
    case kXR_read:     return "kXR_read";
    case kXR_rm:       return "kXR_rm";
    case kXR_rmdir:    return "kXR_rmdir";
    case kXR_sync:     return "kXR_sync";
    case kXR_stat:     return "kXR_stat";
    case kXR_set:      return "kXR_set";
    case kXR_write:    return "kXR_write";
    case kXR_fattr:    return "kXR_fattr";
    case kXR_prepare:  return "kXR_prepare";
    case kXR_statx:    return "kXR_statx";
    case kXR_endsess:  return "kXR_endsess";
    case kXR_bind:     return "kXR_bind";
    case kXR_readv:    return "kXR_readv";
    case kXR_pgwrite:  return "kXR_pgwrite";
    case kXR_locate:   return "kXR_locate";
    case kXR_truncate: return "kXR_truncate";
    case kXR_sigver:   return "kXR_sigver";
    case kXR_pgread:   return "kXR_pgread";
    case kXR_writev:   return "kXR_writev";
    case kXR_clone:    return "kXR_clone";
    default:           return "req?";
    }
}

const char *
xrootd_kxr_response_status_name(int status)
{
    switch (status) {
    case kXR_ok:       return "ok";
    case kXR_oksofar:  return "oksofar";
    case kXR_attn:     return "attn";
    case kXR_authmore: return "authmore";
    case kXR_error:    return "error";
    case kXR_redirect: return "redirect";
    case kXR_wait:     return "wait";
    case kXR_waitresp: return "waitresp";
    case kXR_status:   return "status";
    default:           return "status?";
    }
}

const char *
xrootd_kxr_error_name(int kxr)
{
    switch (kxr) {
    case kXR_ArgInvalid:     return "ArgInvalid";
    case kXR_ArgMissing:     return "ArgMissing";
    case kXR_ArgTooLong:     return "ArgTooLong";
    case kXR_FileLocked:     return "FileLocked";
    case kXR_FileNotOpen:    return "FileNotOpen";
    case kXR_FSError:        return "FSError";
    case kXR_InvalidRequest: return "InvalidRequest";
    case kXR_IOError:        return "IOError";
    case kXR_NoMemory:       return "NoMemory";
    case kXR_NoSpace:        return "NoSpace";
    case kXR_NotAuthorized:  return "NotAuthorized";
    case kXR_NotFound:       return "NotFound";
    case kXR_ServerError:    return "ServerError";
    case kXR_Unsupported:    return "Unsupported";
    case kXR_noserver:       return "noserver";
    case kXR_NotFile:        return "NotFile";
    case kXR_isDirectory:    return "isDirectory";
    case kXR_Cancelled:      return "Cancelled";
    case kXR_ItExists:       return "ItExists";
    case kXR_ChkSumErr:      return "ChkSumErr";
    case kXR_inProgress:     return "inProgress";
    case kXR_overQuota:      return "overQuota";
    case kXR_Overloaded:     return "Overloaded";
    case kXR_fsReadOnly:     return "fsReadOnly";
    case kXR_AttrNotFound:   return "AttrNotFound";
    case kXR_TLSRequired:    return "TLSRequired";
    case kXR_AuthFailed:     return "AuthFailed";
    case kXR_Impossible:     return "Impossible";
    case kXR_Conflict:       return "Conflict";
    case kXR_TooManyErrs:    return "TooManyErrs";
    default:                 return "Unknown";
    }
}
