#ifndef BRIX_FTP_EV_MODE_E_INTERNAL_H
#define BRIX_FTP_EV_MODE_E_INTERNAL_H

#include "ftp_ev.h"

/*
 * ftp_ev_mode_e_internal.h — shared seam between the MODE E RETR framing pump
 * (ftp_ev_mode_e.c) and the STOR extended-block reassembly receiver
 * (ftp_ev_mode_e_recv.c).
 */

#define FTP_EV_EB_MARKER_BYTES      (1 << 20)  /* emit 111/112 each ~1 MiB moved */

/* Emit a GridFTP 112 perf marker (bytes moved) on the control channel. */
void ev_eb_marker_perf(ftp_ev_t *fc, off_t bytes);

#endif /* BRIX_FTP_EV_MODE_E_INTERNAL_H */
