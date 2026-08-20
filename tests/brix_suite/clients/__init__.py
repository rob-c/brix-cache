"""Client-side drivers the suite points at a fleet.

The out-of-process worker *protocol* is core — :mod:`brixtest.clients.procworker`
owns the generic, symmetric form of it — and the PTY runner promoted with it
(:mod:`brixtest.clients.pty`).  What stays here is everything that only makes
sense against XRootD, HTTP guards or GridFTP:

* :mod:`~brix_suite.clients.xrdcl` — the XrdCl isolation layer, whose protocol
  carries four affordances the generic one deliberately does not have (see its
  ``worker_link`` docstring);
* :mod:`~brix_suite.clients.http` — the phase-65 HTTP guard driver;
* :mod:`~brix_suite.clients.gridftp` — the globus-url-copy credential
  environment.

Nothing is imported eagerly: :mod:`~brix_suite.clients.xrdcl` registers an
``atexit`` hook and memoises an interpreter probe at import, which a caller
that only wants ``gsi_client_env`` should not pay for.
"""
