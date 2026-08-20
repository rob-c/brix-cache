"""Quarantined verbatim archives kept only as rollback anchors (§10.2).

Nothing imports from here in normal operation.  Each file is the
byte-identical pre-migration body of a module the migration replaced;
the §15 phase notes say which shim would be repointed at which archive
if a phase had to be rolled back.  The tree is deleted at TS-7.
"""
