"""Security fixtures for the test suite: tokens, X.509, PKI, and the KDC.

TS-5's security cluster.  Each submodule owns one credential family and is
importable on its own; nothing here composes by `exec`.
"""
