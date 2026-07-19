# pblock-fsck — Phase-83 F7 consistency oracle (standalone: libc + sqlite3).
# Self-contained; no nginx/module deps. `make` builds ./pblock-fsck.
CC      ?= cc
CFLAGS  ?= -O2 -Wall -Wextra
SQLITE_CFLAGS := $(shell pkg-config --cflags sqlite3 2>/dev/null)
SQLITE_LIBS   := $(shell pkg-config --libs sqlite3 2>/dev/null || echo -lsqlite3)

PREFIX  ?= /usr/local
BINDIR  ?= $(PREFIX)/bin

pblock-fsck: pblock-fsck.c
	$(CC) $(CFLAGS) $(SQLITE_CFLAGS) -o $@ $< $(SQLITE_LIBS)

install: pblock-fsck
	install -D -m 0755 pblock-fsck $(DESTDIR)$(BINDIR)/pblock-fsck

clean:
	rm -f pblock-fsck

.PHONY: install clean
