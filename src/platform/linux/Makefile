# Linux Platform Abstraction Layer - Development Makefile
# 
# Usage:
#   make          - Build all object files
#   make clean    - Remove object files
#   make test     - Run platform tests
#   make debug    - Build with debug symbols
#   make release  - Build with optimizations

CC ?= gcc
AR ?= ar

# Platform detection
PLATFORM = linux
PLATFORM_FLAG = -DBRIX_PLATFORM_LINUX=1

# Compiler flags
CFLAGS_COMMON = -Wall -Wextra -Werror -Wpedantic -std=c11
CFLAGS_DEBUG = -g3 -O0 -DDEBUG
CFLAGS_RELEASE = -O3 -march=native -DNDEBUG

# Default to debug build
CFLAGS ?= $(CFLAGS_COMMON) $(CFLAGS_DEBUG)

# Source files
SRCS = $(wildcard *.c)
OBJS = $(SRCS:.c=.o)

# Include paths (for standalone development)
# For full build, use nginx build system
INCLUDES = -I../.. -I../../.. -I../../../shared

# Optional: nginx include path for full compilation
# NGINX_SRC = /path/to/nginx/src
# INCLUDES += -I$(NGINX_SRC)/src/core -I$(NGINX_SRC)/src/event

# Default target
all: $(OBJS)
	@echo "✓ Linux PAL build complete: $(OBJS)"

# Pattern rule for object files
%.o: %.c
	@echo "  CC  $<"
	$(CC) $(CFLAGS) $(PLATFORM_FLAG) $(INCLUDES) -c $< -o $@

# Debug build
debug: CFLAGS = $(CFLAGS_COMMON) $(CFLAGS_DEBUG)
debug: clean all

# Release build
release: CFLAGS = $(CFLAGS_COMMON) $(CFLAGS_RELEASE)
release: clean all

# Clean build artifacts
clean:
	@echo "  CLEAN"
	rm -f $(OBJS) *.gcda *.gcno *.gcov

# Show build info
info:
	@echo "Platform: $(PLATFORM)"
	@echo "Compiler: $(CC)"
	@echo "Flags: $(CFLAGS)"
	@echo "Sources: $(SRCS)"
	@echo "Objects: $(OBJS)"

# Static analysis (optional)
analyze: CFLAGS += -fanalyzer
analyze: clean all

# Coverage (optional)
coverage: CFLAGS += --coverage
coverage: LDFLAGS += --coverage
coverage: clean all

.PHONY: all clean debug release info analyze coverage
