# macOS Platform Abstraction Layer - Development Makefile
# 
# Usage:
#   make          - Build all object files
#   make clean    - Remove object files
#   make test     - Run platform tests
#   make debug    - Build with debug symbols
#   make release  - Build with optimizations for current arch
#   make intel    - Build for Intel x86_64
#   make apple_silicon - Build for ARM64 (M1/M2/M3)

CC ?= clang
AR ?= ar

# Platform detection
PLATFORM = darwin
PLATFORM_FLAG = -DBRIX_PLATFORM_DARWIN=1

# Detect architecture
ARCH := $(shell uname -m)
ifeq ($(ARCH),arm64)
    ARCH_FLAG = -march=armv8.5-a -mtune=apple-m1
    PLATFORM_NAME = Apple Silicon
else
    ARCH_FLAG = -march=x86-64-v3 -mtune=haswell
    PLATFORM_NAME = Intel x86_64
endif

# Compiler flags
CFLAGS_COMMON = -Wall -Wextra -Werror -Wpedantic -std=c11
CFLAGS_COMMON += -D_DARWIN_C_SOURCE
CFLAGS_DEBUG = -g3 -O0 -DDEBUG
CFLAGS_RELEASE = -O3 $(ARCH_FLAG) -DNDEBUG

# Default to debug build
CFLAGS ?= $(CFLAGS_COMMON) $(CFLAGS_DEBUG)

# Frameworks (macOS-specific)
# Note: Only needed for linking, not compilation
FRAMEWORKS = -framework Security
FRAMEWORKS_COMPILE =  # Empty for compilation

# Source files
SRCS = $(wildcard *.c)
OBJS = $(SRCS:.c=.o)

# Include paths
INCLUDES = -I../.. -I../../.. -I../../../shared

# Default target
all: $(OBJS)
	@echo "✓ macOS PAL build complete ($(PLATFORM_NAME)): $(OBJS)"

# Pattern rule for object files
%.o: %.c
	@echo "  CC  $<"
	$(CC) $(CFLAGS) $(PLATFORM_FLAG) $(INCLUDES) $(FRAMEWORKS_COMPILE) -c $< -o $@

# Debug build
debug: CFLAGS = $(CFLAGS_COMMON) $(CFLAGS_DEBUG)
debug: clean all

# Release build (auto-detect architecture)
release: CFLAGS = $(CFLAGS_COMMON) $(CFLAGS_RELEASE)
release: clean all

# Intel x86_64 build
intel: CFLAGS = $(CFLAGS_COMMON) -O3 -march=x86-64-v3 -mtune=haswell -DNDEBUG
intel: clean all
	@echo "✓ Built for Intel x86_64"

# Apple Silicon (ARM64) build
apple_silicon: CFLAGS = $(CFLAGS_COMMON) -O3 -march=armv8.5-a -mtune=apple-m1 -DNDEBUG
apple_silicon: clean all
	@echo "✓ Built for Apple Silicon (ARM64)"

# Universal binary (both architectures)
universal: 
	@echo "  Building universal binary..."
	$(MAKE) intel
	mv $(OBJS) objs_intel/
	$(MAKE) apple_silicon
	mv $(OBJS) objs_arm64/
	mkdir -p objs_universal
	for obj in $(OBJS); do \
		base=$$(basename $$obj); \
		lipo -create -output objs_universal/$$base objs_intel/$$base objs_arm64/$$base; \
	done
	@echo "✓ Universal binary created in objs_universal/"

# Clean build artifacts
clean:
	@echo "  CLEAN"
	rm -f $(OBJS) *.gcda *.gcno *.gcov
	rm -rf objs_intel objs_arm64 objs_universal

# Show build info
info:
	@echo "Platform: $(PLATFORM) ($(PLATFORM_NAME))"
	@echo "Architecture: $(ARCH)"
	@echo "Compiler: $(CC)"
	@echo "Flags: $(CFLAGS)"
	@echo "Frameworks: $(FRAMEWORKS)"
	@echo "Sources: $(SRCS)"
	@echo "Objects: $(OBJS)"

# Static analysis (clang-tidy if available)
analyze: CFLAGS += --analyze
analyze: clean all

# Coverage (optional)
coverage: CFLAGS += --coverage -fprofile-instr-generate -fcoverage-mapping
coverage: LDFLAGS += --coverage
coverage: clean all

.PHONY: all clean debug release intel apple_silicon universal info analyze coverage
