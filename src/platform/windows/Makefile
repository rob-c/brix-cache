# Windows Platform Abstraction Layer - Development Makefile
# 
# Usage:
#   mingw32-make          - Build with MinGW (32-bit)
#   mingw32-make x64      - Build with MinGW (64-bit)
#   nmake /f Makefile.msvc  - Build with MSVC
#   make clean            - Remove object files
#   make debug            - Build with debug symbols
#   make release          - Build with optimizations

# Default to MinGW-w64 (most common for nginx/Windows)
CC ?= x86_64-w64-mingw32-gcc
AR ?= x86_64-w64-mingw32-ar

# Platform detection
PLATFORM = windows
PLATFORM_FLAG = -DBRIX_PLATFORM_WINDOWS=1

# Windows version: Windows 8 / Server 2012 minimum
WIN_VER = -D_WIN32_WINNT=0x0602

# Compiler flags
CFLAGS_COMMON = -Wall -Wextra -Wpedantic -std=c11
CFLAGS_COMMON += -DWIN32_LEAN_AND_MEAN -D_CRT_SECURE_NO_WARNINGS
CFLAGS_COMMON += -I../../.. -I../../../shared
CFLAGS_DEBUG = -g3 -O0 -DDEBUG
CFLAGS_RELEASE = -O2 -DNDEBUG

# Default to debug build
CFLAGS ?= $(CFLAGS_COMMON) $(CFLAGS_DEBUG)

# Windows libraries
LIBS = -lws2_32 -ladvapi32 -lkernel32 -lbcrypt

# Source files
SRCS = $(wildcard *.c)
OBJS = $(SRCS:.c=.o)

# Include paths
INCLUDES = -I../.. -I../../.. -I../../../shared

# Default target
all: $(OBJS)
	@echo "✓ Windows PAL build complete (MinGW-w64): $(OBJS)"

# Pattern rule for object files
%.o: %.c
	@echo "  CC  $<"
	$(CC) $(CFLAGS) $(PLATFORM_FLAG) $(WIN_VER) $(INCLUDES) -c $< -o $@

# 64-bit build (default)
x64: CC = x86_64-w64-mingw32-gcc
x64: CFLAGS += -m64
x64: clean all
	@echo "✓ Built for x86_64 (64-bit)"

# 32-bit build
x86: CC = i686-w64-mingw32-gcc
x86: CFLAGS += -m32
x86: clean all
	@echo "✓ Built for x86 (32-bit)"

# Debug build
debug: CFLAGS = $(CFLAGS_COMMON) $(CFLAGS_DEBUG)
debug: clean all

# Release build
release: CFLAGS = $(CFLAGS_COMMON) $(CFLAGS_RELEASE)
release: clean all

# MSVC build (requires Visual Studio Developer Command Prompt)
msvc: 
	@echo "For MSVC build, use: nmake /f Makefile.msvc"
	@echo "Or run: cl.exe /c *.c"

# Clean build artifacts
clean:
	@echo "  CLEAN"
	rm -f $(OBJS) *.exe *.dll *.lib

# Show build info
info:
	@echo "Platform: $(PLATFORM)"
	@echo "Compiler: $(CC)"
	@echo "Flags: $(CFLAGS)"
	@echo "Libraries: $(LIBS)"
	@echo "Sources: $(SRCS)"
	@echo "Objects: $(OBJS)"

# Cross-compile from Linux (default scenario)
cross: all
	@echo "✓ Cross-compiled for Windows from Linux"

.PHONY: all clean debug release x64 x86 msvc info cross

# MSVC Makefile (separate target for Visual Studio)
# Usage: nmake /f Makefile.msvc
# This section documents the MSVC build process

MSVC_NOTE = "\n\
MSVC Build Instructions:\n\
1. Open 'Developer Command Prompt for VS2019' or later\n\
2. Navigate to src/platform/windows/\n\
3. Run: nmake /f Makefile.msvc\n\
\n\
MSVC Flags:\n\
- /c : Compile only\n\
- /W4 : Warning level 4\n\
- /Zi : Debug information\n\
- /O2 : Optimize for speed\n\
- /MT : Static runtime library\n\
\n\
Example:\n\
  cl.exe /c /W4 /Zi /I.. /I../.. /I../../.. *.c\n\
"
