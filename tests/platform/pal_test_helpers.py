"""
tests/platform/pal_test_helpers.py - Python helpers for PAL testing

This module provides:
1. Python implementations of PAL functions for testing logic
2. ctypes wrappers for calling compiled C PAL library
3. Test utilities and assertions

When the C PAL library is compiled, this module will load it via ctypes.
Until then, it provides pure Python implementations for testing test logic.
"""

import os
import sys
import platform
import ctypes
import tempfile
from pathlib import Path
from typing import Optional, Tuple


# =============================================================================
# PAL Library Loading
# =============================================================================

class PALLibrary:
    """Load and wrap the compiled PAL C library"""
    
    def __init__(self):
        self.lib = None
        self.loaded = False
        self._load_library()
    
    def _load_library(self):
        """Attempt to load the compiled PAL library"""
        # Search for compiled library
        lib_paths = [
            "/Users/rcurrie/src/brix-cache/objs/brix_pal.so",
            "/Users/rcurrie/src/brix-cache/libbrix_pal.so",
            "libbrix_pal.so",
        ]
        
        for lib_path in lib_paths:
            if os.path.exists(lib_path):
                try:
                    self.lib = ctypes.CDLL(lib_path)
                    self.loaded = True
                    self._setup_functions()
                    return
                except Exception as e:
                    print(f"Failed to load {lib_path}: {e}")
        
        # Library not found - will use Python fallbacks
        self.loaded = False
    
    def _setup_functions(self):
        """Setup ctypes function signatures"""
        if not self.lib:
            return
        
        # brix_plat_init
        self.lib.brix_plat_init.restype = ctypes.c_int
        self.lib.brix_plat_init.argtypes = []
        
        # brix_plat_cleanup
        self.lib.brix_plat_cleanup.restype = None
        self.lib.brix_plat_cleanup.argtypes = []
        
        # brix_plat_name
        self.lib.brix_plat_name.restype = ctypes.c_char_p
        self.lib.brix_plat_name.argtypes = []
        
        # brix_plat_arch
        self.lib.brix_plat_arch.restype = ctypes.c_char_p
        self.lib.brix_plat_arch.argtypes = []
        
        # brix_plat_random
        self.lib.brix_plat_random.restype = ctypes.c_int
        self.lib.brix_plat_random.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
        
        # brix_plat_anon_fd
        self.lib.brix_plat_anon_fd.restype = ctypes.c_int
        self.lib.brix_plat_anon_fd.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
        
        # ... add more as implemented


# =============================================================================
# Python Fallback Implementations
# =============================================================================

class PALPythonImpl:
    """Pure Python implementations of PAL functions for testing"""
    
    @staticmethod
    def init():
        """Initialize PAL (no-op in Python)"""
        return 0
    
    @staticmethod
    def cleanup():
        """Cleanup PAL (no-op in Python)"""
        pass
    
    @staticmethod
    def plat_name():
        """Get platform name"""
        system = platform.system().lower()
        if system == "linux":
            return "linux"
        elif system == "darwin":
            return "darwin"
        elif system == "windows":
            return "windows"
        else:
            return "unknown"
    
    @staticmethod
    def plat_version():
        """Get platform version"""
        return platform.release()
    
    @staticmethod
    def plat_arch():
        """Get architecture"""
        machine = platform.machine().lower()
        if machine in ("x86_64", "amd64"):
            return "x86_64"
        elif machine in ("aarch64", "arm64", "armv8l"):
            return "arm64"
        elif machine in ("i386", "i686", "x86"):
            return "x86"
        elif machine.startswith("arm"):
            return "arm"
        else:
            return machine
    
    @staticmethod
    def plat_is_root():
        """Check if running as root"""
        return os.getuid() == 0
    
    @staticmethod
    def plat_cpu_count():
        """Get CPU count"""
        return os.cpu_count() or 0
    
    @staticmethod
    def plat_total_memory():
        """Get total memory in bytes"""
        try:
            import psutil
            return psutil.virtual_memory().total
        except ImportError:
            # Fallback for systems without psutil
            if platform.system() == "Linux":
                with open('/proc/meminfo', 'r') as f:
                    for line in f:
                        if line.startswith('MemTotal:'):
                            kb = int(line.split()[1])
                            return kb * 1024
            return 0
    
    @staticmethod
    def plat_available_memory():
        """Get available memory in bytes"""
        try:
            import psutil
            return psutil.virtual_memory().available
        except ImportError:
            if platform.system() == "Linux":
                with open('/proc/meminfo', 'r') as f:
                    for line in f:
                        if line.startswith('MemAvailable:'):
                            kb = int(line.split()[1])
                            return kb * 1024
            return 0
    
    @staticmethod
    def htobe64(value):
        """Host to big-endian 64-bit"""
        if sys.byteorder == 'big':
            return value
        return int.from_bytes(value.to_bytes(8, 'little'), 'big')
    
    @staticmethod
    def be64toh(value):
        """Big-endian to host 64-bit"""
        if sys.byteorder == 'big':
            return value
        return int.from_bytes(value.to_bytes(8, 'big'), 'little')
    
    @staticmethod
    def htobe32(value):
        """Host to big-endian 32-bit"""
        if sys.byteorder == 'big':
            return value
        return int.from_bytes(value.to_bytes(4, 'little'), 'big')
    
    @staticmethod
    def be32toh(value):
        """Big-endian to host 32-bit"""
        if sys.byteorder == 'big':
            return value
        return int.from_bytes(value.to_bytes(4, 'big'), 'little')
    
    @staticmethod
    def htobe16(value):
        """Host to big-endian 16-bit"""
        if sys.byteorder == 'big':
            return value
        return int.from_bytes(value.to_bytes(2, 'little'), 'big')
    
    @staticmethod
    def be16toh(value):
        """Big-endian to host 16-bit"""
        if sys.byteorder == 'big':
            return value
        return int.from_bytes(value.to_bytes(2, 'big'), 'little')
    
    @staticmethod
    def anon_fd(name=None, dir=None):
        """Create anonymous file descriptor"""
        if dir is None:
            dir = tempfile.gettempdir()
        
        if name is None or name == "":
            name = "brix_anon"
        
        # Create temp file
        fd, path = tempfile.mkstemp(prefix=f"{name}_", dir=dir)
        
        # Unlink immediately (file will be deleted when closed)
        os.unlink(path)
        
        return fd
    
    @staticmethod
    def random(buf_size):
        """Generate cryptographically secure random bytes"""
        return os.urandom(buf_size)
    
    @staticmethod
    def setxattr(path, name, value, flags=0):
        """Set extended attribute"""
        os.setxattr(path, name, value)
    
    @staticmethod
    def getxattr(path, name):
        """Get extended attribute"""
        return os.getxattr(path, name)
    
    @staticmethod
    def removexattr(path, name):
        """Remove extended attribute"""
        os.removexattr(path, name)
    
    @staticmethod
    def listxattr(path):
        """List extended attributes"""
        return os.listxattr(path)


# =============================================================================
# Test Helpers
# =============================================================================

class PALTestHelpers:
    """Combined PAL access - C library if available, Python fallback otherwise"""
    
    def __init__(self):
        self.c_lib = PALLibrary()
        self.python = PALPythonImpl()
    
    def init(self):
        """Initialize PAL"""
        if self.c_lib.loaded:
            return self.c_lib.lib.brix_plat_init()
        return self.python.init()
    
    def cleanup(self):
        """Cleanup PAL"""
        if self.c_lib.loaded:
            self.c_lib.lib.brix_plat_cleanup()
        else:
            self.python.cleanup()
    
    def plat_name(self):
        """Get platform name"""
        if self.c_lib.loaded:
            return self.c_lib.lib.brix_plat_name().decode('utf-8')
        return self.python.plat_name()
    
    def plat_arch(self):
        """Get architecture"""
        if self.c_lib.loaded:
            return self.c_lib.lib.brix_plat_arch().decode('utf-8')
        return self.python.plat_arch()
    
    def htobe64(self, value):
        """Host to big-endian 64-bit"""
        if self.c_lib.loaded:
            return self.c_lib.lib.brix_plat_htobe64(value)
        return self.python.htobe64(value)
    
    def be64toh(self, value):
        """Big-endian to host 64-bit"""
        if self.c_lib.loaded:
            return self.c_lib.lib.brix_plat_be64toh(value)
        return self.python.be64toh(value)
    
    def anon_fd(self, name=None, dir=None):
        """Create anonymous fd"""
        if self.c_lib.loaded:
            return self.c_lib.lib.brix_plat_anon_fd(
                name.encode() if name else None,
                dir.encode() if dir else None
            )
        return self.python.anon_fd(name, dir)
    
    def random(self, size):
        """Generate random bytes"""
        if self.c_lib.loaded:
            buf = ctypes.create_string_buffer(size)
            self.c_lib.lib.brix_plat_random(buf, size)
            return buf.raw
        return self.python.random(size)


# =============================================================================
# Convenience Functions
# =============================================================================

def get_pal():
    """Get PAL helper instance"""
    return PALTestHelpers()


def assert_pal_function_exists(func_name):
    """Assert that a PAL function exists in the C library"""
    pal = get_pal()
    if pal.c_lib.loaded:
        assert hasattr(pal.c_lib.lib, f'brix_plat_{func_name}'), \
            f"PAL function brix_plat_{func_name} not found in C library"
    else:
        # Python fallback exists
        assert hasattr(pal.python, func_name), \
            f"PAL function {func_name} not found in Python implementation"


# Export public API
__all__ = [
    'PALLibrary',
    'PALPythonImpl',
    'PALTestHelpers',
    'get_pal',
    'assert_pal_function_exists',
]
