# Windows Process Execution Implementation

**Status**: ✅ Complete  
**File**: `src/platform/windows/process.c`  
**Test Suite**: `src/platform/windows/process_test.c`

---

## Overview

This document describes the Windows implementation of `brix_plat_execvpe()`, which provides POSIX-compatible process execution on Windows using the Win32 API.

## Implementation Details

### Function Signature

```c
int brix_plat_execvpe(const char *file, char *const argv[], char *const envp[]);
```

**Parameters**:
- `file`: Program name or path (UTF-8 encoded)
- `argv`: NULL-terminated argument array (UTF-8 encoded)
- `envp`: NULL-terminated environment array (UTF-8 encoded), or NULL for current environment

**Return Value**:
- Does not return on success (replaces current process)
- Returns -1 on error with `errno` set

### Key Features

1. ✅ **UTF-8 ↔ UTF-16 Conversion**
   - All input strings are UTF-8
   - Converted to UTF-16 for Windows API calls
   - Proper handling of multi-byte characters

2. ✅ **PATH Search**
   - Uses `SearchPathW()` to find executables
   - Automatically adds `.exe` extension if missing
   - Handles absolute and relative paths

3. ✅ **Argument Escaping**
   - Implements Windows command line parsing rules
   - Properly escapes spaces, quotes, and backslashes
   - Prevents command injection

4. ✅ **Environment Handling**
   - Builds Windows environment block from envp
   - Supports NULL envp (inherit current environment)
   - UTF-16 environment block for `CREATE_UNICODE_ENVIRONMENT`

5. ✅ **Process Creation**
   - Uses `CreateProcessW()` for Unicode support
   - Waits for child process to complete
   - Propagates exit code correctly

---

## POSIX vs Windows Differences

### execvpe() Semantics

| Aspect | POSIX `execvpe()` | Windows `CreateProcessW()` | Our Implementation |
|--------|-------------------|----------------------------|-------------------|
| Process model | Replace current | Create new | Create new + exit |
| Return on success | Never | Returns immediately | Never (exits) |
| Return on error | -1, errno set | FALSE, GetLastError() | -1, errno set |
| PATH search | Yes | No (must use SearchPath) | Yes |
| Environment | char **envp | wchar_t *block | char **envp (converted) |
| Encoding | Locale-dependent | UTF-16 | UTF-8 → UTF-16 |
| Argument parsing | Shell rules | Windows rules | Windows rules |

### Implementation Strategy

```
POSIX execvpe() call
    ↓
1. Search PATH (SearchPathW)
    ↓
2. Build command line (escape args)
    ↓
3. Build environment block (UTF-8 → UTF-16)
    ↓
4. CreateProcessW()
    ↓
5. WaitForSingleObject()
    ↓
6. GetExitCodeProcess()
    ↓
7. _exit(exit_code)
```

---

## UTF-8 ↔ UTF-16 Conversion

### Conversion Functions

```c
// Stack-based conversion (fixed buffer)
int brix_win32_utf8_to_utf16(
    const char *utf8_src,
    wchar_t *utf16_dest,
    int dest_size
);

// Heap-based conversion (auto-allocated)
wchar_t *brix_win32_utf8_to_utf16_alloc(const char *utf8_src);

// Reverse conversion
int brix_win32_utf16_to_utf8(
    const wchar_t *utf16_src,
    char *utf8_dest,
    int dest_size
);
```

### Usage Example

```c
wchar_t wide_path[MAX_PATH];
if (brix_win32_utf8_to_utf16("/path/to/file", wide_path, MAX_PATH) < 0) {
    // Handle error
    return -1;
}

// Use wide_path with Windows API
CreateFileW(wide_path, ...);
```

### Error Handling

- Returns -1 on invalid UTF-8 sequences
- Returns -1 on buffer overflow
- Sets `errno` appropriately (EINVAL, ENOMEM)

---

## Argument Escaping

### Windows Command Line Parsing Rules

From Microsoft documentation:

1. **Argument separation**: Arguments are separated by spaces
2. **Quoting**: Arguments with spaces/tabs/quotes must be quoted
3. **Backslash handling**:
   - `N` backslashes + `"` → `N/2` backslashes + `"` (if N even)
   - `N` backslashes + `"` → `(N-1)/2` backslashes + `\"` (if N odd)
4. **Quote escaping**: `"` within quoted arguments must be escaped

### Escaping Examples

| Input | Output | Notes |
|-------|--------|-------|
| `hello` | `hello` | No escaping needed |
| `hello world` | `"hello world"` | Spaces require quotes |
| `say "hi"` | `"say \"hi\""` | Quotes escaped |
| `path\to\file` | `"path\to\file"` | Backslashes before non-quote: no change |
| `path\"file` | `"path\\\"file"` | Backslash before quote: doubled |
| `C:\Program Files\app.exe` | `"C:\Program Files\app.exe"` | Complex case |

### Implementation

```c
char escaped[256];
if (brix_win32_escape_argument("hello world", escaped, sizeof(escaped)) < 0) {
    // Handle error (buffer too small)
    return -1;
}
// escaped = "\"hello world\""
```

### Security Considerations

- **Command injection**: Properly escaped arguments prevent injection
- **PATH injection**: Use absolute paths for sensitive operations
- **Buffer overflow**: All functions check buffer sizes

---

## PATH Search

### SearchPathW() Usage

```c
DWORD SearchPathW(
    LPCWSTR lpPath,         // Directory path (NULL = search PATH)
    LPCWSTR lpFileName,     // File to find
    LPCWSTR lpExtension,    // Extension to add (L".exe")
    DWORD nBufferLength,    // Buffer size
    LPWSTR  lpBuffer,       // Output buffer
    LPWSTR  *lpFilePart     // Pointer to filename part (optional)
);
```

### Implementation

```c
int brix_win32_search_path(const char *file, char *full_path, size_t path_size)
{
    wchar_t file_wide[MAX_PATH];
    wchar_t path_wide[MAX_PATH];
    
    // Convert to UTF-16
    brix_win32_utf8_to_utf16(file, file_wide, MAX_PATH);
    
    // Search PATH (adds .exe if missing)
    DWORD result = SearchPathW(NULL, file_wide, L".exe", 
                               MAX_PATH, path_wide, NULL);
    
    // Convert back to UTF-8
    brix_win32_utf16_to_utf8(path_wide, full_path, path_size);
    
    return (result != 0) ? 0 : -1;
}
```

### Search Order

1. If `file` is absolute → use as-is
2. If `file` is relative → search current directory
3. Search directories in `PATH` environment variable
4. Add `.exe` extension if not present

---

## Environment Block

### Windows Format

```
NAME1=VALUE1\0
NAME2=VALUE2\0
NAME3=VALUE3\0
\0  ← Double-null terminates block
```

### Building from envp

```c
int brix_win32_build_environment_block(char *const envp[], wchar_t **env_block_out)
{
    if (envp == NULL) {
        // Use current process environment
        *env_block_out = GetEnvironmentStringsW();
        return 0;
    }
    
    // Calculate required size
    size_t total_chars = 0;
    for (int i = 0; envp[i] != NULL; i++) {
        int wide_len = MultiByteToWideChar(CP_UTF8, 0, envp[i], -1, NULL, 0);
        total_chars += wide_len;
    }
    total_chars++;  // Final double-null
    
    // Allocate and convert
    wchar_t *env_block = malloc(total_chars * sizeof(wchar_t));
    wchar_t *out = env_block;
    
    for (int i = 0; envp[i] != NULL; i++) {
        int wide_len = MultiByteToWideChar(CP_UTF8, 0, envp[i], -1, out, ...);
        out += wide_len;
    }
    *out = L'\0';  // Double-null terminate
    
    *env_block_out = env_block;
    return 0;
}
```

### Cleanup

```c
void brix_win32_free_environment_block(wchar_t *env_block)
{
    if (env_block != NULL) {
        FreeEnvironmentStringsW(env_block);
    }
}
```

---

## Process Creation

### CreateProcessW() Call

```c
BOOL CreateProcessW(
    LPCWSTR lpApplicationName,    // Program path
    LPWSTR lpCommandLine,         // Command line (args)
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL bInheritHandles,
    DWORD dwCreationFlags,
    LPVOID lpEnvironment,
    LPCWSTR lpCurrentDirectory,
    LPSTARTUPINFOW lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation
);
```

### Our Usage

```c
BOOL success = CreateProcessW(
    file_wide,              // Application name
    cmd_line_wide,          // Command line
    NULL,                   // Process security (default)
    NULL,                   // Thread security (default)
    FALSE,                  // Don't inherit handles
    CREATE_UNICODE_ENVIRONMENT,  // UTF-16 environment
    env_block,              // Environment block
    NULL,                   // Current directory (inherit)
    &si,                    // Startup info
    &pi                     // Process information
);
```

### Wait and Exit

```c
// Wait for child to complete
WaitForSingleObject(pi.hProcess, INFINITE);

// Get exit code
DWORD child_exit_code;
GetExitCodeProcess(pi.hProcess, &child_exit_code);

// Exit with same code
_exit(child_exit_code & 0xFF);
```

---

## Error Handling

### Error Code Mapping

| Windows Error | errno | Meaning |
|---------------|-------|---------|
| `ERROR_FILE_NOT_FOUND` | `ENOENT` | Program not found |
| `ERROR_PATH_NOT_FOUND` | `ENOENT` | PATH directory missing |
| `ERROR_ACCESS_DENIED` | `EACCES` | Permission denied |
| `ERROR_OUTOFMEMORY` | `ENOMEM` | Out of memory |
| `ERROR_ALREADY_EXISTS` | `EEXIST` | File exists |
| `ERROR_INVALID_PARAMETER` | `EINVAL` | Invalid argument |

### Example

```c
if (!CreateProcessW(...)) {
    brix_win32_set_errno(GetLastError());
    return -1;
}
```

---

## Testing

### Test Suite

Run tests with:

```bash
cd src/platform/windows
gcc -DBRIX_PLATFORM_WINDOWS=1 -DBRIX_TEST -o process_test process_test.c
./process_test
```

### Test Coverage

- ✅ UTF-8 ↔ UTF-16 conversion
- ✅ Argument escaping (simple, spaces, quotes, backslashes, complex)
- ✅ Command line building
- ✅ PATH search (absolute, relative, nonexistent)
- ✅ Environment block (NULL, custom)
- ✅ Integration (echo, nonexistent program)

### Example Test

```c
TEST(escape_argument_spaces)
{
    char escaped[256];
    int ret = brix_win32_escape_argument("hello world", escaped, 256);
    ASSERT(ret == 0, "Success");
    ASSERT(strcmp(escaped, "\"hello world\"") == 0, "Correct escaping");
}
```

---

## Security Considerations

### PATH Injection

**Risk**: Attacker modifies PATH to execute malicious program

**Mitigation**:
```c
// Bad: vulnerable to PATH injection
brix_plat_execvpe("myapp", argv, envp);

// Good: use absolute path
brix_plat_execvpe("C:\\Program Files\\MyApp\\myapp.exe", argv, envp);
```

### Command Injection

**Risk**: Unescaped arguments allow command injection

**Mitigation**: Our implementation properly escapes all arguments

```c
// Safe: argument is properly escaped
char *argv[] = {"echo", "hello; rm -rf /", NULL};
brix_plat_execvpe("echo", argv, NULL);
// Output: "hello; rm -rf /" (literal string, not executed)
```

### Buffer Overflow

**Risk**: Fixed-size buffers can overflow

**Mitigation**: All functions check buffer sizes

```c
char small_buf[10];
if (brix_win32_escape_argument("very long", small_buf, sizeof(small_buf)) < 0) {
    // Properly returns error
    return -1;
}
```

---

## Performance

### Overhead

| Operation | Cost | Notes |
|-----------|------|-------|
| UTF-8 → UTF-16 | O(n) | Single pass |
| Argument escaping | O(n) | Single pass |
| PATH search | O(m) | m = number of PATH entries |
| Process creation | O(1) | Windows API call |
| Wait | Variable | Depends on child process |

### Optimization Opportunities

1. **Cache PATH search results** (for frequently-executed programs)
2. **Pre-allocate buffers** (avoid malloc in hot paths)
3. **Batch environment conversion** (if executing multiple processes)

---

## Debugging

### Debug Functions

Enable with `#define BRIX_DEBUG`:

```c
// Print command line (for debugging escaping)
brix_win32_debug_print_command_line(argv);

// Print environment block
brix_win32_debug_print_environment(envp);
```

### Common Issues

1. **Program not found**: Check PATH, verify .exe extension
2. **Argument parsing errors**: Check escaping, especially quotes
3. **Environment not inherited**: Ensure envp is NULL or properly formatted
4. **UTF-8 corruption**: Verify encoding of source strings

---

## References

- [CreateProcessW Documentation](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessw)
- [SearchPathW Documentation](https://docs.microsoft.com/en-us/windows/win32/api/processenv/nf-processenv-searchpathw)
- [Command Line Argument Parsing](https://docs.microsoft.com/en-us/windows/win32/api/shellapi/nf-shellapi-commandlinetoargvw)
- [Environment Blocks](https://docs.microsoft.com/en-us/windows/win32/procthread/environment-variables)
- [MultiByteToWideChar](https://docs.microsoft.com/en-us/windows/win32/api/stringapiset/nf-stringapiset-multibytetowidechar)

---

## Changelog

### v1.0 (2025-12-12)
- ✅ Initial implementation
- ✅ UTF-8 ↔ UTF-16 conversion
- ✅ Argument escaping
- ✅ PATH search
- ✅ Environment handling
- ✅ Test suite
- ✅ Documentation

---

**End of Document**
