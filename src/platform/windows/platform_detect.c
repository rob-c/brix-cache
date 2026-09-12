/*
 * src/platform/windows/platform_detect.c - Windows platform detection
 * 
 * Provides Windows version detection using RtlGetVersion (recommended) or
 * GetVersionExW (deprecated but available). Detects Windows 10/11,
 * Server 2019/2022, and maps to human-readable names.
 * 
 * Detection Methods:
 * 1. RtlGetVersion - Undocumented but reliable, bypasses version lies
 * 2. GetVersionExW - Official API but deprecated, affected by manifest
 * 3. Registry fallback - For very old Windows versions
 * 
 * Supported Windows Versions:
 * - Windows 10 (all versions 1507-22H2)
 * - Windows 11 (21H2, 22H2, 23H2)
 * - Windows Server 2019 (1809)
 * - Windows Server 2022 (21H2)
 * - Windows Server 2025 (24H2)
 */

#include "../platform.h"

#if BRIX_PLATFORM_WINDOWS

#include "win32_compat.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* ==========================================================================
 * WINDOWS VERSION DETECTION
 * ========================================================================== */

/*
 * NTDLL function pointer for RtlGetVersion
 * This is the recommended method as it bypasses version lies
 */
typedef LONG (NTAPI *RtlGetVersionPtr)(PRTL_OSVERSIONINFOW);

/**
 * Get Windows version using RtlGetVersion
 * 
 * @param version Output structure for version info
 * @return 0 on success, -1 on failure
 */
static int
brix_win32_get_version_rtl(RTL_OSVERSIONINFOW *version)
{
    HMODULE h_ntdll;
    RtlGetVersionPtr rtl_get_version;
    
    if (version == NULL) {
        return -1;
    }
    
    /* Load ntdll.dll */
    h_ntdll = GetModuleHandleW(L"ntdll.dll");
    if (h_ntdll == NULL) {
        return -1;
    }
    
    /* Get function pointer */
    rtl_get_version = (RtlGetVersionPtr)GetProcAddress(h_ntdll, "RtlGetVersion");
    if (rtl_get_version == NULL) {
        return -1;
    }
    
    /* Call RtlGetVersion */
    version->dwOSVersionInfoSize = sizeof(RTL_OSVERSIONINFOW);
    if (rtl_get_version(version) == 0) {
        return 0;
    }
    
    return -1;
}

/**
 * Get Windows version using GetVersionExW (fallback)
 * 
 * @param version Output structure for version info
 * @return 0 on success, -1 on failure
 */
static int
brix_win32_get_version_api(RTL_OSVERSIONINFOW *version)
{
    OSVERSIONINFOW osvi;
    
    if (version == NULL) {
        return -1;
    }
    
    ZeroMemory(&osvi, sizeof(OSVERSIONINFOW));
    osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOW);
    
    /* GetVersionExW is deprecated but still available */
#pragma warning(push)
#pragma warning(disable: 4996)  /* Disable deprecation warning */
    if (GetVersionExW(&osvi)) {
        version->dwMajorVersion = osvi.dwMajorVersion;
        version->dwMinorVersion = osvi.dwMinorVersion;
        version->dwBuildNumber = osvi.dwBuildNumber;
        version->dwPlatformId = osvi.dwPlatformId;
        wcsncpy_s(version->szCSDVersion, RTL_NUMBER_OF_FIELD(RTL_OSVERSIONINFOW, szCSDVersion),
                  osvi.szCSDVersion, _TRUNCATE);
        return 0;
    }
#pragma warning(pop)
    
    return -1;
}

/**
 * Check if running on Windows Server
 * 
 * @return 1 if Server, 0 if client
 */
static int
brix_win32_is_server(void)
{
    OSVERSIONINFOEXW osvi;
    DWORDLONG dwlConditionMask = 0;
    
    ZeroMemory(&osvi, sizeof(OSVERSIONINFOEXW));
    osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEXW);
    osvi.wProductType = VER_NT_SERVER;
    
    VER_SET_CONDITION(dwlConditionMask, VER_PRODUCT_TYPE, VER_EQUAL);
    
    return VerifyVersionInfoW(&osvi, VER_PRODUCT_TYPE, dwlConditionMask) ? 1 : 0;
}

/**
 * Get Windows product name from registry
 * 
 * @param buffer Output buffer
 * @param size Buffer size
 * @return 0 on success, -1 on failure
 */
static int
brix_win32_get_product_name(wchar_t *buffer, size_t size)
{
    HKEY h_key;
    DWORD type = REG_SZ;
    DWORD cb_data = (DWORD)(size * sizeof(wchar_t));
    
    if (buffer == NULL || size == 0) {
        return -1;
    }
    
    /* Open registry key */
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                      L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
                      0, KEY_READ, &h_key) != ERROR_SUCCESS) {
        return -1;
    }
    
    /* Try ProductName first (Windows 11+) */
    if (RegQueryValueExW(h_key, L"ProductName", NULL, &type,
                         (LPBYTE)buffer, &cb_data) == ERROR_SUCCESS) {
        RegCloseKey(h_key);
        return 0;
    }
    
    /* Fallback to EditionId */
    cb_data = (DWORD)(size * sizeof(wchar_t));
    if (RegQueryValueExW(h_key, L"EditionId", NULL, &type,
                         (LPBYTE)buffer, &cb_data) == ERROR_SUCCESS) {
        RegCloseKey(h_key);
        return 0;
    }
    
    RegCloseKey(h_key);
    return -1;
}

/* ==========================================================================
 * PUBLIC API FUNCTIONS
 * ========================================================================== */

/**
 * Check if running on Windows
 * 
 * @return 1 if Windows, 0 otherwise
 */
int
brix_plat_is_windows(void)
{
#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__) || defined(__MINGW32__)
    return 1;
#else
    return 0;
#endif
}

/**
 * Get Windows version string
 * 
 * @return Version string (e.g., "Windows 10", "Windows Server 2022")
 *         Static buffer, do not free
 */
const char *
brix_plat_windows_version(void)
{
    static char version_str[128] = {0};
    RTL_OSVERSIONINFOW osvi;
    int is_server;
    const char *product_name;
    
    if (version_str[0] != '\0') {
        return version_str;  /* Already cached */
    }
    
    /* Get version info */
    if (brix_win32_get_version_rtl(&osvi) != 0) {
        if (brix_win32_get_version_api(&osvi) != 0) {
            strncpy_s(version_str, sizeof(version_str), "Unknown Windows", _TRUNCATE);
            return version_str;
        }
    }
    
    is_server = brix_win32_is_server();
    
    /* Map version to product name */
    if (is_server) {
        /* Windows Server versions */
        switch (osvi.dwMajorVersion) {
            case 10:
                if (osvi.dwBuildNumber >= 26100) {
                    product_name = "Windows Server 2025";
                } else if (osvi.dwBuildNumber >= 20348) {
                    product_name = "Windows Server 2022";
                } else if (osvi.dwBuildNumber >= 17763) {
                    product_name = "Windows Server 2019";
                } else {
                    product_name = "Windows Server (unknown)";
                }
                break;
            case 6:
                if (osvi.dwMinorVersion == 3) {
                    product_name = "Windows Server 2012 R2";
                } else if (osvi.dwMinorVersion == 2) {
                    product_name = "Windows Server 2012";
                } else {
                    product_name = "Windows Server (unknown)";
                }
                break;
            default:
                product_name = "Windows Server (unknown)";
                break;
        }
    } else {
        /* Windows client versions */
        switch (osvi.dwMajorVersion) {
            case 10:
                if (osvi.dwBuildNumber >= 22000) {
                    /* Windows 11 */
                    if (osvi.dwBuildNumber >= 26100) {
                        product_name = "Windows 11 (24H2)";
                    } else if (osvi.dwBuildNumber >= 25398) {
                        product_name = "Windows 11 (23H2)";
                    } else if (osvi.dwBuildNumber >= 22621) {
                        product_name = "Windows 11 (22H2)";
                    } else if (osvi.dwBuildNumber >= 22000) {
                        product_name = "Windows 11 (21H2)";
                    } else {
                        product_name = "Windows 11";
                    }
                } else {
                    /* Windows 10 */
                    if (osvi.dwBuildNumber >= 19045) {
                        product_name = "Windows 10 (22H2)";
                    } else if (osvi.dwBuildNumber >= 19044) {
                        product_name = "Windows 10 (21H2)";
                    } else if (osvi.dwBuildNumber >= 19043) {
                        product_name = "Windows 10 (21H1)";
                    } else if (osvi.dwBuildNumber >= 19042) {
                        product_name = "Windows 10 (20H2)";
                    } else if (osvi.dwBuildNumber >= 19041) {
                        product_name = "Windows 10 (2004)";
                    } else if (osvi.dwBuildNumber >= 18363) {
                        product_name = "Windows 10 (1909)";
                    } else if (osvi.dwBuildNumber >= 18362) {
                        product_name = "Windows 10 (1903)";
                    } else if (osvi.dwBuildNumber >= 17763) {
                        product_name = "Windows 10 (1809)";
                    } else if (osvi.dwBuildNumber >= 17134) {
                        product_name = "Windows 10 (1803)";
                    } else if (osvi.dwBuildNumber >= 16299) {
                        product_name = "Windows 10 (1709)";
                    } else if (osvi.dwBuildNumber >= 15063) {
                        product_name = "Windows 10 (1703)";
                    } else if (osvi.dwBuildNumber >= 14393) {
                        product_name = "Windows 10 (1607)";
                    } else if (osvi.dwBuildNumber >= 10586) {
                        product_name = "Windows 10 (1511)";
                    } else {
                        product_name = "Windows 10 (1507)";
                    }
                }
                break;
            case 6:
                if (osvi.dwMinorVersion == 3) {
                    product_name = "Windows 8.1";
                } else if (osvi.dwMinorVersion == 2) {
                    product_name = "Windows 8";
                } else {
                    product_name = "Windows (unknown)";
                }
                break;
            default:
                product_name = "Windows (unknown)";
                break;
        }
    }
    
    snprintf(version_str, sizeof(version_str), "%s (Build %lu)",
             product_name, osvi.dwBuildNumber);
    
    return version_str;
}

/**
 * Get Windows build number
 * 
 * @return Build number (e.g., 22621 for Windows 11 22H2)
 */
unsigned long
brix_plat_windows_build(void)
{
    RTL_OSVERSIONINFOW osvi;
    
    if (brix_win32_get_version_rtl(&osvi) == 0) {
        return osvi.dwBuildNumber;
    }
    
    if (brix_win32_get_version_api(&osvi) == 0) {
        return osvi.dwBuildNumber;
    }
    
    return 0;
}

/**
 * Get Windows version info as structure
 * 
 * @param major Output: Major version
 * @param minor Output: Minor version
 * @param build Output: Build number
 * @return 0 on success, -1 on failure
 */
int
brix_plat_windows_version_info(unsigned long *major,
                               unsigned long *minor,
                               unsigned long *build)
{
    RTL_OSVERSIONINFOW osvi;
    
    if (brix_win32_get_version_rtl(&osvi) == 0) {
        if (major) *major = osvi.dwMajorVersion;
        if (minor) *minor = osvi.dwMinorVersion;
        if (build) *build = osvi.dwBuildNumber;
        return 0;
    }
    
    if (brix_win32_get_version_api(&osvi) == 0) {
        if (major) *major = osvi.dwMajorVersion;
        if (minor) *minor = osvi.dwMinorVersion;
        if (build) *build = osvi.dwBuildNumber;
        return 0;
    }
    
    return -1;
}

/**
 * Check if running on Windows Server
 * 
 * @return 1 if Server, 0 if client
 */
int
brix_plat_is_windows_server(void)
{
    return brix_win32_is_server();
}

/**
 * Get Windows service pack string
 * 
 * @return Service pack string (e.g., "Service Pack 1")
 *         Static buffer, do not free
 */
const char *
brix_plat_windows_service_pack(void)
{
    static char sp_str[64] = {0};
    RTL_OSVERSIONINFOW osvi;
    
    if (sp_str[0] != '\0') {
        return sp_str;  /* Already cached */
    }
    
    if (brix_win32_get_version_rtl(&osvi) == 0) {
        if (osvi.szCSDVersion[0] != L'\0') {
            /* Convert wide string to narrow */
            wcstombs(sp_str, osvi.szCSDVersion, sizeof(sp_str) - 1);
            return sp_str;
        }
    }
    
    strncpy_s(sp_str, sizeof(sp_str), "None", _TRUNCATE);
    return sp_str;
}

/**
 * Get Windows edition from registry
 * 
 * @return Edition string (e.g., "Professional", "Datacenter")
 *         Static buffer, do not free
 */
const char *
brix_plat_windows_edition(void)
{
    static char edition_str[128] = {0};
    wchar_t edition_wide[128];
    
    if (edition_str[0] != '\0') {
        return edition_str;  /* Already cached */
    }
    
    if (brix_win32_get_product_name(edition_wide, 128) == 0) {
        /* Convert wide string to narrow */
        wcstombs(edition_str, edition_wide, sizeof(edition_str) - 1);
        return edition_str;
    }
    
    strncpy_s(edition_str, sizeof(edition_str), "Unknown", _TRUNCATE);
    return edition_str;
}

/**
 * Check if Windows version meets minimum requirements
 * 
 * @param min_major Minimum major version
 * @param min_minor Minimum minor version
 * @param min_build Minimum build number
 * @return 1 if meets requirements, 0 otherwise
 */
int
brix_plat_windows_version_at_least(unsigned long min_major,
                                   unsigned long min_minor,
                                   unsigned long min_build)
{
    RTL_OSVERSIONINFOW osvi;
    
    if (brix_win32_get_version_rtl(&osvi) != 0) {
        return 0;  /* Assume not met if can't detect */
    }
    
    /* Compare major version */
    if (osvi.dwMajorVersion < min_major) {
        return 0;
    }
    if (osvi.dwMajorVersion > min_major) {
        return 1;
    }
    
    /* Major versions equal, compare minor */
    if (osvi.dwMinorVersion < min_minor) {
        return 0;
    }
    if (osvi.dwMinorVersion > min_minor) {
        return 1;
    }
    
    /* Minor versions equal, compare build */
    return (osvi.dwBuildNumber >= min_build) ? 1 : 0;
}

#endif /* BRIX_PLATFORM_WINDOWS */
