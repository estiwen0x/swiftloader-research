#pragma once

#include <windows.h>
#include <tlhelp32.h>
#include <stdint.h>
#include <vector>
#include <string>

/*
 * SwiftLoader - Core Definitions
 * 
 * NOTE: Using status codes instead of bool because it's a pain to debug 
 * remote threads without knowing exactly where it died.
 */

#define SL_OK               0x00
#define SL_ERR_FILE_IO      0x01
#define SL_ERR_INVALID_PE   0x02
#define SL_ERR_ARCH_MISMATCH 0x03
#define SL_ERR_PROC_NOT_FOUND 0x04
#define SL_ERR_MEM_FAIL     0x05
#define SL_ERR_THREAD_FAIL  0x06

// Context passed to our remote stub. 
// Keep this POD (Plain Old Data), don't even think about putting std::string here.
typedef struct _LOADER_CONTEXT {
    void*  ptr_base;
    auto (WINAPI* pLoadLibraryA)(const char*) -> HMODULE;
    auto (WINAPI* pGetProcAddress)(HMODULE, const char*) -> FARPROC;
    
    // Flags for future use (e.g. wiping headers)
    uint32_t flags;
} LOADER_CONTEXT, *PLOADER_CONTEXT;

namespace SwiftLoader {
    // The main entry. Returns one of SL_OK/ERR codes.
    uint32_t PerformInjection(const std::wstring& target_exe, const std::wstring& dll_path);
    
    // Internal utils - keeping them here for easy access
    uint32_t FindProcessId(const std::wstring& name);
}

// Our 'Shellcode' loader. 
DWORD __stdcall RemoteStub(PLOADER_CONTEXT ctx);
void RemoteStubEnd(); // Marker for size calculation
