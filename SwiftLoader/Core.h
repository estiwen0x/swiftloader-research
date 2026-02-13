#pragma once

#include <windows.h>
#include <tlhelp32.h>
#include <stdint.h>
#include <vector>
#include <string>


#define SL_OK                   0x00
#define SL_ERR_FILE_IO          0x01
#define SL_ERR_INVALID_PE       0x02
#define SL_ERR_ARCH_MISMATCH    0x03
#define SL_ERR_PROC_NOT_FOUND   0x04
#define SL_ERR_MEM_FAIL         0x05
#define SL_ERR_THREAD_FAIL      0x06
#define SL_ERR_PRIVILEGE        0x07
#define SL_ERR_PROTECTION       0x08

// remote thread icine gececek olan ctx. 
// senior not: sakin buraya std::string falan koyma patlar, pod kalsin
typedef struct _LOADER_CONTEXT {
    void*  ptr_base;
    auto (WINAPI* pLoadLibraryA)(const char*) -> HMODULE;
    auto (WINAPI* pGetProcAddress)(HMODULE, const char*) -> FARPROC;
    uint32_t flags;
} LOADER_CONTEXT, *PLOADER_CONTEXT;

namespace SwiftLoader {
    // asil is burada donuyor
    uint32_t PerformInjection(const std::wstring& target_exe, const std::wstring& dll_path);
    
    // helperlar
    uint32_t FindProcessId(const std::wstring& name);
    bool SetDebugPrivilege(bool enable);
    DWORD GetSectionProtection(DWORD characteristics);
}

// shellcode stubu
DWORD __stdcall RemoteStub(PLOADER_CONTEXT ctx);
void RemoteStubEnd(); 
