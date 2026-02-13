#pragma once

#include <windows.h>
#include <tlhelp32.h>
#include <stdint.h>
#include <vector>
#include <string>

// Custom error codes for internal logic
#define SL_SUCCESS          0
#define SL_ERR_FILE         1
#define SL_ERR_INVALID_PE    2
#define SL_ERR_ARCH_MISMATCH 3
#define SL_ERR_PROC_OPEN     4
#define SL_ERR_MEM_ALLOC     5
#define SL_ERR_INJECTION     6

// Payload execution context
typedef struct _INJECTION_CONTEXT {
    void*  BaseAddress;
    auto (WINAPI* LoadLibraryA)(const char*) -> HMODULE;
    auto (WINAPI* GetProcAddress)(HMODULE, const char*) -> FARPROC;
    uint32_t Flags;
} INJECTION_CONTEXT, *PINJECTION_CONTEXT;

// Simplified file buffer
struct MemoryBuffer {
    std::vector<uint8_t> Data;
    bool Load(const std::wstring& Path);
};

// Main loader functionality
namespace SwiftLoader {
    // Core injection entry point
    uint32_t Inject(const std::wstring& TargetProcess, const std::wstring& PayloadPath);
    
    // Internal helpers (separated but not over-abstracted)
    uint32_t GetProcessIdByName(const std::wstring& Name);
    bool ValidatePayload(const uint8_t* Buffer, size_t Size, WORD& OutMachine);
}

// The stub that runs inside the target process
void __stdcall InternalLoaderStub(PINJECTION_CONTEXT Context);
