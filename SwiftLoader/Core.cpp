#include "Core.h"
#include <iostream>

// Relocation flags
#define RELOC_FLAG32(info) ((info >> 0x0C) == IMAGE_REL_BASED_HIGHLOW)
#define RELOC_FLAG64(info) ((info >> 0x0C) == IMAGE_REL_BASED_DIR64)

#ifdef _WIN64
#define RELOC_FLAG_NATIVE RELOC_FLAG64
#else
#define RELOC_FLAG_NATIVE RELOC_FLAG32
#endif

bool MemoryBuffer::Load(const std::wstring& Path) {
    HANDLE hFile = CreateFileW(Path.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return false;

    DWORD size = GetFileSize(hFile, NULL);
    if (size != INVALID_FILE_SIZE && size > 0) {
        Data.resize(size);
        DWORD read = 0;
        if (!ReadFile(hFile, Data.data(), size, &read, NULL) || read != size) {
            Data.clear();
        }
    }
    CloseHandle(hFile);
    return !Data.empty();
}

uint32_t SwiftLoader::GetProcessIdByName(const std::wstring& Name) {
    uint32_t pid = 0;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W entry = { sizeof(entry) };
        if (Process32FirstW(snapshot, &entry)) {
            do {
                if (Name == entry.szExeFile) {
                    pid = entry.th32ProcessID;
                    break;
                }
            } while (Process32NextW(snapshot, &entry));
        }
        CloseHandle(snapshot);
    }
    return pid;
}

bool SwiftLoader::ValidatePayload(const uint8_t* Buffer, size_t Size, WORD& OutMachine) {
    if (Size < sizeof(IMAGE_DOS_HEADER)) return false;
    auto dos = (PIMAGE_DOS_HEADER)Buffer;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;

    if (Size < dos->e_lfanew + sizeof(IMAGE_NT_HEADERS)) return false;
    auto nt = (PIMAGE_NT_HEADERS)(Buffer + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;

    OutMachine = nt->FileHeader.Machine;
    return true;
}

uint32_t SwiftLoader::Inject(const std::wstring& TargetProcess, const std::wstring& PayloadPath) {
    MemoryBuffer payload;
    if (!payload.Load(PayloadPath)) return SL_ERR_FILE;

    WORD payloadMachine = 0;
    if (!ValidatePayload(payload.Data.data(), payload.Data.size(), payloadMachine)) 
        return SL_ERR_INVALID_PE;

    // Arch check - don't try to inject x64 into x86 or vice versa
#ifdef _WIN64
    if (payloadMachine != IMAGE_FILE_MACHINE_AMD64) return SL_ERR_ARCH_MISMATCH;
#else
    if (payloadMachine != IMAGE_FILE_MACHINE_I386) return SL_ERR_ARCH_MISMATCH;
#endif

    uint32_t pid = GetProcessIdByName(TargetProcess);
    if (!pid) return SL_ERR_PROC_OPEN;

    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProc || hProc == INVALID_HANDLE_VALUE) return SL_ERR_PROC_OPEN;

    auto nt = (PIMAGE_NT_HEADERS)(payload.Data.data() + ((PIMAGE_DOS_HEADER)payload.Data.data())->e_lfanew);
    size_t imageSize = nt->OptionalHeader.SizeOfImage;

    // Try to get preferred base, if not, let the OS decide
    void* remoteBase = VirtualAllocEx(hProc, (void*)nt->OptionalHeader.ImageBase, imageSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteBase) {
        remoteBase = VirtualAllocEx(hProc, NULL, imageSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    }

    if (!remoteBase) {
        CloseHandle(hProc);
        return SL_ERR_MEM_ALLOC;
    }

    // Map headers and sections
    if (!WriteProcessMemory(hProc, remoteBase, payload.Data.data(), nt->OptionalHeader.SizeOfHeaders, NULL)) {
        VirtualFreeEx(hProc, remoteBase, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return SL_ERR_INJECTION;
    }

    auto section = IMAGE_FIRST_SECTION(nt);
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++, section++) {
        if (section->SizeOfRawData > 0) {
            WriteProcessMemory(hProc, (uint8_t*)remoteBase + section->VirtualAddress, 
                               payload.Data.data() + section->PointerToRawData, 
                               section->SizeOfRawData, NULL);
        }
    }

    // Prepare context for the remote stub
    INJECTION_CONTEXT ctx = { 0 };
    ctx.BaseAddress = remoteBase;
    ctx.LoadLibraryA = LoadLibraryA;
    ctx.GetProcAddress = GetProcAddress;

    void* remoteCtx = VirtualAllocEx(hProc, NULL, sizeof(ctx), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    void* remoteStub = VirtualAllocEx(hProc, NULL, 0x2000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    if (!remoteCtx || !remoteStub) {
        VirtualFreeEx(hProc, remoteBase, 0, MEM_RELEASE);
        if (remoteCtx) VirtualFreeEx(hProc, remoteCtx, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return SL_ERR_MEM_ALLOC;
    }

    WriteProcessMemory(hProc, remoteCtx, &ctx, sizeof(ctx), NULL);
    WriteProcessMemory(hProc, remoteStub, (void*)InternalLoaderStub, 0x2000, NULL);

    // Launch!
    HANDLE hThread = CreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE)remoteStub, remoteCtx, 0, NULL);
    if (hThread) {
        WaitForSingleObject(hThread, INFINITE);
        CloseHandle(hThread);
    } else {
        VirtualFreeEx(hProc, remoteBase, 0, MEM_RELEASE);
        VirtualFreeEx(hProc, remoteCtx, 0, MEM_RELEASE);
        VirtualFreeEx(hProc, remoteStub, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return SL_ERR_INJECTION;
    }

    CloseHandle(hProc);
    return SL_SUCCESS;
}

// This runs in the target process. No global variables, no CRT.
void __stdcall InternalLoaderStub(PINJECTION_CONTEXT Context) {
    auto base = (uintptr_t)Context->BaseAddress;
    auto dos = (PIMAGE_DOS_HEADER)base;
    auto nt = (PIMAGE_NT_HEADERS)(base + dos->e_lfanew);

    // 1. Relocations
    auto delta = base - nt->OptionalHeader.ImageBase;
    if (delta != 0) {
        auto relocDir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (relocDir->Size > 0) {
            auto reloc = (PIMAGE_BASE_RELOCATION)(base + relocDir->VirtualAddress);
            while (reloc->VirtualAddress != 0) {
                uint32_t count = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
                uint16_t* list = (uint16_t*)(reloc + 1);
                
                for (uint32_t i = 0; i < count; i++) {
                    if (RELOC_FLAG_NATIVE(list[i])) {
                        auto ptr = (uintptr_t*)(base + reloc->VirtualAddress + (list[i] & 0xFFF));
                        *ptr += delta;
                    }
                }
                reloc = (PIMAGE_BASE_RELOCATION)((uintptr_t)reloc + reloc->SizeOfBlock);
            }
        }
    }

    // 2. Imports
    auto importDir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (importDir->Size > 0) {
        auto desc = (PIMAGE_IMPORT_DESCRIPTOR)(base + importDir->VirtualAddress);
        for (; desc->Name != 0; desc++) {
            auto mod = Context->LoadLibraryA((char*)(base + desc->Name));
            if (!mod) continue;

            auto thunk = (PIMAGE_THUNK_DATA)(base + desc->FirstThunk);
            auto orig = (PIMAGE_THUNK_DATA)(base + desc->OriginalFirstThunk);
            
            // Handle case where OriginalFirstThunk is 0
            if (!desc->OriginalFirstThunk) orig = thunk;

            for (; orig->u1.AddressOfData != 0; orig++, thunk++) {
                if (IMAGE_SNAP_BY_ORDINAL(orig->u1.Ordinal)) {
                    thunk->u1.Function = (uintptr_t)Context->GetProcAddress(mod, (char*)(orig->u1.Ordinal & 0xFFFF));
                } else {
                    auto importByName = (PIMAGE_IMPORT_BY_NAME)(base + orig->u1.AddressOfData);
                    thunk->u1.Function = (uintptr_t)Context->GetProcAddress(mod, (char*)importByName->Name);
                }
            }
        }
    }

    // 3. Entry point
    if (nt->OptionalHeader.AddressOfEntryPoint != 0) {
        auto entry = (BOOL(WINAPI*)(void*, uint32_t, void*))(base + nt->OptionalHeader.AddressOfEntryPoint);
        entry((void*)base, DLL_PROCESS_ATTACH, NULL);
    }
}
