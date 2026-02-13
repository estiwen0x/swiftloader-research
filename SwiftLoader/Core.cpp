#include "Core.h"
#include <iostream>
#include <fstream>

// Relocation macros - standard stuff
#define RELOC_FLAG32(info) ((info >> 0x0C) == IMAGE_REL_BASED_HIGHLOW)
#define RELOC_FLAG64(info) ((info >> 0x0C) == IMAGE_REL_BASED_DIR64)

#ifdef _WIN64
#define RELOC_FLAG_NATIVE RELOC_FLAG64
#else
#define RELOC_FLAG_NATIVE RELOC_FLAG32
#endif

uint32_t SwiftLoader::FindProcessId(const std::wstring& name) {
    uint32_t pid = 0;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W entry = { sizeof(entry) };
        if (Process32FirstW(snap, &entry)) {
            do {
                if (name == entry.szExeFile) {
                    pid = entry.th32ProcessID;
                    break;
                }
            } while (Process32NextW(snap, &entry));
        }
        CloseHandle(snap);
    }
    return pid;
}

uint32_t SwiftLoader::PerformInjection(const std::wstring& target_exe, const std::wstring& dll_path) {
    // 1. Read file manually to avoid overhead of some fancy wrappers
    std::ifstream file(dll_path, std::ios::binary | std::ios::ate);
    if (!file.is_open()) return SL_ERR_FILE_IO;

    size_t file_size = file.tellg();
    std::vector<uint8_t> buffer(file_size);
    file.seekg(0, std::ios::beg);
    file.read((char*)buffer.data(), file_size);
    file.close();

    // 2. Quick PE validation before we touch the target process
    auto dos = (PIMAGE_DOS_HEADER)buffer.data();
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return SL_ERR_INVALID_PE;

    auto nt = (PIMAGE_NT_HEADERS)(buffer.data() + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return SL_ERR_INVALID_PE;

    // Check machine type. Don't try to inject x64 DLL into x86 process, it will just die.
#ifdef _WIN64
    if (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) return SL_ERR_ARCH_MISMATCH;
#else
    if (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_I386) return SL_ERR_ARCH_MISMATCH;
#endif

    // 3. Open target process
    uint32_t pid = FindProcessId(target_exe);
    if (!pid) return SL_ERR_PROC_NOT_FOUND;

    HANDLE h_proc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!h_proc || h_proc == INVALID_HANDLE_VALUE) return SL_ERR_PROC_NOT_FOUND;

    // 4. Map the image
    // Try to allocate at preferred base first. If it fails, VirtualAlloc will find somewhere else.
    size_t img_size = nt->OptionalHeader.SizeOfImage;
    void* remote_base = VirtualAllocEx(h_proc, (void*)nt->OptionalHeader.ImageBase, img_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remote_base) {
        // (!) Preferred base taken, falling back to dynamic allocation. Relocations will be mandatory.
        remote_base = VirtualAllocEx(h_proc, NULL, img_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    }

    if (!remote_base) {
        CloseHandle(h_proc);
        return SL_ERR_MEM_FAIL;
    }

    // Copy headers & sections
    // Header copy is vital, stub needs it to find reloc/import tables
    WriteProcessMemory(h_proc, remote_base, buffer.data(), nt->OptionalHeader.SizeOfHeaders, NULL);

    auto section = IMAGE_FIRST_SECTION(nt);
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++, section++) {
        if (section->SizeOfRawData > 0) {
            WriteProcessMemory(h_proc, (uint8_t*)remote_base + section->VirtualAddress, 
                               buffer.data() + section->PointerToRawData, 
                               section->SizeOfRawData, NULL);
        }
    }

    // 5. Prepare stub & context
    LOADER_CONTEXT ctx = { 0 };
    ctx.ptr_base = remote_base;
    ctx.pLoadLibraryA = LoadLibraryA;
    ctx.pGetProcAddress = GetProcAddress;

    void* d_ctx = VirtualAllocEx(h_proc, NULL, sizeof(ctx), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    // Calc stub size by using a marker function. Old school but works.
    size_t stub_size = (uintptr_t)RemoteStubEnd - (uintptr_t)RemoteStub;
    void* d_stub = VirtualAllocEx(h_proc, NULL, stub_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    if (!d_ctx || !d_stub) {
        VirtualFreeEx(h_proc, remote_base, 0, MEM_RELEASE);
        CloseHandle(h_proc);
        return SL_ERR_MEM_FAIL;
    }

    WriteProcessMemory(h_proc, d_ctx, &ctx, sizeof(ctx), NULL);
    WriteProcessMemory(h_proc, d_stub, (void*)RemoteStub, stub_size, NULL);

    // 6. Execute remote thread
    HANDLE h_thread = CreateRemoteThread(h_proc, NULL, 0, (LPTHREAD_START_ROUTINE)d_stub, d_ctx, 0, NULL);
    if (h_thread) {
        // Give it some time to finish before we close the handle. 
        // 10s is overkill but some DLLs have heavy DllMain logic.
        WaitForSingleObject(h_thread, 10000);
        CloseHandle(h_thread);
    } else {
        // (!) CreateRemoteThread failed. Check if you have SeDebugPrivilege or if AV blocked it.
        VirtualFreeEx(h_proc, remote_base, 0, MEM_RELEASE);
        VirtualFreeEx(h_proc, d_ctx, 0, MEM_RELEASE);
        VirtualFreeEx(h_proc, d_stub, 0, MEM_RELEASE);
        CloseHandle(h_proc);
        return SL_ERR_THREAD_FAIL;
    }

    CloseHandle(h_proc);
    return SL_OK;
}

// STUB CODE - MUST BE POSITION INDEPENDENT
// No global variables, no string literals (unless handled), no CRT.
DWORD __stdcall RemoteStub(PLOADER_CONTEXT ctx) {
    auto base = (uintptr_t)ctx->ptr_base;
    auto dos = (PIMAGE_DOS_HEADER)base;
    auto nt = (PIMAGE_NT_HEADERS)(base + dos->e_lfanew);

    // 1. Fix Relocations
    auto delta = base - nt->OptionalHeader.ImageBase;
    if (delta != 0) {
        auto reloc_dir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (reloc_dir->Size > 0) {
            auto reloc = (PIMAGE_BASE_RELOCATION)(base + reloc_dir->VirtualAddress);
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

    // 2. Resolve Imports
    auto imp_dir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (imp_dir->Size > 0) {
        auto desc = (PIMAGE_IMPORT_DESCRIPTOR)(base + imp_dir->VirtualAddress);
        for (; desc->Name != 0; desc++) {
            auto mod = ctx->pLoadLibraryA((char*)(base + desc->Name));
            if (!mod) continue;

            auto thunk = (PIMAGE_THUNK_DATA)(base + desc->FirstThunk);
            auto orig = (PIMAGE_THUNK_DATA)(base + desc->OriginalFirstThunk);
            
            // Note: Some older PE files might have OriginalFirstThunk as NULL. 
            // In that case, we use FirstThunk (IAT) itself.
            if (!desc->OriginalFirstThunk) orig = thunk;

            for (; orig->u1.AddressOfData != 0; orig++, thunk++) {
                if (IMAGE_SNAP_BY_ORDINAL(orig->u1.Ordinal)) {
                    thunk->u1.Function = (uintptr_t)ctx->pGetProcAddress(mod, (char*)(orig->u1.Ordinal & 0xFFFF));
                } else {
                    auto ib_name = (PIMAGE_IMPORT_BY_NAME)(base + orig->u1.AddressOfData);
                    thunk->u1.Function = (uintptr_t)ctx->pGetProcAddress(mod, (char*)ib_name->Name);
                }
            }
        }
    }

    // 3. Call Entry Point
    if (nt->OptionalHeader.AddressOfEntryPoint != 0) {
        auto entry = (BOOL(WINAPI*)(void*, uint32_t, void*))(base + nt->OptionalHeader.AddressOfEntryPoint);
        entry((void*)base, DLL_PROCESS_ATTACH, NULL);
    }

    return 0;
}

void RemoteStubEnd() {}
