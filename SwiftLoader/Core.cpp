#include "Core.h"
#include <iostream>
#include <fstream>

#define RELOC_FLAG32(info) ((info >> 0x0C) == IMAGE_REL_BASED_HIGHLOW)
#define RELOC_FLAG64(info) ((info >> 0x0C) == IMAGE_REL_BASED_DIR64)

#ifdef _WIN64
#define RELOC_FLAG_NATIVE RELOC_FLAG64
#else
#define RELOC_FLAG_NATIVE RELOC_FLAG32
#endif

// privilege escalation 
bool SwiftLoader::SetDebugPrivilege(bool enable) {
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return false;

    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {
        CloseHandle(hToken);
        return false;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = enable ? SE_PRIVILEGE_ENABLED : 0;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
        CloseHandle(hToken);
        return false;
    }

    CloseHandle(hToken);
    return true;
}

// characteristics -> page protection mapleme
DWORD SwiftLoader::GetSectionProtection(DWORD characteristics) {
    if (characteristics & IMAGE_SCN_MEM_EXECUTE) {
        if (characteristics & IMAGE_SCN_MEM_WRITE)
            return PAGE_EXECUTE_READWRITE;
        if (characteristics & IMAGE_SCN_MEM_READ)
            return PAGE_EXECUTE_READ;
        return PAGE_EXECUTE;
    }
    if (characteristics & IMAGE_SCN_MEM_WRITE)
        return PAGE_READWRITE;
    if (characteristics & IMAGE_SCN_MEM_READ)
        return PAGE_READONLY;
    return PAGE_NOACCESS;
}

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
    // 1. Yetki yukseltme denemesi
    if (!SetDebugPrivilege(true)) {
        // her zaman kritik degil ama loglamakta fayda var
        std::wcerr << L"(!) SeDebugPrivilege ayarlanamadi, admin olmayabilirsin." << std::endl;
    }

    std::ifstream file(dll_path, std::ios::binary | std::ios::ate);
    if (!file.is_open()) return SL_ERR_FILE_IO;

    size_t file_size = file.tellg();
    std::vector<uint8_t> buffer(file_size);
    file.seekg(0, std::ios::beg);
    file.read((char*)buffer.data(), file_size);
    file.close();

    auto dos = (PIMAGE_DOS_HEADER)buffer.data();
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return SL_ERR_INVALID_PE;

    auto nt = (PIMAGE_NT_HEADERS)(buffer.data() + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return SL_ERR_INVALID_PE;

#ifdef _WIN64
    if (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) return SL_ERR_ARCH_MISMATCH;
#else
    if (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_I386) return SL_ERR_ARCH_MISMATCH;
#endif

    uint32_t pid = FindProcessId(target_exe);
    if (!pid) return SL_ERR_PROC_NOT_FOUND;

    // AI isi PROCESS_ALL_ACCESS yerine minimal mask kullaniyoruz
    DWORD access = PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ;
    HANDLE h_proc = OpenProcess(access, FALSE, pid);
    if (!h_proc || h_proc == INVALID_HANDLE_VALUE) return SL_ERR_PROC_NOT_FOUND;

    size_t img_size = nt->OptionalHeader.SizeOfImage;
    void* remote_base = VirtualAllocEx(h_proc, (void*)nt->OptionalHeader.ImageBase, img_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remote_base) {
        remote_base = VirtualAllocEx(h_proc, NULL, img_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    }

    if (!remote_base) {
        CloseHandle(h_proc);
        return SL_ERR_MEM_FAIL;
    }

    // headers copy
    WriteProcessMemory(h_proc, remote_base, buffer.data(), nt->OptionalHeader.SizeOfHeaders, NULL);

    // sections mapping
    auto section = IMAGE_FIRST_SECTION(nt);
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++, section++) {
        if (section->SizeOfRawData > 0) {
            WriteProcessMemory(h_proc, (uint8_t*)remote_base + section->VirtualAddress, 
                               buffer.data() + section->PointerToRawData, 
                               section->SizeOfRawData, NULL);
        }
    }

    // setup stub context
    LOADER_CONTEXT ctx = { 0 };
    ctx.ptr_base = remote_base;
    ctx.pLoadLibraryA = LoadLibraryA;
    ctx.pGetProcAddress = GetProcAddress;

    void* d_ctx = VirtualAllocEx(h_proc, NULL, sizeof(ctx), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    size_t stub_size = (uintptr_t)RemoteStubEnd - (uintptr_t)RemoteStub;
    void* d_stub = VirtualAllocEx(h_proc, NULL, stub_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    if (!d_ctx || !d_stub) {
        VirtualFreeEx(h_proc, remote_base, 0, MEM_RELEASE);
        CloseHandle(h_proc);
        return SL_ERR_MEM_FAIL;
    }

    WriteProcessMemory(h_proc, d_ctx, &ctx, sizeof(ctx), NULL);
    WriteProcessMemory(h_proc, d_stub, (void*)RemoteStub, stub_size, NULL);

    HANDLE h_thread = CreateRemoteThread(h_proc, NULL, 0, (LPTHREAD_START_ROUTINE)d_stub, d_ctx, 0, NULL);
    if (h_thread) {
        // INFINITE bekleme yapmiyoruz, bazen stub patlarsa sonsuz loopa girmeyelim
        DWORD wait_res = WaitForSingleObject(h_thread, 20000); 
        if (wait_res == WAIT_TIMEOUT) {
            std::wcerr << L"(!) Stub zaman asimina ugradi." << std::endl;
            TerminateThread(h_thread, 0);
        }
        
        DWORD exit_code = 0;
        GetExitCodeThread(h_thread, &exit_code);
        CloseHandle(h_thread);
    } else {
        // cleanup simetrisi
        VirtualFreeEx(h_proc, remote_base, 0, MEM_RELEASE);
        VirtualFreeEx(h_proc, d_ctx, 0, MEM_RELEASE);
        VirtualFreeEx(h_proc, d_stub, 0, MEM_RELEASE);
        CloseHandle(h_proc);
        return SL_ERR_THREAD_FAIL;
    }

    // section protectionlari son haliyle setleyelim - senior level detay
    section = IMAGE_FIRST_SECTION(nt);
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++, section++) {
        DWORD old_prot;
        DWORD new_prot = GetSectionProtection(section->Characteristics);
        VirtualProtectEx(h_proc, (uint8_t*)remote_base + section->VirtualAddress, section->Misc.VirtualSize, new_prot, &old_prot);
    }

    // intentional leak: d_ctx ve d_stub'i bazen debug icin birakiyoruz 
    // ama productionda temizlemek daha dogru.
    VirtualFreeEx(h_proc, d_ctx, 0, MEM_RELEASE);
    VirtualFreeEx(h_proc, d_stub, 0, MEM_RELEASE);

    CloseHandle(h_proc);
    return SL_OK;
}

DWORD __stdcall RemoteStub(PLOADER_CONTEXT ctx) {
    auto base = (uintptr_t)ctx->ptr_base;
    auto dos = (PIMAGE_DOS_HEADER)base;
    auto nt = (PIMAGE_NT_HEADERS)(base + dos->e_lfanew);

    // 1. Relocations - boundary checkleri ekledik
    auto delta = base - nt->OptionalHeader.ImageBase;
    if (delta != 0) {
        auto reloc_dir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (reloc_dir->Size > 0) {
            auto reloc = (PIMAGE_BASE_RELOCATION)(base + reloc_dir->VirtualAddress);
            auto reloc_end = (uintptr_t)reloc + reloc_dir->Size;

            while (reloc->VirtualAddress != 0 && (uintptr_t)reloc < reloc_end) {
                // sanity check: block size sacma olmamali
                if (reloc->SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION)) break;

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
    auto imp_dir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (imp_dir->Size > 0) {
        auto desc = (PIMAGE_IMPORT_DESCRIPTOR)(base + imp_dir->VirtualAddress);
        for (; desc->Name != 0; desc++) {
            auto mod = ctx->pLoadLibraryA((char*)(base + desc->Name));
            if (!mod) continue;

            auto thunk = (PIMAGE_THUNK_DATA)(base + desc->FirstThunk);
            auto orig = (PIMAGE_THUNK_DATA)(base + desc->OriginalFirstThunk);
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

    // 3. TLS Callbacks - asil senior isi burasi
    auto tls_dir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
    if (tls_dir->Size > 0) {
        auto tls = (PIMAGE_TLS_DIRECTORY)(base + tls_dir->VirtualAddress);
        auto callback = (PIMAGE_TLS_CALLBACK*)tls->AddressOfCallBacks;
        if (callback) {
            while (*callback) {
                (*callback)((void*)base, DLL_PROCESS_ATTACH, NULL);
                callback++;
            }
        }
    }

    // 4. Entry Point
    if (nt->OptionalHeader.AddressOfEntryPoint != 0) {
        auto entry = (BOOL(WINAPI*)(void*, uint32_t, void*))(base + nt->OptionalHeader.AddressOfEntryPoint);
        entry((void*)base, DLL_PROCESS_ATTACH, NULL);
    }

    return 1; // basarili
}

void RemoteStubEnd() {}
