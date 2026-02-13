#include "Core.h"
#include <iostream>
#include <string>

void Banner() {
    std::wcout << L"-------------------------------------------" << std::endl;
    std::wcout << L" SwiftLoader v2.1 - Senior Edition" << std::endl;
    std::wcout << L" [Manual PE Mapper / Remote Thread]" << std::endl;
    std::wcout << L"-------------------------------------------" << std::endl;
}

int wmain(int argc, wchar_t** argv) {
    Banner();

    if (argc < 2) {
        std::wcout << L"(!) Usage: SwiftLoader.exe <payload.dll> [target_process.exe]" << std::endl;
        std::wcout << L"(!) If no target specified, I'll try to inject into myself." << std::endl;
        return -1;
    }

    std::wstring dll_path = argv[1];
    std::wstring target_exe;

    if (argc > 2) {
        target_exe = argv[2];
    } else {
        // Just use current process name for self-injection test
        wchar_t buf[MAX_PATH];
        GetModuleFileNameW(NULL, buf, MAX_PATH);
        std::wstring self(buf);
        target_exe = self.substr(self.find_last_of(L"\\/") + 1);
        std::wcout << L"[*] No target provided, using self: " << target_exe << std::endl;
    }

    std::wcout << L"[*] Attempting injection..." << std::endl;
    std::wcout << L"    - DLL: " << dll_path << std::endl;
    std::wcout << L"    - EXE: " << target_exe << std::endl;

    uint32_t status = SwiftLoader::PerformInjection(target_exe, dll_path);

    switch (status) {
    case SL_OK:
        std::wcout << L"[+] Success! Check your target process." << std::endl;
        break;
    case SL_ERR_FILE_IO:
        std::wcerr << L"[-] Error: Could not read DLL file. Check path/permissions." << std::endl;
        break;
    case SL_ERR_INVALID_PE:
        std::wcerr << L"[-] Error: File is not a valid PE image." << std::endl;
        break;
    case SL_ERR_ARCH_MISMATCH:
        std::wcerr << L"[-] Error: Arch mismatch! Don't mix x86/x64." << std::endl;
        break;
    case SL_ERR_PROC_NOT_FOUND:
        std::wcerr << L"[-] Error: Target process not found or access denied." << std::endl;
        break;
    case SL_ERR_MEM_FAIL:
        std::wcerr << L"[-] Error: VirtualAllocEx failed in remote process." << std::endl;
        break;
    case SL_ERR_THREAD_FAIL:
        std::wcerr << L"[-] Error: CreateRemoteThread failed. AV/EDR might be blocking." << std::endl;
        break;
    default:
        std::wcerr << L"[-] Error: Unknown failure (Code: " << status << L")" << std::endl;
        break;
    }

    return (status == SL_OK) ? 0 : (int)status;
}
