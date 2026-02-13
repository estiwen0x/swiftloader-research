#include <windows.h>
#include <iostream>
#include <string>
#include "Core.h"

void PrintBanner() {
    std::wcout << L"--- SwiftLoader v2.0 ---" << std::endl;
}

int wmain(int argc, wchar_t** argv) {
    PrintBanner();

    if (argc < 2) {
        std::wcout << L"Usage: " << argv[0] << L" <payload.dll> [target_exe]" << std::endl;
        return 1;
    }

    std::wstring payloadPath = argv[1];
    std::wstring targetProcess;

    if (argc > 2) {
        targetProcess = argv[2];
    } else {
        // Self-injection if no process specified
        wchar_t currentPath[MAX_PATH];
        GetModuleFileNameW(NULL, currentPath, MAX_PATH);
        targetProcess = std::wstring(currentPath);
        size_t lastSlash = targetProcess.find_last_of(L"\\/");
        if (lastSlash != std::wstring::npos) {
            targetProcess = targetProcess.substr(lastSlash + 1);
        }
    }

    std::wcout << L"[*] Targeting: " << targetProcess << std::endl;
    std::wcout << L"[*] Payload:   " << payloadPath << std::endl;

    uint32_t result = SwiftLoader::Inject(targetProcess, payloadPath);

    switch (result) {
        case SL_SUCCESS:
            std::wcout << L"[+] Injection completed successfully." << std::endl;
            break;
        case SL_ERR_FILE:
            std::wcerr << L"[-] Error: Could not load payload file." << std::endl;
            break;
        case SL_ERR_INVALID_PE:
            std::wcerr << L"[-] Error: Payload is not a valid PE file." << std::endl;
            break;
        case SL_ERR_ARCH_MISMATCH:
            std::wcerr << L"[-] Error: Architecture mismatch (Payload vs Loader)." << std::endl;
            break;
        case SL_ERR_PROC_OPEN:
            std::wcerr << L"[-] Error: Could not find or open target process." << std::endl;
            break;
        case SL_ERR_MEM_ALLOC:
            std::wcerr << L"[-] Error: Memory allocation failed in target process." << std::endl;
            break;
        case SL_ERR_INJECTION:
            std::wcerr << L"[-] Error: Remote thread execution failed." << std::endl;
            break;
        default:
            std::wcerr << L"[-] Error: Unknown failure (Code: " << result << L")" << std::endl;
            break;
    }

    return (result == SL_SUCCESS) ? 0 : 1;
}
