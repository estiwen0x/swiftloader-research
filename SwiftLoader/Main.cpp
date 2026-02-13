#include "Core.h"
#include <iostream>
#include <string>

int wmain(int argc, wchar_t** argv) {
    std::wcout << L"-------------------------------------------" << std::endl;
    std::wcout << L" SwiftLoader v2.2 " << std::endl;
    std::wcout << L"-------------------------------------------" << std::endl;

    if (argc < 2) {
        std::wcout << L"(!) Kullanim: SwiftLoader.exe <payload.dll> [target_process.exe]" << std::endl;
        return -1;
    }

    std::wstring dll_path = argv[1];
    std::wstring target_exe;

    if (argc > 2) {
        target_exe = argv[2];
    } else {
        // target yoksa kendine inject etsin test amacli
        wchar_t buf[MAX_PATH];
        GetModuleFileNameW(NULL, buf, MAX_PATH);
        std::wstring self(buf);
        target_exe = self.substr(self.find_last_of(L"\\/") + 1);
        std::wcout << L"[*] Target yok, self-inject: " << target_exe << std::endl;
    }

    std::wcout << L"[*] Islem basliyor..." << std::endl;
    uint32_t status = SwiftLoader::PerformInjection(target_exe, dll_path);

    switch (status) {
    case SL_OK:
        std::wcout << L"[+] Oldu bu is." << std::endl;
        break;
    case SL_ERR_FILE_IO:
        std::wcerr << L"[-] DLL dosyasi okunmuyor, yolu kontrol et." << std::endl;
        break;
    case SL_ERR_INVALID_PE:
        std::wcerr << L"[-] Dosya PE formatinda degil." << std::endl;
        break;
    case SL_ERR_ARCH_MISMATCH:
        std::wcerr << L"[-] Mimari uyusmuyor (x86/x64)." << std::endl;
        break;
    case SL_ERR_PROC_NOT_FOUND:
        std::wcerr << L"[-] Target process bulunamadi veya yetki yetmedi." << std::endl;
        break;
    case SL_ERR_MEM_FAIL:
        std::wcerr << L"[-] VirtualAllocEx patladi." << std::endl;
        break;
    case SL_ERR_THREAD_FAIL:
        std::wcerr << L"[-] Remote thread acilamadi, AV engellemis olabilir." << std::endl;
        break;
    default:
        std::wcerr << L"[-] Bilinmeyen hata: " << status << std::endl;
        break;
    }

    return (status == SL_OK) ? 0 : (int)status;
}
