# SwiftLoader 

A production-grade, lightweight PE mapping engine rewritten for stability and performance. Focused on understanding Windows internals through manual image mapping.

---

## 🔹 Technical Highlights

- **Manual PE Mapping**: Maps images directly into memory without `LoadLibrary`, bypassing standard Windows API hooks.
- **Arch-Aware**: Intelligent x86/x64 compatibility verification before injection.
- **Robust Import Handling**: Advanced resolution for `OriginalFirstThunk` edge cases and ordinal-based imports.
- **Low-Level Precision**: Zero-abstraction approach, interacting directly with memory structures.

## 🔹 Architecture & Flow

1. **Header Parsing**: Validates DOS and NT headers.
2. **Memory Allocation**: Reserves space in target process using `VirtualAllocEx`.
3. **Section Mapping**: Copies PE sections with correct memory protections.
4. **Relocation Fixed**: Processes the Base Relocation Table.
5. **Import Resolution**: Manually populates the IAT using `GetProcAddress`.


## ⚠️ Educational Disclaimer
This project is for **educational and research purposes only**. It is designed to demonstrate low-level systems programming concepts and Windows OS internals. The author is not responsible for any misuse.
## 🔹 Usage

```powershell
# Inject into a specific process
.\SwiftLoader.exe my_payload.dll notepad.exe

# Self-injection (for testing)
.\SwiftLoader.exe my_payload.dll

Code,Meaning,Analysis
0,Success,Module successfully mapped and executed.
1,File Not Found,Verify the payload path.
2,Invalid PE,Target is not a valid Portable Executable.
3,Arch Mismatch,Target process and DLL must share architecture.
4,Access Denied,Check process permissions (Try Admin).
5,Memory Fail,Unable to allocate memory in target space.
6,Thread Fail,Failed to spawn remote thread (CreateRemoteThread).

---

