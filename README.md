# SwiftLoader v2.0

A production-grade, lightweight PE mapping engine rewritten for stability and performance.

## Features
- **Manual PE Mapping**: Maps images directly into memory without `LoadLibrary`.
- **Arch-Aware**: Built-in checks for x86/x64 compatibility.
- **Improved Stability**: Handles edge cases like missing `OriginalFirstThunk` or ordinal imports.
- **Clean Implementation**: Zero unnecessary abstractions, focused on reliability.

## Usage
```powershell
# Inject into a specific process
.\SwiftLoader.exe my_payload.dll notepad.exe

# Self-injection (for testing)
.\SwiftLoader.exe my_payload.dll
```

## Error Codes
- `0`: Success
- `1`: File not found
- `2`: Invalid PE structure
- `3`: Architecture mismatch
- `4`: Process access denied
- `5`: Memory allocation failure
- `6`: Thread execution failure

## Disclaimer
This project is for educational and research purposes only.
