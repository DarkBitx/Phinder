# Phinder

Phinder is a research-oriented tool designed to help security researchers identify potential **Phantom DLL Hijacking** opportunities by analyzing DLL loading behavior.

It analyzes application DLL activity and searches for suspicious DLL references that may indicate missing dependencies, unusual loading behavior, or potential hijacking conditions.

## Features

- Analyze Process Monitor (Procmon) CSV logs
- Identify missing DLL references
- Compare requested DLLs against successfully loaded modules
- Detect potential Phantom DLL candidates
- Analyze loaded DLL modules for unusual behaviors
- Support multiple analysis approaches

## How It Works

Phinder currently uses two analysis methods:

### Method 1 — Missing DLL Reference Analysis

This method analyzes Procmon logs and extracts DLL loading attempts.

The tool compares:

- DLLs requested by the application
- DLLs successfully loaded during execution

If an application attempts to load a DLL but the module is never successfully loaded, it is marked as a potential Phantom DLL candidate.

Example:

```

Application requests:
example.dll

Loaded modules:
kernel32.dll
user32.dll
ntdll.dll

Result:
example.dll → Potential Phantom DLL

```

---

### Method 2 — Loaded Module Comparison

This method compares the currently loaded DLL modules of a process against observed DLL activity.

It can help identify DLLs that:

- Are loaded during startup
- Appear unusual compared to normal dependencies
- May not have obvious usage during execution

These findings are classified as potential candidates requiring further manual validation.

## Usage

### Method 1

Provide a Procmon CSV capture:

```bash
Phinder.exe -m1 events.csv
```

Example output:

```
[+] Possible Phantom DLL Candidates:

DWriteCore.dll
libexample.dll
example2.dll
```

---

### Method 2

Export loaded modules from tools such as:

- System Informer
- Process Hacker

Save the module names into a text file:

```
modules.txt
```

Run:

```bash
Phinder.exe -m2 modules.txt
```

Example output:

```
[+] Possible Candidates:

DWriteCore.dll
mf.dll
RTWorkQ.dll
```

---

## Workflow

Typical research workflow:

```
Application
     |
     v
Process Monitor Capture
     |
     v
Export CSV
     |
     v
       Phinder
     |
     v
Potential Phantom DLL Candidates
     |
     v
Manual Validation
```

## Limitations

Phinder only identifies potential candidates.

A reported DLL does not automatically mean that a valid Phantom DLL condition exists.

Further analysis is required to verify:

- DLL search behavior
- Application loading logic
- Export requirements
- Privilege context
- Runtime behavior

## Author

[**@DarkBit**](https://t.me/DarkBitx)
