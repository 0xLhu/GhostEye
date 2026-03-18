# 👻 GhostEye — Live Memory Inspection Tool

> See what's hidden. No dump required.

GhostEye is a live memory forensics tool written in Python, built on top of native Windows APIs (`ctypes`).  
Inspired by Volatility, it operates directly on running processes without creating a memory dump.

---

## Requirements

- Windows 10/11 (64-bit)
- Python 3.9+
- Administrator privileges (required for `ReadProcessMemory`, `OpenProcess`)

```bash
pip install cffi
```

> No other external dependencies — everything relies on native Windows APIs.

---

## Installation

```bash
git clone https://github.com/yourrepo/ghosteye.git
cd ghosteye
python -m venv .venv
.venv\Scripts\activate
pip install cffi
```

---

## Usage

```bash
python main.py <command> [filter] [--flags]
```

### Available Commands

| Command | Description |
|---|---|
| `list` | List all running processes |
| `list <n>` | Filter processes by name |
| `scan <n>` | Map memory regions of a process |
| `scan <n> --strings` | Extract readable ASCII strings from memory |
| `scan <n> --pe` | Detect PE headers in memory |
| `network` | List all active TCP connections |
| `network --suspicious` | Show suspicious connections only |
| `dll <n>` | List loaded DLLs for a process |
| `dll <n> --suspicious` | Show DLLs outside trusted paths |
| `hidden` | Detect hidden processes |
| `hooks <n>` | Detect EDR hooks in ntdll.dll |

### Examples

```bash
# List all running processes
python main.py list

# Search for explorer
python main.py list explorer

# Extract strings from explorer's memory
python main.py scan explorer --strings

# Detect suspicious network connections
python main.py network --suspicious

# Detect EDR hooks in explorer
python main.py hooks explorer

# Find suspicious DLLs in a process
python main.py dll explorer --suspicious

# Detect hidden processes
python main.py hidden
```

---

## Architecture

```
ghosteye/
├── main.py        # CLI entry point — orchestrates all modules
├── list_proc.py   # Process listing (CreateToolhelp32Snapshot)
├── mapping.py     # Memory region mapping (VirtualQueryEx)
├── reader.py      # Memory reading + string extraction + PE detection
├── network.py     # Live TCP connections (GetExtendedTcpTable)
├── dll.py         # Loaded DLLs + hijacking detection (EnumProcessModules)
├── hidden.py      # Hidden process detection (EnumProcesses vs Snapshot)
└── hook.py        # EDR inline hook detection + vendor identification
```

---

## Modules

### `list_proc.py`
Lists processes via `CreateToolhelp32Snapshot`.  
Returns PID, PPID, thread count, and process name.

### `mapping.py`
Maps memory regions of a process via `VirtualQueryEx`.  
Displays base address, size, type (`IMAGE`, `PRIVATE`, `MAPPED`) and permissions (`PAGE_READONLY`, `PAGE_EXECUTE_READ`, etc.).

### `reader.py`
Reads process memory via `ReadProcessMemory` in 4KB chunks.  
- ASCII string extraction (sequences ≥ 4 printable characters)
- PE header detection (`MZ` signature) in memory regions

### `network.py`
Lists TCP connections via `GetExtendedTcpTable` with associated PID and process name.  
Flags suspicious connections:
- PID with no matching process name (potential hidden process)
- Non-standard port on an `ESTABLISHED` connection
- Outbound SSH connection from a workstation

### `dll.py`
Lists loaded modules via `EnumProcessModules` + `GetModuleFileNameExW`.  
Flags DLLs loaded from outside trusted paths:
```
C:\Windows\System32
C:\Windows\SysWOW64
C:\Windows\
C:\Program Files\
C:\Program Files (x86)\
```

### `hidden.py`
Cross-references two independent process listing sources:
- `CreateToolhelp32Snapshot` (userland, patchable by rootkits)
- `EnumProcesses` (independent source)

A PID present in `EnumProcesses` but missing from the snapshot = **hidden process**.

### `hook.py`
Detects inline hooks in `ntdll.dll` by comparing the first 5 bytes of each exported function between the on-disk version and the in-memory version.

**Hook detection:**
```
disk:   4c 8b d1 b8 50   → mov r10,rcx / mov eax,syscall  (original)
memory: e9 bb e1 7f fd   → JMP to EDR           (hooked)
```

**Vendor identification:**  
Computes the JMP destination address and resolves the owning DLL via `VirtualQueryEx` + known EDR keywords (Trend Micro, CrowdStrike, Elastic, Defender, Fortinet...).

---

## Detected Indicators of Compromise (IOCs)

| Indicator | Module | Method |
|---|---|---|
| Hidden process | `hidden.py` | Cross-view (Snapshot vs EnumProcesses) |
| Injected DLL outside system paths | `dll.py` | Trusted path verification |
| Connection to unknown IP | `network.py` | Non-standard port + PID without name |
| EDR / Malware hook | `hook.py` | Disk vs memory byte comparison |
| Injected PE in memory | `reader.py` | `MZ` detection in `PRIVATE` regions |
| Suspicious strings in memory | `reader.py` | ASCII extraction from data regions |

---

## Sample Output

```
[*] Process 17556 (explorer.exe)
  [HOOK] NtWriteVirtualMemory        0x7ffda38022f0
         disk:   4c8bd1b83a
         memory: e90be57ffd
         vendor: PRIVATE hook near ntdll.dll | EDR: TmAMSIProvider64.dll

  [HOOK] NtProtectVirtualMemory      0x7ffda38025b0
         disk:   4c8bd1b850
         memory: e9bbe17ffd
         vendor: PRIVATE hook near ntdll.dll | EDR: TmAMSIProvider64.dll
```

---

## Limitations

- **Windows only** — relies on Win32 APIs
- **Admin rights required** — `OpenProcess` with `PROCESS_ALL_ACCESS`
- **ntdll hooks only** — other DLLs (`kernel32`, `user32`) are not scanned yet
- **Kernel-level hooks not detected** — userland analysis only
- **Anti-debug / anti-VM not bypassed** — some malware may detect inspection

---

## Roadmap

### v1.1 — Extended Hook Detection
- [ ] Hook detection in `kernel32.dll`, `user32.dll`, `win32u.dll`
- [ ] Detect `PUSH/RET` hooks (alternative to `JMP`)
- [ ] Detect `MOV RAX / JMP RAX` hooks (5+ byte variants)
- [ ] Export hook report as JSON

### v1.2 — Handle Analysis
- [ ] List open handles per process (files, registry keys, mutexes, pipes)
- [ ] Flag suspicious handle names (e.g. `\\Device\\PhysicalMemory`)
- [ ] Detect processes holding handles to LSASS (credential dumping indicator)

### v1.3 — Process Hollowing Detection
- [ ] Compare on-disk PE with in-memory PE for each process
- [ ] Detect mismatches in section sizes and entry points
- [ ] Flag `MZ` headers in `PRIVATE` memory regions that don't match any loaded module

### v1.4 — Kernel-Level Analysis
- [ ] Read kernel structures via `NtQuerySystemInformation` (SystemProcessInformation)
- [ ] Cross-view detection using kernel PID list vs userland snapshot
- [ ] Detect DKOM (Direct Kernel Object Manipulation) — hidden processes at kernel level
- [ ] Detect SSDT hooks (System Service Descriptor Table patching)

### v1.5 — Network & Threat Intel
- [ ] UDP connections support (`GetExtendedUdpTable`)
- [ ] Automatic IP reputation lookup (AbuseIPDB, VirusTotal)
- [ ] DNS cache inspection
- [ ] GeoIP resolution for remote addresses

### v2.0 — Reporting & Integration
- [ ] Full JSON export for SIEM ingestion (Elastic, Splunk)
- [ ] HTML report generation
- [ ] MITRE ATT&CK technique tagging per finding
- [ ] Scheduled scan mode with delta comparison (baseline vs current state)
- [ ] Remote scan via named pipe or WinRM

---

## Disclaimer

GhostEye is an educational tool built for forensics and malware analysis training.  
**Use only on systems you are authorized to analyze.**  
The author is not responsible for any misuse.

---

## Author

Built from scratch as part of a Python + Windows internals learning journey.  
APIs used: `CreateToolhelp32Snapshot`, `VirtualQueryEx`, `ReadProcessMemory`,  
`GetExtendedTcpTable`, `EnumProcessModules`, `EnumProcesses`, `GetModuleFileNameExW`.
