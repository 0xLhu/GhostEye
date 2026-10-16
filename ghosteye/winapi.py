"""
Win32 bindings (ctypes) with explicit argtypes / restypes.

Every prototype is declared so 64-bit handles and pointers are never
truncated to a C int, and errors come from GetLastError via use_last_error.
"""

import ctypes
import sys
from ctypes import wintypes as wt

if sys.platform != "win32":  # pragma: no cover
    raise ImportError("GhostEye live mode requires Windows")

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
psapi = ctypes.WinDLL("psapi", use_last_error=True)
advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
iphlpapi = ctypes.WinDLL("iphlpapi", use_last_error=True)
shell32 = ctypes.WinDLL("shell32", use_last_error=True)

PTR64 = ctypes.sizeof(ctypes.c_void_p) == 8
ULONG_PTR = ctypes.c_size_t
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

PROCESS_VM_READ = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
STILL_ACTIVE = 259
ERROR_ACCESS_DENIED = 5
ERROR_INSUFFICIENT_BUFFER = 122
TH32CS_SNAPPROCESS = 0x2
LIST_MODULES_ALL = 0x3
TOKEN_ADJUST_PRIVILEGES, TOKEN_QUERY = 0x20, 0x8
SE_PRIVILEGE_ENABLED = 0x2


class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wt.DWORD), ("cntUsage", wt.DWORD), ("th32ProcessID", wt.DWORD),
        ("th32DefaultHeapID", ULONG_PTR), ("th32ModuleID", wt.DWORD), ("cntThreads", wt.DWORD),
        ("th32ParentProcessID", wt.DWORD), ("pcPriClassBase", wt.LONG), ("dwFlags", wt.DWORD),
        ("szExeFile", wt.WCHAR * 260),
    ]


if PTR64:
    class MEMORY_BASIC_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("BaseAddress", ctypes.c_void_p), ("AllocationBase", ctypes.c_void_p),
            ("AllocationProtect", wt.DWORD), ("PartitionTag", wt.WORD), ("RegionSize", ctypes.c_size_t),
            ("State", wt.DWORD), ("Protect", wt.DWORD), ("Type", wt.DWORD),
        ]
else:
    class MEMORY_BASIC_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("BaseAddress", ctypes.c_void_p), ("AllocationBase", ctypes.c_void_p),
            ("AllocationProtect", wt.DWORD), ("RegionSize", ctypes.c_size_t),
            ("State", wt.DWORD), ("Protect", wt.DWORD), ("Type", wt.DWORD),
        ]


class MODULEINFO(ctypes.Structure):
    _fields_ = [("lpBaseOfDll", ctypes.c_void_p), ("SizeOfImage", wt.DWORD), ("EntryPoint", ctypes.c_void_p)]


class LUID(ctypes.Structure):
    _fields_ = [("LowPart", wt.DWORD), ("HighPart", wt.LONG)]


class LUID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("Luid", LUID), ("Attributes", wt.DWORD)]


class TOKEN_PRIVILEGES(ctypes.Structure):
    _fields_ = [("PrivilegeCount", wt.DWORD), ("Privileges", LUID_AND_ATTRIBUTES * 1)]


class MIB_TCPROW_OWNER_PID(ctypes.Structure):
    _fields_ = [("dwState", wt.DWORD), ("dwLocalAddr", wt.DWORD), ("dwLocalPort", wt.DWORD),
                ("dwRemoteAddr", wt.DWORD), ("dwRemotePort", wt.DWORD), ("dwOwningPid", wt.DWORD)]


class MIB_TCP6ROW_OWNER_PID(ctypes.Structure):
    _fields_ = [("ucLocalAddr", ctypes.c_ubyte * 16), ("dwLocalScopeId", wt.DWORD), ("dwLocalPort", wt.DWORD),
                ("ucRemoteAddr", ctypes.c_ubyte * 16), ("dwRemoteScopeId", wt.DWORD), ("dwRemotePort", wt.DWORD),
                ("dwState", wt.DWORD), ("dwOwningPid", wt.DWORD)]


class MIB_UDPROW_OWNER_PID(ctypes.Structure):
    _fields_ = [("dwLocalAddr", wt.DWORD), ("dwLocalPort", wt.DWORD), ("dwOwningPid", wt.DWORD)]


class MIB_UDP6ROW_OWNER_PID(ctypes.Structure):
    _fields_ = [("ucLocalAddr", ctypes.c_ubyte * 16), ("dwLocalScopeId", wt.DWORD), ("dwLocalPort", wt.DWORD),
                ("dwOwningPid", wt.DWORD)]


def _proto(fn, restype, *argtypes):
    fn.restype = restype
    fn.argtypes = list(argtypes)
    return fn


OpenProcess = _proto(kernel32.OpenProcess, wt.HANDLE, wt.DWORD, wt.BOOL, wt.DWORD)
CloseHandle = _proto(kernel32.CloseHandle, wt.BOOL, wt.HANDLE)
GetCurrentProcess = _proto(kernel32.GetCurrentProcess, wt.HANDLE)
CreateToolhelp32Snapshot = _proto(kernel32.CreateToolhelp32Snapshot, wt.HANDLE, wt.DWORD, wt.DWORD)
Process32FirstW = _proto(kernel32.Process32FirstW, wt.BOOL, wt.HANDLE, ctypes.POINTER(PROCESSENTRY32W))
Process32NextW = _proto(kernel32.Process32NextW, wt.BOOL, wt.HANDLE, ctypes.POINTER(PROCESSENTRY32W))
VirtualQueryEx = _proto(kernel32.VirtualQueryEx, ctypes.c_size_t, wt.HANDLE, ctypes.c_void_p,
                        ctypes.POINTER(MEMORY_BASIC_INFORMATION), ctypes.c_size_t)
ReadProcessMemory = _proto(kernel32.ReadProcessMemory, wt.BOOL, wt.HANDLE, ctypes.c_void_p, ctypes.c_void_p,
                           ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t))
QueryFullProcessImageNameW = _proto(kernel32.QueryFullProcessImageNameW, wt.BOOL, wt.HANDLE, wt.DWORD,
                                    wt.LPWSTR, ctypes.POINTER(wt.DWORD))
GetExitCodeProcess = _proto(kernel32.GetExitCodeProcess, wt.BOOL, wt.HANDLE, ctypes.POINTER(wt.DWORD))
GetProcessTimes = _proto(kernel32.GetProcessTimes, wt.BOOL, wt.HANDLE, ctypes.POINTER(wt.FILETIME),
                         ctypes.POINTER(wt.FILETIME), ctypes.POINTER(wt.FILETIME), ctypes.POINTER(wt.FILETIME))
IsWow64Process = _proto(kernel32.IsWow64Process, wt.BOOL, wt.HANDLE, ctypes.POINTER(wt.BOOL))

EnumProcesses = _proto(psapi.EnumProcesses, wt.BOOL, ctypes.POINTER(wt.DWORD), wt.DWORD, ctypes.POINTER(wt.DWORD))
EnumProcessModulesEx = _proto(psapi.EnumProcessModulesEx, wt.BOOL, wt.HANDLE, ctypes.POINTER(ctypes.c_void_p),
                              wt.DWORD, ctypes.POINTER(wt.DWORD), wt.DWORD)
GetModuleFileNameExW = _proto(psapi.GetModuleFileNameExW, wt.DWORD, wt.HANDLE, ctypes.c_void_p, wt.LPWSTR, wt.DWORD)
GetModuleInformation = _proto(psapi.GetModuleInformation, wt.BOOL, wt.HANDLE, ctypes.c_void_p,
                              ctypes.POINTER(MODULEINFO), wt.DWORD)
GetMappedFileNameW = _proto(psapi.GetMappedFileNameW, wt.DWORD, wt.HANDLE, ctypes.c_void_p, wt.LPWSTR, wt.DWORD)

OpenProcessToken = _proto(advapi32.OpenProcessToken, wt.BOOL, wt.HANDLE, wt.DWORD, ctypes.POINTER(wt.HANDLE))
LookupPrivilegeValueW = _proto(advapi32.LookupPrivilegeValueW, wt.BOOL, wt.LPCWSTR, wt.LPCWSTR, ctypes.POINTER(LUID))
AdjustTokenPrivileges = _proto(advapi32.AdjustTokenPrivileges, wt.BOOL, wt.HANDLE, wt.BOOL,
                               ctypes.POINTER(TOKEN_PRIVILEGES), wt.DWORD, ctypes.c_void_p, ctypes.c_void_p)
IsUserAnAdmin = _proto(shell32.IsUserAnAdmin, wt.BOOL)

GetExtendedTcpTable = _proto(iphlpapi.GetExtendedTcpTable, wt.DWORD, ctypes.c_void_p, ctypes.POINTER(wt.DWORD),
                             wt.BOOL, wt.ULONG, ctypes.c_int, wt.ULONG)
GetExtendedUdpTable = _proto(iphlpapi.GetExtendedUdpTable, wt.DWORD, ctypes.c_void_p, ctypes.POINTER(wt.DWORD),
                             wt.BOOL, wt.ULONG, ctypes.c_int, wt.ULONG)


def last_error():
    return ctypes.get_last_error()


def enable_privilege(name="SeDebugPrivilege"):
    """Enable a privilege in our own token. Returns True if it is now enabled."""
    token = wt.HANDLE()
    if not OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ctypes.byref(token)):
        return False
    try:
        luid = LUID()
        if not LookupPrivilegeValueW(None, name, ctypes.byref(luid)):
            return False
        tp = TOKEN_PRIVILEGES(1, (LUID_AND_ATTRIBUTES * 1)(LUID_AND_ATTRIBUTES(luid, SE_PRIVILEGE_ENABLED)))
        ok = AdjustTokenPrivileges(token, False, ctypes.byref(tp), 0, None, None)
        # AdjustTokenPrivileges "succeeds" with ERROR_NOT_ALL_ASSIGNED when not held
        return bool(ok) and last_error() == 0
    finally:
        CloseHandle(token)


class Process:
    """Context manager around OpenProcess."""

    def __init__(self, pid, access=PROCESS_QUERY_INFORMATION | PROCESS_VM_READ):
        self.pid = pid
        self.handle = OpenProcess(access, False, pid)
        if not self.handle:
            raise ctypes.WinError(last_error())

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def close(self):
        if self.handle:
            CloseHandle(self.handle)
            self.handle = None


def filetime_to_unix(ft):
    v = (ft.dwHighDateTime << 32) | ft.dwLowDateTime
    return (v - 116444736000000000) / 1e7 if v else None
