import ctypes
import sys


TH32CS_SNAPPROCESS = 0x00000002

class PROCESSENTRY32(ctypes.Structure):
    _fields_ = [
        ("dwSize",              ctypes.c_uint32),
        ("cntUsage",            ctypes.c_uint32),
        ("th32ProcessID",       ctypes.c_uint32),
        ("th32DefaultHeapID",   ctypes.c_uint64),   
        ("th32ModuleID",        ctypes.c_uint32),
        ("cntThreads",          ctypes.c_uint32),
        ("th32ParentProcessID", ctypes.c_uint32),
        ("pcPriClassBase",      ctypes.c_long),
        ("dwFlags",             ctypes.c_uint32),
        ("szExeFile",           ctypes.c_char * 260),
    ]

def list_processes():
    kernel32 = ctypes.WinDLL("kernel32.dll", use_last_error=True)  
    kernel32.CreateToolhelp32Snapshot.restype  = ctypes.c_void_p
    kernel32.Process32First.argtypes = [ctypes.c_void_p, ctypes.POINTER(PROCESSENTRY32)]
    kernel32.Process32Next.argtypes  = [ctypes.c_void_p, ctypes.POINTER(PROCESSENTRY32)]

    snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if not snapshot:
        raise ctypes.WinError(ctypes.get_last_error())

    entry = PROCESSENTRY32()
    entry.dwSize = ctypes.sizeof(PROCESSENTRY32)  

    processes = []
    if kernel32.Process32First(snapshot, ctypes.byref(entry)):
        while True:
            processes.append({
                "pid":     entry.th32ProcessID,
                "ppid":    entry.th32ParentProcessID,
                "name":    entry.szExeFile.decode("utf-8", errors="replace"),
                "threads": entry.cntThreads,
            })
            if not kernel32.Process32Next(snapshot, ctypes.byref(entry)):
                break

    kernel32.CloseHandle(snapshot)
    return processes

filtre = sys.argv[1:]

if len(filtre) > 0:
    found = False
    for proc in list_processes():
        if any(f.lower() in proc["name"].lower() for f in filtre):
            print(f"{proc['pid']:>6} {proc['ppid']:>6} {proc['threads']:>3} {proc['name']}")
            found = True
    if not found:
        print(f"No process found matching filter: {filtre}")