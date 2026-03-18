import ctypes
import ctypes.wintypes as wt

psapi = ctypes.WinDLL("psapi.dll")

def list_modules(handle):
    # step 1: get the required buffer size
    needed = wt.DWORD(0)
    psapi.EnumProcessModules(handle, None, 0, ctypes.byref(needed))

    # step 2: allocate and fill the array of HMODULEs
    count  = needed.value // ctypes.sizeof(ctypes.c_void_p)
    harray = (ctypes.c_void_p * count)()
    psapi.EnumProcessModules(handle, harray, needed, ctypes.byref(needed))

    # step 3: resolve each HMODULE -> full path
    modules = []
    for hmod in harray:
        buf = ctypes.create_unicode_buffer(260)
        psapi.GetModuleFileNameExW(handle, ctypes.c_void_p(hmod), buf, 260)
        if buf.value:
            modules.append({"base": hmod, "path": buf.value})

    return modules

TRUSTED_PATHS = [
    "c:\\windows\\system32",
    "c:\\windows\\syswow64",
    "c:\\windows\\",
    "c:\\program files\\",
    "c:\\program files (x86)\\",
]

def is_suspicious_dll(path):
    path_lower = path.lower()
    return not any(path_lower.startswith(t) for t in TRUSTED_PATHS)
