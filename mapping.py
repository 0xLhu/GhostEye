from list_proc import list_processes
import ctypes
import sys


MEM_COMMIT  = 0x1000   # région active en mémoire
MEM_PRIVATE = 0x20000  # mémoire privée au process
MEM_IMAGE   = 0x1000000 # une DLL/EXE chargé

PAGE_EXECUTE_READWRITE = 0x40  # la fameuse RWX

PROTECT_FLAGS = {
    0x01: "PAGE_NOACCESS",
    0x02: "PAGE_READONLY",
    0x04: "PAGE_READWRITE",
    0x08: "PAGE_WRITECOPY",
    0x10: "PAGE_EXECUTE",
    0x20: "PAGE_EXECUTE_READ",
    0x40: "PAGE_EXECUTE_READWRITE",
    0x80: "PAGE_EXECUTE_WRITECOPY",
}

class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", ctypes.c_ulong),
        ("PartitionTag", ctypes.c_ushort),
        ("RegionSize", ctypes.c_size_t),
        ("State", ctypes.c_ulong),
        ("Protect", ctypes.c_ulong),
        ("Type", ctypes.c_ulong),
    ]

kernel32 = ctypes.windll.kernel32

def open_process(pid):
    PROCESS_ALL_ACCESS = 0x1F0FFF
    handle = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    if not handle:
        raise ctypes.WinError(ctypes.get_last_error())
    return handle

def query_memory(handle):
    mbi = MEMORY_BASIC_INFORMATION()
    addr = 0
    regions = []
    while kernel32.VirtualQueryEx(handle, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi)):
        if mbi.State == MEM_COMMIT and mbi.Type in (MEM_PRIVATE, MEM_IMAGE):
            regions.append({
                "base": mbi.BaseAddress,
                "size": mbi.RegionSize,
                "protect": mbi.Protect,
            })
        addr += mbi.RegionSize
    print(f"Found {len(regions)} committed regions in process {handle}")
    for r in regions:   
        print(f"  Base: {r['base']:#x}, Size: {r['size']:#x}, Protect: {r['protect']:#x}")
        if r['protect'] in PROTECT_FLAGS:
            print(f"    -> {PROTECT_FLAGS[r['protect']]}")
    return regions
        
        
        
if __name__ == "__main__":
    filtre = sys.argv[1:]
    for proc in list_processes():
        if any(f.lower() in proc["name"].lower() for f in filtre):
            print(f"Checking process {proc['pid']} ({proc['name']})")
            try:
                handle = open_process(proc["pid"])
                query_memory(handle)
                kernel32.CloseHandle(handle)
            except Exception as e:
                print(f"Error accessing process {proc['pid']}: {e}")
        

    
    


