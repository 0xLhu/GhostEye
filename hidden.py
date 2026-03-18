import ctypes

psapi = ctypes.WinDLL("psapi.dll")

def enum_processes():
    # step 1: get the required buffer size
    needed = ctypes.c_ulong(0)
    size   = 1024 * ctypes.sizeof(ctypes.c_ulong)
    while True:
        buf = (ctypes.c_ulong * size)()
        psapi.EnumProcesses(buf, size * ctypes.sizeof(ctypes.c_ulong), ctypes.byref(needed))
        if needed.value < size * ctypes.sizeof(ctypes.c_ulong):
         break       # ← buffer suffisant, on sort
        size *= 2       # ← buffer trop petit, on double

    # ici on est sorti de la boucle avec le bon buf
    count = needed.value // ctypes.sizeof(ctypes.c_ulong)
    return list(buf[:count])


def find_hidden_processes(snapshot_pids, enum_pids):
    snapshot_set = set(snapshot_pids)
    enum_set     = set(enum_pids)
    return sorted(enum_set - snapshot_set)
