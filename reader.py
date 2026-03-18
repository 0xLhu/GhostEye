import ctypes
import re
import sys

from list_proc import list_processes
from mapping import open_process, query_memory, kernel32

def read_memory(handle, address, size):
    kernel32 = ctypes.WinDLL("kernel32.dll")
    kernel32.ReadProcessMemory.restype = ctypes.c_bool

    buf        = ctypes.create_string_buffer(size)
    bytes_read = ctypes.c_size_t(0)

    success = kernel32.ReadProcessMemory(
        ctypes.c_void_p(handle),
        ctypes.c_void_p(address),
        buf,
        size,
        ctypes.byref(bytes_read)
    )

    if success:
        return buf.raw[:bytes_read.value]
    return b""

if __name__ == "__main__":
    filtre = sys.argv[1:]
    for proc in list_processes():
        if any(f.lower() in proc["name"].lower() for f in filtre):
            print(f"Checking process {proc['pid']} ({proc['name']})")
            try:
                handle = open_process(proc["pid"])
                regions = query_memory(handle)
                for r in regions:
                    if r['protect'] in (0x10, 0x02):  # PAGE_EXECUTE_READWRITE or PAGE_EXECUTE_READ
                        print(f"Reading memory from region at {r['base']:#x} with size {r['size']:#x}")
                        offset = 0
                        CHUNK_SIZE = 4096
                        while offset < r['size']:
                            data = read_memory(handle, r['base'] + offset, min(CHUNK_SIZE, r['size'] - offset))
                            ascii_data = ''.join(chr(b) for b in data if 32 <= b < 127)
                            strings = re.findall(b'[\x20-\x7e]{4,}', data)
                            print(f"Data (ASCII): {strings}")
                            if data[:4] == b"MZ\x90\x00" or data[:2] == b"MZ":  # Check for PE header
                                print(f"Found potential PE header at {r['base'] + offset:#x}")
               
                            offset += CHUNK_SIZE
                            
                kernel32.CloseHandle(handle)
            except Exception as e:
                print(f"Error accessing process {proc['pid']}: {e}")
                