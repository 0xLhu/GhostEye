import sys
import os
import struct
import ctypes
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".venv"))

from reader import read_memory
from mapping import open_process, kernel32, MEMORY_BASIC_INFORMATION
from dll import list_modules

def get_module_size(handle, base):
    """Query VirtualQueryEx at base address to get the module's RegionSize."""
    mbi = MEMORY_BASIC_INFORMATION()
    kernel32.VirtualQueryEx(handle, ctypes.c_void_p(base), ctypes.byref(mbi), ctypes.sizeof(mbi))
    return mbi.RegionSize

EDR_KEYWORDS = [
    "trend", "tmk", "fortinet", "forticlient",
    "crowdstrike", "csfalcon", "sentinel", "sentinelone",
    "cylance", "carbon", "cb.", "cbk", "sophos",
    "malwarebytes", "eset", "kaspersky", "bitdefender",
    "mcafee", "symantec", "norton", "avast", "avg",
]

def resolve_hook_destination(dest_addr, modules):
    """Find which DLL owns dest_addr.
    Falls back to closest module + EDR keyword scan for private hooks.
    """
    # step 1: direct match in loaded modules
    for mod in modules:
        if mod["base"] <= dest_addr < mod["base"] + mod["size"]:
            return mod["path"]

    # step 2: private region (hook) — find closest module below dest_addr
    candidates = [m for m in modules if m["base"] <= dest_addr]
    closest = max(candidates, key=lambda m: m["base"]) if candidates else None

    # step 3: scan all loaded modules for EDR vendor keywords
    edr_modules = [
        m["path"] for m in modules
        if any(k in m["path"].lower() for k in EDR_KEYWORDS)
    ]

    if edr_modules:
        near = f" near {closest['path']}" if closest else ""
        return f"PRIVATE hook{near} | EDR: {', '.join(edr_modules)}"

    if closest:
        return f"PRIVATE hook (near {closest['path']})"

    return "unknown"

def get_ntdll_info(handle):
    for mod in list_modules(handle):
        if "ntdll.dll" in mod["path"].lower():
            return mod["base"], mod["path"]
    return None, None

def read_ntdll_from_disk(path):
    with open(path, "rb") as f:
        return f.read()

def read_ntdll_from_memory(handle, base, size):
    return read_memory(handle, base, size)

# --- PE export table parser ---

def _rva_to_offset(rva, sections):
    """Convert a RVA to a file offset using the section table."""
    for sec in sections:
        if sec["vaddr"] <= rva < sec["vaddr"] + sec["vsize"]:
            return rva - sec["vaddr"] + sec["raw_offset"]
    return rva  # fallback: RVA == file offset (header area)

def parse_exports(data):
    """Parse the PE export table from raw bytes.
    Returns a dict {function_name: rva}.
    Works on both disk bytes (needs RVA→offset) and in-memory bytes.
    """
    if data[:2] != b"MZ":
        raise ValueError("Not a PE file")

    # DOS header → PE offset
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    if data[pe_offset:pe_offset + 4] != b"PE\x00\x00":
        raise ValueError("Invalid PE signature")

    # COFF header (20 bytes after the signature)
    coff_offset      = pe_offset + 4
    num_sections     = struct.unpack_from("<H", data, coff_offset + 2)[0]
    size_opt_header  = struct.unpack_from("<H", data, coff_offset + 16)[0]

    # Optional header
    opt_offset = coff_offset + 20
    magic      = struct.unpack_from("<H", data, opt_offset)[0]

    # DataDirectory[0] starts at different offsets for PE32 vs PE32+
    if magic == 0x010B:    # PE32  (32-bit)
        dd_offset = opt_offset + 96
    else:                  # PE32+ (64-bit, magic = 0x020B)
        dd_offset = opt_offset + 112

    export_rva = struct.unpack_from("<I", data, dd_offset)[0]
    if export_rva == 0:
        return {}, []

    # Section table (right after the optional header)
    sections_offset = opt_offset + size_opt_header
    sections = []
    for i in range(num_sections):
        s = sections_offset + i * 40
        sections.append({
            "vaddr":      struct.unpack_from("<I", data, s + 12)[0],
            "vsize":      struct.unpack_from("<I", data, s + 8)[0],
            "raw_offset": struct.unpack_from("<I", data, s + 20)[0],
        })

    # Export Directory (IMAGE_EXPORT_DIRECTORY)
    exp = _rva_to_offset(export_rva, sections)
    num_names = struct.unpack_from("<I", data, exp + 24)[0]
    rva_funcs = struct.unpack_from("<I", data, exp + 28)[0]
    rva_names = struct.unpack_from("<I", data, exp + 32)[0]
    rva_ords  = struct.unpack_from("<I", data, exp + 36)[0]

    off_funcs = _rva_to_offset(rva_funcs, sections)
    off_names = _rva_to_offset(rva_names, sections)
    off_ords  = _rva_to_offset(rva_ords,  sections)

    exports = {}
    for i in range(num_names):
        name_rva = struct.unpack_from("<I", data, off_names + i * 4)[0]
        ordinal  = struct.unpack_from("<H", data, off_ords  + i * 2)[0]
        func_rva = struct.unpack_from("<I", data, off_funcs + ordinal * 4)[0]

        name_off = _rva_to_offset(name_rva, sections)
        name_end = data.index(b"\x00", name_off)
        name     = data[name_off:name_end].decode("ascii")

        exports[name] = func_rva

    return exports, sections

def detect_hooks(handle, pid):
    base, path = get_ntdll_info(handle)
    if not base:
        return []

    # build module list with sizes for destination resolution
    modules = [
        {"base": m["base"], "size": get_module_size(handle, m["base"]), "path": m["path"]}
        for m in list_modules(handle)
    ]

    disk_data         = read_ntdll_from_disk(path)
    exports, sections = parse_exports(disk_data)

    hooks = []
    for name, rva in exports.items():
        disk_offset = _rva_to_offset(rva, sections)
        disk_bytes  = disk_data[disk_offset:disk_offset + 5]
        mem_bytes   = read_memory(handle, base + rva, 5)

        if disk_bytes != mem_bytes and mem_bytes:
            hook = {
                "function":   name,
                "address":    base + rva,
                "disk":       disk_bytes.hex(),
                "memory":     mem_bytes.hex(),
                "hooked":     mem_bytes[0] == 0xE9,
                "vendor":     None,
            }
            # decode JMP destination and resolve owning DLL
            if mem_bytes[0] == 0xE9 and len(mem_bytes) == 5:
                rel          = struct.unpack_from("<i", mem_bytes, 1)[0]
                dest         = (base + rva) + 5 + rel
                hook["dest"] = dest
                hook["vendor"] = resolve_hook_destination(dest, modules)

            hooks.append(hook)
    return hooks