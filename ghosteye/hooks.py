"""
Inline hook detection: compare each exported function of a loaded module
with the same bytes in the file on disk.

Platform independent: works with any backend exposing
    read(pid, address, size) -> bytes
    read_file(path) -> bytes
    region_at(pid, address) -> dict | None
"""

import ntpath
import struct

from . import analysis
from .pe import PE, PEError

WINDOW = 16  # bytes compared at the start of each function
DEFAULT_MODULES = ["ntdll.dll", "kernelbase.dll", "kernel32.dll", "amsi.dll"]


def _wow64_fallback(path):
    p = path.lower()
    return path[:p.index("\\system32\\")] + "\\SysWOW64\\" + path[p.index("\\system32\\") + 10:] \
        if "\\system32\\" in p else None


def load_disk_pe(backend, path, machine=None):
    """Read and parse the on-disk image; handle WOW64 path quirks."""
    for candidate in (path, _wow64_fallback(path)):
        if not candidate:
            continue
        try:
            pe = PE(backend.read_file(candidate))
        except (OSError, PEError):
            continue
        if machine is None or pe.machine == machine:
            return pe, candidate
    return None, None


def owner_of(backend, pid, modules, addr):
    for m in modules:
        if m["base"] <= addr < m["base"] + m["size"]:
            return {"owner": m["path"], "owner_type": "IMAGE", "vendor": analysis.vendor_of(m["path"])}
    r = backend.region_at(pid, addr)
    if not r:
        return {"owner": None, "owner_type": None, "vendor": None}
    t = analysis.MEM_TYPES.get(r["type"], "?")
    return {"owner": r.get("mapped") or f"{t} {r['alloc_base']:#x}", "owner_type": t,
            "vendor": analysis.vendor_of(r.get("mapped") or "")}


def scan_module(backend, pid, module, modules, security_loaded=None):
    """Return a list of raw hook dicts for one loaded module."""
    header = backend.read(pid, module["base"], 0x1000)
    try:
        mem_pe = PE(header, mapped=True)
    except PEError:
        return []
    disk_pe, disk_path = load_disk_pe(backend, module["path"], mem_pe.machine)
    if not disk_pe:
        return []
    is64 = disk_pe.is64
    relocs = disk_pe.relocated_rvas()
    base = module["base"]

    # One read per executable section instead of one per function
    sections = []
    for s in disk_pe.executable_sections():
        mem = backend.read(pid, base + s.vaddr, s.vsize)
        disk = disk_pe.data[s.raw_offset:s.raw_offset + min(s.raw_size, s.vsize)]
        sections.append((s, mem, disk))

    exports = sorted((e for e in disk_pe.exports() if not e["forwarded"]), key=lambda e: e["rva"])
    rvas = [e["rva"] for e in exports]

    def read_ptr(addr):
        raw = backend.read(pid, addr, 8 if is64 else 4)
        if len(raw) < (8 if is64 else 4):
            return None
        return struct.unpack("<Q" if is64 else "<I", raw)[0]

    hooks, seen = [], set()
    for i, e in enumerate(exports):
        rva = e["rva"]
        if rva in seen:
            continue  # aliases (several names, same code)
        seen.add(rva)
        sec = next((x for x in sections if x[0].contains(rva)), None)
        if not sec:
            continue  # data export
        s, mem, disk = sec
        nxt = next((r for r in rvas[i + 1:] if r > rva), rva + WINDOW)
        width = max(1, min(WINDOW, nxt - rva))
        off = rva - s.vaddr
        m, d = mem[off:off + width], disk[off:off + width]
        if not m or len(m) < len(d):
            continue
        diff = [j for j in range(len(d)) if m[j] != d[j] and (rva + j) not in relocs]
        if not diff:
            continue
        addr = base + rva
        code = backend.read(pid, addr, 32) or m
        kind, dest, desc = analysis.decode_hook(code, addr, is64, read_ptr)
        h = {"module": module["path"], "module_name": ntpath.basename(module["path"]), "function": e["name"],
             "address": addr, "disk": d.hex(), "memory": m.hex(), "kind": kind, "dest": dest, "desc": desc,
             "owner": None, "owner_type": None, "vendor": None}
        if dest is not None:
            h.update(owner_of(backend, pid, modules, dest))
            if not h["vendor"] and h["owner_type"] != "IMAGE" and security_loaded:
                # Trampoline allocated by the loaded security product (inferred, not proven)
                h["vendor"], h["vendor_inferred"] = security_loaded, True
        hooks.append(h)
    return hooks


def scan(backend, pid, modules, wanted=None):
    """Scan the wanted module names (default: ntdll, kernelbase, kernel32, amsi)."""
    wanted = [w.lower() for w in (wanted or DEFAULT_MODULES)]
    sec = sorted({analysis.vendor_of(m["path"]) for m in modules} - {None})
    security_loaded = sec[0] if len(sec) == 1 else (", ".join(sec) if sec else None)
    out = []
    for m in modules:
        if ntpath.basename(m["path"]).lower() in wanted:
            out.extend(scan_module(backend, pid, m, modules, security_loaded))
    return out
