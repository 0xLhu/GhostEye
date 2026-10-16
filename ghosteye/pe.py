"""
Minimal, bounds-checked PE parser (pure Python, platform independent).

Works on a file read from disk (file layout) or on bytes read from a
process (mapped layout, where RVA == offset).
"""

import struct

IMAGE_SCN_MEM_EXECUTE = 0x20000000
MACHINES = {0x014C: "x86", 0x8664: "x64", 0xAA64: "arm64", 0x01C4: "arm"}

DIR_EXPORT = 0
DIR_BASERELOC = 5

RELOC_SIZES = {3: 4, 10: 8}  # IMAGE_REL_BASED_HIGHLOW, IMAGE_REL_BASED_DIR64


class PEError(ValueError):
    pass


class Section:
    __slots__ = ("name", "vaddr", "vsize", "raw_offset", "raw_size", "characteristics")

    def __init__(self, name, vaddr, vsize, raw_offset, raw_size, characteristics):
        self.name = name
        self.vaddr = vaddr
        self.vsize = vsize or raw_size
        self.raw_offset = raw_offset
        self.raw_size = raw_size
        self.characteristics = characteristics

    @property
    def executable(self):
        return bool(self.characteristics & IMAGE_SCN_MEM_EXECUTE)

    def contains(self, rva):
        return self.vaddr <= rva < self.vaddr + self.vsize


class PE:
    def __init__(self, data, mapped=False):
        self.data = data
        self.mapped = mapped
        try:
            self._parse_headers()
        except struct.error as e:
            raise PEError(f"Truncated PE: {e}") from None

    # ── helpers ──
    def _u16(self, off):
        return struct.unpack_from("<H", self.data, off)[0]

    def _u32(self, off):
        return struct.unpack_from("<I", self.data, off)[0]

    def _u64(self, off):
        return struct.unpack_from("<Q", self.data, off)[0]

    def _parse_headers(self):
        d = self.data
        if len(d) < 0x40 or d[:2] != b"MZ":
            raise PEError("No MZ signature")
        pe = self._u32(0x3C)
        if pe <= 0 or pe + 24 > len(d) or d[pe:pe + 4] != b"PE\x00\x00":
            raise PEError("Invalid PE signature")
        coff = pe + 4
        self.machine = self._u16(coff)
        nsec = self._u16(coff + 2)
        opt_size = self._u16(coff + 16)
        opt = coff + 20
        magic = self._u16(opt)
        if magic == 0x10B:
            self.is64 = False
            self.image_base = self._u32(opt + 28)
            dd = opt + 96
        elif magic == 0x20B:
            self.is64 = True
            self.image_base = self._u64(opt + 24)
            dd = opt + 112
        else:
            raise PEError(f"Unknown optional header magic {magic:#x}")
        self.entry_point = self._u32(opt + 16)
        self.size_of_image = self._u32(opt + 56)
        self.size_of_headers = self._u32(opt + 60)
        n_dirs = self._u32(dd - 4)
        self.dirs = []
        for i in range(min(n_dirs, 16)):
            self.dirs.append((self._u32(dd + i * 8), self._u32(dd + i * 8 + 4)))
        sec = opt + opt_size
        self.sections = []
        for i in range(min(nsec, 96)):
            s = sec + i * 40
            name = d[s:s + 8].rstrip(b"\x00").decode("ascii", "replace")
            self.sections.append(Section(name, self._u32(s + 12), self._u32(s + 8),
                                         self._u32(s + 20), self._u32(s + 16), self._u32(s + 36)))

    @property
    def arch(self):
        return MACHINES.get(self.machine, hex(self.machine))

    def directory(self, idx):
        return self.dirs[idx] if idx < len(self.dirs) else (0, 0)

    def rva_to_offset(self, rva):
        if self.mapped:
            return rva if rva < len(self.data) else None
        for s in self.sections:
            if s.vaddr <= rva < s.vaddr + max(s.vsize, s.raw_size):
                off = rva - s.vaddr
                return s.raw_offset + off if off < s.raw_size else None
        if rva < self.size_of_headers:
            return rva
        return None

    def section_of(self, rva):
        for s in self.sections:
            if s.contains(rva):
                return s
        return None

    def executable_sections(self):
        return [s for s in self.sections if s.executable]

    def read_rva(self, rva, size):
        off = self.rva_to_offset(rva)
        if off is None:
            return b""
        return self.data[off:off + size]

    def _cstring(self, rva, limit=512):
        off = self.rva_to_offset(rva)
        if off is None:
            return None
        end = self.data.find(b"\x00", off, off + limit)
        if end < 0:
            return None
        return self.data[off:end].decode("ascii", "replace")

    # ── exports ──
    def exports(self):
        """List of {name, ordinal, rva, forwarded} for named exports."""
        exp_rva, exp_size = self.directory(DIR_EXPORT)
        if not exp_rva:
            return []
        base = self.rva_to_offset(exp_rva)
        if base is None:
            return []
        try:
            ord_base = self._u32(base + 16)
            n_funcs = self._u32(base + 20)
            n_names = self._u32(base + 24)
            funcs = self.rva_to_offset(self._u32(base + 28))
            names = self.rva_to_offset(self._u32(base + 32))
            ords = self.rva_to_offset(self._u32(base + 36))
            if None in (funcs, names, ords):
                return []
            out = []
            for i in range(min(n_names, 0x10000)):
                idx = self._u16(ords + i * 2)
                if idx >= n_funcs:
                    continue
                rva = self._u32(funcs + idx * 4)
                name = self._cstring(self._u32(names + i * 4))
                if not name:
                    continue
                out.append({"name": name, "ordinal": ord_base + idx, "rva": rva,
                            "forwarded": exp_rva <= rva < exp_rva + exp_size})
            return out
        except struct.error:
            return []

    # ── relocations ──
    def relocated_rvas(self):
        """Set of every byte RVA patched by the loader's base relocations."""
        rva, size = self.directory(DIR_BASERELOC)
        out = set()
        if not rva or not size:
            return out
        off = self.rva_to_offset(rva)
        if off is None:
            return out
        end = min(off + size, len(self.data))
        try:
            while off + 8 <= end:
                page = self._u32(off)
                block = self._u32(off + 4)
                if block < 8:
                    break
                for j in range((block - 8) // 2):
                    e = self._u16(off + 8 + j * 2)
                    width = RELOC_SIZES.get(e >> 12)
                    if width:
                        start = page + (e & 0xFFF)
                        out.update(range(start, start + width))
                off += block
        except struct.error:
            pass
        return out


def looks_like_pe(data):
    """Cheap check used on raw memory: MZ + valid e_lfanew + PE signature."""
    if len(data) < 0x40 or data[:2] != b"MZ":
        return False
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    return 0 < pe <= len(data) - 4 and data[pe:pe + 4] == b"PE\x00\x00"
