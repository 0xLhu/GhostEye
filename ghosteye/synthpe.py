"""
Tiny PE32+ builder used by the demo mode and the tests. It produces a valid
DLL layout (headers, .text, .rdata export directory, .reloc) and its
loader-mapped image, so the real hook scanner can run on it.
"""

import struct

FA, SA = 0x200, 0x1000
FN_SLOT = 32


def _align(v, a):
    return (v + a - 1) // a * a


def build_pe(dll_name, funcs, image_base=0x180000000, reloc_in=()):
    """
    funcs: list of (name, code_bytes). reloc_in: names of functions whose
    bytes 8..15 hold an absolute address (DIR64 relocation).
    Returns (file_bytes, {name: rva}).
    """
    text = bytearray()
    rvas = {}
    text_rva = 0x1000
    for name, code in funcs:
        rvas[name] = text_rva + len(text)
        text += code[:FN_SLOT].ljust(FN_SLOT, b"\xcc")
    rdata_rva = text_rva + _align(len(text), SA)

    # export directory
    names = sorted(rvas)
    n = len(names)
    exp = bytearray(40)
    p_funcs = 40
    p_names = p_funcs + 4 * n
    p_ords = p_names + 4 * n
    p_str = p_ords + 2 * n
    strings = bytearray()
    name_offsets = []
    dll_off = p_str
    strings += dll_name.encode() + b"\x00"
    for nm in names:
        name_offsets.append(p_str + len(strings))
        strings += nm.encode() + b"\x00"
    struct.pack_into("<IIHHIIIIIII", exp, 0, 0, 0, 0, 0, rdata_rva + dll_off, 1, n, n,
                     rdata_rva + p_funcs, rdata_rva + p_names, rdata_rva + p_ords)
    body = bytearray()
    for nm in names:
        body += struct.pack("<I", rvas[nm])
    for off in name_offsets:
        body += struct.pack("<I", rdata_rva + off)
    for i in range(n):
        body += struct.pack("<H", i)
    rdata = exp + body + strings
    reloc_rva = rdata_rva + _align(len(rdata), SA)

    # relocations (one block for the first text page range)
    entries = [(10 << 12) | ((rvas[nm] + 8) - text_rva) for nm in reloc_in if (rvas[nm] + 8 - text_rva) < 0x1000]
    if len(entries) % 2:
        entries.append(0)
    reloc = struct.pack("<II", text_rva, 8 + 2 * len(entries)) + b"".join(struct.pack("<H", e) for e in entries)
    for nm in reloc_in:  # store the image-base-relative absolute pointer
        off = rvas[nm] - text_rva + 8
        struct.pack_into("<Q", text, off, image_base + rvas[nm])

    size_of_image = reloc_rva + _align(len(reloc), SA)
    sections = [(b".text", text_rva, text, 0x60000020), (b".rdata", rdata_rva, rdata, 0x40000040),
                (b".reloc", reloc_rva, reloc, 0x42000040)]

    hdr = bytearray(0x400)
    hdr[:2] = b"MZ"
    struct.pack_into("<I", hdr, 0x3C, 0x80)
    hdr[0x80:0x84] = b"PE\x00\x00"
    struct.pack_into("<HHIIIHH", hdr, 0x84, 0x8664, len(sections), 0, 0, 0, 0xF0, 0x2022)
    opt = 0x98
    struct.pack_into("<H", hdr, opt, 0x20B)
    struct.pack_into("<I", hdr, opt + 16, text_rva)
    struct.pack_into("<Q", hdr, opt + 24, image_base)
    struct.pack_into("<II", hdr, opt + 32, SA, FA)
    struct.pack_into("<II", hdr, opt + 56, size_of_image, 0x400)
    struct.pack_into("<I", hdr, opt + 108, 16)
    struct.pack_into("<II", hdr, opt + 112, rdata_rva, len(rdata))        # export
    struct.pack_into("<II", hdr, opt + 112 + 5 * 8, reloc_rva, len(reloc))  # basereloc
    sec_off = opt + 0xF0
    raw = 0x400
    blobs = []
    for i, (nm, rva, data, ch) in enumerate(sections):
        rs = _align(len(data), FA)
        s = sec_off + i * 40
        hdr[s:s + 8] = nm.ljust(8, b"\x00")
        struct.pack_into("<IIII", hdr, s + 8, len(data), rva, rs, raw)
        struct.pack_into("<I", hdr, s + 36, ch)
        blobs.append(bytes(data).ljust(rs, b"\x00"))
        raw += rs
    return bytes(hdr) + b"".join(blobs), rvas


def map_image(file_bytes, base):
    """Lay the file out as the loader would at `base`, applying relocations."""
    from .pe import PE
    pe = PE(file_bytes)
    img = bytearray(pe.size_of_image)
    img[:pe.size_of_headers] = file_bytes[:pe.size_of_headers]
    for s in pe.sections:
        img[s.vaddr:s.vaddr + s.raw_size] = file_bytes[s.raw_offset:s.raw_offset + s.raw_size][:pe.size_of_image - s.vaddr]
    delta = base - pe.image_base
    rva, size = pe.directory(5)
    off = rva
    while off + 8 <= rva + size:
        page, block = struct.unpack_from("<II", img, off)
        if block < 8:
            break
        for j in range((block - 8) // 2):
            e = struct.unpack_from("<H", img, off + 8 + j * 2)[0]
            if e >> 12 == 10:
                at = page + (e & 0xFFF)
                struct.pack_into("<Q", img, at, (struct.unpack_from("<Q", img, at)[0] + delta) & (2 ** 64 - 1))
        off += block
    struct.pack_into("<Q", img, 0x98 + 24, base)
    return img
