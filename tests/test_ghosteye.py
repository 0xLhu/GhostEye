import os
import struct
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ghosteye import analysis as A  # noqa: E402
from ghosteye import hooks, triage  # noqa: E402
from ghosteye.demo import DemoBackend  # noqa: E402
from ghosteye.pe import PE, PEError, looks_like_pe  # noqa: E402
from ghosteye.synthpe import build_pe, map_image  # noqa: E402

FUNCS = [("NtA", bytes.fromhex("4c8bd1b818000000")), ("NtB", bytes.fromhex("4c8bd1b819000000")),
         ("Rel", bytes.fromhex("4883ec28")), ("EtwEventWrite", bytes.fromhex("4c8bdc4883ec58"))]


class FakeBackend:
    """One process, one module, memory = mapped image (optionally patched)."""

    def __init__(self, base=0x7FF000000000, patch=None):
        self.file, self.rvas = build_pe("t.dll", FUNCS, reloc_in=["Rel"])
        self.base = base
        self.img = bytearray(map_image(self.file, base))
        for name, data in (patch or {}).items():
            at = self.rvas[name]
            self.img[at:at + len(data)] = data
        self.mods = [{"base": base, "size": len(self.img), "path": "C:\\Windows\\System32\\t.dll", "name": "t.dll"}]

    def read(self, pid, addr, size):
        o = addr - self.base
        return bytes(self.img[o:o + size]) if 0 <= o < len(self.img) else b""

    def read_file(self, path):
        return self.file

    def region_at(self, pid, addr):
        return {"base": addr & ~0xFFF, "size": 0x1000, "type": A.MEM_PRIVATE, "alloc_base": addr & ~0xFFFF, "mapped": ""}

    def scan(self):
        return hooks.scan(self, 1, self.mods, ["t.dll"])


class TestPE(unittest.TestCase):
    def test_exports_and_sections(self):
        data, rvas = build_pe("t.dll", FUNCS)
        pe = PE(data)
        self.assertTrue(pe.is64)
        self.assertEqual(pe.arch, "x64")
        self.assertEqual({e["name"]: e["rva"] for e in pe.exports()}, rvas)
        self.assertEqual([s.name for s in pe.executable_sections()], [".text"])

    def test_relocations(self):
        data, rvas = build_pe("t.dll", FUNCS, reloc_in=["Rel"])
        self.assertEqual(PE(data).relocated_rvas(), set(range(rvas["Rel"] + 8, rvas["Rel"] + 16)))

    def test_mapped_layout(self):
        data, rvas = build_pe("t.dll", FUNCS)
        img = map_image(data, 0x10000000)
        pe = PE(bytes(img), mapped=True)
        self.assertEqual(pe.read_rva(rvas["NtA"], 4), bytes.fromhex("4c8bd1b8"))

    def test_garbage(self):
        for blob in (b"", b"MZ" + b"\x00" * 10, b"MZ" + b"\x00" * 58 + b"\xff\xff\x00\x00"):
            with self.assertRaises(PEError):
                PE(blob)
        self.assertFalse(looks_like_pe(b"MZ" + b"\x00" * 100))


class TestHookScan(unittest.TestCase):
    def test_clean_image_at_other_base_has_no_false_positive(self):
        # Relocated bytes differ from disk but must be ignored
        self.assertEqual(FakeBackend(base=0x7FF000000000).scan(), [])

    def test_jmp_hook_detected_and_resolved(self):
        b = FakeBackend()
        at = b.base + b.rvas["NtA"]
        dest = b.base + 0x50000000
        b.img[b.rvas["NtA"]:b.rvas["NtA"] + 5] = b"\xe9" + struct.pack("<i", dest - at - 5)
        hs = b.scan()
        self.assertEqual([h["function"] for h in hs], ["NtA"])
        self.assertEqual(hs[0]["dest"], dest)
        self.assertEqual(hs[0]["owner_type"], "PRIVATE")
        f = A.hook_finding({"pid": 1, "name": "x.exe"}, hs[0])
        self.assertEqual(f["severity"], "high")

    def test_etw_patch(self):
        hs = FakeBackend(patch={"EtwEventWrite": b"\xc3"}).scan()
        f = A.hook_finding({"pid": 1, "name": "x.exe"}, hs[0])
        self.assertEqual((hs[0]["kind"], f["title"]), ("early-return", "ETW patched: EtwEventWrite"))


class TestDecode(unittest.TestCase):
    def test_variants(self):
        a = 0x1000
        self.assertEqual(A.decode_hook(b"\xe9" + struct.pack("<i", 0x100), a)[:2], ("jmp", a + 5 + 0x100))
        self.assertEqual(A.decode_hook(b"\xeb\x10", a)[:2], ("jmp", a + 0x12))
        self.assertEqual(A.decode_hook(b"\x48\xb8" + struct.pack("<Q", 0xDEADBEEF) + b"\xff\xe0", a)[:2], ("jmp", 0xDEADBEEF))
        self.assertEqual(A.decode_hook(b"\x49\xbb" + struct.pack("<Q", 0x1234) + b"\x41\xff\xe3", a)[:2], ("jmp", 0x1234))
        self.assertEqual(A.decode_hook(b"\x68" + struct.pack("<I", 0x401000) + b"\xc3", a)[:2], ("jmp", 0x401000))
        self.assertEqual(A.decode_hook(b"\xff\x25\x00\x00\x00\x00", a, True, lambda p: 0x99 if p == a + 6 else None)[:2], ("jmp", 0x99))
        self.assertEqual(A.decode_hook(b"\xcc\x90", a)[0], "breakpoint")
        self.assertEqual(A.decode_hook(bytes.fromhex("b857000780c3"), a)[0], "early-return")
        self.assertEqual(A.decode_hook(b"\x90\x90", a)[0], "modified")


class TestRules(unittest.TestCase):
    def P(self, pid, ppid, name, path, created=None):
        return {"pid": pid, "ppid": ppid, "name": name, "path": path, "created": created}

    def test_masquerading(self):
        procs = [self.P(600, 500, "wininit.exe", "C:\\Windows\\System32\\wininit.exe"),
                 self.P(640, 600, "lsass.exe", "C:\\Windows\\System32\\lsass.exe"),
                 self.P(700, 3000, "lsass.exe", "C:\\Users\\Public\\lsass.exe"),
                 self.P(3000, 1, "explorer.exe", "C:\\Windows\\explorer.exe"),
                 self.P(800, 3000, "scvhost.exe", "C:\\ProgramData\\scvhost.exe")]
        titles = {(f["pid"], f["title"]) for f in A.process_findings(procs)}
        self.assertIn((700, "lsass.exe running from an unexpected path"), titles)
        self.assertIn((700, "lsass.exe has an unusual parent"), titles)
        self.assertIn((800, "Look-alike of svchost.exe"), titles)
        self.assertNotIn(640, {p for p, _ in titles if _ != "Multiple lsass.exe instances"})

    def test_pid_reuse_is_not_a_parent(self):
        procs = [self.P(640, 600, "lsass.exe", "C:\\Windows\\System32\\lsass.exe", created=100),
                 self.P(600, 1, "chrome.exe", "C:\\Program Files\\x\\chrome.exe", created=200)]
        self.assertFalse([f for f in A.process_findings(procs) if "parent" in f["title"]])

    def test_path_risk(self):
        self.assertEqual(A.path_risk("C:\\Windows\\System32\\x.dll")[0], "trusted")
        self.assertEqual(A.path_risk("\\\\?\\C:\\Windows\\Temp\\x.dll")[0], "temp")
        self.assertEqual(A.path_risk("C:\\Users\\a\\AppData\\Local\\Temp\\x.dll")[0], "temp")
        self.assertEqual(A.path_risk("C:\\Users\\a\\AppData\\Roaming\\x.dll")[0], "user")
        self.assertEqual(A.path_risk("D:\\tools\\x.dll")[0], "other")

    def test_network(self):
        c = lambda ip, port, st="ESTABLISHED": {"proto": "tcp", "remote_ip": ip, "remote_port": port, "local_port": 50000, "state": st}
        self.assertEqual(A.connection_flags(c("8.8.8.8", 443), "chrome.exe"), [])
        self.assertEqual(A.connection_flags(c("10.0.0.5", 4444), "chrome.exe"), [])
        self.assertEqual(A.connection_flags(c("8.8.8.8", 4444, "LISTENING"), "x.exe"), [])
        self.assertEqual(A.connection_flags(c("8.8.8.8", 4444), "x.exe")[0][0], "low")
        self.assertEqual(A.connection_flags(c("8.8.8.8", 443), "rundll32.exe")[0][0], "high")
        self.assertIn("SSH", A.connection_flags(c("8.8.8.8", 22), "x.exe")[0][1])

    def test_aggregate(self):
        fs = [A.finding("info", "hook", "h", proc={"pid": i, "name": f"p{i}"}, key="k") for i in range(5)]
        out = A.aggregate(fs)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["process"], "5 processes")

    def test_strings(self):
        data = b"\x00http://evil.example/x\x00\x00\x00\x00" + "powershell -enc AAAA".encode("utf-16le")
        got = list(A.extract_strings(data, 0x1000))
        self.assertEqual([(g[1], A.tag_string(g[2])) for g in got], [("ascii", ["url"]), ("utf16", ["command"])])


class TestDemoTriage(unittest.TestCase):
    def test_planted_indicators_found(self):
        r = triage.run(DemoBackend())
        titles = {f["title"] for f in r["findings"]}
        for t in ("ETW patched: EtwEventWrite", "AMSI patched: AmsiScanBuffer", "PE image in private memory",
                  "Look-alike of svchost.exe", "Hidden process", "Inline hook to unbacked memory: NtQuerySystemInformation"):
            self.assertIn(t, titles)
        self.assertEqual(r["skipped"][0]["name"], "lsass.exe")
        # EDR hooks are recognised and aggregated, not reported as threats
        edr = [f for f in r["findings"] if f["title"].startswith("Security product hook")]
        self.assertTrue(edr and all(f["severity"] == "info" for f in edr))


if __name__ == "__main__":
    unittest.main()
