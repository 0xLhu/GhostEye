"""
Detection rules: pure Python, no Windows API. Every function takes plain
dicts produced by a backend (live or demo) and returns findings.
"""

import ipaddress
import ntpath
import re
import struct

SEVERITIES = ["high", "medium", "low", "info"]

MITRE = {
    "T1014": "Rootkit",
    "T1036.005": "Masquerading: Match Legitimate Name or Location",
    "T1055": "Process Injection",
    "T1055.001": "Process Injection: DLL Injection",
    "T1059.001": "Command and Scripting Interpreter: PowerShell",
    "T1071": "Application Layer Protocol",
    "T1218": "System Binary Proxy Execution",
    "T1562.001": "Impair Defenses: Disable or Modify Tools",
    "T1562.006": "Impair Defenses: Indicator Blocking",
    "T1571": "Non-Standard Port",
    "T1574": "Hijack Execution Flow",
    "T1574.001": "Hijack Execution Flow: DLL Search Order Hijacking",
    "T1620": "Reflective Code Loading",
    "T1021": "Remote Services",
}

# ── memory constants ──────────────────────────────────────────────────────

MEM_COMMIT = 0x1000
MEM_IMAGE, MEM_MAPPED, MEM_PRIVATE = 0x1000000, 0x40000, 0x20000
MEM_TYPES = {MEM_IMAGE: "IMAGE", MEM_MAPPED: "MAPPED", MEM_PRIVATE: "PRIVATE"}

PROTECT = {
    0x01: "NOACCESS", 0x02: "R", 0x04: "RW", 0x08: "WC",
    0x10: "X", 0x20: "RX", 0x40: "RWX", 0x80: "WCX",
}
PAGE_GUARD, PAGE_NOCACHE, PAGE_WRITECOMBINE = 0x100, 0x200, 0x400


def protect_str(p):
    s = PROTECT.get(p & 0xFF, hex(p & 0xFF) if p else "-")
    if p & PAGE_GUARD:
        s += "+G"
    return s


def is_exec(p):
    return bool(p & 0xF0)


def is_readable(p):
    return bool(p & 0xEE) and not (p & PAGE_GUARD)


# ── findings ──────────────────────────────────────────────────────────────

def finding(severity, category, title, detail="", proc=None, mitre=(), evidence=None, key=None):
    return {
        "severity": severity,
        "category": category,
        "title": title,
        "detail": detail,
        "pid": proc["pid"] if proc else None,
        "process": proc["name"] if proc else None,
        "mitre": [{"id": t, "name": MITRE.get(t, "")} for t in mitre],
        "evidence": evidence or {},
        "key": key,  # used to aggregate identical findings across processes
    }


def sort_findings(fs):
    return sorted(fs, key=lambda f: (SEVERITIES.index(f["severity"]), f["category"], f["process"] or "", f["pid"] or 0))


def aggregate(fs, min_count=3):
    """Collapse identical low/info findings seen in many processes into one."""
    groups, out = {}, []
    for f in fs:
        if f.get("key") and f["severity"] in ("info", "low"):
            groups.setdefault(f["key"], []).append(f)
        else:
            out.append(f)
    for items in groups.values():
        if len(items) < min_count:
            out.extend(items)
            continue
        f = dict(items[0])
        procs = sorted({(i["process"], i["pid"]) for i in items}, key=lambda x: (x[0] or "", x[1] or 0))
        f["pid"], f["process"] = None, f"{len(procs)} processes"
        f["evidence"] = dict(f["evidence"], processes=[f"{n} ({p})" for n, p in procs])
        out.append(f)
    return sort_findings(out)


# ── paths ─────────────────────────────────────────────────────────────────

def norm_path(p):
    p = (p or "").replace("/", "\\")
    for pre in ("\\\\?\\", "\\??\\"):
        if p.startswith(pre):
            p = p[len(pre):]
    return p.lower()


def system_root(env_root=None):
    return norm_path(env_root or "C:\\Windows").rstrip("\\")


USER_WRITABLE_HIGH = [r"\appdata\local\temp\\", r"\windows\temp\\", r"\downloads\\", r"\users\public\\",
                      r"\$recycle.bin\\", r"\perflogs\\", r"\windows\tasks\\", r"\windows\tracing\\"]
USER_WRITABLE_LOW = [r"\appdata\\", r"\programdata\\"]


def path_risk(path, root="c:\\windows"):
    """Classify where a binary lives: ('trusted'|'user'|'temp'|'other', reason)."""
    p = norm_path(path)
    if not p:
        return "unknown", "path unavailable"
    for frag in USER_WRITABLE_HIGH:
        if frag.replace("\\\\", "\\") in p:
            return "temp", "temporary or world-writable folder"
    drive = root[:2]
    trusted = [root + "\\system32\\", root + "\\syswow64\\", root + "\\winsxs\\", root + "\\microsoft.net\\",
               root + "\\assembly\\", root + "\\systemapps\\", root + "\\immersivecontrolpanel\\",
               drive + "\\program files\\", drive + "\\program files (x86)\\", root + "\\"]
    if any(p.startswith(t) for t in trusted):
        return "trusted", ""
    for frag in USER_WRITABLE_LOW:
        if frag.replace("\\\\", "\\") in p:
            return "user", "user-writable folder"
    return "other", "non-standard location"


# ── security products (used to explain hooks) ─────────────────────────────

SECURITY_VENDORS = {
    "CrowdStrike Falcon": ["crowdstrike", "csfalcon", "umppc"],
    "SentinelOne": ["sentinelone", "inprocessclient"],
    "Microsoft Defender": ["windows defender", "mpoav", "mpclient", "mpsvc", "msmpeng", "payloadrestrictions"],
    "Elastic Defend": ["elastic\\endpoint", "elastic-endpoint"],
    "Trend Micro": ["trend micro", "tmumh", "tmamsiprovider", "tmmon"],
    "Sophos": ["sophos", "hmpalert"],
    "Carbon Black": ["carbonblack", "carbon black", "ctiuser"],
    "Bitdefender": ["bitdefender", "atcuf", "bdhkm"],
    "Kaspersky": ["kaspersky", "klhk"],
    "ESET": ["\\eset\\", "ebehmoni"],
    "Symantec / Broadcom": ["symantec", "sysfer"],
    "Trellix / McAfee": ["mcafee", "trellix", "mfehcs"],
    "Cortex XDR": ["palo alto networks", "cyvera", "cyvrtrap"],
    "Cylance": ["cylance"],
    "FortiEDR / FortiClient": ["fortinet", "forticlient", "fortiedr"],
    "Malwarebytes": ["malwarebytes", "mbae"],
    "Avast / AVG": ["aswhook", "avast software", "\\avg\\"],
    "Check Point Harmony": ["checkpoint", "check point"],
    "WithSecure / F-Secure": ["f-secure", "withsecure"],
    "HarfangLab": ["harfanglab"],
}


def vendor_of(path):
    p = norm_path(path)
    if not p:
        return None
    for vendor, keys in SECURITY_VENDORS.items():
        if any(k in p for k in keys):
            return vendor
    return None


# ── processes ─────────────────────────────────────────────────────────────

# name -> (expected parents, single instance?, expected dir under %SystemRoot%)
SYSTEM_PROCESSES = {
    "smss.exe":      ({"system"}, False, "system32"),
    "csrss.exe":     ({"smss.exe"}, False, "system32"),
    "wininit.exe":   ({"smss.exe"}, True, "system32"),
    "winlogon.exe":  ({"smss.exe"}, False, "system32"),
    "services.exe":  ({"wininit.exe"}, True, "system32"),
    "lsass.exe":     ({"wininit.exe"}, True, "system32"),
    "lsaiso.exe":    ({"wininit.exe"}, True, "system32"),
    "svchost.exe":   ({"services.exe", "msmpeng.exe"}, False, "system32|syswow64"),
    "taskhostw.exe": ({"svchost.exe"}, False, "system32"),
    "runtimebroker.exe": ({"svchost.exe"}, False, "system32"),
    "spoolsv.exe":   ({"services.exe"}, True, "system32"),
    "explorer.exe":  ({"userinit.exe", "winlogon.exe"}, False, ""),
    "conhost.exe":   (None, False, "system32"),
    "dllhost.exe":   (None, False, "system32|syswow64"),
    "rundll32.exe":  (None, False, "system32|syswow64"),
    "cmd.exe":       (None, False, "system32|syswow64"),
    "powershell.exe": (None, False, "system32\\windowspowershell\\v1.0|syswow64\\windowspowershell\\v1.0"),
}

LOLBINS = {"rundll32.exe", "regsvr32.exe", "mshta.exe", "certutil.exe", "bitsadmin.exe", "msbuild.exe",
           "installutil.exe", "wmic.exe", "cscript.exe", "wscript.exe", "regasm.exe", "regsvcs.exe",
           "msiexec.exe", "cmstp.exe", "odbcconf.exe", "forfiles.exe", "pcalua.exe"}
SCRIPT_HOSTS = {"powershell.exe", "pwsh.exe", "cmd.exe"}
NO_NETWORK = {"notepad.exe", "calc.exe", "mspaint.exe", "lsass.exe", "wininit.exe", "winlogon.exe",
              "csrss.exe", "smss.exe", "conhost.exe"} | LOLBINS
JIT_HOSTS = {"chrome.exe", "msedge.exe", "firefox.exe", "brave.exe", "opera.exe", "code.exe", "node.exe",
             "java.exe", "javaw.exe", "teams.exe", "ms-teams.exe", "slack.exe", "discord.exe",
             "msedgewebview2.exe", "powershell.exe", "pwsh.exe", "dotnet.exe", "electron.exe",
             "spotify.exe", "searchhost.exe", "widgets.exe", "olk.exe", "outlook.exe", "winword.exe",
             "excel.exe", "powerpnt.exe", "devenv.exe", "servicehub.host.netfx.x86.exe", "msmpeng.exe",
             "mpdefendercoreservice.exe", "phoneexperiencehost.exe", "searchapp.exe", "startmenuexperiencehost.exe"}


def _dl1(a, b):
    """True if a and b are one edit (insert/delete/substitute/transpose) apart."""
    if a == b or abs(len(a) - len(b)) > 1:
        return False
    if len(a) == len(b):
        diff = [i for i in range(len(a)) if a[i] != b[i]]
        return len(diff) == 1 or (len(diff) == 2 and diff[1] == diff[0] + 1
                                  and a[diff[0]] == b[diff[1]] and a[diff[1]] == b[diff[0]])
    if len(a) > len(b):
        a, b = b, a
    i = 0
    while i < len(a) and a[i] == b[i]:
        i += 1
    return a[i:] == b[i + 1:]


HOMOGLYPHS = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s", "$": "s", "@": "a", "|": "l"})


def process_findings(procs, root="c:\\windows"):
    """Masquerading, parent anomalies, duplicates, suspicious locations."""
    out = []
    by_pid = {p["pid"]: p for p in procs}
    counts = {}
    for p in procs:
        counts[p["name"].lower()] = counts.get(p["name"].lower(), 0) + 1

    for p in procs:
        name = p["name"].lower()
        path = p.get("path") or ""
        parent = by_pid.get(p.get("ppid"))
        # PID reuse: a "parent" created after its child is not the real parent
        if parent and p.get("created") and parent.get("created") and parent["created"] > p["created"]:
            parent = None
        pname = (parent["name"].lower() if parent else None)
        if parent and parent["pid"] == 4:
            pname = "system"

        # Look-alike names (svch0st.exe, lsas.exe, scvhost.exe…)
        if name not in SYSTEM_PROCESSES:
            folded = name.translate(HOMOGLYPHS)
            for real in ("svchost.exe", "lsass.exe", "csrss.exe", "services.exe", "winlogon.exe",
                         "explorer.exe", "smss.exe", "wininit.exe", "spoolsv.exe", "taskhostw.exe"):
                if folded == real or _dl1(name, real):
                    sev = "medium" if path_risk(path, root)[0] == "trusted" else "high"
                    out.append(finding(sev, "masquerading", f"Look-alike of {real}",
                                       f"'{p['name']}' imitates the Windows process '{real}'.", p, ["T1036.005"],
                                       {"path": path}))
                    break

        spec = SYSTEM_PROCESSES.get(name)
        if spec:
            parents, single, folder = spec
            if path and folder is not None:
                allowed = [root + "\\" + f + "\\" + name for f in folder.split("|")] if folder else [root + "\\" + name]
                if norm_path(path) not in allowed:
                    out.append(finding("high", "masquerading", f"{p['name']} running from an unexpected path",
                                       f"Expected {allowed[0]}, got {path}.", p, ["T1036.005"], {"path": path}))
            if parents and pname and pname not in parents:
                sev = "high" if name in ("lsass.exe", "services.exe", "wininit.exe", "smss.exe", "csrss.exe") else "medium"
                out.append(finding(sev, "masquerading", f"{p['name']} has an unusual parent",
                                   f"Parent is {parent['name']} (PID {parent['pid']}); expected {', '.join(sorted(parents))}.",
                                   p, ["T1036.005"], {"parent": f"{parent['name']} ({parent['pid']})"}))
            if single and counts[name] > 1:
                out.append(finding("high", "masquerading", f"Multiple {p['name']} instances",
                                   f"{counts[name]} instances of a process that should be unique.", p, ["T1036.005"],
                                   key=f"multi:{name}"))

        risk, why = path_risk(path, root)
        if risk == "temp":
            out.append(finding("medium", "location", "Process running from a temporary / public folder",
                               f"{path}: {why}.", p, ["T1036.005"], {"path": path}))

        if name in SCRIPT_HOSTS | LOLBINS and pname in ("winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
                                                         "mshta.exe", "wscript.exe", "cscript.exe", "acrord32.exe"):
            out.append(finding("high", "execution", f"{p['name']} spawned by {parent['name']}",
                               "Office / script host launching a shell or LOLBin is a classic initial-access pattern.",
                               p, ["T1218", "T1059.001"] if "powershell" in name else ["T1218"],
                               {"parent": f"{parent['name']} ({parent['pid']})", "cmdline": p.get("cmdline", "")}))
    # Collapse duplicates of the multi-instance finding
    seen, uniq = set(), []
    for f in out:
        k = (f["key"], f["title"]) if f["key"] else id(f)
        if k in seen:
            continue
        seen.add(k)
        uniq.append(f)
    return uniq


# ── modules ───────────────────────────────────────────────────────────────

def module_findings(proc, modules, root="c:\\windows"):
    out = []
    exe = norm_path(proc.get("path") or "")
    exe_dir = ntpath.dirname(exe)
    for m in modules:
        if exe and norm_path(m["path"]) == exe:
            continue  # the main image: covered by process_findings
        risk, why = path_risk(m["path"], root)
        if risk == "temp":
            out.append(finding("high", "module", "DLL loaded from a temporary / public folder",
                               m["path"], proc, ["T1574.001", "T1055.001"], {"base": hex(m["base"]), "path": m["path"]}))
        elif risk in ("user", "other") and not m["path"].lower().endswith(".exe"):
            # Apps installed per-user load DLLs from their own folder: only flag
            # DLLs that sit outside the executable's directory tree.
            if exe_dir and norm_path(m["path"]).startswith(exe_dir):
                continue
            if vendor_of(m["path"]):
                continue
            out.append(finding("low", "module", "DLL outside standard locations", f"{m['path']}: {why}.",
                               proc, ["T1574.001"], {"base": hex(m["base"]), "path": m["path"]},
                               key=f"mod:{norm_path(m['path'])}"))
    return out


# ── memory ────────────────────────────────────────────────────────────────

def region_findings(proc, regions):
    """RWX and executable private memory (shellcode, reflective loading)."""
    jit = proc["name"].lower() in JIT_HOSTS
    rwx = [r for r in regions if r["protect"] & 0xFF == 0x40]
    unbacked = [r for r in regions if r["type"] == MEM_PRIVATE and is_exec(r["protect"])]
    out = []
    if rwx:
        out.append(finding("low" if jit else "medium", "memory",
                           f"RWX memory ({len(rwx)} region{'s' * (len(rwx) > 1)})",
                           "Readable + writable + executable pages." + (" Common in JIT runtimes." if jit else
                                                                        " Typical of unpacked or injected code."),
                           proc, ["T1055"], {"regions": [f"{r['base']:#x} ({r['size']:#x})" for r in rwx[:20]]},
                           key="rwx:jit" if jit else None))
    if unbacked:
        out.append(finding("low" if jit else "medium", "memory",
                           f"Executable private memory ({len(unbacked)} region{'s' * (len(unbacked) > 1)})",
                           "Executable code not backed by any file on disk." + (" Common in JIT runtimes." if jit else ""),
                           proc, ["T1055", "T1620"],
                           {"regions": [f"{r['base']:#x} {protect_str(r['protect'])} ({r['size']:#x})" for r in unbacked[:20]]},
                           key="unbacked:jit" if jit else None))
    return out


def injected_pe_finding(proc, region, header):
    exec_ = is_exec(region["protect"])
    return finding("high" if exec_ else "medium", "memory", "PE image in private memory",
                   "A full PE (MZ + PE header) sits in memory that is not a loaded module. Likely reflective "
                   "DLL injection, manual mapping or an unpacked payload.",
                   proc, ["T1055.001", "T1620"],
                   {"address": hex(region["base"]), "size": hex(region["size"]),
                    "protection": protect_str(region["protect"]), "header": header[:64].hex()})


# ── strings ───────────────────────────────────────────────────────────────

STRING_TAGS = [
    ("url", re.compile(r"\b(?:https?|ftp|wss?)://[\w.-]+(?::\d+)?(?:/[^\s\"'<>]*)?", re.I)),
    ("ip", re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?::\d{2,5})?\b")),
    ("registry", re.compile(r"\b(?:HKLM|HKCU|HKEY_[A-Z_]+|SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run)\b", re.I)),
    ("command", re.compile(r"\b(?:powershell|cmd(?:\.exe)? /c|rundll32|regsvr32|mshta|certutil|bitsadmin|"
                           r"-enc(?:odedcommand)?|invoke-expression|iex\b|downloadstring|frombase64string)", re.I)),
    ("evasion", re.compile(r"\b(?:AmsiUtils|amsiInitFailed|AmsiScanBuffer|EtwEventWrite|VirtualProtect|"
                           r"NtProtectVirtualMemory|MiniDumpWriteDump|sekurlsa|lsadump)\b", re.I)),
    ("path", re.compile(r"\b[a-z]:\\[^\s\"'<>|*?]{3,}", re.I)),
    ("email", re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]{2,}\b")),
    ("base64", re.compile(r"^[A-Za-z0-9+/]{40,}={0,2}$")),
]


def tag_string(s):
    return [t for t, rx in STRING_TAGS if rx.search(s)]


def extract_strings(data, base, min_len=5):
    """Yield (address, encoding, text) for ASCII and UTF-16LE strings."""
    for m in re.finditer(rb"[\x20-\x7e]{%d,}" % min_len, data):
        yield base + m.start(), "ascii", m.group().decode("ascii")
    for m in re.finditer(rb"(?:[\x20-\x7e]\x00){%d,}" % min_len, data):
        yield base + m.start(), "utf16", m.group().decode("utf-16le")


# ── hooks ─────────────────────────────────────────────────────────────────

ETW_FUNCS = {"EtwEventWrite", "EtwEventWriteFull", "EtwEventWriteEx", "EtwEventWriteTransfer",
             "EtwEventWriteString", "NtTraceEvent", "EtwNotificationRegister"}
AMSI_FUNCS = {"AmsiScanBuffer", "AmsiScanString", "AmsiOpenSession", "AmsiInitialize"}
EARLY_RETURN = [
    (bytes.fromhex("c3"), "ret"),
    (bytes.fromhex("c2"), "ret n"),
    (bytes.fromhex("33c0c3"), "xor eax,eax; ret"),
    (bytes.fromhex("31c0c3"), "xor eax,eax; ret"),
    (bytes.fromhex("4833c0c3"), "xor rax,rax; ret"),
    (bytes.fromhex("b857000780c3"), "mov eax,E_INVALIDARG; ret"),
]


def decode_hook(code, addr, is64=True, read_ptr=None):
    """
    Identify the patch at the start of a function.
    Returns (kind, destination or None, description).
    """
    if not code:
        return "unreadable", None, ""
    b0 = code[0]
    for pat, desc in EARLY_RETURN:
        if code.startswith(pat):
            return "early-return", None, desc
    try:
        if b0 == 0xE9 and len(code) >= 5:
            return "jmp", (addr + 5 + struct.unpack_from("<i", code, 1)[0]) & 0xFFFFFFFFFFFFFFFF, "jmp rel32"
        if b0 == 0xEB and len(code) >= 2:
            return "jmp", addr + 2 + struct.unpack_from("<b", code, 1)[0], "jmp rel8"
        if code[:2] == b"\xff\x25" and len(code) >= 6:
            disp = struct.unpack_from("<i", code, 2)[0]
            slot = (addr + 6 + disp) if is64 else (disp & 0xFFFFFFFF)
            dest = read_ptr(slot) if read_ptr else None
            return "jmp", dest, "jmp [mem]"
        # mov r64, imm64 ; jmp r64   (48 B8+r imm64 FF E0+r) / (49 B8+r imm64 41 FF E0+r)
        if len(code) >= 12 and code[0] in (0x48, 0x49) and 0xB8 <= code[1] <= 0xBF:
            reg = code[1] - 0xB8
            tail = code[10:13]
            if tail[:2] == bytes([0xFF, 0xE0 + reg]) or tail == bytes([0x41, 0xFF, 0xE0 + reg]):
                return "jmp", struct.unpack_from("<Q", code, 2)[0], "mov reg, imm64; jmp reg"
        # push imm32 ; ret   /  push lo ; mov dword [rsp+4], hi ; ret
        if b0 == 0x68 and len(code) >= 6:
            lo = struct.unpack_from("<I", code, 1)[0]
            if code[5] == 0xC3:
                return "jmp", lo, "push; ret"
            if code[5:9] == b"\xc7\x44\x24\x04" and len(code) >= 14 and code[13] == 0xC3:
                return "jmp", lo | (struct.unpack_from("<I", code, 9)[0] << 32), "push; mov [rsp+4]; ret"
        if b0 == 0xCC:
            return "breakpoint", None, "int3"
    except struct.error:
        pass
    return "modified", None, "modified bytes"


def hook_finding(proc, h):
    """h: dict from hooks.scan_module: function, module, kind, dest, owner, owner_type, vendor…"""
    fn, mod = h["function"], h["module_name"]
    ev = {"address": hex(h["address"]), "disk": h["disk"], "memory": h["memory"], "patch": h["desc"]}
    if h.get("dest") is not None:
        ev["destination"] = hex(h["dest"])
    if h.get("owner"):
        ev["owner"] = h["owner"]
    if h["kind"] == "early-return":
        if fn in ETW_FUNCS:
            return finding("high", "evasion", f"ETW patched: {fn}", f"{mod}!{fn} returns immediately, event "
                           "tracing is blinded.", proc, ["T1562.006"], ev)
        if fn in AMSI_FUNCS:
            return finding("high", "evasion", f"AMSI patched: {fn}", f"{mod}!{fn} returns immediately, AMSI "
                           "scanning is bypassed.", proc, ["T1562.001"], ev)
        return finding("high", "evasion", f"Function neutralised: {fn}", f"{mod}!{fn} starts with '{h['desc']}'.",
                       proc, ["T1562.001"], ev)
    if h.get("vendor") and h.get("vendor_inferred"):
        return finding("low", "hook", f"Hook to private memory: {fn}",
                       f"{mod}!{fn} jumps to unbacked memory. {h['vendor']} is loaded in this process and "
                       "usually places its trampolines there. Verify if unexpected.",
                       proc, ["T1574"], dict(ev, vendor=h["vendor"]), key=f"hook:{mod}!{fn}:{h['vendor']}:inferred")
    if h.get("vendor"):
        return finding("info", "hook", f"Security product hook: {fn}", f"{mod}!{fn} → {h['vendor']} (expected).",
                       proc, [], dict(ev, vendor=h["vendor"]), key=f"hook:{mod}!{fn}:{h['vendor']}")
    if h["kind"] in ("jmp",):
        if h.get("owner_type") == "IMAGE" and h.get("owner"):
            return finding("medium", "hook", f"Inline hook: {fn}", f"{mod}!{fn} jumps into {h['owner']}.",
                           proc, ["T1574"], ev, key=f"hook:{mod}!{fn}:{norm_path(h['owner'])}")
        return finding("high", "hook", f"Inline hook to unbacked memory: {fn}",
                       f"{mod}!{fn} jumps to memory that belongs to no module.", proc, ["T1055", "T1574"], ev)
    if h["kind"] == "breakpoint":
        return finding("medium", "hook", f"Breakpoint on {fn}", f"{mod}!{fn} starts with int3 (debugger or "
                       "exception-based hook).", proc, ["T1574"], ev)
    return finding("medium", "hook", f"Modified prologue: {fn}", f"{mod}!{fn} differs from the file on disk.",
                   proc, ["T1574"], ev)


# ── network ───────────────────────────────────────────────────────────────

COMMON_PORTS = {20, 21, 25, 53, 80, 110, 123, 143, 389, 443, 465, 587, 636, 853, 993, 995, 1433, 3268,
                5222, 5223, 5228, 8080, 8443, 9243}
REMOTE_ADMIN_PORTS = {22: "SSH", 3389: "RDP", 5985: "WinRM", 5986: "WinRM", 445: "SMB", 135: "RPC"}


def is_public(ip):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (a.is_private or a.is_loopback or a.is_link_local or a.is_multicast or a.is_unspecified or a.is_reserved)


def connection_flags(c, proc_name):
    """Return list of (severity, reason, mitre) for one connection."""
    flags = []
    if c["proto"] != "tcp" or c["state"] not in ("ESTABLISHED", "SYN_SENT"):
        return flags
    pub = is_public(c["remote_ip"])
    port = c["remote_port"]
    name = (proc_name or "").lower()
    if pub and name in NO_NETWORK:
        flags.append(("high", f"{proc_name} should not talk to the Internet", ["T1218", "T1071"]))
    elif pub and name in SCRIPT_HOSTS:
        flags.append(("medium", f"{proc_name} connected to the Internet", ["T1059.001", "T1071"]))
    if port in REMOTE_ADMIN_PORTS and pub:
        flags.append(("medium", f"Outbound {REMOTE_ADMIN_PORTS[port]} to a public address", ["T1021"]))
    elif pub and port not in COMMON_PORTS and c["local_port"] not in COMMON_PORTS and port < 49152:
        flags.append(("low", f"Non-standard remote port {port}", ["T1571"]))
    return flags


def network_findings(conns, by_pid, alive_pids=None):
    out = []
    for c in conns:
        proc = by_pid.get(c["pid"])
        if c["pid"] not in (0, 4) and proc is None and alive_pids is not None and c["pid"] in alive_pids:
            out.append(finding("high", "network", "Connection owned by a hidden process",
                               f"PID {c['pid']} owns {c['local']} → {c['remote']} but is absent from the process list.",
                               {"pid": c["pid"], "name": "?"}, ["T1014"], {"connection": f"{c['local']} → {c['remote']}"}))
            continue
        for sev, reason, mitre in connection_flags(c, proc["name"] if proc else None):
            out.append(finding(sev, "network", reason, f"{c['local']} → {c['remote']} ({c['state']})",
                               proc or {"pid": c["pid"], "name": "?"}, mitre,
                               {"connection": f"{c['local']} → {c['remote']}", "state": c["state"]}))
    return out


def hidden_findings(hidden):
    return [finding("high", "rootkit", "Hidden process",
                    f"PID {h['pid']} is alive (seen by {', '.join(h['seen_by'])}) but missing from the "
                    "process snapshot, possible rootkit / DKOM.",
                    {"pid": h["pid"], "name": h.get("name") or "?"}, ["T1014"], {"seen_by": h["seen_by"]})
            for h in hidden]
