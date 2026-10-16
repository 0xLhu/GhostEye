"""
Live backend: reads the running Windows system through winapi.py.
Read-only: processes are opened with QUERY_INFORMATION | VM_READ only.
"""

import ctypes
import ipaddress
import ntpath
import os
import platform
import socket
import struct
from ctypes import wintypes as wt

from . import analysis, hooks
from . import winapi as w
from .pe import PE, PEError

TCP_STATES = {1: "CLOSED", 2: "LISTENING", 3: "SYN_SENT", 4: "SYN_RECEIVED", 5: "ESTABLISHED",
              6: "FIN_WAIT1", 7: "FIN_WAIT2", 8: "CLOSE_WAIT", 9: "CLOSING", 10: "LAST_ACK",
              11: "TIME_WAIT", 12: "DELETE_TCB"}
TABLE_OWNER_PID_ALL = 5   # TCP_TABLE_OWNER_PID_ALL
UDP_TABLE_OWNER_PID = 1
AF_INET, AF_INET6 = 2, 23
READ_CHUNK = 1 << 20


class LiveBackend:
    name = "live"

    def __init__(self):
        self.debug_privilege = w.enable_privilege("SeDebugPrivilege")
        self._file_cache = {}
        self.root = os.environ.get("SystemRoot", "C:\\Windows")

    # ── system ───────────────────────────────────────────────────────────
    def system(self):
        return {
            "mode": "live",
            "hostname": socket.gethostname(),
            "os": platform.platform(),
            "admin": bool(w.IsUserAnAdmin()),
            "debug_privilege": self.debug_privilege,
            "python": f"{platform.python_version()} ({'64' if w.PTR64 else '32'}-bit)",
            "self_pid": os.getpid(),
            "root": self.root,
        }

    # ── processes ────────────────────────────────────────────────────────
    def snapshot(self):
        snap = w.CreateToolhelp32Snapshot(w.TH32CS_SNAPPROCESS, 0)
        if not snap or snap == w.INVALID_HANDLE_VALUE:
            raise ctypes.WinError(w.last_error())
        out = []
        try:
            e = w.PROCESSENTRY32W()
            e.dwSize = ctypes.sizeof(e)
            ok = w.Process32FirstW(snap, ctypes.byref(e))
            while ok:
                out.append({"pid": e.th32ProcessID, "ppid": e.th32ParentProcessID,
                            "name": e.szExeFile, "threads": e.cntThreads})
                ok = w.Process32NextW(snap, ctypes.byref(e))
        finally:
            w.CloseHandle(snap)
        return out

    def _details(self, pid):
        """Image path, creation time, architecture (needs only limited access)."""
        info = {"path": "", "created": None, "wow64": None, "access": "denied"}
        try:
            with w.Process(pid, w.PROCESS_QUERY_LIMITED_INFORMATION) as p:
                info["access"] = "limited"
                buf = ctypes.create_unicode_buffer(32768)
                n = wt.DWORD(len(buf))
                if w.QueryFullProcessImageNameW(p.handle, 0, buf, ctypes.byref(n)):
                    info["path"] = buf.value
                c, e, k, u = wt.FILETIME(), wt.FILETIME(), wt.FILETIME(), wt.FILETIME()
                if w.GetProcessTimes(p.handle, ctypes.byref(c), ctypes.byref(e), ctypes.byref(k), ctypes.byref(u)):
                    info["created"] = w.filetime_to_unix(c)
                wow = wt.BOOL()
                if w.IsWow64Process(p.handle, ctypes.byref(wow)):
                    info["wow64"] = bool(wow.value)
        except OSError:
            pass
        try:
            with w.Process(pid):
                info["access"] = "full"
        except OSError:
            pass
        return info

    def processes(self):
        procs = self.snapshot()
        for p in procs:
            if p["pid"] in (0, 4):
                p.update({"path": "", "created": None, "wow64": False, "access": "kernel"})
            else:
                p.update(self._details(p["pid"]))
        return procs

    def enum_pids(self):
        size = 4096
        while True:
            arr = (wt.DWORD * size)()
            needed = wt.DWORD()
            if not w.EnumProcesses(arr, ctypes.sizeof(arr), ctypes.byref(needed)):
                raise ctypes.WinError(w.last_error())
            if needed.value < ctypes.sizeof(arr):
                return set(arr[:needed.value // ctypes.sizeof(wt.DWORD)])
            size *= 2

    def pid_alive(self, pid):
        h = w.OpenProcess(w.PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if not h:
            return w.last_error() == w.ERROR_ACCESS_DENIED  # exists but protected
        try:
            code = wt.DWORD()
            return bool(w.GetExitCodeProcess(h, ctypes.byref(code))) and code.value == w.STILL_ACTIVE
        finally:
            w.CloseHandle(h)

    def brute_pids(self, upper):
        """PID brute force through OpenProcess: a source independent of the process list."""
        return {pid for pid in range(8, upper, 4) if self.pid_alive(pid)}

    def hidden(self):
        snap = {p["pid"] for p in self.snapshot()}
        enum = self.enum_pids()
        brute = self.brute_pids(max(max(snap | enum, default=0) + 20000, 1 << 18))
        candidates = (enum | brute) - snap - {0, 4}
        if not candidates:
            return []
        snap2 = {p["pid"] for p in self.snapshot()}  # rule out processes started meanwhile
        out = []
        for pid in sorted(candidates - snap2):
            if self.pid_alive(pid):
                d = self._details(pid)
                out.append({"pid": pid, "name": ntpath.basename(d["path"]) or "?", "path": d["path"],
                            "seen_by": [s for s, src in (("EnumProcesses", enum), ("PID brute force", brute))
                                        if pid in src]})
        return out

    # ── memory ───────────────────────────────────────────────────────────
    def regions(self, pid):
        out = []
        with w.Process(pid) as p:
            mbi = w.MEMORY_BASIC_INFORMATION()
            addr = 0
            name = ctypes.create_unicode_buffer(1024)
            while w.VirtualQueryEx(p.handle, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi)):
                base = mbi.BaseAddress or 0
                if mbi.State == analysis.MEM_COMMIT:
                    r = {"base": base, "size": mbi.RegionSize, "protect": mbi.Protect, "type": mbi.Type,
                         "alloc_base": mbi.AllocationBase or 0, "alloc_protect": mbi.AllocationProtect,
                         "mapped": ""}
                    if mbi.Type in (analysis.MEM_IMAGE, analysis.MEM_MAPPED) and \
                            w.GetMappedFileNameW(p.handle, ctypes.c_void_p(base), name, len(name)):
                        r["mapped"] = name.value
                    out.append(r)
                nxt = base + mbi.RegionSize
                if nxt <= addr:
                    break
                addr = nxt
        return out

    def region_at(self, pid, addr):
        try:
            with w.Process(pid) as p:
                mbi = w.MEMORY_BASIC_INFORMATION()
                if not w.VirtualQueryEx(p.handle, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi)):
                    return None
                r = {"base": mbi.BaseAddress or 0, "size": mbi.RegionSize, "protect": mbi.Protect,
                     "type": mbi.Type, "alloc_base": mbi.AllocationBase or 0, "mapped": ""}
                name = ctypes.create_unicode_buffer(1024)
                if mbi.Type != analysis.MEM_PRIVATE and w.GetMappedFileNameW(p.handle, ctypes.c_void_p(addr), name, 1024):
                    r["mapped"] = name.value
                return r
        except OSError:
            return None

    def _read(self, handle, addr, size):
        buf = ctypes.create_string_buffer(size)
        n = ctypes.c_size_t()
        if w.ReadProcessMemory(handle, ctypes.c_void_p(addr), buf, size, ctypes.byref(n)) or n.value:
            return buf.raw[:n.value]
        return b""

    def read(self, pid, addr, size):
        """Read memory; unreadable pages are skipped (returns what could be read, contiguous)."""
        try:
            with w.Process(pid) as p:
                out = bytearray()
                while size > 0:
                    chunk = self._read(p.handle, addr, min(size, READ_CHUNK))
                    out += chunk
                    if len(chunk) < min(size, READ_CHUNK):
                        break
                    addr += len(chunk)
                    size -= len(chunk)
                return bytes(out)
        except OSError:
            return b""

    def read_file(self, path):
        st = os.stat(path)
        key = (path.lower(), st.st_mtime, st.st_size)
        if key not in self._file_cache:
            with open(path, "rb") as f:
                self._file_cache[key] = f.read()
        return self._file_cache[key]

    # ── modules ──────────────────────────────────────────────────────────
    def modules(self, pid):
        with w.Process(pid) as p:
            needed = wt.DWORD()
            arr = (ctypes.c_void_p * 1024)()
            for _ in range(4):
                if not w.EnumProcessModulesEx(p.handle, arr, ctypes.sizeof(arr), ctypes.byref(needed), w.LIST_MODULES_ALL):
                    raise ctypes.WinError(w.last_error())
                if needed.value <= ctypes.sizeof(arr):
                    break
                arr = (ctypes.c_void_p * (needed.value // ctypes.sizeof(ctypes.c_void_p) + 64))()
            count = min(needed.value, ctypes.sizeof(arr)) // ctypes.sizeof(ctypes.c_void_p)
            out = []
            buf = ctypes.create_unicode_buffer(32768)
            for hmod in arr[:count]:
                if not hmod:
                    continue
                if not w.GetModuleFileNameExW(p.handle, ctypes.c_void_p(hmod), buf, len(buf)):
                    continue
                mi = w.MODULEINFO()
                size = mi.SizeOfImage if w.GetModuleInformation(p.handle, ctypes.c_void_p(hmod), ctypes.byref(mi),
                                                                  ctypes.sizeof(mi)) else 0
                if not size:  # fall back to the PE header in memory
                    try:
                        size = PE(self._read(p.handle, hmod, 0x1000), mapped=True).size_of_image
                    except PEError:
                        size = 0
                out.append({"base": hmod, "size": size, "path": buf.value, "name": ntpath.basename(buf.value)})
            return out

    def scan_hooks(self, pid, wanted=None, modules=None):
        return hooks.scan(self, pid, modules if modules is not None else self.modules(pid), wanted)

    # ── network ──────────────────────────────────────────────────────────
    def _table(self, fn, family, cls, table_class):
        size = wt.DWORD(0)
        for _ in range(5):
            buf = ctypes.create_string_buffer(size.value or 4)
            rc = fn(buf, ctypes.byref(size), False, family, table_class, 0)
            if rc == 0:
                break
            if rc != w.ERROR_INSUFFICIENT_BUFFER:
                raise ctypes.WinError(rc)
        else:
            return []
        count = struct.unpack_from("<I", buf.raw, 0)[0]
        off = 4  # dwNumEntries, then DWORD-aligned rows (IPv4 and IPv6 tables)
        row_size = ctypes.sizeof(cls)
        return [cls.from_buffer_copy(buf.raw, off + i * row_size) for i in range(count)]

    @staticmethod
    def _port(v):
        return socket.ntohs(v & 0xFFFF)

    def connections(self):
        out = []
        for r in self._table(w.GetExtendedTcpTable, AF_INET, w.MIB_TCPROW_OWNER_PID, TABLE_OWNER_PID_ALL):
            lip, rip = socket.inet_ntoa(struct.pack("<I", r.dwLocalAddr)), socket.inet_ntoa(struct.pack("<I", r.dwRemoteAddr))
            out.append(self._conn("tcp", lip, self._port(r.dwLocalPort), rip, self._port(r.dwRemotePort),
                                  TCP_STATES.get(r.dwState, str(r.dwState)), r.dwOwningPid))
        for r in self._table(w.GetExtendedTcpTable, AF_INET6, w.MIB_TCP6ROW_OWNER_PID, TABLE_OWNER_PID_ALL):
            lip, rip = str(ipaddress.IPv6Address(bytes(r.ucLocalAddr))), str(ipaddress.IPv6Address(bytes(r.ucRemoteAddr)))
            out.append(self._conn("tcp", lip, self._port(r.dwLocalPort), rip, self._port(r.dwRemotePort),
                                  TCP_STATES.get(r.dwState, str(r.dwState)), r.dwOwningPid))
        for r in self._table(w.GetExtendedUdpTable, AF_INET, w.MIB_UDPROW_OWNER_PID, UDP_TABLE_OWNER_PID):
            lip = socket.inet_ntoa(struct.pack("<I", r.dwLocalAddr))
            out.append(self._conn("udp", lip, self._port(r.dwLocalPort), "*", 0, "", r.dwOwningPid))
        for r in self._table(w.GetExtendedUdpTable, AF_INET6, w.MIB_UDP6ROW_OWNER_PID, UDP_TABLE_OWNER_PID):
            lip = str(ipaddress.IPv6Address(bytes(r.ucLocalAddr)))
            out.append(self._conn("udp", lip, self._port(r.dwLocalPort), "*", 0, "", r.dwOwningPid))
        return out

    @staticmethod
    def _conn(proto, lip, lport, rip, rport, state, pid):
        fmt = (lambda ip, p: f"[{ip}]:{p}") if ":" in lip else (lambda ip, p: f"{ip}:{p}")
        return {"proto": proto, "local_ip": lip, "local_port": lport, "remote_ip": rip, "remote_port": rport,
                "local": fmt(lip, lport), "remote": rip if rip == "*" else fmt(rip, rport), "state": state, "pid": pid}
