import re
import sys

from list_proc import list_processes
from mapping import open_process, query_memory, kernel32
from reader import read_memory
from network import get_tcp_connections
from dll import list_modules, is_suspicious_dll
from hidden import enum_processes, find_hidden_processes
from hook import detect_hooks

COMMON_PORTS = {80, 443, 53, 21, 25, 110, 143, 8080, 8443, 3389, 445, 139}

def is_suspicious(conn, proc_map):
    remote_port = int(conn["remote"].split(":")[1])

    # rule 1: PID with no matching process name (hidden/injected process)
    if conn["pid"] != 0 and conn["pid"] not in proc_map:
        return True, "PID with no process name"

    # rule 2: non-standard port on an ESTABLISHED connection
    if conn["state"] == "ESTABLISHED" and remote_port not in COMMON_PORTS:
        return True, f"non-standard port {remote_port}"

    # rule 3: outbound SSH (port 22) from a user workstation
    if remote_port == 22 and conn["state"] == "ESTABLISHED":
        return True, "outbound SSH connection"

    return False, None

CHUNK_SIZE = 4096

def cmd_list(filtre):
    procs = list_processes()
    if filtre:
        procs = [p for p in procs if any(f.lower() in p["name"].lower() for f in filtre)]
        if not procs:
            print(f"No process found matching: {filtre}")
            return
    print(f"{'PID':>6}  {'PPID':>6}  {'Threads':>7}  Name")
    print("-" * 40)
    for p in procs:
        print(f"{p['pid']:>6}  {p['ppid']:>6}  {p['threads']:>7}  {p['name']}")

def cmd_scan(filtre, show_strings=False, show_pe=False):
    for proc in list_processes():
        if filtre and not any(f.lower() in proc["name"].lower() for f in filtre):
            continue
        print(f"\n[*] Process {proc['pid']} ({proc['name']})")
        try:
            handle = open_process(proc["pid"])
            regions = query_memory(handle)

            if show_strings or show_pe:
                for r in regions:
                    offset = 0
                    while offset < r["size"]:
                        chunk = read_memory(handle, r["base"] + offset, min(CHUNK_SIZE, r["size"] - offset))
                        if show_strings:
                            found = re.findall(rb"[\x20-\x7e]{4,}", chunk)
                            for s in found:
                                decoded = s.decode("ascii", errors="replace")
                                if re.search(r'[a-zA-Z]{3,}', decoded):
                                    print(f"  [str] {decoded}")
                        if show_pe:
                            pos = chunk.find(b"MZ")
                            if pos != -1:
                                addr = r["base"] + offset + pos
                                print(f"  [PE]  MZ header detected at {addr:#x}")
                        offset += CHUNK_SIZE

            kernel32.CloseHandle(handle)
        except Exception as e:
            print(f"  [!] Error: {e}")

def cmd_dll(filtre, only_suspicious=False):
    for proc in list_processes():
        if filtre and not any(f.lower() in proc["name"].lower() for f in filtre):
            continue
        print(f"\n[*] Process {proc['pid']} ({proc['name']})")
        try:
            handle = open_process(proc["pid"])
            modules = list_modules(handle)
            for m in modules:
                if only_suspicious and not is_suspicious_dll(m["path"]):
                    continue
                tag = "  [!]" if is_suspicious_dll(m["path"]) else "     "
                print(f"{tag} {m['base']:#x}  {m['path']}")
            kernel32.CloseHandle(handle)
        except Exception as e:
            print(f"  [!] Error: {e}")

def cmd_hooks(filtre):
    for proc in list_processes():
        if filtre and not any(f.lower() in proc["name"].lower() for f in filtre):
            continue
        print(f"\n[*] Process {proc['pid']} ({proc['name']})")
        try:
            handle = open_process(proc["pid"])
            hooks  = detect_hooks(handle, proc["pid"])
            if not hooks:
                print("  No hooks detected.")
            for h in hooks:
                tag = "  [HOOK]" if h["hooked"] else "  [DIFF]"
                print(f"{tag} {h['function']:<40} {h['address']:#x}")
                print(f"         disk:   {h['disk']}")
                print(f"         memory: {h['memory']}")
                if h.get("vendor"):
                    print(f"         vendor: {h['vendor']}")
            kernel32.CloseHandle(handle)
        except Exception as e:
            print(f"  [!] Error: {e}")

def cmd_hidden():
    snapshot_pids = [p["pid"] for p in list_processes()]
    enum_pids     = enum_processes()
    hidden        = find_hidden_processes(snapshot_pids, enum_pids)
    if not hidden:
        print("No hidden processes detected.")
    else:
        print(f"Found {len(hidden)} hidden PID(s):")
        for pid in hidden:
            print(f"  [!] PID {pid}")

def cmd_network(only_suspicious=False):
    connections = get_tcp_connections()
    proc_map = {p["pid"]: p["name"] for p in list_processes()}
    for conn in connections:
        suspicious, reason = is_suspicious(conn, proc_map)
        if only_suspicious and not suspicious:
            continue
        name = proc_map.get(conn["pid"], "???")
        tag  = f"  [!] {reason}" if suspicious else ""
        print(f"  {conn['state']:<16} {conn['local']:<25} -> {conn['remote']:<25} PID:{conn['pid']} ({name}){tag}")

def usage():
    
    banner = r"""
  _______  __    __    ______        _______.___________. ___________    ____  _______ 
 /  _____||  |  |  |  /  __  \      /       |           ||   ____\   \  /   / |   ____|
|  |  __  |  |__|  | |  |  |  |    |   (----`---|  |----`|  |__   \   \/   /  |  |__   
|  | |_ | |   __   | |  |  |  |     \   \       |  |     |   __|   \_    _/   |   __|  
|  |__| | |  |  |  | |  `--'  | .----)   |      |  |     |  |____    |  |     |  |____ 
 \______| |__|  |__|  \______/  |_______/       |__|     |_______|   |__|     |_______|
                                                                                        """
    print(banner)
    print("Usage:")
    print("  python main.py list                    # All processes")
    print("  python main.py list <name>             # filter by name")
    print("  python main.py scan <name>             # memory regions")
    print("  python main.py scan <name> --strings   # extract strings")
    print("  python main.py scan <name> --pe        # detect PE headers")
    print("  python main.py network                 # all TCP connections")
    print("  python main.py network --suspicious    # suspicious connections only")
    print("  python main.py dll <name>              # list loaded DLLs")
    print("  python main.py dll <name> --suspicious # suspicious DLLs only")
    print("  python main.py hidden                  # detect hidden processes")
    print("  python main.py hooks <name>            # detect ntdll API hooks")

if __name__ == "__main__":
    args = sys.argv[1:]
    if not args:
        usage()
        sys.exit(1)

    command = args[0]
    flags   = {a for a in args if a.startswith("--")}
    filtre  = [a for a in args[1:] if not a.startswith("--")]

    if command == "list":
        cmd_list(filtre)
    elif command == "scan":
        cmd_scan(filtre, show_strings="--strings" in flags, show_pe="--pe" in flags)
    elif command == "network":
        cmd_network(only_suspicious="--suspicious" in flags)
    elif command == "dll":
        cmd_dll(filtre, only_suspicious="--suspicious" in flags)
    elif command == "hidden":
        cmd_hidden()
    elif command == "hooks":
        cmd_hooks(filtre)
    else:
        print(f"Unknown command: {command!r}")
        usage()
        sys.exit(1)
