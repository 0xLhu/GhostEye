"""Command-line interface."""

import argparse
import json
import os
import sys

from . import __version__, analysis, report, triage

USE_COLOR = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None
C = {"high": "\033[91m", "medium": "\033[33m", "low": "\033[93m", "info": "\033[90m", "dim": "\033[90m",
     "b": "\033[1m", "acc": "\033[95m", "ok": "\033[92m", "x": "\033[0m"}


def col(text, *keys):
    return "".join(C[k] for k in keys) + str(text) + C["x"] if USE_COLOR else str(text)


BANNER = r"""
   ________               __  ______
  / ____/ /_  ____  _____/ /_/ ____/_  _____
 / / __/ __ \/ __ \/ ___/ __/ __/ / / / / _ \
/ /_/ / / / / /_/ (__  ) /_/ /___/ /_/ /  __/
\____/_/ /_/\____/____/\__/_____/\__, /\___/
                                /____/   live memory inspection"""


def get_backend(demo):
    if demo:
        from .demo import DemoBackend
        return DemoBackend()
    if sys.platform != "win32":
        sys.exit("GhostEye inspects live Windows processes. On this OS, use --demo to explore the interface.")
    from .live import LiveBackend
    return LiveBackend()


def match(procs, filters):
    if not filters:
        return procs
    out = []
    for p in procs:
        for f in filters:
            if (f.isdigit() and p["pid"] == int(f)) or (not f.isdigit() and f.lower() in p["name"].lower()):
                out.append(p)
                break
    return out


def targets(b, filters):
    procs = match(b.processes(), filters)
    if not procs:
        sys.exit(f"No process matches {' '.join(filters)}")
    return procs


def header(p):
    print(f"\n{col('[*]', 'acc')} {col(p['name'], 'b')} {col('PID ' + str(p['pid']), 'dim')}")


def print_finding(f):
    tag = col(f"{f['severity'].upper():<6}", f["severity"], "b")
    who = f"{f['process']} ({f['pid']})" if f["pid"] is not None else (f["process"] or "")
    att = " ".join(m["id"] for m in f["mitre"])
    print(f"  {tag} {f['title']}  {col(who, 'dim')}  {col(att, 'acc')}")
    if f["detail"]:
        print(f"         {col(f['detail'], 'dim')}")


# ── commands ──────────────────────────────────────────────────────────────

def cmd_list(b, a):
    procs = match(b.processes(), a.filter)
    if a.json:
        return print(json.dumps(procs, indent=2, default=str))
    print(f"{'PID':>7} {'PPID':>7} {'Thr':>4}  {'Name':<28} Path")
    for p in procs:
        print(f"{p['pid']:>7} {p['ppid']:>7} {p['threads']:>4}  {p['name']:<28} {col(p.get('path', ''), 'dim')}")


def cmd_scan(b, a):
    for p in targets(b, a.filter):
        header(p)
        try:
            regions = b.regions(p["pid"])
        except OSError as e:
            print(f"  {col('[!]', 'medium')} {e}")
            continue
        s = triage.region_summary(regions)
        print(f"  {s['count']} committed regions, {s['committed'] / 1048576:.1f} MB · RWX {s['rwx']} · private exec {s['private_exec']}")
        for r in regions:
            flag = ""
            if r["protect"] & 0xFF == 0x40:
                flag = col(" RWX", "high")
            elif r["type"] == analysis.MEM_PRIVATE and analysis.is_exec(r["protect"]):
                flag = col(" unbacked exec", "medium")
            if a.all or flag:
                print(f"  {r['base']:#16x} {r['size']:>#10x} {analysis.MEM_TYPES.get(r['type'], '?'):<8} "
                      f"{analysis.protect_str(r['protect']):<6}{flag} {col(r.get('mapped', '').split(chr(92))[-1], 'dim')}")
        if a.pe:
            found = triage.injected_pes(b, p["pid"], regions)
            for r, _ in found:
                print(f"  {col('[PE]', 'high')} PE image in private memory at {r['base']:#x} "
                      f"({r['size']:#x}, {analysis.protect_str(r['protect'])})")
            if not found:
                print(f"  {col('[PE]', 'ok')} no PE image in private memory")
        if a.strings:
            res = triage.strings(b, p["pid"], a.min, a.grep or "", a.interesting, a.limit)
            for s in res["strings"]:
                tags = col(",".join(s["tags"]), "acc") if s["tags"] else ""
                print(f"  {s['address']:#16x} {s['encoding']:<5} {tags} {s['text']}")
            if res["truncated"]:
                print(col(f"  … truncated at {a.limit} strings (use --limit)", "dim"))


def cmd_dll(b, a):
    root = analysis.system_root(b.system().get("root"))
    for p in targets(b, a.filter):
        header(p)
        try:
            mods = b.modules(p["pid"])
        except OSError as e:
            print(f"  {col('[!]', 'medium')} {e}")
            continue
        for m in mods:
            risk, why = analysis.path_risk(m["path"], root)
            vendor = analysis.vendor_of(m["path"])
            sus = risk in ("temp", "other", "user") and not vendor
            if a.suspicious and not sus:
                continue
            tag = col(" [!] " + why, "high" if risk == "temp" else "medium") if sus else (col(" [" + vendor + "]", "ok") if vendor else "")
            print(f"  {m['base']:#16x} {m['path']}{tag}")


def cmd_hooks(b, a):
    wanted = [m.strip() for m in a.module.split(",")] if a.module else None
    for p in targets(b, a.filter):
        header(p)
        try:
            hs = b.scan_hooks(p["pid"], wanted)
        except OSError as e:
            print(f"  {col('[!]', 'medium')} {e}")
            continue
        if not hs:
            print(f"  {col('no modified export', 'ok')}")
        for h in hs:
            f = analysis.hook_finding(p, h)
            print(f"  {col(f['severity'].upper(), f['severity'], 'b'):<8} {h['module_name']}!{h['function']:<34} {h['address']:#x}")
            print(f"           disk   {h['disk'][:32]}\n           memory {h['memory'][:32]}  ({h['desc']})")
            if h.get("dest") is not None:
                print(f"           → {h['dest']:#x} {col(h.get('owner') or '', 'dim')} {col(h.get('vendor') or '', 'ok')}")


def cmd_hidden(b, a):
    hidden = b.hidden()
    if not hidden:
        return print(col("No hidden process detected (snapshot vs EnumProcesses vs PID brute force).", "ok"))
    for h in hidden:
        print(f"  {col('[!]', 'high')} PID {h['pid']} {h.get('name', '')} (seen by {', '.join(h['seen_by'])})")


def cmd_network(b, a):
    procs = {p["pid"]: p["name"] for p in b.processes()}
    for c in b.connections():
        name = procs.get(c["pid"], "?")
        flags = analysis.connection_flags(c, name)
        if a.suspicious and not flags:
            continue
        tag = "  " + "; ".join(col(r, s) for s, r, _ in flags) if flags else ""
        print(f"  {c['proto']:<4} {c['state']:<12} {c['local']:<26} → {c['remote']:<26} {name} ({c['pid']}){tag}")


def cmd_triage(b, a):
    def progress(done, total, label):
        if sys.stderr.isatty():
            sys.stderr.write(f"\r  scanning {done}/{total} {label[:40]:<40}")
            sys.stderr.flush()
    r = triage.run(b, check_hooks=not a.no_hooks, progress=progress)
    if sys.stderr.isatty():
        sys.stderr.write("\r" + " " * 70 + "\r")
    if a.json:
        with open(a.json, "w", encoding="utf-8") as f:
            f.write(report.to_json(r))
        print(f"JSON report → {a.json}")
    if a.html:
        with open(a.html, "w", encoding="utf-8") as f:
            f.write(report.to_html(r))
        print(f"HTML report → {a.html}")
    c = r["counts"]
    print(f"\n{col('GhostEye triage', 'b')}: {r['system']['hostname']} · {len(r['processes'])} processes · {r['duration_s']}s")
    print("  " + "  ".join(col(f"{k}: {v}", k) for k, v in c.items()))
    for f in r["findings"]:
        if f["severity"] != "info" or a.verbose:
            print_finding(f)
    if r["skipped"]:
        print(col(f"\n  {len(r['skipped'])} protected process(es) not inspected.", "dim"))
    if not r["system"]["admin"]:
        print(col("  Run as Administrator for full coverage.", "medium"))


def cmd_gui(b, a):
    from . import gui
    gui.run(b, port=a.port, open_browser=not a.no_browser)


def main(argv=None):
    p = argparse.ArgumentParser(prog="ghosteye", description="GhostEye: live memory inspection for Windows (read-only).")
    p.add_argument("--demo", action="store_true", help="use the simulated workstation instead of this machine")
    p.add_argument("--version", action="version", version=f"GhostEye {__version__}")
    sub = p.add_subparsers(dest="cmd")

    def add(name, fn, help_, filt=True):
        sp = sub.add_parser(name, help=help_)
        if filt:
            sp.add_argument("filter", nargs="*", help="process name(s) or PID(s)")
        sp.set_defaults(fn=fn)
        return sp

    sp = add("gui", cmd_gui, "graphical interface in the browser (default)", False)
    sp.add_argument("--port", type=int, default=8770)
    sp.add_argument("--no-browser", action="store_true")
    sp = add("triage", cmd_triage, "run every check and print the findings", False)
    sp.add_argument("--json", metavar="FILE")
    sp.add_argument("--html", metavar="FILE")
    sp.add_argument("--no-hooks", action="store_true", help="skip inline hook scan (faster)")
    sp.add_argument("-v", "--verbose", action="store_true", help="also print info-level findings")
    sp = add("list", cmd_list, "list processes")
    sp.add_argument("--json", action="store_true")
    sp = add("scan", cmd_scan, "memory regions of a process")
    sp.add_argument("--all", action="store_true", help="print every region, not only flagged ones")
    sp.add_argument("--pe", action="store_true", help="look for PE images in private memory")
    sp.add_argument("--strings", action="store_true", help="extract strings")
    sp.add_argument("--interesting", action="store_true", help="with --strings: only URLs, IPs, commands…")
    sp.add_argument("--grep", help="with --strings: substring filter")
    sp.add_argument("--min", type=int, default=5)
    sp.add_argument("--limit", type=int, default=2000)
    sp = add("dll", cmd_dll, "loaded DLLs")
    sp.add_argument("--suspicious", action="store_true")
    sp = add("hooks", cmd_hooks, "inline hooks in ntdll / kernelbase / kernel32 / amsi")
    sp.add_argument("--module", help="comma-separated module names to scan instead of the defaults")
    add("hidden", cmd_hidden, "hidden processes (3-source cross-view)", False)
    sp = add("network", cmd_network, "TCP/UDP endpoints", False)
    sp.add_argument("--suspicious", action="store_true")

    a = p.parse_args(argv)
    if not a.cmd:
        if USE_COLOR:
            print(col(BANNER, "acc"))
        a = p.parse_args((["--demo"] if a.demo else []) + ["gui"])
    if a.cmd in ("scan", "dll", "hooks") and not a.filter:
        p.error(f"{a.cmd} needs a process name or PID")
    b = get_backend(a.demo)
    try:
        a.fn(b, a)
    except KeyboardInterrupt:
        print()
