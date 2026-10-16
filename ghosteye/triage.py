"""
Triage engine: runs every check through a backend (live or demo) and
returns a JSON-serialisable report.
"""

import datetime
import time

from . import analysis
from .pe import looks_like_pe

SKIP_NAMES = {"system idle process", "system", "registry", "memory compression", "secure system", "[system process]"}
MAX_STRING_BYTES = 256 << 20
MAX_REGION_BYTES = 32 << 20


def now():
    return datetime.datetime.now().isoformat(timespec="seconds")


def injected_pes(backend, pid, regions):
    """MZ/PE headers at the start of private (or file-less mapped) allocations."""
    out = []
    for r in regions:
        file_less = r["type"] == analysis.MEM_PRIVATE or (r["type"] == analysis.MEM_MAPPED and not r.get("mapped"))
        if not file_less or r["base"] != r["alloc_base"] or not analysis.is_readable(r["protect"]):
            continue
        head = backend.read(pid, r["base"], 0x400)
        if looks_like_pe(head):
            out.append((r, head))
    return out


def strings(backend, pid, min_len=5, query="", tagged_only=False, limit=5000, include_images=False):
    """Extract strings from readable committed memory, newest-first by address."""
    q = (query or "").lower()
    results, total = [], 0
    for r in backend.regions(pid):
        if not analysis.is_readable(r["protect"]):
            continue
        if r["type"] == analysis.MEM_IMAGE and not include_images:
            continue
        size = min(r["size"], MAX_REGION_BYTES)
        if total + size > MAX_STRING_BYTES:
            break
        data = backend.read(pid, r["base"], size)
        total += len(data)
        for addr, enc, text in analysis.extract_strings(data, r["base"], min_len):
            if q and q not in text.lower():
                continue
            tags = analysis.tag_string(text)
            if tagged_only and not tags:
                continue
            results.append({"address": addr, "encoding": enc, "text": text[:400], "tags": tags,
                            "region": analysis.MEM_TYPES.get(r["type"], "?")})
            if len(results) >= limit:
                return {"strings": results, "truncated": True, "bytes_scanned": total}
    return {"strings": results, "truncated": False, "bytes_scanned": total}


def region_summary(regions):
    s = {"count": len(regions), "committed": sum(r["size"] for r in regions), "by_type": {}, "rwx": 0, "private_exec": 0}
    for r in regions:
        t = analysis.MEM_TYPES.get(r["type"], "?")
        s["by_type"][t] = s["by_type"].get(t, 0) + r["size"]
        s["rwx"] += r["protect"] & 0xFF == 0x40
        s["private_exec"] += r["type"] == analysis.MEM_PRIVATE and analysis.is_exec(r["protect"])
    return s


def scan_process(backend, proc, root, check_hooks=True, wanted=None):
    """All per-process checks. Returns (findings, info)."""
    pid = proc["pid"]
    findings, info = [], {"pid": pid, "errors": []}
    try:
        modules = backend.modules(pid)
    except OSError as e:
        info["errors"].append(f"modules: {e}")
        modules = []
    try:
        regions = backend.regions(pid)
    except OSError as e:
        info["errors"].append(f"memory: {e}")
        regions = []
    info["modules"] = len(modules)
    info["memory"] = region_summary(regions)
    info["security_products"] = sorted({analysis.vendor_of(m["path"]) for m in modules} - {None})

    findings += analysis.module_findings(proc, modules, root)
    findings += analysis.region_findings(proc, regions)
    for r, head in injected_pes(backend, pid, regions):
        findings.append(analysis.injected_pe_finding(proc, r, head))
    if check_hooks and modules:
        try:
            for h in backend.scan_hooks(pid, wanted, modules):
                findings.append(analysis.hook_finding(proc, h))
        except OSError as e:
            info["errors"].append(f"hooks: {e}")
    return findings, info


def run(backend, check_hooks=True, wanted=None, progress=None):
    """Full triage. progress(done, total, label) is called as it goes."""
    t0 = time.time()
    sysinfo = backend.system()
    root = analysis.system_root(sysinfo.get("root"))
    procs = backend.processes()
    by_pid = {p["pid"]: p for p in procs}
    findings = analysis.process_findings(procs, root)

    targets = [p for p in procs if p["pid"] not in (0, 4, sysinfo.get("self_pid"))
               and p["name"].lower() not in SKIP_NAMES]
    steps = len(targets) + 2
    per_proc, skipped = {}, []
    for i, p in enumerate(targets):
        if progress:
            progress(i, steps, f"{p['name']} ({p['pid']})")
        if p.get("access") not in ("full",):
            skipped.append({"pid": p["pid"], "name": p["name"], "reason": "access denied (protected process)"})
            continue
        f, info = scan_process(backend, p, root, check_hooks, wanted)
        findings += f
        per_proc[p["pid"]] = info
        if info["errors"] and not info.get("modules"):
            skipped.append({"pid": p["pid"], "name": p["name"], "reason": "; ".join(info["errors"])})

    if progress:
        progress(len(targets), steps, "hidden processes")
    hidden = backend.hidden()
    findings += analysis.hidden_findings(hidden)

    if progress:
        progress(len(targets) + 1, steps, "network")
    try:
        conns = backend.connections()
    except OSError:
        conns = []
    alive = {h["pid"] for h in hidden}
    findings += analysis.network_findings(conns, by_pid, alive)
    for c in conns:
        c["process"] = by_pid.get(c["pid"], {}).get("name", "?")
        c["flags"] = [r for _, r, _ in analysis.connection_flags(c, c["process"])]

    findings = analysis.aggregate(findings)
    counts = {s: sum(1 for f in findings if f["severity"] == s) for s in analysis.SEVERITIES}
    for p in procs:
        p["findings"] = sum(1 for f in findings if f["pid"] == p["pid"] and f["severity"] != "info")
        p["worst"] = next((s for s in analysis.SEVERITIES
                           if any(f["pid"] == p["pid"] and f["severity"] == s for f in findings)), None)
        if p["pid"] in per_proc:
            p["scan"] = per_proc[p["pid"]]
    if progress:
        progress(steps, steps, "done")
    return {
        "tool": "GhostEye",
        "started": datetime.datetime.fromtimestamp(t0).isoformat(timespec="seconds"),
        "duration_s": round(time.time() - t0, 1),
        "system": sysinfo,
        "options": {"hooks": check_hooks, "modules": wanted or "default"},
        "counts": counts,
        "findings": findings,
        "processes": procs,
        "connections": conns,
        "hidden": hidden,
        "skipped": skipped,
        "techniques": sorted({(m["id"], m["name"]) for f in findings for m in f["mitre"]}),
    }
