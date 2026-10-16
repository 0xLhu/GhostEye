/* GhostEye web UI: all detection runs in Python; this file only renders. */
"use strict";

const S = { system: null, job: null, report: null, procs: null, net: null, detail: {}, hooks: {}, strings: {},
            fSev: new Set(["high", "medium", "low"]), fText: "", pText: "", nSusp: false };
const SEV = ["high", "medium", "low", "info"];
const $ = (s) => document.querySelector(s);
const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const hex = (n) => (n == null ? "" : "0x" + Number(n).toString(16));
const size = (n) => n >= 1 << 30 ? (n / (1 << 30)).toFixed(1) + " GB" : n >= 1 << 20 ? (n / (1 << 20)).toFixed(1) + " MB" : n >= 1024 ? Math.round(n / 1024) + " KB" : n + " B";

async function api(url, body) {
  const r = await fetch(url, body === undefined ? {} : { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
  const d = await r.json().catch(() => ({}));
  if (!r.ok && r.status !== 409) throw new Error(d.error || r.statusText);
  return d;
}
function toast(m, err) {
  const t = $("#toast"); t.textContent = m; t.className = "toast" + (err ? " err" : ""); t.hidden = false;
  clearTimeout(toast.t); toast.t = setTimeout(() => (t.hidden = true), err ? 5000 : 2200);
}
const sevBadge = (s) => `<span class="sev ${s}">${s}</span>`;
const attack = (m) => m.map((x) => `<a class="tag att" target="_blank" rel="noopener" href="https://attack.mitre.org/techniques/${x.id.replace(".", "/")}/" title="${esc(x.name)}">${x.id}</a>`).join("");

/* ── routing ─────────────────────────────────────────────────────────── */

function route() {
  const [view, a, b] = (location.hash.slice(1) || "overview").split("/");
  return { view, pid: a ? +a : null, tab: b || "summary" };
}
window.addEventListener("hashchange", render);
const go = (h) => (location.hash = h);

/* ── chrome ──────────────────────────────────────────────────────────── */

function chrome() {
  const s = S.system;
  $("#host").innerHTML = s ? `
    ${s.mode === "demo" ? '<span class="tag warn">DEMO: simulated data</span>' : ""}
    <b>${esc(s.hostname)}</b><span>${esc(s.os)}</span>
    <span class="tag ${s.admin ? "ok" : "bad"}">${s.admin ? "Administrator" : "Not admin"}</span>
    <span class="tag ${s.debug_privilege ? "ok" : "bad"}">SeDebugPrivilege ${s.debug_privilege ? "on" : "off"}</span>` : "";
  const running = S.job && S.job.running;
  $("#topActions").innerHTML = `
    ${S.report ? `<a class="btn" href="/api/export.json" download>⬇ JSON</a><a class="btn" href="/api/export.html" target="_blank">Report</a>` : ""}
    <button class="btn primary" data-act="triage" ${running ? "disabled" : ""}>${running ? "Scanning…" : S.report ? "Re-scan" : "Run triage"}</button>`;
  const r = route();
  const c = S.report ? S.report.counts : null;
  const items = [
    ["overview", "Overview", ""],
    ["findings", "Findings", c ? `<span class="count ${c.high ? "high" : ""}">${c.high + c.medium + c.low}</span>` : ""],
    ["processes", "Processes", S.procs ? `<span class="count">${S.procs.length}</span>` : ""],
    ["network", "Network", ""],
  ];
  $("#nav").innerHTML = items.map(([id, label, extra]) =>
    `<button class="${r.view === id || (r.view === "process" && id === "processes") ? "on" : ""}" data-go="#${id}"><span>${label}</span>${extra}</button>`).join("");
}

/* ── views ───────────────────────────────────────────────────────────── */

const VIEWS = {};

VIEWS.overview = () => {
  const s = S.system, R = S.report, job = S.job || {};
  const warn = [];
  if (s.mode === "live" && !s.admin) warn.push(["bad", "Not running as Administrator. Most processes cannot be inspected. Restart the terminal with “Run as administrator”."]);
  else if (s.mode === "live" && !s.debug_privilege) warn.push(["warn", "SeDebugPrivilege could not be enabled, system processes will be skipped."]);
  if (s.mode === "demo") warn.push(["info", "Demo mode: a simulated workstation with planted indicators (ETW/AMSI patching, reflective injection, masquerading, hidden process). Run on Windows as Administrator for live data."]);
  const pct = job.total ? Math.round((job.done / job.total) * 100) : 0;
  let body;
  if (job.running) {
    body = `<div class="card"><h3>Scanning…</h3><div class="progress"><div style="width:${pct}%"></div></div>
      <div class="mono" style="color:var(--muted)">${pct}% · ${esc(job.label)}</div></div>`;
  } else if (!R) {
    body = `<div class="card hero"><div><div class="verdict">Ready to inspect this machine</div>
      <div style="color:var(--muted);max-width:640px">The triage reads every process (read-only): process tree, loaded DLLs, memory protections, injected PE images, inline hooks in ntdll / kernel32 / kernelbase / amsi, hidden processes and network connections. Nothing is written or dumped.</div></div>
      <div style="display:flex;flex-direction:column;gap:8px"><button class="btn primary" data-act="triage">▶ Run full triage</button>
      <button class="btn" data-act="triage-fast">Quick triage (no hooks)</button></div></div>
      ${job.error ? `<div class="alert bad">Last scan failed: ${esc(job.error)}</div>` : ""}`;
  } else {
    const c = R.counts;
    const verdict = c.high ? ["var(--high)", `${c.high} high-severity finding${c.high > 1 ? "s" : ""}, investigate`] :
      c.medium ? ["var(--medium)", "Suspicious activity, review the findings"] : ["var(--ok)", "No significant indicator found"];
    const cats = {};
    R.findings.filter((f) => f.severity !== "info").forEach((f) => (cats[f.category] = (cats[f.category] || 0) + 1));
    const maxCat = Math.max(1, ...Object.values(cats));
    body = `
      <div class="card hero"><div><div class="verdict" style="color:${verdict[0]}">${verdict[1]}</div>
        <div style="color:var(--muted)">Scan of ${R.processes.length} processes · ${R.connections.length} sockets · ${R.duration_s}s · ${esc(R.started.replace("T", " "))}${R.skipped.length ? ` · ${R.skipped.length} protected process(es) not inspected` : ""}</div></div></div>
      <div class="grid g4" style="margin-bottom:18px">${SEV.map((sv) => `<div class="kpi" data-sev="${sv}"><div class="k">${sv}</div><div class="v" style="color:var(--${sv})">${c[sv]}</div></div>`).join("")}</div>
      <div class="grid g2">
        <div class="card"><h3>Top findings</h3>${R.findings.filter((f) => f.severity === "high").slice(0, 6).map(findingCard).join("") || '<div class="empty">No high-severity finding.</div>'}</div>
        <div>
          <div class="card"><h3>By category</h3><div class="bars">${Object.entries(cats).sort((a, b) => b[1] - a[1]).map(([k, v]) =>
            `<div class="bar"><span>${esc(k)}</span><div class="track"><div style="width:${(v / maxCat) * 100}%;background:var(--accent)"></div></div><b>${v}</b></div>`).join("") || '<div class="empty">Nothing</div>'}</div></div>
          <div class="card"><h3>MITRE ATT&amp;CK techniques observed</h3>${R.techniques.map(([id, name]) =>
            `<div style="margin:4px 0">${attack([{ id, name }])} <span style="color:var(--muted)">${esc(name)}</span></div>`).join("") || '<div class="empty">None</div>'}</div>
          ${R.skipped.length ? `<div class="card"><h3>Not inspected</h3>${R.skipped.map((x) => `<div class="mono" style="color:var(--muted)">${esc(x.name)} (${x.pid}): ${esc(x.reason)}</div>`).join("")}</div>` : ""}
        </div>
      </div>`;
  }
  return `<div class="head"><div><h2>Overview</h2><p class="lead">Live, read-only triage of running processes.</p></div></div>
    ${warn.map(([k, t]) => `<div class="alert ${k}">${esc(t)}</div>`).join("")}${body}`;
};

function findingCard(f) {
  const ev = Object.entries(f.evidence || {}).map(([k, v]) => `<b>${esc(k)}</b><span>${esc(Array.isArray(v) ? v.join(", ") : v)}</span>`).join("");
  const proc = f.pid != null ? `<span class="p" data-go="#process/${f.pid}">${esc(f.process)} <span class="pid">${f.pid}</span></span>` : `<span style="color:var(--muted)">${esc(f.process || "")}</span>`;
  return `<div class="finding ${f.severity}"><div class="t">${sevBadge(f.severity)} ${esc(f.title)} ${attack(f.mitre)}</div>
    <div class="d">${proc} · ${esc(f.detail)}</div>${ev ? `<div class="ev">${ev}</div>` : ""}</div>`;
}

VIEWS.findings = () => {
  const R = S.report;
  if (!R) return needScan("Findings");
  const q = S.fText.toLowerCase();
  const list = R.findings.filter((f) => S.fSev.has(f.severity) && (!q || JSON.stringify(f).toLowerCase().includes(q)));
  return `<div class="head"><div><h2>Findings</h2><p class="lead">${R.findings.length} total. Click a process name to inspect it.</p></div></div>
    <div class="filters">${SEV.map((s) => `<button class="chip ${S.fSev.has(s) ? "on" : ""}" data-fsev="${s}">${s} · ${R.counts[s]}</button>`).join("")}
      <input class="search" id="fText" placeholder="Filter: process, technique, DLL, function…" value="${esc(S.fText)}"></div>
    <div id="fList">${list.map(findingCard).join("") || '<div class="empty">No finding matches.</div>'}</div>`;
};

function needScan(title) {
  return `<div class="head"><div><h2>${title}</h2></div></div><div class="empty">Run a triage first.<br><br><button class="btn primary" data-act="triage">▶ Run triage</button></div>`;
}

function tree(procs) {
  const by = new Map(procs.map((p) => [p.pid, p]));
  const kids = new Map();
  const roots = [];
  procs.forEach((p) => {
    const parent = by.get(p.ppid);
    const valid = parent && p.pid !== p.ppid && !(p.created && parent.created && parent.created > p.created);
    if (valid) (kids.get(p.ppid) || kids.set(p.ppid, []).get(p.ppid)).push(p);
    else roots.push(p);
  });
  const out = [];
  const walk = (p, depth, last) => {
    out.push({ p, depth, last });
    const k = (kids.get(p.pid) || []).sort((a, b) => a.pid - b.pid);
    k.forEach((c, i) => walk(c, depth + 1, i === k.length - 1));
  };
  roots.sort((a, b) => a.pid - b.pid).forEach((r) => walk(r, 0, true));
  return out;
}

VIEWS.processes = () => {
  if (!S.procs) return `<div class="empty">Loading…</div>`;
  const q = S.pText.toLowerCase();
  const rows = q ? S.procs.filter((p) => `${p.name} ${p.pid} ${p.path}`.toLowerCase().includes(q)).map((p) => ({ p, depth: 0 })) : tree(S.procs);
  return `<div class="head"><div><h2>Processes</h2><p class="lead">Process tree. Click a process for memory, DLLs, hooks and strings.</p></div>
    <input class="search" id="pText" placeholder="Search name, PID or path" value="${esc(S.pText)}"></div>
    <div class="card wrap" style="padding:0"><table><thead><tr><th>Process</th><th>PID</th><th>Path</th><th>Threads</th><th>Access</th><th>Findings</th></tr></thead><tbody>
    ${rows.map(({ p, depth }) => `<tr class="click ${p.worst ? "sev-" + p.worst : ""}" data-go="#process/${p.pid}">
      <td><span class="tree-name"><span class="indent">${depth ? "  ".repeat(depth - 1) + "└ " : ""}</span><b>${esc(p.name)}</b></span></td>
      <td class="pid">${p.pid}</td><td class="mono" style="color:var(--muted);max-width:420px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${esc(p.path)}">${esc(p.path)}</td>
      <td>${p.threads}</td><td>${p.access === "full" ? '<span class="tag ok">full</span>' : `<span class="tag">${esc(p.access)}</span>`}</td>
      <td>${p.worst ? sevBadge(p.worst) + (p.findings ? ` ${p.findings}` : "") : ""}</td></tr>`).join("")}
    </tbody></table></div>`;
};

VIEWS.process = () => {
  const { pid, tab } = route();
  const d = S.detail[pid];
  if (!d) { loadDetail(pid); return `<div class="empty">Loading PID ${pid}…</div>`; }
  if (d.error) return `<div class="alert bad">${esc(d.error)}</div>`;
  const p = d.process;
  const tabs = [["summary", "Summary"], ["memory", `Memory (${d.regions.length})`], ["modules", `DLLs (${d.modules.length})`], ["hooks", "Hooks"], ["strings", "Strings"]];
  const parent = (S.procs || []).find((x) => x.pid === p.ppid);
  return `<div class="head"><div><div style="color:var(--muted);font-size:12px"><a href="#processes">Processes</a> / ${p.pid}</div>
      <h2>${esc(p.name)} <span class="pid">PID ${p.pid}</span></h2>
      <p class="lead mono">${esc(p.path || "path unavailable")}</p></div>
      <div>${parent ? `Parent: <a href="#process/${parent.pid}">${esc(parent.name)} (${parent.pid})</a>` : `<span style="color:var(--muted)">Parent ${p.ppid} (exited)</span>`}
      ${p.wow64 ? '<span class="tag">32-bit</span>' : ""}</div></div>
    ${d.errors.length ? `<div class="alert warn">${d.errors.map(esc).join("<br>")} (protected process or insufficient rights).</div>` : ""}
    <div class="tabs">${tabs.map(([id, l]) => `<button class="${tab === id ? "on" : ""}" data-go="#process/${pid}/${id}">${l}</button>`).join("")}</div>
    ${PTABS[tab] ? PTABS[tab](d, pid) : ""}`;
};

function memmap(regions) {
  if (!regions.length) return "";
  const total = regions.reduce((a, r) => a + Math.log2(r.size + 1), 0);
  return `<div class="memmap">${regions.map((r) =>
    `<span class="${r.type_name} ${r.exec ? "exec" : ""} ${r.flag ? "flag" : ""}" style="width:${(Math.log2(r.size + 1) / total) * 100}%" title="${hex(r.base)} · ${size(r.size)} · ${r.type_name} ${r.protect_name}${r.flag ? " · " + r.flag : ""}"></span>`).join("")}</div>
    <div class="legend"><span><i style="background:var(--img)"></i>Image</span><span><i style="background:var(--map)"></i>Mapped</span>
    <span><i style="background:var(--priv);opacity:.55"></i>Private</span><span><i style="background:var(--high)"></i>RWX / unbacked exec</span><span>Hatched = executable · width ∝ log(size)</span></div>`;
}

const PTABS = {
  summary: (d) => {
    const ex = d.regions.filter((r) => r.flag);
    const bad = d.modules.filter((m) => m.risk === "temp" || m.risk === "other");
    const sec = [...new Set(d.modules.map((m) => m.vendor).filter(Boolean))];
    return `<div class="grid g4" style="margin-bottom:18px">
        <div class="kpi" data-go="#process/${d.process.pid}/memory"><div class="k">Committed memory</div><div class="v" style="font-size:22px">${size(d.regions.reduce((a, r) => a + r.size, 0))}</div></div>
        <div class="kpi" data-go="#process/${d.process.pid}/memory"><div class="k">RWX / unbacked exec</div><div class="v" style="color:${ex.length ? "var(--medium)" : "var(--ok)"}">${ex.length}</div></div>
        <div class="kpi" data-go="#process/${d.process.pid}/modules"><div class="k">DLLs outside system paths</div><div class="v" style="color:${bad.length ? "var(--medium)" : "var(--ok)"}">${bad.length}</div></div>
        <div class="kpi"><div class="k">Security products</div><div style="margin-top:6px">${sec.map((v) => `<span class="tag ok">${esc(v)}</span>`).join("") || '<span style="color:var(--muted)">none detected</span>'}</div></div>
      </div>
      <div class="card"><h3>Memory layout</h3>${memmap(d.regions)}</div>
      <div class="card"><h3>Findings for this process</h3>${d.findings.map(findingCard).join("") || `<div class="empty">${S.report ? "No finding." : "Run a triage to see findings."}</div>`}</div>`;
  },
  memory: (d) => `<div class="card">${memmap(d.regions)}</div><div class="card wrap" style="padding:0"><table>
    <thead><tr><th>Base</th><th>Size</th><th>Type</th><th>Protection</th><th>Allocation</th><th>File / flag</th></tr></thead><tbody>
    ${d.regions.map((r) => `<tr class="${r.flag ? "sev-medium" : ""}"><td class="mono">${hex(r.base)}</td><td class="mono">${size(r.size)}</td>
      <td><span class="tag">${r.type_name}</span></td><td class="mono" style="color:${r.exec ? "var(--medium)" : "inherit"}">${r.protect_name}</td>
      <td class="mono" style="color:var(--muted)">${hex(r.alloc_base)}</td>
      <td class="mono">${r.flag ? `<span class="tag bad">${r.flag}</span> ` : ""}<span style="color:var(--muted)">${esc((r.mapped || "").split("\\").pop())}</span></td></tr>`).join("")}
    </tbody></table></div>`,
  modules: (d) => `<div class="card wrap" style="padding:0"><table>
    <thead><tr><th>Module</th><th>Base</th><th>Size</th><th>Location</th></tr></thead><tbody>
    ${d.modules.map((m) => `<tr class="${m.risk === "temp" ? "sev-high" : m.risk === "other" ? "sev-medium" : ""}">
      <td><b>${esc(m.name)}</b><div class="mono" style="color:var(--muted)">${esc(m.path)}</div></td>
      <td class="mono">${hex(m.base)}</td><td class="mono">${size(m.size)}</td>
      <td>${m.vendor ? `<span class="tag ok">${esc(m.vendor)}</span>` : m.risk === "trusted" ? '<span class="tag">system / program files</span>' :
        `<span class="tag ${m.risk === "temp" ? "bad" : "warn"}">${esc(m.why)}</span>`}</td></tr>`).join("")}
    </tbody></table></div>`,
  hooks: (d, pid) => {
    const h = S.hooks[pid];
    if (!h) return `<div class="card"><h3>Inline hook scan</h3><p style="color:var(--muted)">Compares the first bytes of every exported function in ntdll, kernelbase, kernel32 and amsi with the files on disk (relocations excluded), then decodes where patched code jumps to.</p>
      <button class="btn primary" data-act="hooks" data-pid="${pid}">Scan hooks</button></div>`;
    if (h === "loading") return `<div class="empty">Scanning exports…</div>`;
    if (h.error) return `<div class="alert bad">${esc(h.error)}</div>`;
    if (!h.length) return `<div class="card"><h3>No modified function</h3><p style="color:var(--muted)">All scanned exports match the files on disk.</p><button class="btn small" data-act="hooks" data-pid="${pid}">Re-scan</button></div>`;
    return `<div class="card wrap" style="padding:0"><table><thead><tr><th>Function</th><th>Patch</th><th>Bytes (disk → memory)</th><th>Destination</th><th>Assessment</th></tr></thead><tbody>
      ${h.map((x) => `<tr class="sev-${x.finding.severity}"><td><b>${esc(x.function)}</b><div class="mono" style="color:var(--muted)">${esc(x.module_name)} · ${hex(x.address)}</div></td>
        <td class="mono">${esc(x.desc)}</td><td class="mono" style="font-size:11.5px"><span style="color:var(--muted)">${esc(x.disk.slice(0, 24))}</span><br>${esc(x.memory.slice(0, 24))}</td>
        <td class="mono">${x.dest != null ? hex(x.dest) : "-"}<div style="color:var(--muted)">${esc((x.owner || "").split("\\").pop())}</div></td>
        <td>${sevBadge(x.finding.severity)} ${esc(x.finding.title)}</td></tr>`).join("")}</tbody></table></div>`;
  },
  strings: (d, pid) => {
    const st = S.strings[pid] || { q: "", tagged: true };
    const res = st.res;
    return `<div class="card"><div class="filters" style="margin:0">
        <input class="search" id="sQ" placeholder="Contains…" value="${esc(st.q)}">
        <label style="color:var(--muted)"><input type="checkbox" id="sTag" ${st.tagged ? "checked" : ""}> Only interesting (URL, IP, command, registry, evasion…)</label>
        <button class="btn primary" data-act="strings" data-pid="${pid}">Extract</button></div>
        <div style="color:var(--muted);font-size:12px;margin-top:6px">Private and mapped memory, ASCII + UTF-16, min. 5 chars.</div></div>
      ${res === "loading" ? '<div class="empty">Reading memory…</div>' : res && res.error ? `<div class="alert bad">${esc(res.error)}</div>` : res ? `
        <div style="color:var(--muted);margin-bottom:8px">${res.strings.length} string(s)${res.truncated ? " (truncated)" : ""} · ${size(res.bytes_scanned)} scanned</div>
        <div class="card wrap" style="padding:0"><table><thead><tr><th>Address</th><th>Enc.</th><th>Tags</th><th>String</th></tr></thead><tbody>
        ${res.strings.map((s) => `<tr class="str-row"><td>${hex(s.address)}</td><td>${s.encoding}</td><td>${s.tags.map((t) => `<span class="tag ${["command", "evasion"].includes(t) ? "bad" : "att"}">${t}</span>`).join("")}</td><td>${esc(s.text)}</td></tr>`).join("")}
        </tbody></table></div>` : ""}`;
  },
};

VIEWS.network = () => {
  if (!S.net) { loadNet(); return `<div class="empty">Loading connections…</div>`; }
  const rows = S.net.filter((c) => !S.nSusp || c.flags.length);
  return `<div class="head"><div><h2>Network</h2><p class="lead">TCP and UDP endpoints (IPv4 + IPv6) with their owning process.</p></div>
    <div class="filters" style="margin:0"><button class="chip ${S.nSusp ? "on" : ""}" data-act="nsusp">Flagged only · ${S.net.filter((c) => c.flags.length).length}</button>
    <button class="btn small" data-act="net-refresh">↻ Refresh</button></div></div>
    <div class="card wrap" style="padding:0"><table><thead><tr><th>Proto</th><th>Local</th><th>Remote</th><th>State</th><th>Process</th><th>Flags</th></tr></thead><tbody>
    ${rows.map((c) => `<tr class="${c.flags.length ? "sev-medium" : ""}"><td>${c.proto.toUpperCase()}</td><td class="mono">${esc(c.local)}</td><td class="mono">${esc(c.remote)}</td>
      <td>${esc(c.state)}</td><td>${c.pid ? `<a href="#process/${c.pid}">${esc(c.process)}</a> <span class="pid">${c.pid}</span>` : '<span class="pid">0</span>'}</td>
      <td>${c.flags.map((f) => `<span class="tag warn">${esc(f)}</span>`).join("")}</td></tr>`).join("")}
    </tbody></table></div>`;
};

/* ── data loading ────────────────────────────────────────────────────── */

async function loadDetail(pid) {
  try { S.detail[pid] = await api(`/api/process/${pid}`); }
  catch (e) { S.detail[pid] = { error: e.message }; }
  render();
}
async function loadNet() {
  try { S.net = await api("/api/network"); } catch (e) { S.net = []; toast(e.message, true); }
  render();
}
async function loadProcs() {
  try { S.procs = await api("/api/processes"); } catch (e) { toast(e.message, true); }
  render();
}

async function triage(hooks = true) {
  try {
    S.job = await api("/api/triage", { hooks });
    render();
    poll();
  } catch (e) { toast(e.message, true); }
}
async function poll() {
  S.job = await api("/api/job");
  if (S.job.running) { render(); return setTimeout(poll, 500); }
  const st = await api("/api/state");
  S.report = st.report; S.procs = st.report ? st.report.processes : S.procs;
  S.net = st.report ? st.report.connections : S.net;
  S.detail = {};
  if (S.job.error) toast("Scan failed: " + S.job.error, true);
  else toast("Triage complete");
  render();
}

/* ── events ──────────────────────────────────────────────────────────── */

document.addEventListener("click", async (ev) => {
  const g = ev.target.closest("[data-go]");
  if (g && !ev.target.closest("a")) return go(g.dataset.go);
  const sv = ev.target.closest("[data-sev]");
  if (sv) { S.fSev = new Set([sv.dataset.sev]); return go("#findings"); }
  const fs = ev.target.closest("[data-fsev]");
  if (fs) { const s = fs.dataset.fsev; S.fSev.has(s) ? S.fSev.delete(s) : S.fSev.add(s); return render(); }
  const a = ev.target.closest("[data-act]");
  if (!a) return;
  const act = a.dataset.act, pid = +a.dataset.pid;
  if (act === "triage") triage(true);
  if (act === "triage-fast") triage(false);
  if (act === "nsusp") { S.nSusp = !S.nSusp; render(); }
  if (act === "net-refresh") { S.net = null; render(); }
  if (act === "hooks") {
    S.hooks[pid] = "loading"; render();
    try { S.hooks[pid] = await api(`/api/process/${pid}/hooks`, {}); } catch (e) { S.hooks[pid] = { error: e.message }; }
    render();
  }
  if (act === "strings") {
    const q = $("#sQ").value, tagged = $("#sTag").checked;
    S.strings[pid] = { q, tagged, res: "loading" }; render();
    try { S.strings[pid].res = await api(`/api/process/${pid}/strings?q=${encodeURIComponent(q)}&tagged=${tagged ? 1 : 0}`); }
    catch (e) { S.strings[pid].res = { error: e.message }; }
    render();
  }
});

document.addEventListener("input", (ev) => {
  if (ev.target.id === "fText") {
    S.fText = ev.target.value;
    const R = S.report, q = S.fText.toLowerCase();
    $("#fList").innerHTML = R.findings.filter((f) => S.fSev.has(f.severity) && (!q || JSON.stringify(f).toLowerCase().includes(q))).map(findingCard).join("") || '<div class="empty">No finding matches.</div>';
  }
  if (ev.target.id === "pText") {
    S.pText = ev.target.value;
    const pos = ev.target.selectionStart;
    render();
    const el = $("#pText"); el.focus(); el.setSelectionRange(pos, pos);
  }
});
document.addEventListener("keydown", (ev) => {
  if (ev.key === "Enter" && ev.target.id === "sQ") document.querySelector('[data-act="strings"]').click();
});

function render() {
  if (!S.system) return;
  chrome();
  const r = route();
  $("#main").innerHTML = (VIEWS[r.view] || VIEWS.overview)();
}

(async () => {
  try {
    const st = await api("/api/state");
    S.system = st.system; S.job = st.job; S.report = st.report;
    render();
    if (st.job.running) poll();
    if (st.report) { S.procs = st.report.processes; S.net = st.report.connections; render(); }
    else loadProcs();
  } catch (e) { toast("Cannot reach GhostEye: " + e.message, true); }
})();
