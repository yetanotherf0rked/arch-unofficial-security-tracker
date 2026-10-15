import { vercmp } from "./vercmp.js";
import { assess, parsePackageList, GROUPS } from "./assess.js";

const $ = id => document.getElementById(id);
const esc = s => String(s ?? "").replace(/[&<>"']/g, c =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const enc = encodeURIComponent;
const CHIPS = 2;  // issue chips shown on a collapsed row

const REASONS = {
  "below-fix": "Arch's version is below the upstream fix",
  "distro-patch": "other distros patched this exact version; Arch's build predates the issue",
  "distro-patch-rebuilt": "other distros patched this exact version; Arch rebuilt since and might carry the patch",
  "patch-only": "fixed only by distro patches, no upstream release",
  "no-fix": "no fix released anywhere yet",
  "newer-than-assessed": "reported unfixed for older versions; Arch's newer version is unassessed",
  "between-branches": "Arch's release line may not have the fix",
  "arch-snapshot": "Arch builds a VCS snapshot",
  "fix-snapshot": "the fix is an unreleased snapshot",
  "version-scheme": "version schemes differ",
};
const STATUS_LABEL = { vulnerable: "vulnerable", unfixed: "no upstream fix", uncertain: "uncertain" };

// Commands point at wherever this page is served from.
const base = new URL(".", location.href).href;
$("cmdCheck").textContent = `curl -fsSO ${base}arch-cve-check\npython arch-cve-check`;
$("cmdAudit").textContent = `arch-audit --source ${base}all.json\n\n# or permanently, in /etc/arch-audit/settings.toml:\n[network]\nsource = "${base}all.json"`;

let data;
try {
  const resp = await fetch("data/advisories.json", { cache: "no-cache" });
  if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
  data = await resp.json();
} catch (e) {
  $("rows").innerHTML = `<tr><td colspan="5" class="empty">Failed to load data/advisories.json: ${esc(e)}</td></tr>`;
  throw e;
}

// Dates in the viewer's own time zone.
const dateFmt = new Intl.DateTimeFormat(undefined, { year: "numeric", month: "short", day: "numeric" });
const dateTimeFmt = new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" });
const relFmt = new Intl.RelativeTimeFormat(undefined, { numeric: "auto" });
const ts = iso => { const t = Date.parse(iso || ""); return Number.isNaN(t) ? 0 : t; };
const relative = t => {
  const days = Math.round((t - Date.now()) / 86400000);
  if (Math.abs(days) < 1) return relFmt.format(Math.round((t - Date.now()) / 3600000), "hour");
  if (Math.abs(days) < 60) return relFmt.format(days, "day");
  if (Math.abs(days) < 730) return relFmt.format(Math.round(days / 30), "month");
  return relFmt.format(Math.round(days / 365), "year");
};

const pkgbases = Object.entries(data.pkgbases).map(([name, p]) => ({ name, ...p }));
const st = data.stats || {};
const withOpen = pkgbases.filter(p => p.issues.some(i => i.status === "vulnerable")).length;
$("meta").innerHTML =
  `<span><strong>${withOpen}</strong> packages vulnerable with an upstream fix available</span>` +
  `<span><strong>${st.vulnerable ?? 0}</strong> vulnerable · <strong>${st.unfixed ?? 0}</strong> no upstream fix · <strong>${st.uncertain ?? 0}</strong> uncertain</span>` +
  `<span><strong>${st.covered_pkgbases ?? "?"}</strong> of ${st.pkgbases ?? "?"} pkgbases have CVE data</span>` +
  `<span>refreshed <strong>${esc(dateTimeFmt.format(new Date(data.generated_at * 1000)))}</strong></span>`;
$("limitsText").textContent = data.limitations || "";

// ---------------------------------------------------------------------------
// Check a pasted package list
// ---------------------------------------------------------------------------

const cveHref = id => /^CVE-/.test(id) ? `https://www.cve.org/CVERecord?id=${enc(id)}` : `https://osv.dev/vulnerability/${enc(id)}`;

function runCheck() {
  const installed = parsePackageList($("pkglist").value);
  const out = $("result");
  if (!installed.length) {
    out.innerHTML = `<p class="note">Paste the output of <code>pacman -Q</code> first.</p>`;
    return;
  }
  const res = assess(installed, data, $("checkMinor").checked);
  const definite = res.findings.filter(f => f.group !== "uncertain");
  let html = definite.length
    ? `<p class="verdict bad">${new Set(definite.map(f => f.package)).size} of your packages are affected.</p>`
    : `<p class="verdict ok">No known CVE affects your installed versions${res.findings.length ? " (some matches are uncertain, see below)" : ""}.</p>`;
  for (const [group, title] of Object.entries(GROUPS)) {
    const rows = res.findings.filter(f => f.group === group);
    if (!rows.length) continue;
    const nIds = new Set(rows.flatMap(f => f.issues)).size;
    html += `<div class="group"><h4>${esc(title)} — ${rows.length} packages, ${nIds} issues</h4>`;
    for (const f of rows) {
      let what = esc(f.version);
      if (group === "upgrade") what += ` → ${esc(f.repo_version)} <span class="note">(fixed in ${esc(f.fixed)})</span>`;
      else if (group === "vulnerable" && f.upstream_fix.length) what += ` <span class="note">(upstream fix: ${esc(f.upstream_fix.slice(0, 3).join(", "))})</span>`;
      const ids = f.issues.slice(0, 12).map(id => `<a href="${cveHref(id)}" target="_blank" rel="noopener">${esc(id)}</a>`).join(" ")
        + (f.issues.length > 12 ? ` +${f.issues.length - 12} more` : "");
      const why = group !== "upgrade" && f.reasons.length
        ? `<div class="why">${esc(f.reasons.map(r => REASONS[r] || r).join("; "))}</div>` : "";
      html += `<div class="finding"><span class="sev ${esc(f.severity)}">${esc(f.severity)}</span>` +
        `<span><strong class="mono">${esc(f.package)}</strong> <span class="mono">${what}</span></span>` +
        `<div class="ids">${ids}</div>${why}</div>`;
    }
    html += `</div>`;
  }
  const notes = [];
  if (res.foreign.length) notes.push(`${res.foreign.length} packages are not from the official repos (AUR / local builds) and were not checked: ${esc(res.foreign.slice(0, 30).join(", "))}${res.foreign.length > 30 ? " …" : ""}`);
  if (res.uncovered.length) notes.push(`${res.uncovered.length} packages have no CVE records in the tracker's sources, so nothing can be said about them.`);
  if (notes.length) html += `<p class="note">${notes.join("<br>")}</p>`;
  out.innerHTML = html;
}
$("run").addEventListener("click", runCheck);
$("checkMinor").addEventListener("change", () => $("pkglist").value.trim() && runCheck());

// ---------------------------------------------------------------------------
// Browse open issues
// ---------------------------------------------------------------------------

// Same mapping Arch's devtools use for packaging repo paths on GitLab.
const gitlabPath = n => n
  .replace(/([a-zA-Z0-9]+)\+([a-zA-Z]+)/g, "$1-$2").replace(/\+/g, "plus")
  .replace(/[^a-zA-Z0-9_\-.]/g, "-").replace(/[_\-]{2,}/g, "-").replace(/^tree$/, "unix-tree");
const gitlab = p => `https://gitlab.archlinux.org/archlinux/packaging/packages/${gitlabPath(p.name)}`;
const pkgPage = p => {
  const name = (p.packages || []).includes(p.name) ? p.name : (p.packages || [p.name])[0];
  return `https://archlinux.org/packages/${enc(p.repo)}/${enc(p.arch || "x86_64")}/${enc(name)}/`;
};
const safeUrl = u => /^https?:\/\//i.test(u || "") ? u : "";
const issueLinks = i => {
  const links = [];
  if (/^CVE-/.test(i.id)) {
    links.push(["CVE.org", cveHref(i.id)]);
    links.push(["NVD", `https://nvd.nist.gov/vuln/detail/${enc(i.id)}`]);
    links.push(["Debian", `https://security-tracker.debian.org/tracker/${enc(i.id)}`]);
  }
  for (const id of i.sources || []) links.push([id.startsWith("ALPINE") ? "OSV (Alpine)" : "OSV", `https://osv.dev/vulnerability/${enc(id)}`]);
  return links;
};

const filters = {
  q: $("q"), repo: $("repoFilter"), since: $("since"),
  vulnerable: $("showVulnerable"), unfixed: $("showUnfixed"), uncertain: $("showUncertain"), minor: $("showMinor"),
};
let sortKey = "latest", sortDir = -1;
const expanded = new Set();

function render() {
  const term = filters.q.value.trim().toLowerCase();
  const windowMs = Number(filters.since.value) * 86400000;
  const issuesOf = p => p.issues.filter(i => filters[i.status].checked && (filters.minor.checked || !i.minor));
  const latestOf = p => Math.max(0, ...issuesOf(p).map(i => ts(i.published)));

  const items = pkgbases.filter(p => {
    if (filters.repo.value && p.repo !== filters.repo.value) return false;
    const list = issuesOf(p);
    if (!list.length) return false;
    if (windowMs && latestOf(p) < Date.now() - windowMs) return false;
    if (!term) return true;
    if (p.name.toLowerCase().includes(term)) return true;
    if ((p.packages || []).some(n => n.toLowerCase().includes(term))) return true;
    return list.some(i => i.id.toLowerCase().includes(term));
  });

  const keyOf = {
    count: p => issuesOf(p).length, name: p => p.name, version: p => p.version, latest: latestOf,
  }[sortKey];
  items.sort((a, b) => {
    if (sortKey === "version") return sortDir * vercmp(a.version, b.version);
    const va = keyOf(a), vb = keyOf(b);
    return va < vb ? -sortDir : va > vb ? sortDir : 0;
  });
  document.querySelectorAll("th[data-sort]").forEach(th => {
    th.textContent = th.textContent.replace(/ [▴▾]$/, "") + (th.dataset.sort === sortKey ? (sortDir < 0 ? " ▾" : " ▴") : "");
  });

  if (!items.length) {
    $("rows").innerHTML = `<tr><td colspan="5" class="empty">no matches</td></tr>`;
    return;
  }

  $("rows").innerHTML = items.map(p => {
    const list = issuesOf(p).slice().sort((a, b) => ts(b.published) - ts(a.published));
    const key = `${p.repo}/${p.name}`, open = expanded.has(key);
    const chip = i => {
      const title = [STATUS_LABEL[i.status], REASONS[i.reason], i.severity !== "Unknown" ? i.severity : "", i.summary]
        .filter(Boolean).join(" — ");
      return `<a class="cve ${esc(i.status)}" href="${cveHref(i.id)}" target="_blank" rel="noopener" title="${esc(title)}">${esc(i.id)}</a>`;
    };
    const counts = Object.keys(STATUS_LABEL).map(s => {
      const n = list.filter(i => i.status === s).length;
      return n ? `<span class="count ${s}" title="${esc(STATUS_LABEL[s])}">${n} ${esc(STATUS_LABEL[s])}</span>` : "";
    }).join("");
    const toggle = `<button class="more" data-key="${esc(key)}" aria-expanded="${open}">${
      open ? "hide" : list.length > CHIPS ? `+${list.length - CHIPS} · details` : "details"}</button>`;

    const subs = (p.packages || []).filter(x => x !== p.name);
    const upstream = safeUrl(p.url);
    const links = [
      `<a href="${gitlab(p)}" target="_blank" rel="noopener">PKGBUILD</a>`,
      `<a href="${gitlab(p)}/-/issues" target="_blank" rel="noopener">issues</a>`,
      upstream ? `<a href="${esc(upstream)}" target="_blank" rel="noopener">upstream</a>` : "",
    ].filter(Boolean).join(" · ");
    const subHtml = subs.length
      ? `<div class="subpkgs">${esc(subs.slice(0, 4).join(", "))}${subs.length > 4 ? ` +${subs.length - 4}` : ""}</div>` : "";
    const fixes = [...new Set(list.flatMap(i => i.fix || []))].sort(vercmp);
    const fixText = fixes.slice(0, 3).join(", ") + (fixes.length > 3 ? " …" : "");
    const latest = latestOf(p);
    const built = p.builddate ? `Arch build: ${dateTimeFmt.format(new Date(p.builddate * 1000))}` : "";

    let html = `<tr>
      <td class="when">${latest ? `${esc(dateFmt.format(new Date(latest)))}<small>${esc(relative(latest))}</small>` : "—"}</td>
      <td class="pkg mono"><a class="name" href="${pkgPage(p)}" target="_blank" rel="noopener">${esc(p.name)}</a> <span class="badge-repo">${esc(p.repo)}</span>${subHtml}<div class="links">${links}</div></td>
      <td class="mono nowrap" title="${esc(built)}">${esc(p.version)}</td>
      <td class="mono" style="color:var(--muted);font-size:12px">${esc(fixText) || "—"}</td>
      <td><div class="counts">${counts}</div><div class="cve-line" style="margin-top:4px">${list.slice(0, CHIPS).map(chip).join("")}${toggle}</div></td>
    </tr>`;
    if (open) {
      html += `<tr class="detail"><td colspan="5"><table>
        <thead><tr><th>Issue</th><th>Published</th><th>Status</th><th>Severity</th><th>Fix</th><th>Summary</th><th>Links</th></tr></thead>
        <tbody>${list.map(i => {
          const t = ts(i.published);
          const own = issueLinks(i);
          const known = new Set(own.map(([, u]) => u.replace(/\/$/, "")));
          const refs = own.map(([label, u]) => `<a href="${u}" target="_blank" rel="noopener">${esc(label)}</a>`)
            .concat((i.refs || []).map(safeUrl).filter(u => u && !known.has(u.replace(/\/$/, ""))).slice(0, 3)
              .map((u, n) => `<a href="${esc(u)}" target="_blank" rel="noopener" title="${esc(u)}">ref ${n + 1}</a>`));
          const fix = (i.fix || []).join(", ") || (i.patched_in ? `distro patch: ${i.patched_in.join(", ")}` : "—");
          return `<tr>
            <td class="mono">${chip(i)}</td>
            <td class="when">${t ? esc(dateFmt.format(new Date(t))) : "—"}</td>
            <td><span class="tag" title="${esc(REASONS[i.reason] || "")}">${esc(STATUS_LABEL[i.status])}</span>${i.minor ? ` <span class="tag" title="Debian rates this issue unimportant">unimportant</span>` : ""}</td>
            <td><span class="sev ${esc(i.severity)}" title="${esc(i.vector || "")}">${esc(i.severity)}${i.score ? ` ${esc(i.score)}` : ""}</span></td>
            <td class="mono">${esc(fix)}</td>
            <td class="summary">${esc(i.summary) || "—"}<div class="note" style="margin:2px 0 0">${esc(REASONS[i.reason] || "")}</div></td>
            <td class="refs">${refs.join("")}</td>
          </tr>`;
        }).join("")}</tbody></table></td></tr>`;
    }
    return html;
  }).join("");
}

$("rows").addEventListener("click", e => {
  const btn = e.target.closest("button.more");
  if (!btn) return;
  const key = btn.dataset.key;
  expanded.has(key) ? expanded.delete(key) : expanded.add(key);
  render();
});
document.querySelectorAll("th[data-sort]").forEach(th => {
  th.addEventListener("click", () => {
    const k = th.dataset.sort;
    if (sortKey === k) sortDir = -sortDir;
    else { sortKey = k; sortDir = (k === "count" || k === "latest") ? -1 : 1; }
    render();
  });
});
filters.q.addEventListener("input", render);
Object.values(filters).filter(el => el !== filters.q).forEach(el => el.addEventListener("change", render));
render();
