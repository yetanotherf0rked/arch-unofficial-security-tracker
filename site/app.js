// The page: the feed's open issues, and a `pacman -Q` checker that runs here.
// norm / key / affects / assess mirror arch_cve_check.py (tests/site.test.mjs).
import { vercmp } from "./vercmp.js";

export function norm(v) {
  v = v.replace(/^((?:19|20)\d\d)[._-]?(\d\d)[._-]?(\d\d)(?!\d)/, "$1$2$3");
  v = v.replace(/[-_.]stable$/i, "");
  v = v.replace(/[-_.~]?(alpha|beta|pre|rc)(?=\d|$)/i, "$1");
  v = v.replaceAll("~", "").replaceAll("-", ".").replaceAll("_", ".");
  return v.replace(/(?<=\d)\.?p(?=\d)/g, ".p");
}

export function key(version) {
  const i = version.lastIndexOf(":");
  const epoch = i >= 0 ? version.slice(0, i) : "", rest = version.slice(i + 1);
  const pkgver = rest.includes("-") ? rest.slice(0, rest.lastIndexOf("-")) : rest;
  return epoch ? `${epoch}:${norm(pkgver)}` : norm(pkgver);
}

export function affects(version, issue) {
  if ("since" in issue) return vercmp(version, issue.since) < 0;
  if ("fixed" in issue) return vercmp(key(version), issue.fixed) < 0;
  if ("upto" in issue) return vercmp(key(version), issue.upto) <= 0;
  return true;
}

export const GROUPS = {
  upgrade: "Fixed in the repos: upgrade with pacman -Syu",
  vulnerable: "Vulnerable: upstream has a fix, the Arch package does not have it yet",
  unfixed: "Vulnerable: no upstream fix known",
  uncertain: "Possibly affected: the sources do not cover this version",
};

export function assess(installed, feed, minor = false) {
  const findings = [], foreign = [], nodata = [];
  for (const [name, version] of installed) {
    const base = feed.packages[name];
    if (base === undefined) { foreign.push(name); continue; }
    const entry = feed.pkgbases[base];
    if (!entry) { nodata.push(name); continue; }
    const groups = {};
    for (const i of entry.issues) {
      if ((i.minor && !minor) || !affects(version, i)) continue;
      (groups[i.status === "fixed" ? "upgrade" : i.status] ||= []).push(i.id);
    }
    for (const [group, issues] of Object.entries(groups)) findings.push({ package: name, version, group, repo: entry.version, issues });
  }
  const order = Object.keys(GROUPS);
  findings.sort((a, b) => order.indexOf(a.group) - order.indexOf(b.group) || a.package.localeCompare(b.package));
  return { findings, foreign, nodata };
}

// --- page -------------------------------------------------------------------

const $ = id => document.getElementById(id);
const esc = s => String(s).replace(/[&<>"]/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c]);
const cves = ids => ids.map(id => `<a href="https://security-tracker.debian.org/tracker/${id}">${id}</a>`).join(" ");

async function main() {
  if (typeof document === "undefined") return;
  const site = new URL(".", location.href).href;
  $("cmdCheck").textContent = `curl -fsSO ${site}arch-cve-check\npython arch-cve-check`;
  $("cmdAudit").textContent = `arch-audit --source ${site}all.json`;
  const feed = await (await fetch("data/advisories.json")).json();
  const hours = (Date.now() / 1000 - feed.generated_at) / 3600, s = feed.stats;
  $("meta").innerHTML = `<span class="${hours > 24 ? "stale" : ""}">data from ${new Date(feed.generated_at * 1000).toLocaleString()}` +
    `${hours > 24 ? " (stale)" : ""}</span><span><strong>${s.vulnerable}</strong> vulnerable · <strong>${s.unfixed}</strong> no fix known · ` +
    `<strong>${s.uncertain}</strong> uncertain</span><span>${s.covered} of ${s.pkgbases} pkgbases have CVE data</span>`;

  const render = () => {
    const q = $("q").value.trim().toLowerCase(), unc = $("showUncertain").checked, rows = [];
    for (const [base, b] of Object.entries(feed.pkgbases).sort()) {
      const by = st => b.issues.filter(i => i.status === st && !i.minor).map(i => i.id);
      const [v, u, c] = [by("vulnerable"), by("unfixed"), unc ? by("uncertain") : []];
      if (!(v.length + u.length + c.length)) continue;
      if (q && !base.includes(q) && ![...v, ...u, ...c].some(id => id.toLowerCase().includes(q))) continue;
      rows.push(`<tr><td><strong>${esc(base)}</strong></td><td class="mono">${esc(b.version)}</td><td>${esc(b.source)}</td>` +
        `<td class="ids">${cves(v)}</td><td class="ids">${cves(u)}</td><td class="ids">${cves(c)}</td></tr>`);
    }
    $("rows").innerHTML = rows.join("") || `<tr><td colspan="6">nothing matches</td></tr>`;
  };
  $("q").oninput = $("showUncertain").onchange = render;
  render();

  $("run").onclick = () => {
    const installed = $("pkglist").value.split(/\r?\n/).map(l => l.trim().split(/\s+/)).filter(p => p.length >= 2);
    const r = assess(installed, feed, $("minor").checked);
    let out = `<p class="verdict ${r.findings.length ? "bad" : "ok"}">${r.findings.length ? `${new Set(r.findings.map(f => f.package)).size} packages affected` : "No known CVE affects these versions."}</p>`;
    for (const [group, title] of Object.entries(GROUPS)) {
      const rows = r.findings.filter(f => f.group === group);
      if (rows.length) out += `<h4>${title}</h4>` + rows.map(f => `<div><strong>${esc(f.package)}</strong> <span class="mono">${esc(f.version)}${group === "upgrade" ? " → " + esc(f.repo) : ""}</span><div class="ids">${cves(f.issues)}</div></div>`).join("");
    }
    const unchecked = r.nodata.length + r.foreign.length;
    if (!r.findings.length) out = `<p class="verdict ok">No known CVE affects the ${installed.length - unchecked} packages that could be checked.</p>`;
    if (unchecked) out += `<p class="note"><strong>${unchecked} of ${installed.length} packages were not checked</strong>: ` +
      `${r.nodata.length} have no CVE data in the tracker's sources (${esc(r.nodata.slice(0, 20).join(", "))}${r.nodata.length > 20 ? ", …" : ""}), ` +
      `${r.foreign.length} are not from the Arch repos.</p>`;
    $("result").innerHTML = out;
  };
}
main();
