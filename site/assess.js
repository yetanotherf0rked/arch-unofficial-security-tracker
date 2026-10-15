// Match installed packages against the feed — the same rules as
// archsec/check.py's assess(); see there for the feed's thresholds.
import { vercmp } from "./vercmp.js";

export const SEVERITIES = ["Unknown", "Low", "Medium", "High", "Critical"];
export const GROUPS = {
  upgrade: "Fixed in the Arch repos — upgrade with pacman -Syu",
  vulnerable: "Vulnerable — upstream has a fix, Arch does not ship it yet",
  unfixed: "Vulnerable — no fixed version known yet",
  uncertain: "Possibly affected — version comparison not conclusive",
};

const byVersion = (a, b) => vercmp(a, b);

/** `pacman -Q` output ("name version" per line) -> [{name, version}] */
export function parsePackageList(text) {
  return text.split(/\r?\n/).map(l => l.trim().split(/\s+/))
    .filter(p => p.length >= 2 && !p[0].startsWith("#"))
    .map(([name, version]) => ({ name, version }));
}

export function assess(installed, feed, includeMinor) {
  const repoPkgs = feed.packages || {}, bases = feed.pkgbases || {};
  const findings = [], foreign = [], uncovered = [];
  for (const { name, version, base: localBase } of installed) {
    if (!(name in repoPkgs)) { foreign.push(name); continue; }
    const base = localBase || repoPkgs[name];
    const entry = bases[base] || bases[repoPkgs[name]];
    if (!entry) { uncovered.push(name); continue; }
    const hits = {};
    const add = (group, issue) => (hits[group] ||= []).push(issue);
    for (const g of entry.fixed || []) {
      if (vercmp(version, g.fixed) < 0) {
        for (const id of g.ids) add("upgrade", { id, fixed: g.fixed, severity: g.severity || "Unknown" });
      }
    }
    for (const issue of entry.issues || []) {
      if (issue.minor && !includeMinor) continue;
      if (!(issue.fixed && vercmp(version, issue.fixed) >= 0)) add(issue.status, issue);
    }
    for (const [group, issues] of Object.entries(hits)) {
      const sev = Math.max(0, ...issues.map(i => SEVERITIES.indexOf(i.severity || "Unknown")));
      const fixes = [...new Set(issues.map(i => i.fixed).filter(Boolean))].sort(byVersion);
      findings.push({
        package: name, version, base, group,
        repo_version: entry.version,
        severity: SEVERITIES[sev],
        fixed: fixes.length ? fixes[fixes.length - 1] : null,
        upstream_fix: [...new Set(issues.flatMap(i => i.fix || []))].sort(byVersion),
        issues: issues.map(i => i.id),
        reasons: [...new Set(issues.map(i => i.reason).filter(Boolean))].sort(),
      });
    }
  }
  const order = Object.keys(GROUPS);
  findings.sort((a, b) => order.indexOf(a.group) - order.indexOf(b.group)
    || SEVERITIES.indexOf(b.severity) - SEVERITIES.indexOf(a.severity)
    || (a.package < b.package ? -1 : a.package > b.package ? 1 : 0));
  return { findings, foreign, uncovered, checked: installed.length };
}
