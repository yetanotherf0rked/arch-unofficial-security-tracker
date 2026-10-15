# Architecture

This document reviews the first version of the tracker (aim, design,
logic, flaws, all measured on the 2026-10-15 data) and describes the
architecture that replaced it.

## 1. Aim

The official Arch Security Tracker stopped publishing advisories in June
2025, which also left `arch-audit` without data. This project rebuilds
that service from structured feeds. The goal is more specific than "list
CVEs in Arch": **an Arch user must be able to tell whether a CVE affects
their machine**, what to do about it, and which packages could not be
checked at all.

## 2. The first version

### Design

```
Arch repo DBs ──► pkgbase list (repo version)
OSV exports (Debian, Alpine) ──► records by package name
     │  exact-name match (lib32- stripped)
     ▼
evaluate each record against the *repo* version
     │  affected / uncertain / unfixed kept, fixed dropped
     ▼
data/vulns.json (committed) ──► index.html (browse table)
```

`update.py` downloaded the Arch sync databases and OSV's bulk exports,
looked each pkgbase up by name, normalized distro versions to an
"upstream" form (`1.2.3-1+deb12u1` → `1.2.3`), and compared Arch's
version with each record's ranges. A branch rule treated a fix on Arch's
own `major.minor` line as conclusive. Results went to `data/vulns.json`,
which the workflow committed, and a static page listed them.
`tools/compare_sources.py` audited precision against NVD and MITRE.

The version handling and the precision audit were careful (several
documented misreadings had already been fixed), and the build was fast
and dependency-free. The flaws were in what the output could tell a user,
and in one silent failure mode of the matching.

### Flaws

1. **It answered "is the repo affected?", not "am I affected?"** Verdicts
   were computed for the current repo version only, and issues the repo
   had already fixed were dropped. A machine that hadn't been upgraded
   since a fix landed was told nothing — the exact case where a user is
   at risk and the remedy is one `pacman -Syu` away. There was no way to
   compare an installed system with the data: no client, no
   machine-readable feed in a format existing tools read (`arch-audit`
   still points at the dead official URL), only a web table to read by
   eye.

2. **Distro patches were read as upstream fixes (silent false
   negatives).** Debian's "fixed in `0.9.15+dfsg-1+deb13u1`" or
   "`1.2.16.1-2`", and Alpine's "`1.2.3-r2`", are the distro patching the
   upstream release it already ships; that upstream version is still
   vulnerable. Stripping the revision turned them into "upstream 0.9.15 is
   fixed", so Arch's unpatched 0.9.15 was reported fixed and never shown.
   On the 2026-10-15 data this hid **88 package/CVE pairs** (libvncserver,
   alsa-lib, openvpn, qemu, sudo, wget, net-snmp, …). The branch rule made
   it worse: a stable backport (`1.2.3+deb13u1`) on Arch's `1.2` line
   counted as a fix even when upstream fixed the issue later in `1.2.9`.
   One more artefact pointed the other way: Debian lists backport builds
   (`2.7.8-1~bpo13+1`) as affected only because they sort below the fixing
   upload.

3. **"Unfixed" was mostly noise.** 2,064 CVEs across 406 packages were
   listed as having no fix anywhere. 791 of them are issues Debian rates
   *unimportant*, and in about 60% of the rest Arch ships a newer version
   than anything Debian has assessed (Debian's ESR Thunderbird vs Arch's
   current one, 60 CVEs alone): "still open in Debian 140.x" says nothing
   about Arch's 157. Every record was also evaluated on its own, so a
   Debian "no fix" won even when Alpine knew the upstream fix.

4. **Coverage was low and invisible.** Only 1,515 of 12,383 pkgbases
   matched a Debian/Alpine name exactly. Core packages were missing because
   the distros name them differently: `sqlite` (Debian `sqlite3`), `xz`
   (`xz-utils`), `glib2`, `gtk3`, `gnutls`, `libpng`, `freetype2`, `go`,
   `rust`, `gcc`, the OpenJDKs, Node.js LTS, NetworkManager, docker,
   `python-*` modules. A package without data looked exactly like a
   package without vulnerabilities.

5. **No severity.** CVSS vectors were shown as raw strings; nothing ranked
   a remote code execution above a local denial of service.

6. **Generated data committed on every run.** Each refresh committed
   ~5.7 MB of JSON (one refresh commit changed 81k lines),
   growing the history and forcing `pull --rebase` dances in workflows
   and merges on every feature branch.

7. **No tests.** The version logic had been corrected by hand several
   times; nothing kept those corrections from regressing.

8. **The audit tool only measured half the problem, and misread some
   records.** `compare_sources.py` checked whether reported issues were
   real (precision) but never whether dropped ones were (misses), which is
   where flaw 2 hid. Its MITRE reader also took the kernel CNA's
   `lessThanOrEqual: "7.2.*"` as `7.2` (so every 6.x LTS kernel read as
   unaffected), treated boilerplate `defaultStatus: "affected"` as a claim
   about versions above the listed ranges, and read free-text versions
   such as `"< 3.1.9"` as exact versions.

## 3. New architecture

The principle: **all fuzzy matching happens once, in the builder, and
produces thresholds written as Arch versions.** Clients then need nothing
but pacman's own version ordering, so a laptop, a browser and `arch-audit`
reach the same answer.

```
Arch repo DBs ─────────┐
OSV: Debian, Alpine,   │   archsec.build
  PyPI, Linux exports ─┤   ├─ names     pkgbase → names in each ecosystem
aliases.json ──────────┘   ├─ match     union of all records per CVE,
                           │            upstream fix vs distro patch
                           ├─ severity  CVSS v3 score, Debian urgency
                           ▼
          _site/data/advisories.json   native feed (GitHub Pages)
          _site/all.json               security.archlinux.org format
                           │
      ┌────────────────────┼─────────────────────────┐
      ▼                    ▼                         ▼
arch-cve-check       arch-audit --source        web page: paste
(reads pacman DB)    …/all.json                 `pacman -Q`, browse
```

### Modules (`archsec/`)

| Module | Role |
|---|---|
| `archrepo.py` | Parse Arch sync DBs (`<repo>.db.tar.gz`). |
| `osv.py` | Load OSV bulk exports, index by (ecosystem family, name), group records by CVE. |
| `names.py` | Candidate names per pkgbase: exact, `lib32-` stripped, versioned names built from Arch's own version (`python3.14`, `postgresql-18`, `golang-1.27`), `python-foo` → Alpine `py3-foo` / PyPI `foo`, the kernels → OSV `Linux/Kernel` (the kernel CNA's per-branch fixes), plus the curated `aliases.json`. A candidate is used only if some record carries it. |
| `versions.py` | Upstream normalization and Debian-ish comparison (unchanged semantics), `arch_form()` to write an upstream version as Arch would (epoch carried over, `~rc1` → `rc1`, dates with Arch's separator). |
| `match.py` | The verdict for one issue (below). |
| `severity.py` | CVSS v3.x base score from the vector; Debian urgency as fallback. |
| `build.py` | Assemble both feeds; refuse to publish an empty one. |
| `check.py` | The client — self-contained, published as `arch-cve-check`; contains an exact port of libalpm's `vercmp`. |

`site/` holds the page; `site/vercmp.js` and `site/assess.js` are the
JavaScript twins of the client's comparison and matching, tested against
the same vectors (pacman's own `vercmptest` cases) and fuzzed against the
Python port.

### Matching rules (`match.evaluate`)

All records about one CVE (Debian, Alpine, PyPI GHSA/PYSEC, the kernel
CNA) are evaluated together, so a fix known to any source counts.

* **Fix classification.** A distro fix version is an *upstream* fix when
  it imports a new release (Debian revision `-1`, `-0.1`, `-1~…`,
  `-0+debNuM`; Alpine `-r0`; any PyPI version) and the distro never
  shipped an affected build of that same upstream version (ignoring
  backport/experimental builds of the fixing upload). Otherwise it is a
  *patch*: proof that the upstream version is vulnerable, not a fix.
* **Only upstream fixes** feed the branch rule and the "past a fix"
  checks. Arch at exactly a patched version is `unfixed` (or `vulnerable`
  when a later upstream release fixes it), reason `distro-patch`, or
  `distro-patch-rebuilt` when Arch rebuilt after the CVE was published and
  might carry the patch. (A first version called the rebuilt case
  uncertain; NVD/MITRE called 116 of 123 decidable ones affected.)
* A range with its own lower bound (the kernel's `introduced 6.19.0,
  fixed 7.2.6`) is scoped to one release line, so being past a fix on
  another line no longer makes the verdict uncertain.
* **Open ranges** count only from each distro's newest release (old
  releases stay open forever after end of life). If Arch is newer than
  every version that release lists as affected, the verdict is
  `uncertain` (`newer-than-assessed`), not `unfixed`.
* Kept from v1: snapshot and decimal-version handling, the name-collision
  guard, the branch rule.

Statuses: `vulnerable` (an upstream release fixes it; Arch hasn't shipped
it), `unfixed` (no upstream release fixes it — maybe distro patches),
`uncertain` (with a reason), `fixed` (the repo has the fix).

### The feed contract (`data/advisories.json`)

```jsonc
{
  "schema": 1,
  "generated_at": 1792037667,
  "packages": { "python-thrift": "thrift", … },      // every repo package → pkgbase
  "pkgbases": {
    "openssl": {                                     // only pkgbases with CVE records
      "version": "3.6.5-1", "repo": "core", "packages": ["openssl"],
      "sources": ["Alpine:openssl", "Debian:openssl"],
      "issues": [                                    // affect the repo version
        { "id": "CVE-…", "status": "vulnerable", "reason": "below-fix",
          "fixed": "3.6.6",        // upstream fix as an Arch version (optional)
          "fix": ["3.6.6"], "severity": "High", "score": 7.5, "urgency": "medium",
          "minor": false, "published": "…", "summary": "…", "refs": […], "sources": […] } ],
      "fixed": [                                     // the repo has these fixes
        { "fixed": "3.6.5", "severity": "High", "published": "2026-09-30",
          "ids": ["CVE-…", …] } ]
    }
  }
}
```

A client decides, for an installed `name version`:

1. `name` not in `packages` → not from the official repos (AUR/local):
   *not checked*. Its pkgbase not in `pkgbases` → *no CVE data*.
2. For each `fixed` group: installed `< fixed` (pacman ordering) →
   affected, **upgrade fixes it**.
3. For each issue: affected unless it has a `fixed` and installed `≥` it
   (a newer build, e.g. from `[testing]`). `minor` issues (Debian:
   unimportant) are hidden by default.

The "fixed" thresholds are the upstream fix written as an Arch version
and checked with pacman's ordering against the repo version. When that
check fails (version schemes don't line up) the repo version itself is
the threshold, but only for issues published in the last 120 days, so an
old CVE never flags a machine that is merely one pkgrel behind.

`all.json` regroups the same data per pkgbase / status / fixed version in
the official tracker's schema (`name`, `packages`, `status`, `severity`,
`type`, `affected`, `fixed`, `issues`, …), leaving out unimportant issues
and fixed groups older than two years. `arch-audit` lists a package when it
is installed and below `fixed`, or when `fixed` is null.

### Operations

* `update.yml` runs the tests, builds the feed every 6 hours and deploys
  it with the page and the client script to GitHub Pages. Generated data
  is no longer committed; `update.py --packages snapshot.json --osv-dir
  zips/` rebuilds offline.
* `tests.yml` runs the Python suite on 3.10 and the JavaScript tests.
* `compare.yml` builds the feed, then audits it against NVD and MITRE,
  now including a **miss check**: a sample of recent issues the tracker
  considers fixed in the repos (at most 40 per package), checked for
  official records that still call Arch's version affected, counting only
  records matched by product name. The MITRE reader handles `X.Y.*`
  bounds, boilerplate `defaultStatus` and free-text versions.

## 4. Effect on the 2026-10-15 data

| | v1 | v2 |
|---|---|---|
| pkgbases with CVE data | 1,515 matched by name | 1,713 (aliases, versioned names, PyPI, kernel CNA) |
| issues an outdated machine can be told about | 0 (fixed issues dropped) | 124,446, grouped into Arch fix versions |
| distro-patch cases reported fixed | 88 | 0 — reported `unfixed` with the patching distro named (183) |
| kernels (`linux`, `-lts`, `-zen`, `-hardened`, `-rt`, `-rt-lts`) | `linux` via Debian only | all six via the kernel CNA's per-branch ranges (e.g. 367 CVEs not yet fixed on the 6.18 LTS line) |
| "unfixed" shown by default | 2,064 CVEs in 406 packages | 703 CVEs in 182 packages (unimportant and newer-than-assessed moved out) |
| severity | raw vector | rating from CVSS 3.x score, else Debian urgency |
| feed size (gzip) | 2.1 MB + 3.6 MB raw, committed | ~1 MB (`advisories.json`), ~330 KB (`all.json`), not committed |
| tests | none | 42 Python + JS vercmp/assess, pacman's vercmp vectors |

## 5. Known limits and next steps

* **Coverage is still the main gap.** 10,674 pkgbases have no record
  under any candidate name. Some never had a CVE; others are packaged
  under unrelated names, and **Firefox has no source at all** (Debian
  ships ESR only; Alpine's secdb has no entry). Next steps, in order of
  value: match by homepage URL against Debian's `Sources` and Alpine's
  `APKINDEX` (Arch's `%URL%` vs `Homepage:` / `U:`) to generate aliases
  automatically; add the CVE List (cvelistV5) / NVD CPE ranges as a source
  for upstream products no distro proxies well (Mozilla first).
* **Exact Arch fix versions.** Thresholds are upstream versions; the Arch
  package that first shipped a fix is not recorded. Keeping a small state
  file between runs (first refresh at which an issue turned fixed) would
  give the exact `pkgver-pkgrel`, like the official tracker had.
* **Arch's own patches** are only detectable when they bump nothing
  but `pkgrel`; reading PKGBUILD `source=()` for CVE-named patches would
  turn many `distro-patch-rebuilt` verdicts into definite answers.
* **CVSS 4.0** vectors (about 4% of records) are not scored yet.
