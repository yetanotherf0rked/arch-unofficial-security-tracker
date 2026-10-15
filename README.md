# Arch Linux Security Tracker

A minimal, auto-updating static tracker for CVEs affecting packages in the
official Arch Linux repositories.

Built because the official Arch Security Tracker stopped publishing
advisories after June 2025, which also makes `arch-audit` largely stale.

## What it does

Once a day, a GitHub Action:

1. Pulls `core.db.tar.gz`, `extra.db.tar.gz` and `multilib.db.tar.gz` from
   a public Arch mirror (`https://geo.mirror.pkgbuild.com` by default).
   These are Arch's canonical pacman sync files — the same ones every Arch
   install downloads. No HTML scraping.
2. Downloads [OSV.dev](https://osv.dev/)'s bulk exports for the
   **Debian** and **Alpine** ecosystems (one zip each, ~80 MB total) and
   indexes every record by package name. Ubuntu is skipped by default: its
   export is ~780 MB and mostly mirrors Debian (`OSV_ECOSYSTEMS` env var
   overrides the list).
3. For every **pkgbase** (Arch's source package — the distros above key
   their records by source package too; `lib32-foo` is looked up as `foo`),
   takes the records for that name.
4. **Verifies** every candidate locally against the record's affected
   ranges (`introduced` / `fixed` / `last_affected`). Distro version noise
   is normalized away first (`-rN`, Debian/Ubuntu revisions, `+dfsg`,
   `+repack`, `+debNuM`, `~debNuM`, `+really`, epochs; Arch's inline
   `1.0beta2` is read as Debian's `1.0~beta2`). Snapshot versions that
   don't start with a digit (`r12985.5236ecb04`) can't be compared and are
   skipped. A fix released on
   Arch's own `major.minor` branch counts even when a distro backported it
   to an older line. Results:
   - **affected** — Arch is below a fix: listed.
   - **unfixed** — no fix exists anywhere yet: listed separately (hidden
     behind a toggle on the page).
   - **fixed** — Arch already has the fix: dropped.
   - **mismatch** — Arch's version is far below anything the distro ever
     shipped under that name (e.g. Arch's `keystone` assembler 0.9 vs.
     Debian's OpenStack `keystone` 22+): treated as a different project,
     dropped.

   The same CVE reported by several distros is merged into one entry.
5. Writes `data/packages.json` and `data/vulns.json`, commits them, and
   deploys the static site (page + those two files) via GitHub Pages.

Everything comes from structured feeds — no HTML parsers. A full refresh
takes well under a minute.

## Data sources

| Source | Role | Trusted / active? |
|---|---|---|
| `*.db.tar.gz` from Arch mirror | Package list (name + version per repo) | Yes — Arch's own distribution format, served by every mirror |
| [OSV.dev](https://osv.dev/) bulk exports (`osv-vulnerabilities.storage.googleapis.com/<ecosystem>/all.zip`) | CVE data | Yes — Google-maintained, aggregates GHSA, NVD, Debian Security Tracker, Ubuntu Security Notices, Alpine SecDB and more |

Explicitly **not** used (stale or unmaintained):

- `security.archlinux.org` advisories (halted June 2025)
- `arch-audit` upstream (depends on the above)
- `archlinux.org/feeds/news/` (stale per project maintainer)

## Known limitations

- **Not an OSV ecosystem.** Arch is not natively tracked by OSV. We proxy
  through Debian / Alpine, which share upstream names with most
  Arch packages but not all. Packages renamed in Arch (`openssh` vs
  `openssh-server`, `python-foo` vs `python3-foo`, etc.) may be missed.
- **Unfixed CVEs can't be version-checked.** When no distro has a fix,
  every version is considered affected; these are shown separately as
  "unfixed upstream" and some will be low-priority issues distros chose
  not to patch.
- **Name collisions are caught heuristically.** The mismatch check only
  fires when Arch's major version is less than half of everything the
  distro knows; a collision between projects with similar version numbers
  will still slip through.
- **Backported patches.** Arch sometimes carries upstream patches without
  a version bump; those CVEs can appear as false positives here. The
  tracker has no way to know about such patches.
- **vercmp is simplified.** Handles the common cases (digits, letters,
  `~` and `rc`/`alpha`/`beta`/`pre` pre-releases, epoch, pkgrel). It does not perfectly mirror pacman's
  `vercmp` or Debian's `dpkg --compare-versions` in exotic corners.
- **Non-x86_64.** The fetcher only pulls x86_64 DBs. Other architectures
  track the same source versions, so the CVE list applies either way.

Treat the tracker as a best-effort cross-check, not an authoritative
advisory feed.

## Cross-checking against official sources

`tools/compare_sources.py` (run by the manual **Compare against NVD /
MITRE / Repology** workflow) audits the tracker's output:

- **Precision** — for every package/CVE pair reported, checks whether
  NIST's NVD (CPE version ranges) and MITRE's CVE List
  ([cvelistV5](https://github.com/CVEProject/cvelistV5), CNA/ADP
  `affected` ranges) agree that Arch's version is affected.
- **Recall** — lists Arch packages Repology flags as vulnerable that the
  tracker doesn't, and vice versa.

Results land in `reports/compare.md` / `reports/compare.json` and the
workflow run summary. NVD is rate-limited to 5 requests / 30 s without a
key; add an `NVD_API_KEY` repository secret to go ten times faster.

## Running locally

```sh
python update.py
python -m http.server 8000  # then open http://localhost:8000/
```

Python 3.10+ stdlib only. No dependencies, no API keys.

## License

MIT — see `LICENSE`.
