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
2. For every package, queries [OSV.dev](https://osv.dev/)'s batch API
   proxying against the **Debian**, **Ubuntu** and **Alpine** ecosystems,
   using the Arch package name and the upstream version (pkgrel stripped).
   This returns candidate CVE ids.
3. Fetches full OSV records for each candidate (with a per-run cache keyed
   on each record's `modified` timestamp, so unchanged CVEs skip the
   network).
4. **Verifies** every candidate locally: finds the fixed-in version in the
   OSV record, strips distro suffixes (`-rN`, `-pkgrel`, `N:`) and
   compares against Arch's upstream version with a Debian-aware vercmp
   (handles `~`-pre-releases). CVEs whose fix is already in Arch are
   dropped; so are records with no explicit fixed version.
5. Writes `data/packages.json` and `data/vulns.json`, commits them, and
   deploys the static site via GitHub Pages.

Everything comes from APIs / structured feeds — no HTML parsers.

## Data sources

| Source | Role | Trusted / active? |
|---|---|---|
| `*.db.tar.gz` from Arch mirror | Package list (name + version per repo) | Yes — Arch's own distribution format, served by every mirror |
| [OSV.dev](https://osv.dev/) `/v1/querybatch` and `/v1/vulns/{id}` | CVE data | Yes — Google-maintained, aggregates GHSA, NVD, Debian Security Tracker, Ubuntu Security Notices, Alpine SecDB and more |

Explicitly **not** used (stale or unmaintained):

- `security.archlinux.org` advisories (halted June 2025)
- `arch-audit` upstream (depends on the above)
- `archlinux.org/feeds/news/` (stale per project maintainer)

## Known limitations

- **Not an OSV ecosystem.** Arch is not natively tracked by OSV. We proxy
  through Debian / Ubuntu / Alpine, which share upstream names with most
  Arch packages but not all. Packages renamed in Arch (`openssh` vs
  `openssh-server`, `python-foo` vs `python3-foo`, etc.) may be missed.
- **Unverifiable records are dropped.** CVE records lacking an explicit
  fixed-in version are discarded rather than reported — we can't tell
  whether Arch is affected. This favours precision over recall.
- **Backported patches.** Arch sometimes carries upstream patches without
  a version bump; those CVEs can appear as false positives here. The
  tracker has no way to know about such patches.
- **vercmp is simplified.** Handles the common cases (digits, letters,
  `~` pre-releases, epoch, pkgrel). It does not perfectly mirror pacman's
  `vercmp` or Debian's `dpkg --compare-versions` in exotic corners.
- **Non-x86_64.** The fetcher only pulls x86_64 DBs. Other architectures
  track the same source versions, so the CVE list applies either way.

Treat the tracker as a best-effort cross-check, not an authoritative
advisory feed.

## Running locally

```sh
python update.py
python -m http.server 8000  # then open http://localhost:8000/
```

Python 3.10+ stdlib only. No dependencies, no API keys.

## License

MIT — see `LICENSE`.
