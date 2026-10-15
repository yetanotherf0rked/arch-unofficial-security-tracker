# Arch Linux Security Tracker (unofficial)

Tells you whether known CVEs affect **your** Arch Linux machine, and what to
do about it.

The official Arch Security Tracker stopped publishing advisories after June
2025, which also left `arch-audit` without data. This project rebuilds that
service from structured feeds (Arch's repository databases and OSV.dev),
refreshed every 6 hours and published on GitHub Pages:
<https://yetanotherf0rked.github.io/arch-unofficial-security-tracker/>

## Am I affected?

**From a terminal** — reads your pacman database, Python standard library
only:

```sh
curl -fsSO https://yetanotherf0rked.github.io/arch-unofficial-security-tracker/arch-cve-check
python arch-cve-check
```

```
Fixed in the Arch repos — upgrade with `pacman -Syu`  (2 packages, 70 CVEs)
  Critical openssl 3.5.0-1 -> 3.6.5-1  (fixed in 3.6.5)
           CVE-2026-84784 CVE-2026-84782 CVE-2026-77696 +62 more

Vulnerable — upstream has a fix, Arch does not ship it yet  (1 packages, 258 CVEs)
  Critical chromium 154.0.8037.97-1  (upstream fix: 155.0.8059.39)
           CVE-2026-106317 CVE-2026-106318 CVE-2026-106320 +255 more

Coverage: 37 not from the official repos (AUR/local) — not checked; …
```

Options: `-u` only what an upgrade fixes, `-c` list every CVE, `-a` include
issues Debian rates unimportant, `--json`, `--list-unchecked`, `-q`.
`pacman -Q | python arch-cve-check -` checks a package list from another
machine. Exit status is 1 when an installed package is affected (upgradable,
vulnerable or unfixed), so it can run from a timer or a pacman hook.

**With arch-audit** — the tracker also publishes `all.json` in the official
tracker's format:

```sh
arch-audit --source https://yetanotherf0rked.github.io/arch-unofficial-security-tracker/all.json
```

or permanently in `/etc/arch-audit/settings.toml`:

```toml
[network]
source = "https://yetanotherf0rked.github.io/arch-unofficial-security-tracker/all.json"
```

**In the browser** — paste `pacman -Q` output on the page. It is checked
in the page; nothing is uploaded.

## What the answers mean

| Answer | Meaning | What to do |
|---|---|---|
| Fixed in the Arch repos | Your installed version is below the version that fixes it, and the repos have it. | `pacman -Syu` |
| Vulnerable | An upstream release fixes it; Arch doesn't ship that release yet. | Wait for the update, or mitigate. |
| No upstream fix | No upstream release fixes it. Other distros may carry a patch (shown), which Arch could backport. | Mitigate; consider reporting to the Arch package's GitLab issues. |
| Possibly affected | The version comparison isn't conclusive; the reason is given (Arch newer than anything the distros assessed, Arch rebuilt after another distro patched the same version, snapshot versions, …). | Check the linked records. |
| Not checked | AUR/local packages, and repo packages without CVE records in any source. | — |

Severity comes from the CVSS 3.x score when a record has one, otherwise from
Debian's urgency.

## How it works

1. Read the Arch sync databases (`core`, `extra`, `multilib`) from a mirror.
2. Download OSV.dev's bulk exports for **Debian**, **Alpine**, **PyPI** and
   **Linux** (the kernel CNA's per-branch data). Arch isn't an OSV ecosystem;
   these proxy it. Look each pkgbase up by name: the same name, `lib32-`
   stripped, versioned names built from Arch's version (`python3.14`,
   `postgresql-18`), `python-foo` → `py3-foo` / PyPI `foo`, and the curated
   [`aliases.json`](aliases.json) (which also maps the kernels).
3. Evaluate all records about a CVE together against Arch's version. A
   distro's own patch (Debian `1.2.3-3` or `+deb13u1`, Alpine `-r2`) is not
   an upstream fix: it proves upstream 1.2.3 is still vulnerable.
4. Write every threshold as an Arch version, so clients only need pacman's
   version ordering, and publish:
   - `data/advisories.json` — every repo package → pkgbase; per pkgbase the
     issues affecting the repo version and the issues the repos have fixed,
     grouped by the Arch version that fixes them;
   - `all.json` — the same, in the format `arch-audit` reads;
   - `arch-cve-check` and the page.

[docs/architecture.md](docs/architecture.md) has the design, the matching
rules, the feed contract, and the review of the first version this replaced.

## Known limitations

- **Coverage.** About 1,700 of 12,400 pkgbases have CVE records in the
  sources. Packages the proxy distros don't ship, or ship under a name the
  rules and aliases don't find, are reported as *not checked* — never as
  safe. Firefox in particular has no source (Debian only ships ESR).
- **Arch's own patches** are invisible unless a rebuild after the CVE
  hints at them (then the answer is *possibly affected*).
- **Version schemes.** Upstream versions are normalized from distro
  versions; snapshots and unusual schemes end up *possibly affected*
  rather than guessed.
- **Thresholds are upstream versions**, not the exact Arch package that
  first shipped a fix.

Treat it as a best-effort cross-check, not an authoritative advisory feed.

## Cross-checking against official sources

`tools/compare_sources.py` (run by the manual **Compare against NVD /
MITRE / Repology** workflow) builds the feed and audits it:

- **Precision** — for every package/CVE pair reported, do NIST's NVD (CPE
  version ranges) and MITRE's CVE List
  ([cvelistV5](https://github.com/CVEProject/cvelistV5), CNA/ADP `affected`
  ranges) agree that Arch's version is affected?
- **Misses** — for a sample of recent issues the tracker considers fixed in
  the repos, does an official record still call Arch's version affected?
- **Recall** — Arch packages Repology flags as vulnerable that the tracker
  doesn't, and vice versa.

Results land in `reports/compare.md` / `reports/compare.json`. NVD records
are read from the
[fkie-cad/nvd-json-data-feeds](https://github.com/fkie-cad/nvd-json-data-feeds)
mirror; with an `NVD_API_KEY` repository secret, CVEs not yet in the mirror
fall back to NVD's API.

## Development

```sh
python update.py                     # build into _site/ (downloads ~175 MB)
cp site/* _site/ && cp archsec/check.py _site/arch-cve-check
python -m http.server -d _site 8000  # then open http://localhost:8000/

python -m unittest discover -s tests -t .
node tests/vercmp.test.mjs

# offline rebuild from saved inputs (--dump-packages saves the package list;
# osv-zips/ holds Debian.zip, Alpine.zip, PyPI.zip, Linux.zip from OSV's bulk exports)
python update.py --packages packages.json --osv-dir osv-zips/ --out _site
python -m archsec.check --feed _site/data/advisories.json
```

Python 3.10+, standard library only. No API keys.

## License

MIT — see `LICENSE`.
