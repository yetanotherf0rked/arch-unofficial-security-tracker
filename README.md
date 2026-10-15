# Arch Linux Security Tracker (unofficial)

Tells you whether known CVEs affect the packages installed on **your** Arch Linux machine.

The official Arch Security Tracker stopped publishing in 2025, which also left `arch-audit` without
data. This project rebuilds it from sources that already do the triage work, every 6 hours on GitHub
Actions, published on GitHub Pages: <https://yetanotherf0rked.github.io/arch-unofficial-security-tracker/>

## Am I affected?

```sh
curl -fsSO https://yetanotherf0rked.github.io/arch-unofficial-security-tracker/arch-cve-check
python arch-cve-check
```

It runs `pacman -Q`, fetches one JSON feed and compares versions with pacman's own libalpm. Python
standard library only, no root.

| Exit status | Meaning |
|---|---|
| 0 | no known CVE affects the installed versions of the covered packages |
| 1 | affected: fixed in the repos (upgrade), or vulnerable with or without an upstream fix |
| 3 | only "uncertain" findings: Arch ships a version newer than anything the source assessed |
| 2 | error |

Options: `-u` only what an upgrade fixes, `-a` include issues Debian rates unimportant, `-q` names only,
`-v` every CVE and the unchecked packages, `--json`. `pacman -Q | python arch-cve-check -` checks a list
from another machine.

**arch-audit:** `arch-audit --source https://yetanotherf0rked.github.io/arch-unofficial-security-tracker/all.json`
lists open issues. Use arch-cve-check for "is my outdated install affected?".

**Browser:** paste `pacman -Q` output on the page. It is checked in the page; nothing is sent.

## Where the answers come from

- **Packages:** pacman's sync databases (core, extra, multilib), read with `expac`.
- **Userland CVEs:** the [Debian security tracker](https://security-tracker.debian.org/tracker/) JSON.
  It covers every Debian release including unstable, with Debian's triage (fixed version, not
  affected, unimportant).
- **Kernels:** the [kernel CNA's records](https://git.kernel.org/pub/scm/linux/security/vulns.git).
  These give per stable line which version has the fix.
- **Version comparison:** always libalpm's `alpm_pkg_vercmp`.

Rules and limits: [docs/architecture.md](docs/architecture.md).

**Not covered:** packages Debian doesn't ship, or ships under a name we can't match. The client names
them (`-v`). Thunderbird is "uncertain": Debian ships the ESR line only. Patches Arch applies without
a new upstream version are not visible, so such packages can stay listed until the next upstream
release.

## Development

```sh
sudo pacman -S --needed python expac git nodejs
python -m unittest discover -s tests -t .
python build.py --out _site      # needs fresh sync DBs (pacman -Sy), multilib enabled
```

Everything runs in an `archlinux:base-devel` container on GitHub Actions (`.github/workflows/update.yml`).
The feed is built and deployed in the same job, never committed.
