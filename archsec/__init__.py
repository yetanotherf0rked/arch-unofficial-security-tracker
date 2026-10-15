"""
Unofficial Arch Linux security tracker.

The builder (`archsec.build`) turns Arch's repository databases and OSV.dev
data into a feed of per-package advisories whose versions are written in
Arch's own format. The client (`archsec.check`, published standalone as
`arch-cve-check`) compares that feed with the packages installed on a
machine using pacman's version ordering.
"""
