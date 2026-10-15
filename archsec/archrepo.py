"""Arch's repository databases (`<repo>.db.tar.gz`), the same files pacman syncs."""

from __future__ import annotations

import io
import tarfile

from .net import http_get

REPOS = ("core", "extra", "multilib")
ARCH = "x86_64"


def parse_desc(text: str) -> dict[str, str]:
    """Parse an Arch repo `desc` file (key is `%KEY%`, value is next line(s))."""
    fields: dict[str, str] = {}
    key: str | None = None
    buf: list[str] = []
    for line in text.splitlines():
        if line.startswith("%") and line.endswith("%"):
            if key is not None:
                fields[key] = "\n".join(buf).strip()
            key = line.strip("%")
            buf = []
        elif line == "":
            if key is not None:
                fields[key] = "\n".join(buf).strip()
                key = None
                buf = []
        else:
            buf.append(line)
    if key is not None:
        fields[key] = "\n".join(buf).strip()
    return fields


def parse_repo_db(blob: bytes, repo: str) -> list[dict]:
    """[{name, base, version, repo, arch, url, builddate}] from a .db.tar.gz."""
    out: list[dict] = []
    with tarfile.open(fileobj=io.BytesIO(blob), mode="r:*") as tf:
        for member in tf:
            if not member.isfile() or not member.name.endswith("/desc"):
                continue
            f = tf.extractfile(member)
            if f is None:
                continue
            fields = parse_desc(f.read().decode("utf-8", errors="replace"))
            name, version = fields.get("NAME"), fields.get("VERSION")
            if name and version:
                out.append({
                    "name": name,
                    "base": fields.get("BASE") or name,
                    "version": version,
                    "repo": repo,
                    "arch": fields.get("ARCH", ARCH),
                    "url": fields.get("URL", ""),
                    "builddate": int(fields.get("BUILDDATE") or 0),
                })
    return out


def fetch_repo_db(mirror: str, repo: str) -> list[dict]:
    url = f"{mirror}/{repo}/os/{ARCH}/{repo}.db.tar.gz"
    print(f"  fetching {url}", flush=True)
    return parse_repo_db(http_get(url), repo)
