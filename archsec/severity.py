"""
Severity of an issue: CVSS v3 base score when a record carries a vector,
otherwise Debian's urgency. Ratings use arch-audit's vocabulary
(Unknown / Low / Medium / High / Critical).
"""

from __future__ import annotations

import math

RATINGS = ["Unknown", "Low", "Medium", "High", "Critical"]

_V3 = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
}
_PR = {"U": {"N": 0.85, "L": 0.62, "H": 0.27}, "C": {"N": 0.85, "L": 0.68, "H": 0.5}}


def _roundup(x: float) -> float:
    """CVSS 3.1 Roundup: smallest one-decimal number >= x, robust to float noise."""
    i = round(x * 100000)
    return i / 100000.0 if i % 10000 == 0 else (math.floor(i / 10000) + 1) / 10.0


def cvss3_score(vector: str) -> float | None:
    """Base score of a "CVSS:3.x/AV:N/AC:L/…" vector; None if it doesn't parse."""
    if not vector.startswith("CVSS:3"):
        return None
    try:
        m = dict(part.split(":", 1) for part in vector.split("/")[1:])
        scope = m["S"]
        av, ac, ui = _V3["AV"][m["AV"]], _V3["AC"][m["AC"]], _V3["UI"][m["UI"]]
        pr = _PR[scope][m["PR"]]
        c, i, a = (_V3["C"][m[k]] for k in ("C", "I", "A"))
    except (KeyError, ValueError):
        return None
    iss = 1 - (1 - c) * (1 - i) * (1 - a)
    if scope == "U":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    if impact <= 0:
        return 0.0
    exploitability = 8.22 * av * ac * pr * ui
    if scope == "U":
        return _roundup(min(impact + exploitability, 10))
    return _roundup(min(1.08 * (impact + exploitability), 10))


def rating(score: float | None) -> str:
    if score is None or score == 0:
        return "Unknown"
    if score < 4:
        return "Low"
    if score < 7:
        return "Medium"
    if score < 9:
        return "High"
    return "Critical"


_URGENCY = {"low": "Low", "medium": "Medium", "high": "High", "unimportant": "Low"}


def from_urgency(urgency: str | None) -> str:
    """Debian urgency ("low", "medium", "high", "unimportant", …) as a rating."""
    return _URGENCY.get((urgency or "").lower(), "Unknown")
