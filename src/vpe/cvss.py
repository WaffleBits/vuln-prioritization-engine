"""CVSS v3.1 base score calculator.

Implements the base metric equations from the FIRST CVSS v3.1 specification,
section 7.1, including the spec's Roundup function (appendix A) so results match
the official calculator exactly instead of drifting on floating point edges.
"""

from __future__ import annotations

import math
from dataclasses import dataclass

AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
AC = {"L": 0.77, "H": 0.44}
PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.5}
UI = {"N": 0.85, "R": 0.62}
CIA = {"H": 0.56, "L": 0.22, "N": 0.0}

REQUIRED = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")
ALLOWED = {
    "AV": set(AV),
    "AC": set(AC),
    "PR": set(PR_UNCHANGED),
    "UI": set(UI),
    "S": {"U", "C"},
    "C": set(CIA),
    "I": set(CIA),
    "A": set(CIA),
}


class CvssError(ValueError):
    """Raised for a vector string that is not a valid CVSS v3.x base vector."""


@dataclass(frozen=True)
class CvssV3:
    vector: str
    metrics: dict[str, str]
    base_score: float
    impact: float
    exploitability: float

    @property
    def severity(self) -> str:
        return severity(self.base_score)

    @property
    def network_reachable(self) -> bool:
        return self.metrics["AV"] == "N"

    @property
    def no_privileges(self) -> bool:
        return self.metrics["PR"] == "N"

    @property
    def needs_user(self) -> bool:
        return self.metrics["UI"] == "R"


def roundup(value: float) -> float:
    """Smallest number, to one decimal place, that is >= value (CVSS v3.1 appendix A)."""
    int_input = round(value * 100_000)
    if int_input % 10_000 == 0:
        return int_input / 100_000.0
    return (math.floor(int_input / 10_000) + 1) / 10.0


def severity(score: float) -> str:
    if score == 0:
        return "None"
    if score < 4.0:
        return "Low"
    if score < 7.0:
        return "Medium"
    if score < 9.0:
        return "High"
    return "Critical"


def parse_vector(vector: str) -> dict[str, str]:
    parts = vector.strip().split("/")
    if not parts or not parts[0].startswith("CVSS:3."):
        raise CvssError(f"not a CVSS v3 vector: {vector!r}")
    metrics: dict[str, str] = {}
    for part in parts[1:]:
        if ":" not in part:
            raise CvssError(f"malformed metric {part!r} in {vector!r}")
        key, value = part.split(":", 1)
        if key in metrics:
            raise CvssError(f"duplicate metric {key} in {vector!r}")
        metrics[key] = value
    for key in REQUIRED:
        if key not in metrics:
            raise CvssError(f"missing base metric {key} in {vector!r}")
        if metrics[key] not in ALLOWED[key]:
            raise CvssError(f"invalid value {key}:{metrics[key]} in {vector!r}")
    return metrics


def score(vector: str) -> CvssV3:
    m = parse_vector(vector)
    changed = m["S"] == "C"
    iss = 1 - (1 - CIA[m["C"]]) * (1 - CIA[m["I"]]) * (1 - CIA[m["A"]])
    if changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss
    pr = (PR_CHANGED if changed else PR_UNCHANGED)[m["PR"]]
    exploitability = 8.22 * AV[m["AV"]] * AC[m["AC"]] * pr * UI[m["UI"]]
    if impact <= 0:
        base = 0.0
    elif changed:
        base = roundup(min(1.08 * (impact + exploitability), 10))
    else:
        base = roundup(min(impact + exploitability, 10))
    return CvssV3(
        vector=vector.strip(),
        metrics=m,
        base_score=base,
        impact=round(impact, 4),
        exploitability=round(exploitability, 4),
    )
