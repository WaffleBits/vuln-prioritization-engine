"""Export the ranked worklist as a POA&M-style CSV and as JSON.

Column names follow the vulnerability fields of the FedRAMP POA&M template so
the output can be pasted into an existing tracker. This is a working draft for
an ISSO to review, not a submission-ready document.
"""

from __future__ import annotations

import csv
import json
from pathlib import Path

from .prioritize import RISK_RATING, Assessed

POAM_COLUMNS = [
    "POAM ID",
    "Controls",
    "Weakness Name",
    "Weakness Description",
    "Weakness Detector Source",
    "Weakness Source Identifier",
    "Asset Identifier",
    "Point of Contact",
    "Original Detection Date",
    "Scheduled Completion Date",
    "Original Risk Rating",
    "Priority",
    "Overdue",
    "Known Exploited (KEV)",
    "EPSS",
    "CVSS v3 Base",
    "CVSS v3 Vector",
    "ATT&CK (heuristic)",
    "Comments",
]


def _name(a: Assessed) -> str:
    if a.kev and a.kev.name:
        return a.kev.name
    return f"{a.finding.cve} on {a.asset.hostname or a.asset.asset_id}"


def _description(a: Assessed, limit: int = 400) -> str:
    text = a.nvd.description if a.nvd else ""
    return text if len(text) <= limit else text[: limit - 3].rstrip() + "..."


def rows(assessed: list[Assessed]) -> list[dict[str, str]]:
    out = []
    for i, a in enumerate(assessed, start=1):
        out.append({
            "POAM ID": f"V-{i:04d}",
            "Controls": "RA-5; SI-2",
            "Weakness Name": _name(a),
            "Weakness Description": _description(a),
            "Weakness Detector Source": a.finding.source or "vulnerability scan",
            "Weakness Source Identifier": a.finding.cve,
            "Asset Identifier": f"{a.asset.asset_id} ({a.asset.hostname})" if a.asset.hostname
            else a.asset.asset_id,
            "Point of Contact": a.asset.owner,
            "Original Detection Date": a.finding.first_seen.isoformat(),
            "Scheduled Completion Date": a.due.isoformat() if a.due else "",
            "Original Risk Rating": RISK_RATING[a.tier],
            "Priority": a.priority,
            "Overdue": "Yes" if a.overdue else "No",
            "Known Exploited (KEV)": "Yes" if a.kev else "No",
            "EPSS": f"{a.epss.probability:.4f}" if a.epss else "",
            "CVSS v3 Base": f"{a.cvss.base_score:.1f}" if a.cvss else "",
            "CVSS v3 Vector": a.cvss.vector if a.cvss else "",
            "ATT&CK (heuristic)": f"{a.attack.technique} {a.attack.name}",
            "Comments": "; ".join(a.reasons),
        })
    return out


def write_csv(assessed: list[Assessed], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=POAM_COLUMNS)
        writer.writeheader()
        writer.writerows(rows(assessed))


def write_json(assessed: list[Assessed], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(rows(assessed), indent=2), encoding="utf-8")
