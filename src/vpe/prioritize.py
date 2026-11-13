"""Turn raw findings plus asset context and threat intel into a ranked worklist.

The rules are deliberately a short, readable table rather than a weighted score,
so every priority can be explained in one line to the system owner who has to
fix it. See docs/scoring.md for the reasoning behind each threshold.
"""

from __future__ import annotations

import csv
from dataclasses import dataclass, field
from datetime import date, timedelta
from pathlib import Path

from .attack import Mapping, map_technique
from .cvss import CvssError, CvssV3, score
from .feeds import EpssScore, KevEntry, NvdRecord

# Days to remediate per tier. P1 follows the two-week window CISA BOD 22-01 sets
# for newly added KEV entries; P2-P4 follow the FedRAMP continuous monitoring
# timelines for high, moderate and low risk findings.
SLA_DAYS = {1: 15, 2: 30, 3: 90, 4: 180}
TIER_LABEL = {1: "P1", 2: "P2", 3: "P3", 4: "P4"}
RISK_RATING = {1: "High", 2: "High", 3: "Moderate", 4: "Low"}
CRITICALITY_RANK = {"high": 0, "moderate": 1, "low": 2}

EPSS_URGENT = 0.5
EPSS_ELEVATED = 0.1


@dataclass(frozen=True)
class Asset:
    asset_id: str
    hostname: str
    environment: str
    internet_facing: bool
    criticality: str
    owner: str


@dataclass(frozen=True)
class Finding:
    asset_id: str
    cve: str
    first_seen: date
    vector: str | None = None
    source: str = ""


@dataclass
class Assessed:
    finding: Finding
    asset: Asset
    cvss: CvssV3 | None
    kev: KevEntry | None
    epss: EpssScore | None
    nvd: NvdRecord | None
    attack: Mapping
    tier: int
    reasons: list[str] = field(default_factory=list)
    due: date | None = None
    overdue: bool = False

    @property
    def priority(self) -> str:
        return TIER_LABEL[self.tier]

    @property
    def cvss_score(self) -> float:
        return self.cvss.base_score if self.cvss else 0.0

    @property
    def epss_probability(self) -> float:
        return self.epss.probability if self.epss else 0.0

    def sort_key(self) -> tuple:
        return (
            self.tier,
            0 if self.kev else 1,
            -self.epss_probability,
            -self.cvss_score,
            CRITICALITY_RANK.get(self.asset.criticality, 3),
            self.finding.cve,
            self.asset.asset_id,
        )


def _yes(value: str) -> bool:
    return value.strip().lower() in {"yes", "y", "true", "1"}


def load_assets(path: Path) -> dict[str, Asset]:
    with path.open(newline="", encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    assets = {}
    for r in rows:
        crit = r["criticality"].strip().lower()
        if crit not in CRITICALITY_RANK:
            raise ValueError(f"asset {r['asset_id']}: criticality must be high, moderate or low")
        assets[r["asset_id"].strip()] = Asset(
            asset_id=r["asset_id"].strip(),
            hostname=r.get("hostname", "").strip(),
            environment=r.get("environment", "").strip(),
            internet_facing=_yes(r.get("internet_facing", "")),
            criticality=crit,
            owner=r.get("owner", "").strip(),
        )
    return assets


def load_findings(path: Path) -> list[Finding]:
    with path.open(newline="", encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    return [
        Finding(
            asset_id=r["asset_id"].strip(),
            cve=r["cve"].strip().upper(),
            first_seen=date.fromisoformat(r["first_seen"].strip()),
            vector=(r.get("cvss_vector") or "").strip() or None,
            source=(r.get("source") or "").strip(),
        )
        for r in rows
    ]


def assign_tier(cvss: CvssV3 | None, kev: KevEntry | None, epss: EpssScore | None,
                asset: Asset) -> tuple[int, list[str]]:
    reasons: list[str] = []
    base = cvss.base_score if cvss else 0.0
    prob = epss.probability if epss else 0.0
    exposed = asset.internet_facing

    if kev:
        reasons.append("listed in CISA KEV (known exploited)")
        if kev.ransomware:
            reasons.append("KEV notes known ransomware use")
        return 1, reasons
    if prob >= EPSS_URGENT and exposed:
        return 1, [f"EPSS {prob:.2f} on an internet-facing asset"]
    if (cvss and base >= 9.0 and cvss.network_reachable and cvss.no_privileges
            and not cvss.needs_user and exposed):
        return 1, [f"CVSS {base} unauthenticated network flaw on an internet-facing asset"]

    if prob >= EPSS_ELEVATED:
        tier = 2
        reasons.append(f"EPSS {prob:.2f} (elevated exploitation likelihood)")
    elif base >= 9.0:
        tier = 2
        reasons.append(f"CVSS {base} critical")
    elif base >= 7.0 and exposed:
        tier = 2
        reasons.append(f"CVSS {base} on an internet-facing asset")
    elif base >= 7.0:
        tier = 3
        reasons.append(f"CVSS {base} high")
    else:
        tier = 4
        reasons.append(f"CVSS {base}" if cvss else "no CVSS data")

    if asset.criticality == "high" and tier > 2:
        tier -= 1
        reasons.append("raised one tier: high-criticality asset")
    return tier, reasons


def assess(findings: list[Finding], assets: dict[str, Asset], kev: dict[str, KevEntry],
           epss: dict[str, EpssScore], nvd: dict[str, NvdRecord], as_of: date) -> list[Assessed]:
    out: list[Assessed] = []
    for f in findings:
        asset = assets.get(f.asset_id)
        if asset is None:
            raise ValueError(f"finding {f.cve} references unknown asset {f.asset_id}")
        record = nvd.get(f.cve)
        vector = f.vector or (record.cvss_vector if record else None)
        cvss = None
        if vector:
            try:
                cvss = score(vector)
            except CvssError:
                cvss = None
        k, e = kev.get(f.cve), epss.get(f.cve)
        tier, reasons = assign_tier(cvss, k, e, asset)
        cwes = record.cwes if record else ()
        due = f.first_seen + timedelta(days=SLA_DAYS[tier])
        out.append(Assessed(
            finding=f, asset=asset, cvss=cvss, kev=k, epss=e, nvd=record,
            attack=map_technique(cvss, cwes, asset.internet_facing),
            tier=tier, reasons=reasons, due=due, overdue=due < as_of,
        ))
    out.sort(key=Assessed.sort_key)
    return out
