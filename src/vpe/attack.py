"""Heuristic MITRE ATT&CK mapping for a vulnerability on a specific asset.

This maps how an attacker would most likely use the flaw, from the CVSS vector,
the CWE and where the asset sits. It is a starting point for an analyst, not a
ground truth: the report labels every mapping as heuristic.
"""

from __future__ import annotations

from dataclasses import dataclass

from .cvss import CvssV3

TECHNIQUES = {
    "T1190": "Exploit Public-Facing Application",
    "T1210": "Exploitation of Remote Services",
    "T1203": "Exploitation for Client Execution",
    "T1068": "Exploitation for Privilege Escalation",
    "T1212": "Exploitation for Credential Access",
    "T1499.004": "Endpoint Denial of Service: Application or System Exploitation",
    "T1189": "Drive-by Compromise",
}

CREDENTIAL_CWES = {"CWE-522", "CWE-256", "CWE-312", "CWE-798", "CWE-200", "CWE-307"}
DOS_ONLY_CWES = {"CWE-400", "CWE-770", "CWE-835", "CWE-674", "CWE-404"}
BROWSER_CWES = {"CWE-79"}


@dataclass(frozen=True)
class Mapping:
    technique: str
    name: str
    reason: str


def map_technique(cvss: CvssV3 | None, cwes: tuple[str, ...], internet_facing: bool) -> Mapping:
    def m(tid: str, reason: str) -> Mapping:
        return Mapping(tid, TECHNIQUES[tid], reason)

    cwe_set = set(cwes)
    if cvss is None:
        if internet_facing:
            return m("T1190", "no CVSS vector; asset is internet-facing")
        return m("T1210", "no CVSS vector; internal asset")

    mt = cvss.metrics
    availability_only = mt["C"] == "N" and mt["I"] == "N" and mt["A"] != "N"
    if availability_only or (cwe_set and cwe_set <= DOS_ONLY_CWES):
        return m("T1499.004", "impact is availability only")
    if cwe_set & CREDENTIAL_CWES and mt["C"] != "N":
        return m("T1212", "weakness exposes credentials or secrets")
    if mt["AV"] in ("L", "P"):
        return m("T1068", "local attack vector; useful after initial access")
    if cwe_set & BROWSER_CWES:
        return m("T1189", "script injection delivered through a browser")
    if mt["UI"] == "R":
        return m("T1203", "network vector but needs a user to act")
    if internet_facing:
        return m("T1190", "network reachable with no user interaction on an internet-facing asset")
    return m("T1210", "network reachable with no user interaction on an internal asset")
