from datetime import date

import pytest

from vpe.feeds import EpssScore, KevEntry, NvdRecord
from vpe.prioritize import Asset, Finding

CRIT_NET = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"   # 9.8
HIGH_NET = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"   # 8.8
HIGH_LOCAL = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"  # 7.8
MED = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"        # 5.3
DOS = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"        # 7.5


def make_asset(asset_id="A-1", internet_facing=False, criticality="moderate"):
    return Asset(asset_id=asset_id, hostname=f"host-{asset_id}", environment="prod",
                 internet_facing=internet_facing, criticality=criticality, owner="Team")


def make_kev(cve, ransomware=False):
    return KevEntry(cve=cve, vendor="V", product="P", name=f"{cve} name", date_added="2024-01-01",
                    due_date="2024-01-22", ransomware=ransomware, required_action="Patch")


def make_epss(cve, p):
    return EpssScore(cve=cve, probability=p, percentile=0.5, date="2026-11-13")


def make_nvd(cve, vector=None, cwes=()):
    return NvdRecord(cve=cve, description=f"{cve} description", cvss_vector=vector, cwes=tuple(cwes))


def make_finding(cve, asset_id="A-1", first_seen=date(2026, 10, 1), vector=None):
    return Finding(asset_id=asset_id, cve=cve, first_seen=first_seen, vector=vector)


@pytest.fixture
def as_of():
    return date(2026, 11, 13)
