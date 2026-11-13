from datetime import date

import pytest
from conftest import (
    CRIT_NET,
    HIGH_LOCAL,
    HIGH_NET,
    MED,
    make_asset,
    make_epss,
    make_finding,
    make_kev,
    make_nvd,
)

from vpe.cvss import score
from vpe.prioritize import assess, assign_tier, load_assets, load_findings


def tier(vector=None, kev=None, epss=None, **asset_kw):
    cvss = score(vector) if vector else None
    return assign_tier(cvss, kev, epss, make_asset(**asset_kw))[0]


def test_kev_is_always_p1_even_when_low_cvss_and_internal():
    assert tier(MED, kev=make_kev("CVE-1")) == 1


def test_high_epss_on_internet_facing_is_p1():
    assert tier(MED, epss=make_epss("CVE-1", 0.6), internet_facing=True) == 1


def test_high_epss_internal_is_p2_not_p1():
    assert tier(MED, epss=make_epss("CVE-1", 0.6)) == 2


def test_unauthenticated_critical_on_internet_facing_is_p1():
    assert tier(CRIT_NET, internet_facing=True) == 1


def test_critical_internal_is_p2():
    assert tier(CRIT_NET) == 2


def test_high_on_internet_facing_is_p2():
    assert tier(HIGH_NET, internet_facing=True) == 2


def test_high_internal_is_p3():
    assert tier(HIGH_LOCAL) == 3


def test_high_criticality_raises_one_tier_but_never_into_p1():
    assert tier(HIGH_LOCAL, criticality="high") == 2
    assert tier(MED, criticality="high") == 3
    assert tier(CRIT_NET, criticality="high") == 2


def test_medium_without_signals_is_p4():
    assert tier(MED) == 4
    assert tier(None) == 4


def test_ransomware_reason_recorded():
    _, reasons = assign_tier(score(MED), make_kev("CVE-1", ransomware=True), None, make_asset())
    assert any("ransomware" in r for r in reasons)


def test_assess_orders_and_sets_due_dates(as_of):
    assets = {"A-1": make_asset("A-1", internet_facing=True), "A-2": make_asset("A-2")}
    findings = [
        make_finding("CVE-LOW", "A-2", vector=MED),
        make_finding("CVE-KEV", "A-2", vector=MED, first_seen=date(2026, 10, 1)),
        make_finding("CVE-CRIT", "A-1", vector=CRIT_NET, first_seen=date(2026, 11, 10)),
    ]
    out = assess(findings, assets, {"CVE-KEV": make_kev("CVE-KEV")}, {}, {}, as_of)
    assert [a.finding.cve for a in out] == ["CVE-KEV", "CVE-CRIT", "CVE-LOW"]
    kev = out[0]
    assert kev.due == date(2026, 10, 16) and kev.overdue
    assert out[1].due == date(2026, 11, 25) and not out[1].overdue


def test_scanner_vector_wins_over_nvd(as_of):
    assets = {"A-1": make_asset()}
    findings = [make_finding("CVE-1", vector=MED)]
    out = assess(findings, assets, {}, {}, {"CVE-1": make_nvd("CVE-1", CRIT_NET)}, as_of)
    assert out[0].cvss_score == 5.3


def test_nvd_vector_used_when_scanner_has_none(as_of):
    out = assess([make_finding("CVE-1")], {"A-1": make_asset()}, {}, {},
                 {"CVE-1": make_nvd("CVE-1", CRIT_NET)}, as_of)
    assert out[0].cvss_score == 9.8


def test_bad_vector_degrades_to_no_cvss(as_of):
    out = assess([make_finding("CVE-1", vector="garbage")], {"A-1": make_asset()}, {}, {}, {}, as_of)
    assert out[0].cvss is None and out[0].tier == 4


def test_unknown_asset_is_an_error(as_of):
    with pytest.raises(ValueError):
        assess([make_finding("CVE-1", "A-9")], {"A-1": make_asset()}, {}, {}, {}, as_of)


def test_csv_loaders(tmp_path):
    a = tmp_path / "a.csv"
    a.write_text("asset_id,hostname,environment,internet_facing,criticality,owner\n"
                 "A-1,web,prod,Yes,High,Team\n", encoding="utf-8")
    f = tmp_path / "f.csv"
    f.write_text("asset_id,cve,first_seen,cvss_vector,source\n"
                 "A-1,cve-2021-44228,2026-09-15,,scan\n", encoding="utf-8")
    assets = load_assets(a)
    findings = load_findings(f)
    assert assets["A-1"].internet_facing and assets["A-1"].criticality == "high"
    assert findings[0].cve == "CVE-2021-44228" and findings[0].vector is None


def test_invalid_criticality_rejected(tmp_path):
    a = tmp_path / "a.csv"
    a.write_text("asset_id,hostname,environment,internet_facing,criticality,owner\n"
                 "A-1,web,prod,yes,urgent,Team\n", encoding="utf-8")
    with pytest.raises(ValueError):
        load_assets(a)
