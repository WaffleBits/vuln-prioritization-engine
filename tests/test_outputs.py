import csv
import json

from conftest import CRIT_NET, MED, make_asset, make_finding, make_kev, make_nvd

from vpe import cli, dashboard, poam
from vpe.feeds import EPSS_URL, KEV_URL, NVD_URL, CachedFetch
from vpe.prioritize import assess


def sample(as_of):
    assets = {"A-1": make_asset("A-1", internet_facing=True, criticality="high"),
              "A-2": make_asset("A-2")}
    findings = [make_finding("CVE-1", "A-1", vector=CRIT_NET), make_finding("CVE-2", "A-2", vector=MED)]
    nvd = {"CVE-1": make_nvd("CVE-1", cwes=("CWE-78",)), "CVE-2": make_nvd("CVE-2")}
    return assess(findings, assets, {"CVE-1": make_kev("CVE-1")}, {}, nvd, as_of)


def test_poam_csv_has_template_columns(tmp_path, as_of):
    path = tmp_path / "poam.csv"
    poam.write_csv(sample(as_of), path)
    with path.open(encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    assert list(rows[0].keys()) == poam.POAM_COLUMNS
    assert rows[0]["POAM ID"] == "V-0001"
    assert rows[0]["Known Exploited (KEV)"] == "Yes"
    assert rows[0]["Original Risk Rating"] == "High"
    assert rows[1]["Priority"] == "P4"


def test_dashboard_escapes_untrusted_text(as_of):
    items = sample(as_of)
    items[0].asset = make_asset("<script>alert(1)</script>")
    html = dashboard.render(items, as_of, "test")
    assert "<script>alert(1)" not in html
    assert "&lt;script&gt;" in html


def test_cli_end_to_end_offline(tmp_path, capsys):
    cache = tmp_path / "cache"
    seed = CachedFetch(cache, fetch=lambda url: {
        KEV_URL: {"vulnerabilities": [{"cveID": "CVE-2021-44228", "vulnerabilityName": "Log4Shell",
                                       "dueDate": "2021-12-24", "knownRansomwareCampaignUse": "Known"}]},
    }.get(url) or ({"data": [{"cve": "CVE-2021-44228", "epss": "0.94", "percentile": "0.99"}]}
                   if url.startswith(EPSS_URL) else {"vulnerabilities": [{"cve": {
                       "id": "CVE-2021-44228", "descriptions": [{"lang": "en", "value": "JNDI"}],
                       "metrics": {"cvssMetricV31": [{"type": "Primary", "cvssData": {
                           "vectorString": CRIT_NET}}]}}}]}))
    seed(KEV_URL)
    seed(f"{EPSS_URL}?cve=CVE-2021-44228")
    seed(f"{NVD_URL}?cveId=CVE-2021-44228")

    assets = tmp_path / "assets.csv"
    assets.write_text("asset_id,hostname,environment,internet_facing,criticality,owner\n"
                      "A-1,web-01,prod,yes,high,Web\n", encoding="utf-8")
    findings = tmp_path / "findings.csv"
    findings.write_text("asset_id,cve,first_seen,cvss_vector,source\n"
                        "A-1,CVE-2021-44228,2026-09-15,,scan\n", encoding="utf-8")
    out = tmp_path / "out"
    code = cli.main(["run", "--assets", str(assets), "--findings", str(findings), "--out", str(out),
                     "--cache-dir", str(cache), "--offline", "--as-of", "2026-11-13"])
    assert code == 0
    data = json.loads((out / "findings.json").read_text(encoding="utf-8"))
    assert data[0]["Priority"] == "P1" and data[0]["Overdue"] == "Yes"
    assert (out / "dashboard.html").read_text(encoding="utf-8").startswith("<!doctype html>")
    assert "P1=1" in capsys.readouterr().out
