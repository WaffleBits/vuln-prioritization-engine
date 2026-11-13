import pytest

from vpe.feeds import (
    EPSS_URL,
    KEV_URL,
    NVD_URL,
    CachedFetch,
    load_epss,
    load_kev,
    load_nvd,
    parse_nvd,
)

KEV_DOC = {"vulnerabilities": [{
    "cveID": "CVE-2021-44228", "vendorProject": "Apache", "product": "Log4j2",
    "vulnerabilityName": "Apache Log4j2 Remote Code Execution Vulnerability",
    "dateAdded": "2021-12-10", "dueDate": "2021-12-24",
    "knownRansomwareCampaignUse": "Known", "requiredAction": "Apply updates",
}]}

NVD_DOC = {"vulnerabilities": [{"cve": {
    "id": "CVE-2021-44228",
    "descriptions": [{"lang": "es", "value": "x"}, {"lang": "en", "value": "Log4j JNDI"}],
    "metrics": {"cvssMetricV31": [
        {"type": "Secondary", "cvssData": {"vectorString": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N"}},
        {"type": "Primary", "cvssData": {"vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"}},
    ]},
    "weaknesses": [{"description": [{"lang": "en", "value": "CWE-502"},
                                    {"lang": "en", "value": "NVD-CWE-Other"}]},
                   {"description": [{"lang": "en", "value": "CWE-502"}]}],
}}]}


def fake(docs, calls=None):
    def fetch(url):
        if calls is not None:
            calls.append(url)
        for prefix, doc in docs.items():
            if url.startswith(prefix):
                return doc
        raise AssertionError(f"unexpected url {url}")
    return fetch


def test_kev_parse():
    kev = load_kev(fake({KEV_URL: KEV_DOC}))
    entry = kev["CVE-2021-44228"]
    assert entry.ransomware and entry.due_date == "2021-12-24"


def test_epss_batches_and_uppercases():
    calls = []
    doc = {"data": [{"cve": "CVE-2021-44228", "epss": "0.94358", "percentile": "0.99957",
                     "date": "2026-11-13"}]}
    out = load_epss(fake({EPSS_URL: doc}, calls), ["cve-2021-44228"] + [f"CVE-2000-{i}" for i in range(150)])
    assert len(calls) == 2
    assert out["CVE-2021-44228"].probability == pytest.approx(0.94358)


def test_nvd_prefers_primary_and_dedupes_cwes():
    rec = parse_nvd(NVD_DOC)["CVE-2021-44228"]
    assert rec.cvss_vector.endswith("S:C/C:H/I:H/A:H")
    assert rec.cwes == ("CWE-502",)
    assert rec.description == "Log4j JNDI"


def test_nvd_own_score_wins_even_when_marked_secondary():
    # Shape of the real Zerologon (CVE-2020-1472) record: vendor 5.5 first, NVD 10.0 second.
    doc = {"vulnerabilities": [{"cve": {"id": "CVE-2020-1472", "descriptions": [], "metrics": {
        "cvssMetricV31": [
            {"source": "secure@microsoft.com", "type": "Secondary",
             "cvssData": {"vectorString": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"}},
            {"source": "nvd@nist.gov", "type": "Secondary",
             "cvssData": {"vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"}},
        ]}}}]}
    assert parse_nvd(doc)["CVE-2020-1472"].cvss_vector.startswith("CVSS:3.1/AV:N")


def test_nvd_without_v3_metrics():
    doc = {"vulnerabilities": [{"cve": {"id": "CVE-2000-1", "descriptions": [], "metrics": {}}}]}
    assert parse_nvd(doc)["CVE-2000-1"].cvss_vector is None


def test_long_urls_do_not_collide_in_cache(tmp_path):
    cache = CachedFetch(tmp_path, fetch=lambda url: {"url": url})
    a = f"{EPSS_URL}?cve=" + ",".join(f"CVE-2020-{i:05d}" for i in range(40))
    b = a + ",CVE-2024-99999"
    assert cache(a)["url"] == a
    assert cache(b)["url"] == b


def test_cache_serves_second_call_and_offline(tmp_path):
    calls = []
    live = CachedFetch(tmp_path, fetch=fake({NVD_URL: NVD_DOC}, calls))
    load_nvd(live, ["CVE-2021-44228"])
    load_nvd(live, ["CVE-2021-44228"])
    assert len(calls) == 1
    offline = CachedFetch(tmp_path, fetch=fake({}), offline=True)
    assert "CVE-2021-44228" in load_nvd(offline, ["CVE-2021-44228"])
    # Offline and uncached: skipped rather than crashing the whole run.
    assert load_nvd(offline, ["CVE-1999-0001"]) == {}
