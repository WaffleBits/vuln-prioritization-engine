# vuln-prioritization-engine

Risk-based vulnerability prioritization. It takes scanner findings and an asset
inventory, adds public threat intelligence, and produces a ranked worklist, a
POA&M-style CSV and a static dashboard.

Severity alone is a poor queue. A CVSS 9.8 nobody exploits can wait while a 6.1
on an internet-facing server that attackers are actively using cannot. This tool
ranks by evidence of exploitation first, then exposure, then severity:

- **CISA KEV**: is it known to be exploited in the wild, and used by ransomware?
- **FIRST EPSS**: how likely is exploitation in the next 30 days?
- **CVSS v3.1**: base score computed from the vector with the spec's equations
- **Asset context**: internet-facing or internal, and business criticality

Every priority comes with a one-line reason, a due date and a heuristic MITRE
ATT&CK technique, so the owner who has to fix it can see why.

**[Example dashboard](https://wafflebits.github.io/vuln-prioritization-engine/examples/output/dashboard.html)**
built from the sample data below against live feeds on 13 Nov 2026.

## Priority rules

| Priority | Fires when | Due |
|---|---|---|
| **P1** | Listed in CISA KEV; or EPSS >= 0.5 on an internet-facing asset; or CVSS >= 9.0, network, no privileges, no user interaction, on an internet-facing asset | 15 days |
| **P2** | EPSS >= 0.1; or CVSS >= 9.0; or CVSS >= 7.0 on an internet-facing asset | 30 days |
| **P3** | CVSS >= 7.0 | 90 days |
| **P4** | Everything else | 180 days |

A high-criticality asset raises P3 or P4 by one tier, but never into P1: P1 is
reserved for evidence of exploitation or direct exposure. The 15-day window
follows CISA BOD 22-01 for newly added KEV entries; 30, 90 and 180 days follow
the FedRAMP continuous monitoring timelines for high, moderate and low findings.
[docs/scoring.md](docs/scoring.md) explains each threshold.

## Example result

The sample inventory has 8 synthetic assets and 22 findings using real CVEs.
Run on 13 Nov 2026 against live KEV, EPSS and NVD data:

| | Count |
|---|---|
| Findings | 22 |
| P1 / P2 / P3 / P4 | 9 / 7 / 1 / 5 |
| In CISA KEV | 8 |
| Past due | 12 |

Two results show why the ordering matters. CVE-2019-11358 (jQuery, CVSS 6.1)
lands in P1 because its EPSS is 0.87 and it sits on an internet-facing web
server. CVE-2020-8203 (lodash, CVSS 7.4) lands in P3 because nothing suggests
it is being exploited and the build server is internal.

The assets, hostnames and dates are made up. Only the CVE IDs and the feed data
are real.

## Run it

Python 3.11+, no runtime dependencies.

```bash
pip install -e .[dev]
pytest
ruff check .

vpe run --assets examples/assets.csv --findings examples/findings.csv --out out
```

Outputs:

- `out/poam.csv`: one row per finding, with column names from the vulnerability
  fields of the FedRAMP POA&M template (controls RA-5 and SI-2)
- `out/findings.json`: the same rows as JSON
- `out/dashboard.html`: one file, no JavaScript, light and dark mode

Feed responses are cached under `.cache/feeds`. `--offline` runs from the cache
only, and `--as-of YYYY-MM-DD` pins the date used for overdue checks. NVD is
rate-limited to one request every 6.5 seconds without an API key, so the first
run on a large list is slow.

### Input format

`assets.csv`

```
asset_id,hostname,environment,internet_facing,criticality,owner
A-001,vpn-gw-01,edge,yes,high,Network Team
```

`findings.csv` (the vector column is optional; if empty, the NVD vector is used)

```
asset_id,cve,first_seen,cvss_vector,source
A-001,CVE-2024-3400,2026-10-28,,network scan
```

## What it does not do

- It does not scan anything. It ranks findings that a scanner already produced.
- CVSS v4.0 vectors are not scored yet; v3.0 and v3.1 are.
- ATT&CK mappings come from the CVSS vector, the CWE and the asset's exposure.
  They are a starting point for an analyst, not ground truth.
- The POA&M output is a draft for an ISSO to review, not a submission.
- Only CVE IDs are sent to the public feeds. Asset data never leaves the machine.

## Layout

```
src/vpe/cvss.py         CVSS v3.1 base score from the spec equations
src/vpe/feeds.py        KEV, EPSS and NVD clients with an on-disk cache
src/vpe/prioritize.py   priority rules, due dates, ordering
src/vpe/attack.py       heuristic ATT&CK technique mapping
src/vpe/poam.py         POA&M CSV and JSON export
src/vpe/dashboard.py    static HTML dashboard
tests/                  60 tests, no network access needed
```

## License

MIT
