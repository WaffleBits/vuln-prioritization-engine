"""Single-file HTML dashboard. No JavaScript, no external assets, opens anywhere."""

from __future__ import annotations

from collections import Counter
from datetime import date
from html import escape
from pathlib import Path

from .prioritize import TIER_LABEL, Assessed

CSS = """
:root{--bg:#f7f7f5;--card:#fff;--ink:#1d1d1f;--mute:#6b6b70;--line:#e3e3e0;
--p1:#b42318;--p2:#c4570c;--p3:#a17c00;--p4:#4b6b8a}
@media (prefers-color-scheme:dark){:root{--bg:#141416;--card:#1d1d20;--ink:#ececee;
--mute:#9a9aa2;--line:#2c2c31;--p1:#f0645a;--p2:#f59a4a;--p3:#e0c04a;--p4:#8db3d9}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);
font:14px/1.45 system-ui,-apple-system,Segoe UI,sans-serif}
main{max-width:1180px;margin:0 auto;padding:24px 16px 48px}
h1{font-size:22px;margin:0 0 4px}h2{font-size:16px;margin:28px 0 10px}
.sub{color:var(--mute);margin:0 0 20px}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px}
.tile{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px}
.tile b{display:block;font-size:26px}.tile span{color:var(--mute)}
.bars{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px}
.bar{display:grid;grid-template-columns:150px 1fr 40px;gap:10px;align-items:center;margin:6px 0}
.track{background:var(--line);border-radius:4px;height:12px;overflow:hidden}
.fill{height:100%}
.wrap{overflow-x:auto;background:var(--card);border:1px solid var(--line);border-radius:10px}
table{border-collapse:collapse;width:100%;min-width:900px}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--mute);font-weight:600;font-size:12px}
.pill{display:inline-block;padding:1px 8px;border-radius:999px;color:#fff;font-weight:600;font-size:12px}
.P1{background:var(--p1)}.P2{background:var(--p2)}.P3{background:var(--p3)}.P4{background:var(--p4)}
.why{color:var(--mute);font-size:12px}.over{color:var(--p1);font-weight:600}
footer{color:var(--mute);font-size:12px;margin-top:24px}
"""


def _bar(label: str, count: int, total: int, color: str) -> str:
    pct = 0 if total == 0 else round(100 * count / total)
    return (f'<div class="bar"><span>{escape(label)}</span><div class="track">'
            f'<div class="fill" style="width:{pct}%;background:{color}"></div></div>'
            f"<span>{count}</span></div>")


def render(assessed: list[Assessed], as_of: date, sources: str) -> str:
    total = len(assessed)
    tiers = Counter(a.tier for a in assessed)
    kev = sum(1 for a in assessed if a.kev)
    overdue = sum(1 for a in assessed if a.overdue)
    exposed = sum(1 for a in assessed if a.asset.internet_facing and a.tier <= 2)
    techniques = Counter(f"{a.attack.technique} {a.attack.name}" for a in assessed)
    by_asset = Counter(a.asset.hostname or a.asset.asset_id for a in assessed if a.tier <= 2)

    tiles = "".join(
        f'<div class="tile"><b>{v}</b><span>{escape(k)}</span></div>'
        for k, v in [("findings", total), ("known exploited (KEV)", kev),
                     ("P1 + P2 on internet-facing", exposed), ("past due", overdue)]
    )
    tier_bars = "".join(_bar(TIER_LABEL[t], tiers.get(t, 0), total, f"var(--p{t})")
                        for t in (1, 2, 3, 4))
    asset_bars = "".join(_bar(k, v, max(by_asset.values(), default=1), "var(--p2)")
                         for k, v in by_asset.most_common(8)) or "<p class='why'>none</p>"
    tech_bars = "".join(_bar(k, v, total, "var(--p4)") for k, v in techniques.most_common())

    body_rows = []
    for a in assessed:
        due = a.due.isoformat() if a.due else ""
        due_cell = f'<span class="over">{due} (overdue)</span>' if a.overdue else due
        body_rows.append(
            "<tr>"
            f'<td><span class="pill {a.priority}">{a.priority}</span></td>'
            f"<td>{escape(a.finding.cve)}<div class='why'>{escape(a.kev.name if a.kev else '')}</div></td>"
            f"<td>{escape(a.asset.hostname or a.asset.asset_id)}"
            f"<div class='why'>{escape(a.asset.environment)}"
            f"{' / internet-facing' if a.asset.internet_facing else ''}"
            f" / {escape(a.asset.criticality)}</div></td>"
            f"<td>{a.cvss_score:.1f}</td>"
            f"<td>{a.epss_probability:.3f}</td>"
            f"<td>{'Yes' if a.kev else ''}</td>"
            f"<td>{escape(a.attack.technique)}<div class='why'>{escape(a.attack.name)}</div></td>"
            f"<td>{due_cell}</td>"
            f"<td class='why'>{escape('; '.join(a.reasons))}</td>"
            "</tr>"
        )

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Vulnerability Priorities</title><style>{CSS}</style></head>
<body><main>
<h1>Vulnerability priorities</h1>
<p class="sub">As of {as_of.isoformat()} &middot; {escape(sources)}</p>
<div class="tiles">{tiles}</div>
<h2>By priority</h2><div class="bars">{tier_bars}</div>
<h2>Assets with the most P1/P2 findings</h2><div class="bars">{asset_bars}</div>
<h2>Likely ATT&amp;CK technique (heuristic)</h2><div class="bars">{tech_bars}</div>
<h2>Worklist</h2>
<div class="wrap"><table><thead><tr><th>Priority</th><th>CVE</th><th>Asset</th>
<th>CVSS</th><th>EPSS</th><th>KEV</th><th>ATT&amp;CK</th><th>Due</th><th>Why</th></tr></thead>
<tbody>{''.join(body_rows)}</tbody></table></div>
<footer>Generated by vuln-prioritization-engine.
ATT&amp;CK mappings are heuristic and need analyst review.</footer>
</main></body></html>
"""


def write(assessed: list[Assessed], path: Path, as_of: date, sources: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render(assessed, as_of, sources), encoding="utf-8")
