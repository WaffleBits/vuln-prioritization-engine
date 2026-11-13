"""Command line entry point: vpe run --assets A.csv --findings F.csv --out DIR"""

from __future__ import annotations

import argparse
import sys
from collections import Counter
from datetime import date
from pathlib import Path

from . import dashboard, poam
from .feeds import CachedFetch, load_epss, load_kev, load_nvd
from .prioritize import TIER_LABEL, assess, load_assets, load_findings


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="vpe", description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)
    run = sub.add_parser("run", help="enrich, prioritize and export findings")
    run.add_argument("--assets", type=Path, required=True, help="asset inventory CSV")
    run.add_argument("--findings", type=Path, required=True, help="scanner findings CSV")
    run.add_argument("--out", type=Path, default=Path("out"), help="output directory")
    run.add_argument("--cache-dir", type=Path, default=Path(".cache/feeds"))
    run.add_argument("--offline", action="store_true", help="use cached feed data only")
    run.add_argument("--as-of", type=date.fromisoformat, default=date.today(),
                     help="date used for overdue checks (YYYY-MM-DD)")
    return p


def run(args: argparse.Namespace) -> int:
    assets = load_assets(args.assets)
    findings = load_findings(args.findings)
    cves = {f.cve for f in findings}

    fetch = CachedFetch(args.cache_dir, offline=args.offline)
    # NVD allows about 5 requests per 30 seconds without an API key.
    nvd_fetch = CachedFetch(args.cache_dir, offline=args.offline, min_interval=6.5)

    kev = load_kev(fetch)
    epss = load_epss(fetch, cves)
    need_nvd = {f.cve for f in findings if not f.vector}
    nvd = load_nvd(nvd_fetch, cves if need_nvd else set())

    assessed = assess(findings, assets, kev, epss, nvd, args.as_of)
    sources = f"CISA KEV ({len(kev)} entries), FIRST EPSS, NVD"
    args.out.mkdir(parents=True, exist_ok=True)
    poam.write_csv(assessed, args.out / "poam.csv")
    poam.write_json(assessed, args.out / "findings.json")
    dashboard.write(assessed, args.out / "dashboard.html", args.as_of, sources)

    tiers = Counter(a.tier for a in assessed)
    summary = ", ".join(f"{TIER_LABEL[t]}={tiers.get(t, 0)}" for t in (1, 2, 3, 4))
    print(f"{len(assessed)} findings on {len(assets)} assets: {summary}")
    print(f"KEV matches: {sum(1 for a in assessed if a.kev)}; "
          f"overdue: {sum(1 for a in assessed if a.overdue)}")
    print(f"wrote {args.out / 'poam.csv'}, {args.out / 'findings.json'}, "
          f"{args.out / 'dashboard.html'}")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.cmd == "run":
        return run(args)
    return 2


if __name__ == "__main__":
    sys.exit(main())
