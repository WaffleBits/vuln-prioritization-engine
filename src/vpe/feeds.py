"""Public threat-intel feeds: CISA KEV, FIRST EPSS and NVD.

Everything goes through one small fetch function so tests can swap in fixtures
and so the tool can run fully offline from a cache directory. Only CVE IDs are
ever sent to these services.
"""

from __future__ import annotations

import hashlib
import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
USER_AGENT = "vuln-prioritization-engine/0.1"

Fetch = Callable[[str], dict]


@dataclass(frozen=True)
class KevEntry:
    cve: str
    vendor: str
    product: str
    name: str
    date_added: str
    due_date: str
    ransomware: bool
    required_action: str


@dataclass(frozen=True)
class EpssScore:
    cve: str
    probability: float
    percentile: float
    date: str


@dataclass(frozen=True)
class NvdRecord:
    cve: str
    description: str
    cvss_vector: str | None
    cwes: tuple[str, ...] = field(default_factory=tuple)


def http_fetch(url: str, attempts: int = 4, backoff: float = 6.0) -> dict:
    if not url.startswith("https://"):
        raise ValueError(f"refusing non-https URL: {url}")
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})  # noqa: S310 (https checked)
    for attempt in range(1, attempts + 1):
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:  # noqa: S310 (https checked)
                return json.load(resp)
        except (TimeoutError, urllib.error.URLError) as exc:
            retryable = not isinstance(exc, urllib.error.HTTPError) or exc.code in (403, 429, 500, 502, 503)
            if attempt == attempts or not retryable:
                raise
            time.sleep(backoff * attempt)
    raise AssertionError("unreachable")


class CachedFetch:
    """Wraps a fetch function with an on-disk JSON cache keyed by URL."""

    def __init__(self, cache_dir: Path, fetch: Fetch = http_fetch, offline: bool = False,
                 min_interval: float = 0.0):
        self.cache_dir = cache_dir
        self.fetch = fetch
        self.offline = offline
        self.min_interval = min_interval
        self._last = 0.0
        cache_dir.mkdir(parents=True, exist_ok=True)

    def _path(self, url: str) -> Path:
        # Hash the full URL: truncating it would let two long EPSS batch URLs collide.
        digest = hashlib.sha256(url.encode()).hexdigest()[:24]
        host = urllib.parse.urlsplit(url).hostname or "url"
        return self.cache_dir / f"{host}-{digest}.json"

    def __call__(self, url: str) -> dict:
        path = self._path(url)
        if path.exists():
            return json.loads(path.read_text(encoding="utf-8"))
        if self.offline:
            raise LookupError(f"offline and not cached: {url}")
        wait = self.min_interval - (time.monotonic() - self._last)
        if wait > 0:
            time.sleep(wait)
        data = self.fetch(url)
        self._last = time.monotonic()
        path.write_text(json.dumps(data), encoding="utf-8")
        return data


def parse_kev(doc: dict) -> dict[str, KevEntry]:
    out: dict[str, KevEntry] = {}
    for v in doc.get("vulnerabilities", []):
        cve = v["cveID"].upper()
        out[cve] = KevEntry(
            cve=cve,
            vendor=v.get("vendorProject", ""),
            product=v.get("product", ""),
            name=v.get("vulnerabilityName", ""),
            date_added=v.get("dateAdded", ""),
            due_date=v.get("dueDate", ""),
            ransomware=v.get("knownRansomwareCampaignUse", "").lower() == "known",
            required_action=v.get("requiredAction", ""),
        )
    return out


def parse_epss(doc: dict) -> dict[str, EpssScore]:
    out: dict[str, EpssScore] = {}
    for row in doc.get("data", []):
        cve = row["cve"].upper()
        out[cve] = EpssScore(
            cve=cve,
            probability=float(row["epss"]),
            percentile=float(row["percentile"]),
            date=row.get("date", ""),
        )
    return out


def _pick_metric(entries: list[dict]) -> dict:
    """NVD's own assessment first, then any entry marked Primary, then the first one.

    Older records can carry NVD's score marked "Secondary" next to a vendor (CNA)
    score, so the type field alone is not enough to find NVD's assessment.
    """
    for e in entries:
        if e.get("source") == "nvd@nist.gov":
            return e
    for e in entries:
        if e.get("type") == "Primary":
            return e
    return entries[0]


def parse_nvd(doc: dict) -> dict[str, NvdRecord]:
    out: dict[str, NvdRecord] = {}
    for item in doc.get("vulnerabilities", []):
        cve = item["cve"]
        cve_id = cve["id"].upper()
        desc = next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
        vector = None
        metrics = cve.get("metrics", {})
        for key in ("cvssMetricV31", "cvssMetricV30"):
            entries = metrics.get(key) or []
            if entries:
                vector = _pick_metric(entries)["cvssData"]["vectorString"]
                break
        cwes = []
        for w in cve.get("weaknesses", []):
            for d in w.get("description", []):
                val = d.get("value", "")
                if val.startswith("CWE-") and val not in cwes:
                    cwes.append(val)
        out[cve_id] = NvdRecord(cve=cve_id, description=desc, cvss_vector=vector, cwes=tuple(cwes))
    return out


def load_kev(fetch: Fetch) -> dict[str, KevEntry]:
    return parse_kev(fetch(KEV_URL))


def load_epss(fetch: Fetch, cves: Iterable[str]) -> dict[str, EpssScore]:
    ids = sorted({c.upper() for c in cves})
    out: dict[str, EpssScore] = {}
    for i in range(0, len(ids), 100):
        chunk = ",".join(ids[i : i + 100])
        out.update(parse_epss(fetch(f"{EPSS_URL}?cve={chunk}")))
    return out


def load_nvd(fetch: Fetch, cves: Iterable[str]) -> dict[str, NvdRecord]:
    out: dict[str, NvdRecord] = {}
    for cve in sorted({c.upper() for c in cves}):
        try:
            out.update(parse_nvd(fetch(f"{NVD_URL}?cveId={cve}")))
        except LookupError:
            continue
        except (TimeoutError, urllib.error.URLError) as exc:
            print(f"warning: NVD lookup failed for {cve}: {exc}", file=sys.stderr)
    return out
