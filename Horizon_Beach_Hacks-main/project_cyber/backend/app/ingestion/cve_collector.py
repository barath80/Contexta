"""
Contexta Backend - CVE Feed Collector

Sources:
  * CISA Known Exploited Vulnerabilities (KEV) catalog
  * NVD CVE API 2.0 (CVSS, vectors, CPE, references)
  * FIRST EPSS (probability of exploitation in the next 30 days)
"""

import asyncio
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

import httpx
import structlog

from app.config import settings

logger = structlog.get_logger()

_DATE_FORMATS = ("%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d")


def parse_date(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    raw = value.replace("Z", "").split("+")[0]
    for fmt in _DATE_FORMATS:
        try:
            return datetime.strptime(raw, fmt)
        except ValueError:
            continue
    return None


class CVECollector:
    """Fetches and normalises vulnerability intelligence."""

    def __init__(self, client: Optional[httpx.AsyncClient] = None):
        self._client = client
        self._owns_client = client is None
        self._nvd_delay = 0.7 if settings.nvd_api_key else 6.5  # NVD public rate limit

    async def _http(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=settings.feed_http_timeout_seconds, follow_redirects=True)
        return self._client

    async def close(self) -> None:
        if self._client is not None and self._owns_client:
            await self._client.aclose()
            self._client = None

    def _nvd_headers(self) -> Dict[str, str]:
        return {"apiKey": settings.nvd_api_key} if settings.nvd_api_key else {}

    # ------------------------------------------------------------------ KEV
    async def fetch_cisa_kev(self) -> List[Dict[str, Any]]:
        """Fetch the CISA KEV catalog. Raises httpx.HTTPError on failure."""
        client = await self._http()
        response = await client.get(settings.cisa_kev_url)
        response.raise_for_status()
        vulns = response.json().get("vulnerabilities", [])
        items = [self._normalize_kev(v) for v in vulns if v.get("cveID")]
        logger.info("Fetched CISA KEV", count=len(items))
        return items

    @staticmethod
    def _normalize_kev(vuln: Dict[str, Any]) -> Dict[str, Any]:
        vendor = (vuln.get("vendorProject") or "").strip()
        product = (vuln.get("product") or "").strip()
        refs = []
        notes = vuln.get("notes") or ""
        for part in notes.replace(";", " ").split():
            if part.startswith("http"):
                refs.append(part)
        return {
            "cve_id": vuln["cveID"],
            "description": vuln.get("shortDescription") or vuln.get("vulnerabilityName") or "",
            "cvss_score": 0.0,  # not provided by KEV; enriched from NVD
            "affected_software": [f"{vendor} {product}".strip()],
            "published_date": parse_date(vuln.get("dateAdded")),
            "has_exploit": True,
            "exploit_sources": ["cisa_kev"],
            "cisa_kev": True,
            "kev_ransomware_use": (vuln.get("knownRansomwareCampaignUse") or "").lower() == "known",
            "cwes": list(vuln.get("cwes") or []),
            "references": refs,
            "required_action": vuln.get("requiredAction"),
            "due_date": vuln.get("dueDate"),
        }

    # ------------------------------------------------------------------ NVD
    async def _nvd_get(self, params: Dict[str, Any], attempts: int = 4) -> Dict[str, Any]:
        """GET the NVD API, backing off on rate limits (403/429), 5xx and timeouts."""
        client = await self._http()
        last: Optional[Exception] = None
        for attempt in range(attempts):
            try:
                response = await client.get(settings.nvd_api_url, params=params, headers=self._nvd_headers())
                if response.status_code in (403, 429, 503):
                    raise httpx.HTTPStatusError(f"NVD returned HTTP {response.status_code}", request=response.request, response=response)
                response.raise_for_status()
                return response.json()
            except (httpx.TransportError, httpx.HTTPStatusError) as exc:
                last = exc
                if isinstance(exc, httpx.HTTPStatusError) and exc.response.status_code < 500 and exc.response.status_code not in (403, 429):
                    break
                await asyncio.sleep(self._nvd_delay * (attempt + 1) * 2)
        raise RuntimeError(f"NVD request failed: {type(last).__name__}: {last}") from last

    async def fetch_nvd_recent(
        self,
        days_back: int = 14,
        severities: tuple = ("CRITICAL", "HIGH"),
        max_results: int = 200,
        page_size: int = 100,
    ) -> List[Dict[str, Any]]:
        """Recently modified CVEs of the given CVSS v3 severities."""
        end = datetime.utcnow()
        start = end - timedelta(days=min(days_back, 120))
        out: Dict[str, Dict[str, Any]] = {}
        for severity in severities:
            index = 0
            while True:
                params = {
                    "lastModStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
                    "lastModEndDate": end.strftime("%Y-%m-%dT%H:%M:%S.000"),
                    "cvssV3Severity": severity,
                    "resultsPerPage": page_size,
                    "startIndex": index,
                }
                data = await self._nvd_get(params)
                for vuln in data.get("vulnerabilities", []):
                    item = self.normalize_nvd(vuln)
                    if item:
                        out[item["cve_id"]] = item
                index += page_size
                if index >= data.get("totalResults", 0) or len(out) >= max_results:
                    break
                await asyncio.sleep(self._nvd_delay)
            await asyncio.sleep(self._nvd_delay)
        logger.info("Fetched NVD CVEs", count=len(out))
        return list(out.values())

    async def fetch_nvd_cve(self, cve_id: str) -> Optional[Dict[str, Any]]:
        vulns = (await self._nvd_get({"cveId": cve_id})).get("vulnerabilities", [])
        return self.normalize_nvd(vulns[0]) if vulns else None

    @staticmethod
    def normalize_nvd(vuln: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        cve = vuln.get("cve", {})
        cve_id = cve.get("id", "")
        if not cve_id.startswith("CVE-"):
            return None
        description = next(
            (d.get("value", "") for d in cve.get("descriptions", []) if d.get("lang") == "en"), ""
        )

        cvss_score, cvss_vector, attack_vector = 0.0, None, None
        metrics = cve.get("metrics", {})
        for version in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            entries = metrics.get(version)
            if entries:
                data = entries[0].get("cvssData", {})
                cvss_score = float(data.get("baseScore", 0.0) or 0.0)
                cvss_vector = data.get("vectorString")
                attack_vector = data.get("attackVector")
                break

        affected: List[str] = []
        ranges: List[Dict[str, Any]] = []
        for config in cve.get("configurations", []):
            for node in config.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    if not match.get("vulnerable"):
                        continue
                    parts = (match.get("criteria") or "").split(":")
                    if len(parts) >= 5:
                        product = f"{parts[3]}:{parts[4]}"
                        affected.append(product)
                        exact = parts[5] if len(parts) > 5 and parts[5] not in ("*", "-", "") else None
                        ranges.append({
                            "product": product, "exact": exact,
                            "start_incl": match.get("versionStartIncluding"), "start_excl": match.get("versionStartExcluding"),
                            "end_incl": match.get("versionEndIncluding"), "end_excl": match.get("versionEndExcluding"),
                        })

        has_exploit, sources, refs = False, [], []
        for ref in cve.get("references", []):
            url = (ref.get("url") or "")
            refs.append(url)
            if "Exploit" in (ref.get("tags") or []):
                has_exploit = True
                low = url.lower()
                if "github.com" in low:
                    sources.append("github")
                elif "exploit-db.com" in low:
                    sources.append("exploit-db")
                elif "metasploit" in low or "rapid7" in low:
                    sources.append("metasploit")
                else:
                    sources.append("other")

        cwes = []
        for w in cve.get("weaknesses", []):
            for d in w.get("description", []):
                if d.get("value", "").startswith("CWE-"):
                    cwes.append(d["value"])

        return {
            "cve_id": cve_id,
            "description": description,
            "cvss_score": cvss_score,
            "cvss_vector": cvss_vector,
            "attack_vector": (attack_vector or "").upper() or None,
            "affected_software": list(dict.fromkeys(affected)),
            "version_ranges": ranges[:200],
            "published_date": parse_date(cve.get("published")),
            "last_modified": parse_date(cve.get("lastModified")),
            "has_exploit": has_exploit,
            "exploit_sources": list(dict.fromkeys(sources)),
            "cisa_kev": bool(cve.get("cisaExploitAdd")),
            "cwes": list(dict.fromkeys(cwes)),
            "references": refs[:10],
        }

    # ----------------------------------------------------------------- EPSS
    async def fetch_epss(self, cve_ids: List[str]) -> Dict[str, Dict[str, float]]:
        """EPSS score/percentile per CVE (batches of 100)."""
        client = await self._http()
        out: Dict[str, Dict[str, float]] = {}
        for i in range(0, len(cve_ids), 100):
            batch = cve_ids[i:i + 100]
            response = await client.get(settings.epss_api_url, params={"cve": ",".join(batch)})
            response.raise_for_status()
            for row in response.json().get("data", []):
                try:
                    out[row["cve"]] = {"epss": float(row["epss"]), "percentile": float(row["percentile"])}
                except (KeyError, ValueError):
                    continue
        return out
