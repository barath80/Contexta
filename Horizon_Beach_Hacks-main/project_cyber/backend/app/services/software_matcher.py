"""
Contexta Backend - Software matcher

Decides whether a CVE's affected products (CPE-style "vendor:product", CISA
"Vendor Product", or free text) apply to the software installed on an asset
("Apache Log4j 2.14.1", "PostgreSQL 15", "Cisco IOS XE 17.6").

Matching is token based and requires the *product* tokens to match, so that a
shared vendor name alone (e.g. "microsoft") does not link unrelated products.
"""

import re
from dataclasses import dataclass
from typing import Iterable, List, Optional, Set

_STOP = {
    "the", "and", "for", "of", "server", "client", "software", "system", "systems",
    "inc", "corp", "corporation", "ltd", "project", "foundation", "software",
    "enterprise", "edition", "services", "service", "application", "platform",
}
# Vendor names too generic to count as a product match on their own.
_VENDORS = {
    "microsoft", "apache", "oracle", "cisco", "google", "ibm", "vmware", "adobe",
    "linux", "red", "hat", "redhat", "canonical", "fortinet", "paloalto", "palo", "alto",
    "f5", "sap", "atlassian", "citrix", "juniper", "dell", "hp", "hpe", "intel",
}
_VERSION = re.compile(r"^\d+([._-]\d+)*[a-z]?$")


def tokens(text: str) -> List[str]:
    parts = re.split(r"[^a-z0-9]+", (text or "").lower())
    return [p for p in parts if p and p not in _STOP]


def _product_tokens(text: str) -> Set[str]:
    return {t for t in tokens(text) if not _VERSION.match(t) and len(t) > 1 and not t.isdigit()}


@dataclass
class Match:
    asset_software: str
    cve_product: str
    score: int  # 0-100
    reason: str


def _split_cve_product(entry: str) -> tuple[str, str]:
    """Return (vendor_part, product_part) for 'vendor:product' / 'Vendor Product'."""
    entry = (entry or "").strip()
    if ":" in entry:
        vendor, _, product = entry.partition(":")
        return vendor.replace("_", " "), product.replace("_", " ")
    return "", entry.replace("_", " ")


def match_entry(cve_entry: str, installed: str) -> Optional[Match]:
    """Match one CVE affected-software entry against one installed-software string."""
    vendor, product = _split_cve_product(cve_entry)
    if not product.strip():
        return None
    # For CISA "Vendor Product" free text the vendor is the first token.
    cve_tokens = _product_tokens(product)
    if not vendor and cve_tokens:
        ordered = [t for t in tokens(product) if not _VERSION.match(t)]
        if len(ordered) > 1 and ordered[0] in _VENDORS:
            cve_tokens_no_vendor = set(ordered[1:])
            if cve_tokens_no_vendor:
                cve_tokens = cve_tokens_no_vendor
                vendor = ordered[0]
    inst_tokens = _product_tokens(installed)
    if not cve_tokens or not inst_tokens:
        return None

    meaningful = {t for t in cve_tokens if t not in _VENDORS} or cve_tokens
    overlap = meaningful & inst_tokens
    if not overlap:
        return None
    coverage = len(overlap) / len(meaningful)
    if coverage < 0.5:
        return None

    score = int(60 + 30 * coverage)
    vendor_tokens = _product_tokens(vendor)
    if vendor_tokens and (vendor_tokens & inst_tokens):
        score = min(100, score + 10)
    return Match(
        asset_software=installed,
        cve_product=cve_entry,
        score=score,
        reason=f"software:{'+'.join(sorted(overlap))}",
    )


def match_cve_to_software(cve_products: Iterable[str], installed: Iterable[str]) -> List[Match]:
    """All matches (best per installed item) between a CVE and an asset's software list."""
    best: dict[str, Match] = {}
    for inst in installed or []:
        for entry in cve_products or []:
            m = match_entry(entry, inst)
            if m and (inst not in best or m.score > best[inst].score):
                best[inst] = m
    return sorted(best.values(), key=lambda m: m.score, reverse=True)


def match_asset(cve_products: Iterable[str], software: Iterable[str], os_name: Optional[str] = None) -> List[Match]:
    """Match against installed software and the asset OS string."""
    items = list(software or [])
    if os_name:
        items.append(os_name)
    return match_cve_to_software(cve_products, items)


# ------------------------------------------------------------------ versions
_VER_IN_TEXT = re.compile(r"(?<![\w.])v?(\d+(?:\.\d+)*)")


def installed_version(installed: str) -> Optional[str]:
    """First dotted version found in an installed-software string ('Apache Log4j 2.14.1' -> '2.14.1')."""
    m = _VER_IN_TEXT.search(installed or "")
    return m.group(1) if m else None


def _vtuple(v: str) -> tuple:
    out = []
    for part in re.split(r"[._-]", str(v).lower().lstrip("v")):
        m = re.match(r"\d+", part)
        if not m:
            break
        out.append(int(m.group()))
    return tuple(out)


def _cmp(a: tuple, b: tuple) -> int:
    n = max(len(a), len(b))
    a, b = a + (0,) * (n - len(a)), b + (0,) * (n - len(b))
    return (a > b) - (a < b)


def _norm_product(entry: str) -> str:
    vendor, product = _split_cve_product(entry)
    return re.sub(r"[^a-z0-9]+", "", f"{vendor}{product}".lower())


def version_verdict(cve_product: str, ranges: Iterable[dict], installed: str) -> str:
    """
    'affected' | 'not_affected' | 'unknown' for an installed item against NVD CPE version bounds.
    Unknown whenever the data needed to decide is missing, so nothing is silently dropped.
    """
    version = installed_version(installed)
    if version is None:
        return "unknown"
    want = _norm_product(cve_product)
    relevant = [r for r in (ranges or []) if _norm_product(r.get("product", "")) == want]
    if not relevant:
        return "unknown"
    v = _vtuple(version)
    if not v:
        return "unknown"
    for r in relevant:
        bounds = [r.get("start_incl"), r.get("start_excl"), r.get("end_incl"), r.get("end_excl")]
        if r.get("exact") and not any(bounds):
            e = _vtuple(r["exact"])
            if e and _cmp(v[: len(e)], e) == 0:
                return "affected"
            continue
        if not any(bounds) and not r.get("exact"):
            return "affected"  # every version of this product
        ok = True
        if r.get("start_incl") and _cmp(v, _vtuple(r["start_incl"])) < 0:
            ok = False
        if r.get("start_excl") and _cmp(v, _vtuple(r["start_excl"])) <= 0:
            ok = False
        if r.get("end_incl") and _cmp(v, _vtuple(r["end_incl"])) > 0:
            ok = False
        if r.get("end_excl") and _cmp(v, _vtuple(r["end_excl"])) >= 0:
            ok = False
        if ok:
            return "affected"
    return "not_affected"


def match_asset_versioned(cve_products: Iterable[str], ranges: Iterable[dict], software: Iterable[str], os_name: Optional[str] = None) -> List[Match]:
    """Name matches filtered by version: patched software (outside NVD's affected range) is dropped."""
    out: List[Match] = []
    for m in match_asset(cve_products, software, os_name):
        verdict = version_verdict(m.cve_product, ranges, m.asset_software)
        if verdict == "not_affected":
            continue
        ver = installed_version(m.asset_software)
        m.reason += f" (v{ver} confirmed in affected range)" if verdict == "affected" else " (version not verified)"
        out.append(m)
    return out
