"""
agent_05_assets.py — Asset Matching Agent
Responsibility: For each CVE, determine which assets in the organization's
inventory are actually affected. A CVE that doesn't run on any of your
systems is not your problem — this agent filters the noise.

Matching strategy (most specific → least specific, stops at first hit):
  1. CPE string match   — exact vendor/product from NVD CPE data       [HIGH confidence]
  2. Vendor keyword     — vendor name in CVE description vs asset stack [MEDIUM confidence]
  3. Package name match — specific package/product in CVE vs asset list [MEDIUM confidence]
  4. CWE→asset_type     — CWE category maps to named asset types only   [LOW confidence]

REMOVED: the old "strategy 4 stack fallback" that matched every CVE to the org's
technology stack regardless of any specific connection. That caused 487/500 CVEs
to map to the same critical server, which is wrong and inflates scores.

A CVE with NO asset match is correctly treated as LOW priority (no confirmed exposure).
"""

from __future__ import annotations
from typing import Optional
import pandas as pd

from agents.shared.data_loader import load_assets
from agents.agent_01_ingest import extract_vendor_from_cpe, extract_product_from_cpe


# ── Vendor → stack keyword mapping ───────────────────────────────────────────
# Maps vendor names to specific software strings that must appear in asset stack.
# Only used when vendor name appears in CVE CPE list OR description.
VENDOR_TO_STACK_KEYWORDS: dict[str, list[str]] = {
    "microsoft":   ["windows", "iis", "exchange", "sharepoint", "azure", ".net", "mssql"],
    "apache":      ["apache", "tomcat", "httpd", "struts", "kafka", "spark"],
    "nginx":       ["nginx"],
    "openssl":     ["openssl"],
    "linux":       ["linux", "ubuntu", "centos", "rhel", "debian"],
    "cisco":       ["cisco", "ios"],
    "oracle":      ["oracle", "mysql", "weblogic"],
    "vmware":      ["vmware", "vsphere", "esxi"],
    "wordpress":   ["wordpress"],
    "drupal":      ["drupal"],
    "jquery":      ["jquery"],
    "spring":      ["spring", "springboot"],
    "log4j":       ["log4j"],
    "jenkins":     ["jenkins"],
    "docker":      ["docker"],
    "kubernetes":  ["kubernetes", "k8s"],
    "nodejs":      ["nodejs", "node/"],
    "express":     ["express/"],
    "react":       ["react/"],
    "mongodb":     ["mongodb"],
    "postgresql":  ["postgresql", "postgres"],
    "redis":       ["redis"],
    "nginx":       ["nginx"],
    "php":         ["php"],
}

# CWE → asset_type mapping — only matches assets that have an explicit 'asset_type' field
# matching one of these values. No asset_type field = no CWE match.
CWE_TO_ASSET_TYPE: dict[str, list[str]] = {
    "CWE-89":  ["database", "api"],
    "CWE-79":  ["web_app", "frontend"],
    "CWE-78":  ["server", "vm"],
    "CWE-287": ["identity", "auth"],
    "CWE-306": ["api", "server"],
    "CWE-22":  ["storage", "server"],
    "CWE-787": ["server", "vm", "endpoint"],
    "CWE-416": ["server", "vm", "endpoint"],
    "CWE-502": ["api", "server"],
}


def run(
    cve_records:      list[dict],
    business_context: dict | None = None,
) -> list[dict]:
    """
    Match each CVE to affected assets using 4-strategy layered matching.
    Strategy 4 (broad stack fallback) is intentionally removed.
    A CVE with no match stays unmatched and gets LOW priority — correct behaviour.
    """
    assets = load_assets()

    # Normalize column names
    if "asset_name" in assets.columns and "name" not in assets.columns:
        assets = assets.rename(columns={"asset_name": "name"})
    if "software_installed" in assets.columns and "software_stack" not in assets.columns:
        assets = assets.rename(columns={"software_installed": "software_stack"})

    assets_list = assets.to_dict("records")

    enriched = []
    match_stats = {"cpe": 0, "vendor": 0, "package": 0, "cwe": 0, "none": 0}

    for rec in cve_records:
        rec = dict(rec)

        matched, method, confidence = _match_assets(rec, assets_list)
        match_stats[method] = match_stats.get(method, 0) + 1

        if matched:
            worst = _pick_worst_asset(matched)
            rec["matched_assets"]         = matched
            rec["worst_asset"]            = worst
            rec["asset_name"]             = worst.get("name", "")
            rec["criticality"]            = worst.get("criticality", "medium")
            rec["internet_facing"]        = bool(worst.get("internet_facing", False))
            rec["asset_match_method"]     = method
            rec["asset_match_confidence"] = confidence
        else:
            rec["matched_assets"]         = []
            rec["worst_asset"]            = {}
            rec["asset_name"]             = "No direct asset match"
            rec["criticality"]            = "low"
            rec["internet_facing"]        = False
            rec["asset_match_method"]     = "none"
            rec["asset_match_confidence"] = "NONE"

        enriched.append(rec)

    _print_summary(enriched, match_stats)
    return enriched


def _match_assets(
    rec:    dict,
    assets: list[dict],
) -> tuple[list[dict], str, str]:
    """Try each strategy in order; return on first hit."""

    cpe_vendors  = set()
    cpe_products = set()
    for cpe in rec.get("affected", []):
        v = extract_vendor_from_cpe(cpe).lower()
        p = extract_product_from_cpe(cpe).lower().replace("_", " ")
        if v: cpe_vendors.add(v)
        if p: cpe_products.add(p)

    # ── Strategy 1: CPE vendor/product exact match ────────────────────────────
    if cpe_vendors or cpe_products:
        matched = []
        for asset in assets:
            stack = _get_stack(asset)
            # Check vendor keywords
            for vendor in cpe_vendors:
                kws = VENDOR_TO_STACK_KEYWORDS.get(vendor, [vendor])
                if any(kw in s for kw in kws for s in stack):
                    matched.append(asset)
                    break
            else:
                # Check product name directly in stack
                for prod in cpe_products:
                    if prod and any(prod in s for s in stack):
                        matched.append(asset)
                        break
        if matched:
            return _dedup(matched), "cpe", "HIGH"

    # ── Strategy 2: Vendor name in CVE description → specific stack match ─────
    description = rec.get("description", "").lower()
    vendor_matched = []
    for vendor, stack_kws in VENDOR_TO_STACK_KEYWORDS.items():
        # Require vendor to be explicitly named in description
        if f" {vendor} " in f" {description} " or f"{vendor}/" in description:
            for asset in assets:
                stack = _get_stack(asset)
                if any(kw in s for kw in stack_kws for s in stack):
                    vendor_matched.append(asset)
    if vendor_matched:
        return _dedup(vendor_matched), "vendor", "MEDIUM"

    # ── Strategy 3: Specific package name in CVE description ─────────────────
    # Look for any asset's specific package version mentioned in CVE text
    pkg_matched = []
    for asset in assets:
        stack = _get_stack(asset)
        for pkg in stack:
            # e.g. "express/4.18" — check if pkg name (before /) appears in description
            pkg_name = pkg.split("/")[0].lower()
            if len(pkg_name) >= 4 and pkg_name in description:
                pkg_matched.append(asset)
                break
    if pkg_matched:
        return _dedup(pkg_matched), "package", "MEDIUM"

    # ── Strategy 4: CWE → asset_type (only if asset has explicit asset_type) ──
    cwe = rec.get("cwe", "UNKNOWN")
    target_types = CWE_TO_ASSET_TYPE.get(cwe, [])
    if target_types:
        type_matched = [
            a for a in assets
            if any(t in str(a.get("asset_type", "")).lower() for t in target_types)
        ]
        if type_matched:
            return type_matched, "cwe", "LOW"

    return [], "none", "NONE"


def _get_stack(asset: dict) -> list[str]:
    stack = asset.get("software_stack", asset.get("software_installed", []))
    if not isinstance(stack, list):
        stack = [str(stack)]
    return [s.lower() for s in stack]


def _dedup(assets: list[dict]) -> list[dict]:
    seen = set()
    result = []
    for a in assets:
        key = a.get("asset_id", id(a))
        if key not in seen:
            seen.add(key)
            result.append(a)
    return result


def _pick_worst_asset(assets: list[dict]) -> dict:
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    return min(
        assets,
        key=lambda a: (
            order.get(str(a.get("criticality", "low")).lower(), 9),
            not a.get("internet_facing", False),
        )
    )


def _print_summary(records: list[dict], stats: dict) -> None:
    matched_count = sum(1 for r in records if r["matched_assets"])
    unmatched     = len(records) - matched_count
    print(f"[Agent 5] Asset matching complete for {len(records)} CVEs:")
    print(f"  Matched           : {matched_count}  Unmatched: {unmatched}")
    print(f"  By method         : CPE={stats.get('cpe',0)}  "
          f"Vendor={stats.get('vendor',0)}  "
          f"Package={stats.get('package',0)}  "
          f"CWE={stats.get('cwe',0)}  "
          f"None={stats.get('none',0)}")
    if matched_count:
        internet = sum(1 for r in records if r.get("internet_facing"))
        critical = sum(1 for r in records if r.get("criticality") == "critical")
        print(f"  Internet-facing   : {internet} matched CVEs on exposed assets")
        print(f"  Critical assets   : {critical} matched CVEs on critical assets")
