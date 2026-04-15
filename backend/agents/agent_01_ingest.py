"""
agent_01_ingest.py — CVE Ingestion Agent
Responsibility: Load CVEs from NVD, normalize fields, filter to a
working set, and return structured CVE records ready for downstream agents.

Input:  optional list of cve_ids to focus on (if empty → use full NVD sample)
Output: list of CVERecord dicts
"""

from __future__ import annotations
import re
from dataclasses import dataclass, asdict
from typing import Optional
import pandas as pd

from agents.shared.data_loader import load_nvd


@dataclass
class CVERecord:
    cve_id:      str
    cvss:        Optional[float]
    severity:    str              # CRITICAL / HIGH / MEDIUM / LOW / UNKNOWN
    cwe:         str              # e.g. "CWE-79"
    published:   str              # ISO date string
    year:        Optional[int]
    description: str
    affected:    list             # list of CPE strings (vendor/product identifiers)


def run(
    cve_ids:    list[str] | None = None,
    min_year:   int | None       = None,
    severities: list[str] | None = None,
) -> list[dict]:
    """
    Main entry point for Agent 1.

    Args:
        cve_ids:    Specific CVE IDs to retrieve. If None, returns full NVD sample.
        min_year:   Only include CVEs published >= this year (e.g. 2023).
        severities: Filter to these severity levels e.g. ["CRITICAL","HIGH"].

    Returns:
        List of CVERecord dicts, sorted by CVSS descending (unknowns at bottom).
    """
    nvd = load_nvd()

    # ── Filter by requested CVE IDs ───────────────────────────────────────────
    if cve_ids:
        requested = set(c.upper().strip() for c in cve_ids)
        nvd = nvd[nvd["cve_id"].isin(requested)].copy()
        # Warn about any not found
        found = set(nvd["cve_id"])
        missing = requested - found
        if missing:
            print(f"[Agent 1] Warning: {len(missing)} CVE(s) not in NVD sample: "
                  f"{', '.join(sorted(missing)[:5])}{'...' if len(missing)>5 else ''}")

    # ── Year filter ───────────────────────────────────────────────────────────
    if min_year is not None:
        nvd = nvd[nvd["year"] >= min_year].copy()

    # ── Severity filter ───────────────────────────────────────────────────────
    if severities:
        upper = [s.upper() for s in severities]
        nvd = nvd[nvd["severity"].isin(upper)].copy()

    # ── Build output records ──────────────────────────────────────────────────
    records = []
    for _, row in nvd.iterrows():
        records.append(asdict(CVERecord(
            cve_id      = row["cve_id"],
            cvss        = float(row["cvss"]) if pd.notna(row["cvss"]) else None,
            severity    = row["severity"],
            cwe         = row["cwe"],
            published   = row["published"].isoformat() if pd.notna(row["published"]) else "",
            year        = int(row["year"]) if pd.notna(row["year"]) else None,
            description = row.get("description", ""),
            affected    = row.get("affected", []),
        )))

    # Sort: CVSS descending; None CVSS goes to the bottom
    records.sort(key=lambda r: (r["cvss"] is None, -(r["cvss"] or 0)))

    print(f"[Agent 1] Ingested {len(records)} CVEs from NVD "
          f"({sum(1 for r in records if r['cvss'] is not None)} with CVSS, "
          f"{sum(1 for r in records if r['cvss'] is None)} without)")
    return records


# ── Utility helpers used by other agents ─────────────────────────────────────

def extract_vendor_from_cpe(cpe: str) -> str:
    """
    Parse a CPE 2.3 string and return the vendor name.
    cpe:2.3:a:microsoft:windows_10:*:*:*:*:*:*:*:* → 'microsoft'
    """
    parts = cpe.split(":")
    return parts[3] if len(parts) > 3 else ""


def extract_product_from_cpe(cpe: str) -> str:
    """
    Parse a CPE 2.3 string and return the product name.
    cpe:2.3:a:microsoft:windows_10:*:*:*:*:*:*:*:* → 'windows_10'
    """
    parts = cpe.split(":")
    return parts[4] if len(parts) > 4 else ""


def get_cve_ids(records: list[dict]) -> list[str]:
    """Convenience: extract just the CVE ID list from a records list."""
    return [r["cve_id"] for r in records]


if __name__ == "__main__":
    results = run()
    print(f"\nTop 5 by CVSS:")
    for r in results[:5]:
        print(f"  {r['cve_id']}  CVSS={r['cvss']}  {r['severity']}  {r['cwe']}")
