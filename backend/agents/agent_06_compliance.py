"""
agent_06_compliance.py — Compliance Impact Agent
Responsibility: For each CVE × matched asset, estimate the regulatory fine
exposure if this CVE is exploited. Converts abstract risk into dollar amounts
that CFOs and boards understand.

Frameworks covered: PCI DSS, HIPAA, SOC2, GDPR

Input:  CVE records (from Agent 5) + business_context dict
Output: same records + compliance_fine, compliance_flags, compliance_reasoning
"""

from __future__ import annotations
from typing import Optional


# ── Fine models ────────────────────────────────────────────────────────────────
# Based on publicly documented regulatory fine ranges and real breach settlements.

PCI_DSS = {
    "description": "Payment Card Industry Data Security Standard",
    "fine_per_month_min":   5_000,
    "fine_per_month_max": 100_000,
    "fine_per_month_mid":  60_000,   # midpoint used for estimates
    "months_exposure":      3,       # typical investigation + remediation period
    "applies_when":         "handles_payments",
    "severity_multiplier": {
        "CRITICAL": 1.5,
        "HIGH":     1.0,
        "MEDIUM":   0.5,
        "LOW":      0.25,
    }
}

HIPAA = {
    "description": "Health Insurance Portability and Accountability Act",
    "fine_per_record_min":      100,
    "fine_per_record_max":   50_000,
    "fine_per_record_mid":   10_000,   # per-record midpoint (varies by negligence)
    "records_exposed_default": 5_000,  # conservative assumed exposure
    "max_annual_penalty":  1_900_000,  # HIPAA annual cap per violation category
    "applies_when":         "handles_health_data",
    "severity_multiplier": {
        "CRITICAL": 1.5,   # willful neglect tier
        "HIGH":     1.0,   # reasonable cause tier
        "MEDIUM":   0.25,  # no knowledge tier
        "LOW":      0.10,
    }
}

SOC2 = {
    "description": "Service Organization Control 2",
    "remediation_cost_min":  20_000,
    "remediation_cost_max": 200_000,
    "remediation_cost_mid":  50_000,  # re-audit + remediation
    "customer_churn_risk":   25_000,  # estimated contract risk per enterprise customer
    "applies_when":         "is_technology_company",
    "severity_multiplier": {
        "CRITICAL": 2.0,
        "HIGH":     1.0,
        "MEDIUM":   0.5,
        "LOW":      0.25,
    }
}

GDPR = {
    "description": "General Data Protection Regulation (EU)",
    "fine_pct_global_revenue":  0.04,  # up to 4% global annual revenue
    "fine_absolute_max":  20_000_000,  # €20M cap
    "fine_estimate_smb":     500_000,  # conservative for smaller orgs
    "applies_when":         "handles_eu_data",
    "severity_multiplier": {
        "CRITICAL": 2.0,
        "HIGH":     1.0,
        "MEDIUM":   0.5,
        "LOW":      0.1,
    }
}

# CWE types that directly expose regulated data (higher fine multiplier)
DATA_EXPOSURE_CWES = {
    "CWE-89",   # SQL Injection — direct database access
    "CWE-22",   # Path Traversal — file system access
    "CWE-611",  # XXE — data extraction
    "CWE-200",  # Information Exposure
    "CWE-918",  # SSRF — internal data access
    "CWE-359",  # Privacy Violation
    "CWE-256",  # Plaintext Password Storage
    "CWE-522",  # Insufficiently Protected Credentials
}


def run(
    cve_records:      list[dict],
    business_context: dict,
) -> list[dict]:
    """
    For each CVE record, compute:
      - compliance_fine       : total estimated annual fine exposure ($)
      - compliance_flags      : list of applicable frameworks ("PCI DSS", "HIPAA", etc.)
      - compliance_breakdown  : dict of {framework: dollar_amount}
      - compliance_reasoning  : plain-English explanation for the report

    Returns records sorted by compliance_fine descending within each priority tier.
    """
    enriched = []
    total_fine_exposure = 0

    for rec in cve_records:
        rec   = dict(rec)
        asset = rec.get("worst_asset", {})

        # Determine which frameworks apply based on asset scope + org context
        flags      = []
        breakdown  = {}
        reasoning  = []

        severity = rec.get("severity", "MEDIUM").upper()
        cwe      = rec.get("cwe", "UNKNOWN")
        is_data_exposure = cwe in DATA_EXPOSURE_CWES

        # ── PCI DSS ───────────────────────────────────────────────────────────
        pci_scope = asset.get("pci_dss_scope", False) or business_context.get("handles_payments", False)
        if pci_scope:
            mult = PCI_DSS["severity_multiplier"].get(severity, 0.5)
            if is_data_exposure:
                mult *= 1.5
            fine = PCI_DSS["fine_per_month_mid"] * PCI_DSS["months_exposure"] * mult
            flags.append("PCI DSS")
            breakdown["PCI DSS"] = round(fine)
            reasoning.append(
                f"PCI DSS: ${fine:,.0f} estimated fine — "
                f"payment data asset, {severity.lower()} severity CVE, "
                f"{PCI_DSS['months_exposure']} month exposure window."
            )

        # ── HIPAA ─────────────────────────────────────────────────────────────
        hipaa_scope = asset.get("hipaa_scope", False) or business_context.get("handles_health_data", False)
        if hipaa_scope:
            mult    = HIPAA["severity_multiplier"].get(severity, 0.25)
            records = HIPAA["records_exposed_default"]
            fine    = min(
                HIPAA["fine_per_record_mid"] * records * mult,
                HIPAA["max_annual_penalty"]
            )
            if is_data_exposure:
                fine = min(fine * 2, HIPAA["max_annual_penalty"])
            flags.append("HIPAA")
            breakdown["HIPAA"] = round(fine)
            reasoning.append(
                f"HIPAA: ${fine:,.0f} estimated penalty — "
                f"health data asset, ~{records:,} records at risk, "
                f"{severity.lower()} negligence tier."
            )

        # ── SOC2 ──────────────────────────────────────────────────────────────
        soc2_scope = asset.get("soc2_scope", False) or business_context.get("is_technology_company", False)
        if soc2_scope:
            mult = SOC2["severity_multiplier"].get(severity, 0.5)
            fine = (SOC2["remediation_cost_mid"] + SOC2["customer_churn_risk"]) * mult
            flags.append("SOC2")
            breakdown["SOC2"] = round(fine)
            reasoning.append(
                f"SOC2: ${fine:,.0f} estimated cost — "
                f"re-audit + enterprise customer churn risk at {severity.lower()} severity."
            )

        # ── GDPR ──────────────────────────────────────────────────────────────
        gdpr_scope = business_context.get("handles_eu_data", False)
        if gdpr_scope:
            mult = GDPR["severity_multiplier"].get(severity, 0.5)
            fine = GDPR["fine_estimate_smb"] * mult
            flags.append("GDPR")
            breakdown["GDPR"] = round(fine)
            reasoning.append(
                f"GDPR: ${fine:,.0f} estimated fine — "
                f"EU data handling, {severity.lower()} severity breach."
            )

        total_fine = sum(breakdown.values())
        total_fine_exposure += total_fine

        rec["compliance_fine"]      = total_fine
        rec["compliance_flags"]     = flags
        rec["compliance_breakdown"] = breakdown
        rec["compliance_reasoning"] = reasoning

        enriched.append(rec)

    _print_summary(enriched, total_fine_exposure)
    return enriched


def _print_summary(records: list[dict], total: float) -> None:
    with_fines = sum(1 for r in records if r["compliance_fine"] > 0)
    all_flags  = []
    for r in records:
        all_flags.extend(r["compliance_flags"])
    from collections import Counter
    flag_counts = Counter(all_flags)

    print(f"[Agent 6] Compliance impact assessed for {len(records)} CVEs:")
    print(f"  CVEs with fine exposure : {with_fines}")
    print(f"  Total fine exposure     : ${total:,.0f}")
    print(f"  By framework            : " +
          ", ".join(f"{k}={v}" for k, v in flag_counts.items()))


if __name__ == "__main__":
    from agents.agent_01_ingest  import run as ingest
    from agents.agent_02_exploit import run as exploit
    from agents.agent_03_threat  import run as threat
    from agents.agent_04_business import run as business, DEMO_ORG
    from agents.agent_05_assets  import run as assets

    cves = ingest()
    cves = exploit(cves)
    cves = threat(cves)
    ctx  = business(DEMO_ORG, "Acme HealthTech")
    cves = assets(cves, ctx)
    results = run(cves, ctx)

    with_fines = [r for r in results if r["compliance_fine"] > 0]
    print(f"\nTop 5 compliance fine exposures:")
    for r in sorted(with_fines, key=lambda x: -x["compliance_fine"])[:5]:
        print(f"  {r['cve_id']}  ${r['compliance_fine']:,.0f}  {r['compliance_flags']}")
