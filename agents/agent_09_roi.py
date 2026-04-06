"""
agent_09_roi.py — ROI Calculation Agent
Responsibility: Compute the dollar value of patching vs. not patching each CVE.
Outputs a CFO-level justification: "patching this CVE costs $X in engineering
time but prevents an expected $Y in breach costs."

This is the output that no competitor produces. It turns a security recommendation
into a business decision with quantified outcomes.

Input:  CVE records (from Agent 8) + business_context dict
Output: same records + roi_patch_cost, roi_breach_risk, roi_net_benefit, roi_summary
"""

from __future__ import annotations
from typing import Optional

from agents.shared.scoring import score_cve


# ── Cost constants ─────────────────────────────────────────────────────────────

# Engineering cost to apply a patch (hours × hourly rate)
PATCH_HOURS = {
    "PATCH NOW — EMERGENCY":           8,    # emergency all-hands
    "PATCH NOW":                       4,    # dedicated sprint ticket
    "PATCH — SCHEDULED":               2,    # next sprint
    "PATCH WITH CAUTION — Test in staging first": 6,  # test + deploy
    "MONITOR":                         1,    # ticket + watch
    "UNKNOWN — Check vendor advisory": 2,
}
ENGINEER_HOURLY_RATE = 75   # $75/hr — mid-market senior engineer rate

# Breach cost components (IBM Cost of a Data Breach 2024 anchors)
BREACH_COST_BASE     = 4_880_000    # IBM 2024 global average
RANSOMWARE_MULTIPLIER = 1.5         # ransomware incidents cost 50% more on average
DOWNTIME_DAILY_COST  =    50_000    # conservative enterprise downtime cost per day
DOWNTIME_DAYS        =       21     # median days from breach to containment

# Analyst labor cost (manual triage — what ARIA eliminates)
ANALYST_HOURLY      = 60
MANUAL_TRIAGE_HOURS = 2            # hours spent per CVE under manual CVSS-only triage

# Probability models: how likely is exploitation without patching?
# Based on EPSS ranges validated in our data analysis
EXPLOIT_PROBABILITY_BY_PRIORITY = {
    "CRITICAL":  0.85,   # KEV/ransomware: near-certain if unpatched
    "HIGH":      0.50,   # EPSS ≥ 0.50
    "MEDIUM":    0.15,   # EPSS ≥ 0.10
    "LOW":       0.02,   # low EPSS
}


def run(
    cve_records:      list[dict],
    business_context: dict,
) -> list[dict]:
    """
    Compute ROI for each CVE. Adds:
      - roi_patch_cost      : $  — engineering cost to apply the patch
      - roi_breach_risk     : $  — expected breach cost (probability × impact)
      - roi_net_benefit     : $  — breach_risk - patch_cost (positive = good ROI to patch)
      - roi_annual_savings  : $  — annualized savings if patched vs. not patched
      - roi_payback_days    : int — days until ROI is positive
      - roi_vs_manual       : $  — savings vs. manual CVSS-only triage
      - roi_recommendation  : str — "HIGH ROI — Patch immediately" etc.
      - roi_summary         : str — one-line CFO summary
      - aria_score          : ARIAScore dataclass (full scoring result)
      - final_score         : float — ARIA risk score for sorting
    """
    org_breach_cost = business_context.get("breach_cost_estimate", BREACH_COST_BASE)
    enriched        = []

    for rec in cve_records:
        rec = dict(rec)

        # ── Full ARIA score ────────────────────────────────────────────────────
        aria = score_cve(
            cve_id          = rec["cve_id"],
            cvss            = rec.get("cvss"),
            epss            = rec.get("epss", 0.00197),
            in_kev          = rec.get("in_kev", False),
            ransomware      = rec.get("ransomware", False),
            asset_name      = rec.get("asset_name"),
            criticality     = rec.get("criticality", "medium"),
            internet_facing = rec.get("internet_facing", False),
            compliance_fine = rec.get("compliance_fine", 0.0),
            blast_radius    = rec.get("blast_radius", 0.0),
            patch_available = rec.get("patch_available"),
        )

        rec["aria_score_obj"]  = None   # don't serialize the dataclass directly
        rec["base_score"]      = aria.base_score
        rec["final_score"]     = aria.final_score
        rec["aria_reasoning"]  = aria.reasoning  # replaces old reasoning list
        rec["confidence"]      = aria.confidence
        rec["confidence_score"]= aria.confidence_score

        # ── Patch cost ────────────────────────────────────────────────────────
        action       = rec.get("patch_action", "MONITOR")
        patch_hours  = PATCH_HOURS.get(action, 2)
        patch_cost   = patch_hours * ENGINEER_HOURLY_RATE
        rec["roi_patch_cost"] = patch_cost

        # ── Breach risk ───────────────────────────────────────────────────────
        priority       = rec.get("exploit_priority", "LOW")
        exploit_prob   = EXPLOIT_PROBABILITY_BY_PRIORITY.get(priority, 0.05)

        # Adjust probability by EPSS (blend with lookup default)
        epss       = rec.get("epss", 0.0)
        blend_prob = max(exploit_prob, epss)   # use whichever is higher

        # Breach impact = org breach cost + compliance fine + downtime
        compliance_fine = rec.get("compliance_fine", 0.0)
        downtime_cost   = DOWNTIME_DAYS * DOWNTIME_DAILY_COST
        blast_multiplier = 1.0 + rec.get("blast_radius", 0.0)  # blast radius amplifies impact

        if rec.get("ransomware"):
            total_impact = (org_breach_cost * RANSOMWARE_MULTIPLIER
                           + compliance_fine + downtime_cost) * blast_multiplier
        else:
            total_impact = (org_breach_cost + compliance_fine + downtime_cost) * blast_multiplier

        breach_risk = round(blend_prob * total_impact)
        rec["roi_breach_risk"] = breach_risk

        # ── Net benefit of patching ───────────────────────────────────────────
        net_benefit = breach_risk - patch_cost
        rec["roi_net_benefit"]  = net_benefit
        rec["roi_annual_savings"] = round(net_benefit * 12 / 30)  # annualize over 30-day window

        # ── Payback period ────────────────────────────────────────────────────
        if breach_risk > 0:
            payback_days = max(1, round(patch_cost / (breach_risk / 365)))
        else:
            payback_days = 365
        rec["roi_payback_days"] = payback_days

        # ── Savings vs. manual CVSS-only approach ────────────────────────────
        # Manual approach: 2 analyst hours per CVE, but misses high-EPSS/low-CVSS CVEs
        manual_cost  = MANUAL_TRIAGE_HOURS * ANALYST_HOURLY
        aria_cost    = 0.10   # ARIA API cost per CVE at claude-sonnet-4-6 rates
        manual_miss_risk = breach_risk * 0.6 if priority == "CRITICAL" else 0  # 60% chance CVSS misses KEV
        rec["roi_vs_manual"] = round(manual_cost - aria_cost + manual_miss_risk)

        # ── ROI recommendation ────────────────────────────────────────────────
        rec["roi_recommendation"] = _roi_recommendation(net_benefit, patch_cost, priority)

        # ── CFO-level one-line summary ────────────────────────────────────────
        rec["roi_summary"] = (
            f"Patch cost: ${patch_cost:,} | Breach risk prevented: ${breach_risk:,} | "
            f"Net ROI: ${net_benefit:,} | Payback: {payback_days} day(s)"
        )

        enriched.append(rec)

    # Final sort: highest final_score first
    enriched.sort(key=lambda r: -r["final_score"])

    _print_summary(enriched)
    return enriched


def _roi_recommendation(net_benefit: float, patch_cost: float, priority: str) -> str:
    if net_benefit > 1_000_000:
        return "EXCEPTIONAL ROI — Patch immediately, high financial risk prevented"
    if net_benefit > 100_000:
        return "HIGH ROI — Prioritize in current sprint"
    if net_benefit > 10_000:
        return "POSITIVE ROI — Schedule patch this week"
    if net_benefit > 0:
        return "MARGINAL ROI — Patch in next sprint"
    if priority in ("CRITICAL", "HIGH"):
        return "LOW ROI but HIGH RISK — Patch regardless (KEV/ransomware risk)"
    return "LOW ROI — Deprioritize unless risk tolerance is low"


def _print_summary(records: list[dict]) -> None:
    total_breach_risk = sum(r["roi_breach_risk"] for r in records)
    total_patch_cost  = sum(r["roi_patch_cost"]  for r in records)
    net_total         = sum(r["roi_net_benefit"]  for r in records)
    high_roi          = sum(1 for r in records if r["roi_net_benefit"] > 100_000)

    print(f"[Agent 9] ROI computed for {len(records)} CVEs:")
    print(f"  Total breach risk   : ${total_breach_risk:,.0f}")
    print(f"  Total patch cost    : ${total_patch_cost:,.0f}")
    print(f"  Net ROI of patching : ${net_total:,.0f}")
    print(f"  High-ROI patches    : {high_roi} (>$100K net benefit)")


if __name__ == "__main__":
    from agents.agent_01_ingest    import run as ingest
    from agents.agent_02_exploit   import run as exploit
    from agents.agent_03_threat    import run as threat
    from agents.agent_04_business  import run as business, DEMO_ORG
    from agents.agent_05_assets    import run as assets_agent
    from agents.agent_06_compliance import run as compliance
    from agents.agent_07_blast     import run as blast
    from agents.agent_08_patch     import run as patch

    cves = ingest()
    cves = exploit(cves)
    cves = threat(cves)
    ctx  = business(DEMO_ORG, "Acme HealthTech")
    cves = assets_agent(cves, ctx)
    cves = compliance(cves, ctx)
    cves = blast(cves)
    cves = patch(cves)
    results = run(cves, ctx)

    print(f"\nTop 5 by ARIA final score:")
    for r in results[:5]:
        print(f"  {r['cve_id']}  score={r['final_score']:.3f}  "
              f"ROI=${r['roi_net_benefit']:,.0f}  "
              f"action={r['patch_action']}")
